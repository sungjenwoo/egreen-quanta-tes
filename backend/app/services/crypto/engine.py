"""Verification orchestration — ties the crypto primitives into a VerificationResult."""

from __future__ import annotations

import base64
import contextlib
import datetime as dt
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.certificate import Certificate
from app.services.crypto import cms_pkcs7, jws, rsa_ecc, weak_algo
from app.services.crypto.errors import MaterialParseError
from app.services.crypto.hashes import sha256_hex
from app.services.crypto.revocation import check_revocation
from app.services.crypto.types import (
    CertInfo,
    ChainResult,
    CryptoFinding,
    FindingCategory,
    RevocationResult,
    Severity,
    SignatureParams,
    Verdict,
    VerificationResult,
)
from app.services.crypto.x509_chain import build_and_validate
from app.services.crypto.x509_utils import (
    cert_info,
    load_certificates,
    load_public_key,
    spki_sha256,
)

log = get_logger("egreen.verify")


def _b64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise MaterialParseError(f"Invalid base64 input: {exc}") from exc


def _decide(
    sig_ok: bool, chain: ChainResult | None, revocation: RevocationResult | None
) -> Verdict:
    if not sig_ok:
        return Verdict.INVALID
    if revocation is not None and revocation.status == "revoked":
        return Verdict.INVALID
    if chain is not None and chain.status not in {"trusted", None}:
        return Verdict.INDETERMINATE
    return Verdict.VALID


async def _persist_certificate(
    session: AsyncSession, cert: x509.Certificate
) -> list[CryptoFinding]:
    """Upsert an observed certificate; emit T11 if the key reappears under a new subject."""
    findings: list[CryptoFinding] = []
    der = cert.public_bytes(serialization.Encoding.DER)
    fp = hashlib.sha256(der).hexdigest()
    spki = spki_sha256(cert.public_key())
    info = cert_info(cert)
    now = dt.datetime.now(dt.UTC)

    existing = (
        await session.execute(select(Certificate).where(Certificate.fingerprint_sha256 == fp))
    ).scalar_one_or_none()

    if existing is not None:
        existing.times_seen += 1
        existing.last_seen_at = now
    else:
        others = (
            (
                await session.execute(
                    select(Certificate.subject).where(
                        Certificate.spki_sha256 == spki, Certificate.subject != info.subject
                    )
                )
            )
            .scalars()
            .all()
        )
        if others:
            findings.append(
                CryptoFinding(
                    code="T11",
                    title="Public key reused across identities",
                    severity=Severity.HIGH,
                    category=FindingCategory.POLICY,
                    detail=f"SPKI also seen under: {', '.join(sorted(set(others))[:3])}",
                )
            )
        session.add(
            Certificate(
                spki_sha256=spki,
                fingerprint_sha256=fp,
                subject=info.subject,
                issuer=info.issuer,
                serial_hex=info.serial_hex,
                not_before=info.not_before,
                not_after=info.not_after,
                sig_algo=info.sig_algo,
                key_type=info.key.key_type,
                key_bits=info.key.key_bits,
                curve=info.key.curve,
                is_ca=info.is_ca,
                self_signed=info.self_signed,
                pem=info.pem,
                first_seen_at=now,
                last_seen_at=now,
            )
        )
    await session.commit()
    return findings


async def _chain_and_revocation(
    session: AsyncSession,
    leaf: x509.Certificate,
    extra: list[x509.Certificate],
    at_time: dt.datetime,
) -> tuple[ChainResult, RevocationResult | None, list[CryptoFinding]]:
    from app.services.crypto.trust_store import enabled_anchor_certs

    anchors = await enabled_anchor_certs(session)
    chain, findings = build_and_validate(
        leaf, extra_certs=extra, trust_anchors=anchors, at_time=at_time
    )

    issuer = None
    if len(chain.chain) > 1:
        issuer_subject = chain.chain[1].subject
        for c in [*extra, *anchors]:
            if c.subject.rfc4514_string() == issuer_subject:
                issuer = c
                break

    revocation, rev_findings = check_revocation(leaf, issuer)
    findings.extend(rev_findings)
    return chain, revocation, findings


async def verify_raw_signature(
    session: AsyncSession,
    *,
    data_b64: str,
    signature_b64: str,
    hash_alg: str | None,
    padding: str | None = None,
    certificate_pem: str | None = None,
    public_key_pem: str | None = None,
    is_prehashed: bool = False,
    verify_time: dt.datetime | None = None,
) -> VerificationResult:
    data = _b64(data_b64)
    signature = _b64(signature_b64)
    at_time = verify_time or dt.datetime.now(dt.UTC)

    leaf_cert: x509.Certificate | None = None
    extra_certs: list[x509.Certificate] = []
    if certificate_pem:
        certs = load_certificates(certificate_pem.encode())
        leaf_cert, extra_certs = certs[0], certs[1:]
        public_key = leaf_cert.public_key()
    elif public_key_pem:
        public_key = load_public_key(public_key_pem.encode())
    else:
        raise MaterialParseError("Provide either certificate_pem or public_key_pem")

    outcome = rsa_ecc.verify_raw(
        public_key=public_key,
        message=None if is_prehashed else data,
        prehashed_digest=data if is_prehashed else None,
        hash_alg=hash_alg,
        signature=signature,
        padding_mode=padding,
    )
    params: SignatureParams = outcome.params

    result = VerificationResult(
        verdict=Verdict.INDETERMINATE,
        envelope="raw",
        signature=params,
        signer=None,
        chain=None,
        revocation=None,
        signing_time=None,
        tsa_present=False,
        tsa_trusted=False,
        payload_sha256=sha256_hex(data),
    )

    if not outcome.verified:
        result.add(
            CryptoFinding(
                code="T01",
                title="Signature does not verify",
                severity=Severity.CRITICAL,
                category=FindingCategory.FORGERY,
                detail=outcome.error or "cryptographic verification failed",
            )
        )

    for f in weak_algo.signature_findings(params):
        result.add(f)

    if leaf_cert is not None:
        result.signer = cert_info(leaf_cert)
        for f in weak_algo.certificate_findings(result.signer):
            result.add(f)
        for f in await _persist_certificate(session, leaf_cert):
            result.add(f)
        chain, revocation, chain_findings = await _chain_and_revocation(
            session, leaf_cert, extra_certs, at_time
        )
        result.chain = chain
        result.revocation = revocation
        for f in chain_findings:
            result.add(f)

    result.verdict = _decide(outcome.verified, result.chain, result.revocation)
    result.summary = _summarize(result)
    return result


async def validate_certificate(
    session: AsyncSession,
    *,
    certificate_pem: str,
    extra_chain_pem: str | None = None,
    expected_eku: str | None = None,
    verify_time: dt.datetime | None = None,
) -> VerificationResult:
    at_time = verify_time or dt.datetime.now(dt.UTC)
    certs = load_certificates(certificate_pem.encode())
    leaf, inline_extra = certs[0], certs[1:]
    extra = list(inline_extra)
    if extra_chain_pem:
        extra.extend(load_certificates(extra_chain_pem.encode()))

    info: CertInfo = cert_info(leaf)
    result = VerificationResult(
        verdict=Verdict.INDETERMINATE,
        envelope="raw",
        signature=None,
        signer=info,
        chain=None,
        revocation=None,
        signing_time=None,
        tsa_present=False,
        tsa_trusted=False,
    )

    for f in weak_algo.certificate_findings(info, expected_eku=expected_eku):
        result.add(f)
    for f in await _persist_certificate(session, leaf):
        result.add(f)

    chain, revocation, chain_findings = await _chain_and_revocation(session, leaf, extra, at_time)
    result.chain = chain
    result.revocation = revocation
    for f in chain_findings:
        result.add(f)

    # issuer-anomaly (T12) against the CA allow-list
    for f in await _issuer_allowlist_findings(session, info, chain):
        result.add(f)

    trusted = chain.status == "trusted"
    revoked = revocation is not None and revocation.status == "revoked"
    expired = any(f.code == "T08" for f in result.findings)
    if revoked or expired:
        result.verdict = Verdict.INVALID
    elif trusted:
        result.verdict = Verdict.VALID
    else:
        result.verdict = Verdict.INDETERMINATE
    result.summary = _summarize(result)
    return result


async def _issuer_allowlist_findings(
    session: AsyncSession, info: CertInfo, chain: ChainResult
) -> list[CryptoFinding]:
    from app.models.trust_anchor import CaAllowlistEntry

    rows = (await session.execute(select(CaAllowlistEntry))).scalars().all()
    if not rows:
        return []
    actual_issuer_spki = chain.chain[1].spki_sha256 if len(chain.chain) > 1 else None
    out: list[CryptoFinding] = []
    for entry in rows:
        if entry.subject_pattern.lower() in info.subject.lower() and (
            actual_issuer_spki != entry.issuer_spki_sha256
        ):
            out.append(
                CryptoFinding(
                    code="T12",
                    title="Unexpected issuing CA",
                    severity=Severity.HIGH,
                    category=FindingCategory.POLICY,
                    detail=f"'{info.subject}' should be issued by "
                    f"{entry.issuer_spki_sha256[:16]}… but was issued by "
                    f"{(actual_issuer_spki or 'unknown')[:16]}…",
                )
            )
    return out


async def verify_document(
    session: AsyncSession,
    *,
    filename: str,
    content: bytes,
    external_content: bytes | None = None,
    verify_time: dt.datetime | None = None,
) -> VerificationResult:
    at_time = verify_time or dt.datetime.now(dt.UTC)
    lower = filename.lower()

    if lower.endswith(".pdf") or content[:5] == b"%PDF-":
        return await _verify_pdf(session, content, at_time)
    if lower.endswith((".jws", ".jwt")) or (content[:2] == b"ey" and content.count(b".") == 2):
        return _verify_jws(content)
    if _looks_like_image(content, lower):
        return _verify_image(content)

    # Everything else is treated as CMS/PKCS#7 — but only if it actually looks
    # like one, so an unrelated upload gets a helpful error instead of a raw
    # ASN.1 parser complaint.
    cms_ext = lower.endswith((".p7s", ".p7m", ".p7b", ".p7c", ".cms", ".der", ".pkcs7"))
    looks_der = content[:1] == b"\x30"
    looks_pem = b"-----BEGIN" in content[:256] and (
        b"PKCS7" in content[:256] or b"CMS" in content[:256]
    )
    if cms_ext or looks_der or looks_pem:
        return await _verify_cms(session, content, external_content, at_time)

    raise MaterialParseError(
        "Unrecognised file. Upload a signed PDF (starts with %PDF-), a CMS/PKCS#7 "
        "signature (.p7s / .p7m, DER or PEM), or a compact JWS token. This file "
        "matches none of those."
    )


def _looks_like_image(content: bytes, filename: str) -> bool:
    """Identify common image containers without trusting the filename alone."""
    signatures = (
        content.startswith(b"\xff\xd8\xff"),
        content.startswith(b"\x89PNG\r\n\x1a\n"),
        content.startswith((b"GIF87a", b"GIF89a")),
        content.startswith(b"BM"),
        content.startswith(b"RIFF") and content[8:12] == b"WEBP",
        content.startswith(b"II*\x00") or content.startswith(b"MM\x00*"),
    )
    extension_hint = filename.endswith(
        (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff")
    )
    return any(signatures) or (extension_hint and bool(content))


def _verify_image(content: bytes) -> VerificationResult:
    """Return an honest result for a photograph/scan.

    OCR or visual metadata is evidence only; an image has no signed envelope that
    this cryptographic engine can validate. This deliberately cannot return VALID.
    """
    digest = hashlib.sha256(content).hexdigest()
    return VerificationResult(
        verdict=Verdict.INDETERMINATE,
        envelope="image",
        signature=None,
        signer=None,
        chain=None,
        revocation=None,
        signing_time=None,
        tsa_present=False,
        tsa_trusted=False,
        payload_sha256=digest,
        summary=(
            "Image/scan received. Cryptographic verification is INSUFFICIENT / "
            "NOT AVAILABLE. Extracted certificate fields may be compared with an "
            "Admin trusted record, but that correspondence is not cryptographic proof."
        ),
        trusted_record_status="NOT_CHECKED",
        cryptographic_verification="INSUFFICIENT / NOT AVAILABLE",
        overall_result="INDETERMINATE",
    )


def _verify_jws(content: bytes) -> VerificationResult:
    token = content.decode("ascii", errors="ignore").strip()
    header = jws.parse_header(token)
    # A JWS with x5c can carry its own cert; otherwise we can only report structure.
    x5c = header.get("x5c")
    result = VerificationResult(
        verdict=Verdict.INDETERMINATE,
        envelope="jws",
        signature=SignatureParams(algorithm=f"jws-{header.get('alg', '?').lower()}", hash_alg=None),
        signer=None,
        chain=None,
        revocation=None,
        signing_time=None,
        tsa_present=False,
        tsa_trusted=False,
    )
    if not x5c:
        result.add(
            CryptoFinding(
                code="T13",
                title="JWS carries no embedded certificate",
                severity=Severity.LOW,
                category=FindingCategory.POLICY,
                detail="No x5c header; supply the signer key via the raw endpoint to verify.",
            )
        )
        result.summary = "JWS parsed; no key material to verify against."
        return result

    cert_der = base64.b64decode(x5c[0])
    cert = x509.load_der_x509_certificate(cert_der)
    outcome = jws.verify_compact(token, cert.public_key())
    result.signature = outcome.params
    result.signer = cert_info(cert)
    if not outcome.verified:
        result.add(
            CryptoFinding(
                code="T01",
                title="JWS signature does not verify",
                severity=Severity.CRITICAL,
                category=FindingCategory.FORGERY,
                detail=outcome.error or "verification failed",
            )
        )
    for f in weak_algo.signature_findings(outcome.params):
        result.add(f)
    result.payload_sha256 = sha256_hex(outcome.payload) if outcome.payload else None
    result.verdict = Verdict.VALID if outcome.verified else Verdict.INVALID
    result.summary = _summarize(result)
    return result


async def _verify_cms(
    session: AsyncSession,
    content: bytes,
    external_content: bytes | None,
    at_time: dt.datetime,
) -> VerificationResult:
    cms_result = cms_pkcs7.verify_cms(content, external_content=external_content)
    params = SignatureParams(
        algorithm=f"cms-{cms_result.signature_alg}",
        hash_alg=cms_result.digest_alg or None,
    )
    result = VerificationResult(
        verdict=Verdict.INDETERMINATE,
        envelope="cms",
        signature=params,
        signer=None,
        chain=None,
        revocation=None,
        signing_time=cms_result.signing_time,
        tsa_present=cms_result.tsa_present,
        tsa_trusted=False,
        payload_sha256=sha256_hex(cms_result.content) if cms_result.content else None,
    )

    if not cms_result.verified:
        result.add(
            CryptoFinding(
                code="T01",
                title="CMS signature does not verify",
                severity=Severity.CRITICAL,
                category=FindingCategory.FORGERY,
                detail="; ".join(cms_result.errors) or "verification failed",
            )
        )
    if not cms_result.tsa_present:
        result.add(
            CryptoFinding(
                code="T13",
                title="No trusted timestamp token",
                severity=Severity.LOW,
                category=FindingCategory.TIMESTAMP,
                detail="CMS SignerInfo has no RFC 3161 signature-timestamp attribute.",
            )
        )

    if cms_result.signer_cert_pem:
        signer_cert = load_certificates(cms_result.signer_cert_pem.encode())[0]
        extra = [load_certificates(p.encode())[0] for p in cms_result.extra_certs_pem]
        result.signer = cert_info(signer_cert)
        params.key = result.signer.key
        for f in weak_algo.signature_findings(params):
            result.add(f)
        for f in weak_algo.certificate_findings(result.signer):
            result.add(f)
        for f in await _persist_certificate(session, signer_cert):
            result.add(f)
        chain, revocation, chain_findings = await _chain_and_revocation(
            session, signer_cert, extra, cms_result.signing_time or at_time
        )
        result.chain = chain
        result.revocation = revocation
        for f in chain_findings:
            result.add(f)

    sig_ok = cms_result.verified
    result.verdict = _decide(sig_ok, result.chain, result.revocation)
    result.summary = _summarize(result)
    return result


async def _verify_pdf(
    session: AsyncSession, content: bytes, at_time: dt.datetime
) -> VerificationResult:
    from app.services.crypto.pdf_pades import validate_pdf
    from app.services.crypto.trust_store import enabled_anchor_certs

    anchors = await enabled_anchor_certs(session)
    roots_pem = [a.public_bytes(serialization.Encoding.PEM) for a in anchors]
    report = await validate_pdf(content, trust_roots_pem=roots_pem)

    result = VerificationResult(
        verdict=Verdict.INDETERMINATE,
        envelope="pdf",
        signature=SignatureParams(algorithm="pdf-pkcs7", hash_alg=None),
        signer=None,
        chain=None,
        revocation=None,
        signing_time=None,
        tsa_present=False,
        tsa_trusted=False,
        payload_sha256=sha256_hex(content),
    )
    _ = at_time

    if report.signature_count == 0:
        result.add(
            CryptoFinding(
                code="T13",
                title="PDF has no digital signature",
                severity=Severity.MEDIUM,
                category=FindingCategory.POLICY,
                detail="No embedded signature fields found.",
            )
        )
        result.summary = "Unsigned PDF."
        return result

    any_broken = False
    any_untrusted = False
    for sig in report.signatures:
        if not sig.intact or not sig.valid:
            any_broken = True
            result.add(
                CryptoFinding(
                    code="T01",
                    title=f"PDF signature '{sig.field_name}' is not valid",
                    severity=Severity.CRITICAL,
                    category=FindingCategory.FORGERY,
                    detail="; ".join(sig.errors) or "signature not intact / invalid",
                )
            )
        elif not sig.trusted:
            any_untrusted = True
            result.add(
                CryptoFinding(
                    code="T07",
                    title=f"PDF signature '{sig.field_name}' chains to an untrusted anchor",
                    severity=Severity.HIGH,
                    category=FindingCategory.CHAIN,
                    detail="Signer chain does not terminate in the configured trust store.",
                )
            )
        if sig.digest_algorithm and sig.digest_algorithm.lower() in {"md5", "sha1"}:
            result.add(
                CryptoFinding(
                    code="T02",
                    title="PDF signature uses a weak digest",
                    severity=Severity.HIGH,
                    category=FindingCategory.WEAK_CRYPTO,
                    detail=f"digest = {sig.digest_algorithm}",
                )
            )
        if sig.signing_time and result.signing_time is None:
            with contextlib.suppress(ValueError):
                result.signing_time = dt.datetime.fromisoformat(sig.signing_time)

    if any_broken:
        result.verdict = Verdict.INVALID
    elif any_untrusted:
        result.verdict = Verdict.INDETERMINATE
    else:
        result.verdict = Verdict.VALID
    result.summary = _summarize(result)
    return result


def _summarize(result: VerificationResult) -> str:
    crit = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in result.findings if f.severity == Severity.HIGH)
    bits = [f"verdict={result.verdict.value}"]
    if result.signature:
        bits.append(result.signature.algorithm)
    if result.chain:
        bits.append(f"chain={result.chain.status}")
    if result.revocation:
        bits.append(f"revocation={result.revocation.status}")
    if crit or high:
        bits.append(f"{crit} critical / {high} high findings")
    return ", ".join(bits)
