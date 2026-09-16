"""End-to-end verification orchestration (engine.verify_raw_signature)."""

from __future__ import annotations

import base64
import hashlib

import pytest
from app.models.trust_anchor import TrustAnchor
from app.services.crypto import engine
from app.services.crypto.errors import MaterialParseError
from app.services.crypto.x509_utils import spki_sha256
from cryptography.hazmat.primitives import serialization

from tests.crypto.conftest import sign_message

pytestmark = pytest.mark.asyncio

MSG = b"contract v3 final"


async def _add_root(db_session, pki) -> None:
    cert = pki.root.cert
    db_session.add(
        TrustAnchor(
            name="Demo Root",
            subject=cert.subject.rfc4514_string(),
            spki_sha256=spki_sha256(cert.public_key()),
            fingerprint_sha256=hashlib.sha256(
                cert.public_bytes(serialization.Encoding.DER)
            ).hexdigest(),
            not_after=cert.not_valid_after_utc,
            pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
        )
    )
    await db_session.commit()


async def test_valid_signature_trusted_chain(db_session, demo_pki) -> None:
    await _add_root(db_session, demo_pki)
    leaf = demo_pki.leaves["healthy-ec"]
    sig = sign_message(leaf.key, MSG)

    result = await engine.verify_raw_signature(
        db_session,
        data_b64=base64.b64encode(MSG).decode(),
        signature_b64=base64.b64encode(sig).decode(),
        hash_alg="sha256",
        certificate_pem=demo_pki.chain_pem("healthy-ec"),
    )
    assert result.verdict.value == "valid"
    assert result.chain.status == "trusted"
    assert not any(f.code == "T01" for f in result.findings)


async def test_forged_signature_invalid(db_session, demo_pki) -> None:
    await _add_root(db_session, demo_pki)
    leaf = demo_pki.leaves["healthy-ec"]
    sig = bytearray(sign_message(leaf.key, MSG))
    sig[-1] ^= 0x01

    result = await engine.verify_raw_signature(
        db_session,
        data_b64=base64.b64encode(MSG).decode(),
        signature_b64=base64.b64encode(bytes(sig)).decode(),
        hash_alg="sha256",
        certificate_pem=demo_pki.chain_pem("healthy-ec"),
    )
    assert result.verdict.value == "invalid"
    assert any(f.code == "T01" for f in result.findings)


async def test_untrusted_chain_is_indeterminate(db_session, demo_pki) -> None:
    # no trust anchor inserted
    leaf = demo_pki.leaves["healthy-rsa"]
    sig = sign_message(leaf.key, MSG, rsa_padding="pss")

    result = await engine.verify_raw_signature(
        db_session,
        data_b64=base64.b64encode(MSG).decode(),
        signature_b64=base64.b64encode(sig).decode(),
        hash_alg="sha256",
        padding="pss",
        certificate_pem=demo_pki.chain_pem("healthy-rsa"),
    )
    assert result.verdict.value == "indeterminate"
    assert result.chain.status in {"untrusted", "incomplete"}


async def test_weak_key_leaf_emits_finding(db_session, demo_pki) -> None:
    await _add_root(db_session, demo_pki)
    leaf = demo_pki.leaves["weak-key-rsa1024"]
    sig = sign_message(leaf.key, MSG, rsa_padding="pkcs1v15")

    result = await engine.verify_raw_signature(
        db_session,
        data_b64=base64.b64encode(MSG).decode(),
        signature_b64=base64.b64encode(sig).decode(),
        hash_alg="sha256",
        padding="pkcs1v15",
        certificate_pem=demo_pki.chain_pem("weak-key-rsa1024"),
    )
    assert any(f.code == "T03" for f in result.findings)


async def test_key_reuse_detected(db_session, demo_pki) -> None:
    """Same SPKI under two subjects ⇒ T11 on the second sighting."""
    from app.models.certificate import Certificate

    ec_leaf = demo_pki.leaves["healthy-ec"]
    info_der = ec_leaf.cert.public_bytes(serialization.Encoding.DER)
    db_session.add(
        Certificate(
            spki_sha256=spki_sha256(ec_leaf.cert.public_key()),
            fingerprint_sha256=hashlib.sha256(info_der + b"other").hexdigest(),
            subject="CN=Some Other Identity",
            issuer="CN=whatever",
            serial_hex="01",
            not_before=ec_leaf.cert.not_valid_before_utc,
            not_after=ec_leaf.cert.not_valid_after_utc,
            sig_algo="ecdsa-with-SHA256",
            key_type="ec",
            key_bits=256,
            curve="secp256r1",
            is_ca=False,
            self_signed=False,
            pem="dummy",
        )
    )
    await db_session.commit()

    sig = sign_message(ec_leaf.key, MSG)
    result = await engine.verify_raw_signature(
        db_session,
        data_b64=base64.b64encode(MSG).decode(),
        signature_b64=base64.b64encode(sig).decode(),
        hash_alg="sha256",
        certificate_pem=ec_leaf.cert_pem,
    )
    assert any(f.code == "T11" for f in result.findings)


async def test_verify_document_rejects_non_signature_file(db_session) -> None:
    """A plain upload (e.g. a Markdown doc) must not fall through to the ASN.1
    parser — the caller should get a clear 'unrecognised file' message."""
    with pytest.raises(MaterialParseError, match="Unrecognised file"):
        await engine.verify_document(
            db_session,
            filename="DEMO.md",
            content=b"# Egreen Quanta\n\nThis is documentation, not a signature.\n",
        )


async def test_image_upload_is_not_reported_as_cryptographically_valid(db_session) -> None:
    """A certificate photograph/scan cannot become cryptographic proof by matching fields."""
    result = await engine.verify_document(
        db_session,
        filename="certificate-photo.jpg",
        content=b"\xff\xd8\xff\xe0fake-photo-bytes",
    )
    assert result.envelope == "image"
    assert result.verdict.value == "indeterminate"
    assert result.cryptographic_verification == "INSUFFICIENT / NOT AVAILABLE"
    assert result.overall_result == "INDETERMINATE"
    assert "not cryptographic proof" in result.summary


async def test_verify_document_routes_compact_jws(db_session, demo_pki) -> None:
    """A raw compact JWS (no .jws extension) is still recognised by shape."""
    import jwt as _jwt

    token = _jwt.encode({"sub": "demo"}, demo_pki.leaves["healthy-ec"].key_pem, algorithm="ES256")
    result = await engine.verify_document(db_session, filename="upload.bin", content=token.encode())
    assert result.envelope == "jws"
