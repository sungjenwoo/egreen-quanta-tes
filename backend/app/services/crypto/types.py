"""Domain value objects for the cryptographic core (framework-independent)."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from enum import StrEnum


class Verdict(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    INDETERMINATE = "indeterminate"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(StrEnum):
    FORGERY = "forgery"
    WEAK_CRYPTO = "weak_crypto"
    CHAIN = "chain"
    REVOCATION = "revocation"
    VALIDITY = "validity"
    POLICY = "policy"
    TIMESTAMP = "timestamp"
    QUANTUM = "quantum"


@dataclass(frozen=True, slots=True)
class CryptoFinding:
    """A single observation about a signature/certificate.

    ``code`` matches the threat-model IDs in docs/ARCHITECTURE.md (T01-T18).
    """

    code: str
    title: str
    severity: Severity
    category: FindingCategory
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "detail": self.detail,
        }


@dataclass(slots=True)
class KeyParams:
    key_type: str  # rsa | ec | ed25519 | ed448 | dsa | unknown
    key_bits: int | None = None
    curve: str | None = None
    rsa_exponent: int | None = None


@dataclass(slots=True)
class SignatureParams:
    algorithm: str  # e.g. "sha256-rsa-pss", "sha256-ecdsa", "ed25519"
    hash_alg: str | None  # e.g. "sha256"; None for pure EdDSA
    padding: str | None = None  # "pss" | "pkcs1v15" | None
    key: KeyParams | None = None
    low_s: bool | None = None  # ECDSA only
    der_canonical: bool | None = None


@dataclass(slots=True)
class CertInfo:
    subject: str
    issuer: str
    serial_hex: str
    not_before: dt.datetime
    not_after: dt.datetime
    spki_sha256: str
    sig_algo: str
    key: KeyParams
    is_ca: bool
    self_signed: bool
    key_usage: list[str] = field(default_factory=list)
    ext_key_usage: list[str] = field(default_factory=list)
    san: list[str] = field(default_factory=list)
    pem: str = ""

    def as_dict(self) -> dict:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_hex": self.serial_hex,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "spki_sha256": self.spki_sha256,
            "sig_algo": self.sig_algo,
            "key_type": self.key.key_type,
            "key_bits": self.key.key_bits,
            "curve": self.key.curve,
            "is_ca": self.is_ca,
            "self_signed": self.self_signed,
            "key_usage": self.key_usage,
            "ext_key_usage": self.ext_key_usage,
            "san": self.san,
        }


@dataclass(slots=True)
class ChainResult:
    status: str  # trusted | untrusted | incomplete | error
    chain: list[CertInfo] = field(default_factory=list)
    trust_anchor_spki: str | None = None
    error: str | None = None


@dataclass(slots=True)
class RevocationResult:
    status: str  # good | revoked | unknown | not_checked | error
    method: str | None = None  # crl | ocsp
    detail: str = ""
    revoked_at: dt.datetime | None = None


@dataclass(slots=True)
class VerificationResult:
    verdict: Verdict
    envelope: str  # raw | pdf | cms | jws
    signature: SignatureParams | None
    signer: CertInfo | None
    chain: ChainResult | None
    revocation: RevocationResult | None
    signing_time: dt.datetime | None
    tsa_present: bool
    tsa_trusted: bool
    findings: list[CryptoFinding] = field(default_factory=list)
    payload_sha256: str | None = None
    summary: str = ""
    trusted_record_status: str = "NOT_CHECKED"
    cryptographic_verification: str = "NOT_AVAILABLE"
    overall_result: str = "INDETERMINATE"

    def add(self, finding: CryptoFinding) -> None:
        self.findings.append(finding)

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "envelope": self.envelope,
            "signature": _sig_dict(self.signature),
            "signer": self.signer.as_dict() if self.signer else None,
            "chain": _chain_dict(self.chain),
            "revocation": _rev_dict(self.revocation),
            "signing_time": self.signing_time.isoformat() if self.signing_time else None,
            "tsa_present": self.tsa_present,
            "tsa_trusted": self.tsa_trusted,
            "findings": [f.as_dict() for f in self.findings],
            "payload_sha256": self.payload_sha256,
            "summary": self.summary,
            "trusted_record_status": self.trusted_record_status,
            "cryptographic_verification": self.cryptographic_verification,
            "overall_result": self.overall_result,
        }


def _sig_dict(s: SignatureParams | None) -> dict | None:
    if s is None:
        return None
    return {
        "algorithm": s.algorithm,
        "hash_alg": s.hash_alg,
        "padding": s.padding,
        "key_type": s.key.key_type if s.key else None,
        "key_bits": s.key.key_bits if s.key else None,
        "curve": s.key.curve if s.key else None,
        "low_s": s.low_s,
        "der_canonical": s.der_canonical,
    }


def _chain_dict(c: ChainResult | None) -> dict | None:
    if c is None:
        return None
    return {
        "status": c.status,
        "trust_anchor_spki": c.trust_anchor_spki,
        "error": c.error,
        "chain": [ci.as_dict() for ci in c.chain],
    }


def _rev_dict(r: RevocationResult | None) -> dict | None:
    if r is None:
        return None
    return {
        "status": r.status,
        "method": r.method,
        "detail": r.detail,
        "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
    }
