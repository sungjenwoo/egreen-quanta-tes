"""Schemas for the cryptographic-core API (Module 2)."""

from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, ConfigDict, Field


class RawVerifyRequest(BaseModel):
    data_b64: str = Field(description="Base64 of the signed message (or its digest)")
    signature_b64: str = Field(description="Base64 of the detached signature")
    hash_alg: str | None = Field(
        default="sha256", description="Digest name; omit/None for pure EdDSA"
    )
    padding: str | None = Field(default=None, description="RSA padding: 'pss' or 'pkcs1v15'")
    is_prehashed: bool = False
    certificate_pem: str | None = Field(
        default=None, description="Signer cert (PEM), optionally a chain"
    )
    public_key_pem: str | None = Field(default=None, description="Signer public key (PEM)")
    verify_time: dt.datetime | None = None


class CertValidateRequest(BaseModel):
    certificate_pem: str = Field(description="Leaf certificate (PEM); may include the chain")
    extra_chain_pem: str | None = Field(default=None, description="Additional intermediates (PEM)")
    verify_time: dt.datetime | None = None
    expected_eku: str | None = Field(
        default=None, description="e.g. 'codeSigning', 'emailProtection'"
    )


class FindingOut(BaseModel):
    code: str
    title: str
    severity: str
    category: str
    detail: str


class KeySummary(BaseModel):
    key_type: str | None = None
    key_bits: int | None = None
    curve: str | None = None


class CertInfoOut(BaseModel):
    subject: str
    issuer: str
    serial_hex: str
    not_before: dt.datetime
    not_after: dt.datetime
    spki_sha256: str
    sig_algo: str
    key_type: str
    key_bits: int | None
    curve: str | None
    is_ca: bool
    self_signed: bool
    key_usage: list[str]
    ext_key_usage: list[str]
    san: list[str]


class ChainNodeOut(CertInfoOut):
    pass


class ChainOut(BaseModel):
    status: str
    trust_anchor_spki: str | None
    error: str | None
    chain: list[CertInfoOut]


class RevocationOut(BaseModel):
    status: str
    method: str | None
    detail: str
    revoked_at: dt.datetime | None


class SignatureOut(BaseModel):
    algorithm: str
    hash_alg: str | None
    padding: str | None
    key_type: str | None
    key_bits: int | None
    curve: str | None
    low_s: bool | None
    der_canonical: bool | None


class VerificationOut(BaseModel):
    verdict: str
    envelope: str
    signature: SignatureOut | None
    signer: CertInfoOut | None
    chain: ChainOut | None
    revocation: RevocationOut | None
    signing_time: dt.datetime | None
    tsa_present: bool
    tsa_trusted: bool
    findings: list[FindingOut]
    payload_sha256: str | None
    summary: str
    trusted_record_status: str = "NOT_CHECKED"
    cryptographic_verification: str = "NOT_AVAILABLE"
    overall_result: str = "INDETERMINATE"
    # populated by the detection engine (Module 3)
    risk_score: float = 0.0
    event_id: str | None = None
    alert_id: str | None = None
    incident_id: str | None = None


# ---- trust store ----


class TrustAnchorCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    certificate_pem: str


class TrustAnchorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    subject: str
    spki_sha256: str
    fingerprint_sha256: str
    not_after: dt.datetime
    enabled: bool
    created_at: dt.datetime


class TrustAnchorPatch(BaseModel):
    enabled: bool


class AllowlistCreate(BaseModel):
    subject_pattern: str = Field(min_length=1, max_length=255)
    issuer_spki_sha256: str = Field(min_length=64, max_length=64)
    note: str = Field(default="", max_length=255)


class AllowlistOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    subject_pattern: str
    issuer_spki_sha256: str
    note: str
    created_at: dt.datetime


class CertificateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    spki_sha256: str
    fingerprint_sha256: str
    subject: str
    issuer: str
    serial_hex: str
    not_before: dt.datetime
    not_after: dt.datetime
    sig_algo: str
    key_type: str
    key_bits: int | None
    curve: str | None
    is_ca: bool
    self_signed: bool
    times_seen: int
    first_seen_at: dt.datetime
    last_seen_at: dt.datetime
