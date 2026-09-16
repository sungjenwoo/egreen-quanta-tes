"""Signature verification routes (Module 2 + Module 3 detection)."""

from __future__ import annotations

import base64
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile

from app.api.deps import CurrentUser, SessionDep, client_ip
from app.core.config import settings
from app.core.exceptions import ValidationAppError
from app.core.rate_limit import VERIFY_LIMIT, rate_limit
from app.core.security import hash_ip
from app.models.enums import EventSource
from app.schemas.crypto import RawVerifyRequest, VerificationOut
from app.services.crypto import engine
from app.services.detection.engine import attach_detection

router = APIRouter(prefix="/signatures", tags=["signatures"])

_VerifyRate = Depends(rate_limit("verify", VERIFY_LIMIT))


@router.post("/verify", response_model=VerificationOut, dependencies=[_VerifyRate])
async def verify_signature(
    payload: RawVerifyRequest,
    request: Request,
    session: SessionDep,
    user: CurrentUser,
) -> VerificationOut:
    if not payload.certificate_pem and not payload.public_key_pem:
        raise ValidationAppError("Provide certificate_pem or public_key_pem")
    result = await engine.verify_raw_signature(
        session,
        data_b64=payload.data_b64,
        signature_b64=payload.signature_b64,
        hash_alg=payload.hash_alg,
        padding=payload.padding,
        certificate_pem=payload.certificate_pem,
        public_key_pem=payload.public_key_pem,
        is_prehashed=payload.is_prehashed,
        verify_time=payload.verify_time,
    )
    try:
        sig_bytes = base64.b64decode(payload.signature_b64, validate=True)
    except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
        sig_bytes = None
    enriched = await attach_detection(
        session,
        result,
        source=EventSource.API,
        source_ref="signatures/verify",
        submitter_id=user.id,
        ip_hash=hash_ip(client_ip(request)),
        signature_bytes=sig_bytes,
    )
    return VerificationOut.model_validate(enriched)


@router.post("/verify-document", response_model=VerificationOut, dependencies=[_VerifyRate])
async def verify_document(
    request: Request,
    session: SessionDep,
    user: CurrentUser,
    file: Annotated[
        UploadFile,
        File(description="Signed document, certificate artifact, photograph, or scan"),
    ],
    detached_content: Annotated[
        UploadFile | None, File(description="Original content for a detached CMS signature")
    ] = None,
    filename: Annotated[str | None, Form()] = None,
) -> VerificationOut:
    max_bytes = settings.max_upload_mb * 1024 * 1024
    content = await file.read()
    if len(content) > max_bytes:
        raise ValidationAppError(f"File exceeds the {settings.max_upload_mb} MB limit")

    external = None
    if detached_content is not None:
        external = await detached_content.read()
        if len(external) > max_bytes:
            raise ValidationAppError("Detached content exceeds the size limit")

    result = await engine.verify_document(
        session,
        filename=filename or file.filename or "upload.bin",
        content=content,
        external_content=external,
    )
    enriched = await attach_detection(
        session,
        result,
        source=EventSource.UPLOAD,
        source_ref=(file.filename or "upload")[:255],
        submitter_id=user.id,
        ip_hash=hash_ip(client_ip(request)),
    )
    return VerificationOut.model_validate(enriched)
