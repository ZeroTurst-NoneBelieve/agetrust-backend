"""키오스크 현장 인증 - Challenge 생성 + VC/VP/Challenge/얼굴 최종 검증."""

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_kiosk
from app.config import settings
from app.core.did_crypto import VcError, compute_challenge_hash, decode_vc, verify_holder_signature
from app.database import get_db
from app.models import Device, Kiosk, VcCredential, VerificationChallenge, VerificationLog
from app.schemas.errors import VerificationResultStatus
from app.schemas.verify import (
    CreateChallengeRequest,
    CreateChallengeResponse,
    VerifyRequest,
    VerifyResponse,
)

router = APIRouter(prefix="/api/v1", tags=["verify"])


@router.post("/did/challenges", response_model=CreateChallengeResponse)
async def create_challenge(
    body: CreateChallengeRequest, kiosk: Kiosk = Depends(get_current_kiosk),
    db: AsyncSession = Depends(get_db),
):
    nonce = secrets.token_urlsafe(16)
    timestamp = datetime.now(timezone.utc).isoformat()
    expires_at_dt = datetime.now(timezone.utc) + timedelta(seconds=settings.challenge_expire_seconds)
    expires_at = expires_at_dt.isoformat()

    challenge_hash = compute_challenge_hash(nonce, kiosk.id, timestamp, expires_at)
    row = VerificationChallenge(
        kiosk_id=kiosk.id, transport_type=body.transport_type,
        challenge_hash=challenge_hash, status="PENDING", expires_at=expires_at_dt,
    )
    db.add(row)
    await db.commit()

    return CreateChallengeResponse(
        nonce=nonce, kiosk_id=kiosk.id, timestamp=timestamp,
        expires_at=expires_at, challenge_hash=challenge_hash,
    )


async def _log_and_return(db: AsyncSession, challenge: VerificationChallenge, is_vc_valid: bool,
                           is_vp_valid: bool, is_face_matched: bool,
                           result: VerificationResultStatus, failure_code: str | None) -> VerifyResponse:
    """검증 결과를 기록하고 challenge를 소모 처리한다.

    challenge는 replay 방지를 위한 일회용 nonce이므로, 성공/실패와 무관하게
    한 번 검증을 시도한 시점에 CONSUMED로 전이시킨다.
    실패 경로에서 PENDING으로 남겨두면 같은 challenge로 재시도가 가능해지고,
    verification_logs.challenge_id UNIQUE 제약을 위반해 IntegrityError(500)가 발생한다.
    사용자는 실패 시 새 challenge를 발급받아 재시도한다.
    """
    challenge.status = "CONSUMED"
    challenge.consumed_at = datetime.now(timezone.utc)
    db.add(VerificationLog(
        challenge_id=challenge.id, is_vc_valid=is_vc_valid, is_vp_valid=is_vp_valid,
        is_face_matched=is_face_matched, result_status=result.value, failure_code=failure_code,
    ))
    await db.commit()
    return VerifyResponse(result_status=result.value, failure_code=failure_code)


@router.post("/did/verify", response_model=VerifyResponse)
async def verify(body: VerifyRequest, kiosk: Kiosk = Depends(get_current_kiosk),
                  db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(VerificationChallenge).where(VerificationChallenge.challenge_hash == body.challenge_hash)
    )
    challenge = result.scalar_one_or_none()
    if challenge is None or challenge.kiosk_id != kiosk.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="challenge not found")

    if challenge.status != "PENDING":
        # verification_logs.challenge_id는 UNIQUE(1건당 결과 1건)라서,
        # 이미 처리된 challenge를 재사용(replay)하려는 시도는 새 로그를 쓰지 않는다.
        # (이 challenge에 대한 최초 결과는 이미 기록되어 있다)
        return VerifyResponse(
            result_status=VerificationResultStatus.FAIL_CHALLENGE.value,
            failure_code="CHALLENGE_ALREADY_USED",
        )
    if datetime.now(timezone.utc) > challenge.expires_at:
        return await _log_and_return(db, challenge, False, False, False,
                                      VerificationResultStatus.FAIL_EXPIRED, "CHALLENGE_EXPIRED")

    try:
        vc_payload = decode_vc(body.credential)
    except VcError as e:
        # 만료와 서명/구조 오류를 구분해서 기록한다.
        failure_code = ("VC_EXPIRED" if e.code == VerificationResultStatus.FAIL_EXPIRED
                        else "VC_SIGNATURE_INVALID")
        return await _log_and_return(db, challenge, False, False, False, e.code, failure_code)

    credential_id = vc_payload.get("jti")
    holder_did = vc_payload.get("sub")

    result = await db.execute(select(VcCredential).where(VcCredential.credential_id == credential_id))
    vc_record = result.scalar_one_or_none()
    if vc_record is None:
        return await _log_and_return(db, challenge, False, False, False,
                                      VerificationResultStatus.FAIL_INVALID_VC, "VC_NOT_FOUND")
    if vc_record.status != "ACTIVE":
        return await _log_and_return(db, challenge, True, False, False,
                                      VerificationResultStatus.FAIL_REVOKED_VC, "VC_REVOKED")

    result = await db.execute(select(Device).where(Device.holder_did == holder_did))
    device = result.scalar_one_or_none()
    if device is None or not device.holder_public_key:
        return await _log_and_return(db, challenge, True, False, False,
                                      VerificationResultStatus.FAIL_INVALID_VP, "HOLDER_KEY_NOT_FOUND")

    vp_ok = verify_holder_signature(device.holder_public_key, body.challenge_hash, body.holder_signature_b64)
    if not vp_ok:
        return await _log_and_return(db, challenge, True, False, False,
                                      VerificationResultStatus.FAIL_INVALID_VP, "HOLDER_SIGNATURE_INVALID")

    if not body.face_matched:
        return await _log_and_return(db, challenge, True, True, False,
                                      VerificationResultStatus.FAIL_FACE_MISMATCH, "FACE_NOT_MATCHED")

    return await _log_and_return(db, challenge, True, True, True,
                                  VerificationResultStatus.SUCCESS, None)