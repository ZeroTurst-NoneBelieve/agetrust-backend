"""최초 성인 인증 기록 + VC 발급 + DID Document 조회."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.config import settings
from app.core.did_crypto import ISSUER_DID, build_did_document, issue_vc
from app.database import get_db
from app.models import AdultVerification, Device, User, VcCredential
from app.schemas.errors import AdultVerificationStatus
from app.schemas.vc import (
    AdultVerificationRequest,
    AdultVerificationResponse,
    IssueVcRequest,
    IssueVcResponse,
)

router = APIRouter(prefix="/api/v1", tags=["did-vc"])


@router.post("/adult-verifications", response_model=AdultVerificationResponse)
async def record_adult_verification(
    body: AdultVerificationRequest, user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    device = await db.get(Device, body.device_id)
    if device is None or device.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="device not found")

    if not body.age_check_passed:
        result_status, failure_code = AdultVerificationStatus.FAIL_AGE, "AGE_POLICY_FAILED"
    elif not body.id_face_match_passed:
        result_status, failure_code = AdultVerificationStatus.FAIL_FACE_MISMATCH, "ID_SELFIE_MISMATCH"
    elif body.liveness_passed is False:
        result_status, failure_code = AdultVerificationStatus.FAIL_LIVENESS, "LIVENESS_FAILED"
    else:
        result_status, failure_code = AdultVerificationStatus.SUCCESS, None

    row = AdultVerification(
        user_id=user.id, device_id=body.device_id,
        age_check_passed=body.age_check_passed,
        id_face_match_passed=body.id_face_match_passed,
        liveness_passed=body.liveness_passed,
        result_status=result_status.value, failure_code=failure_code,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


@router.post("/did/issue", response_model=IssueVcResponse)
async def issue_credential(
    body: IssueVcRequest, user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    av = await db.get(AdultVerification, body.adult_verification_id)
    if av is None or av.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="verification not found")
    if av.result_status != AdultVerificationStatus.SUCCESS.value:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="adult verification was not successful")

    device = await db.get(Device, av.device_id)
    if device is None or not device.holder_did:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                             detail="device has no holder_did. Register device and bind holder key first.")

    vc_jwt, credential_id = issue_vc(device.holder_did)
    expires_at = (datetime.now(timezone.utc) + timedelta(days=settings.vc_expire_days)
                  if settings.vc_expire_days else None)

    vc_row = VcCredential(
        user_id=user.id, device_id=device.id, adult_verification_id=av.id,
        credential_id=credential_id, holder_did=device.holder_did,
        issuer_did=ISSUER_DID, status="ACTIVE", expires_at=expires_at,
    )
    db.add(vc_row)
    await db.commit()

    return IssueVcResponse(
        credential=vc_jwt, credential_id=credential_id,
        holder_did=device.holder_did, issuer_did=ISSUER_DID, expires_at=expires_at,
    )


@router.get("/did/issuer")
async def get_issuer_did_document():
    """EduTrust 발급자의 DID Document를 반환한다.

    VC 서명을 검증하려는 쪽(키오스크 등)이 발급자 공개키를 확인하는 통로다.
    DID Document는 공개 정보이므로 인증을 요구하지 않는다.
    """
    return build_did_document(ISSUER_DID)


@router.get("/did/{did}")
async def resolve_did_document(did: str):
    """did:key DID를 DID Document로 해석(resolve)한다.

    did:key는 DID 문자열 자체에 공개키가 들어 있어 저장소 조회 없이
    Document를 유도할 수 있다. 형식이 올바르지 않으면 400을 반환한다.
    """
    try:
        return build_did_document(did)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(e))