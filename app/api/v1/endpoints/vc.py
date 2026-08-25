"""최초 성인 인증 결과 기록, VC 발급 및 DID Document 조회."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.audit import record_audit_event
from app.core.vc import ISSUER_DID, build_did_document, issue_vc
from app.database import get_db
from app.models import AdultVerification, Device, User, VcCredential
from app.schemas.audit import AuditActorType, AuditAggregateType, AuditEventType
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
    body: AdultVerificationRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """모바일에서 수행한 최초 성인·얼굴 대조 결과를 기록한다."""
    device = await db.get(Device, body.device_id)
    if device is None or device.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="device not found")
    if device.status != "ACTIVE":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="device is not active",
        )

    if not body.age_check_passed:
        result_status, failure_code = (
            AdultVerificationStatus.FAIL_AGE,
            "AGE_POLICY_FAILED",
        )
    elif not body.id_face_match_passed:
        result_status, failure_code = (
            AdultVerificationStatus.FAIL_FACE_MISMATCH,
            "ID_SELFIE_MISMATCH",
        )
    elif body.liveness_passed is False:
        result_status, failure_code = (
            AdultVerificationStatus.FAIL_LIVENESS,
            "LIVENESS_FAILED",
        )
    else:
        result_status, failure_code = AdultVerificationStatus.SUCCESS, None

    row = AdultVerification(
        user_id=user.id,
        device_id=body.device_id,
        age_check_passed=body.age_check_passed,
        id_face_match_passed=body.id_face_match_passed,
        liveness_passed=body.liveness_passed,
        age_policy_version=body.age_policy_version,
        model_version=body.model_version,
        threshold_version=body.threshold_version,
        result_status=result_status.value,
        failure_code=failure_code,
    )
    db.add(row)
    await db.flush()  # audit의 aggregate_id로 쓸 row.id 확보

    # 성공·실패를 가리지 않고 남긴다. 실패 시도야말로 감사 추적의 대상이다.
    await record_audit_event(
        db,
        event_type=AuditEventType.ADULT_VERIFICATION_RECORDED.value,
        actor_type=AuditActorType.USER.value,
        actor_ref=str(user.id),
        aggregate_type=AuditAggregateType.ADULT_VERIFICATION.value,
        aggregate_id=str(row.id),
        payload={
            "device_id": body.device_id,
            "result_status": result_status.value,
            "failure_code": failure_code,
            "age_check_passed": body.age_check_passed,
            "id_face_match_passed": body.id_face_match_passed,
            "liveness_passed": body.liveness_passed,
            "age_policy_version": body.age_policy_version,
            "model_version": body.model_version,
            "threshold_version": body.threshold_version,
        },
    )
    await db.commit()
    await db.refresh(row)
    return row


@router.post("/did/issue", response_model=IssueVcResponse)
async def issue_credential(
    body: IssueVcRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """성공한 최초 성인 인증 결과를 근거로 Holder에게 VC를 발급한다."""
    verification = await db.get(AdultVerification, body.adult_verification_id)
    if verification is None or verification.user_id != user.id:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail="verification not found",
        )
    if verification.result_status != AdultVerificationStatus.SUCCESS.value:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="adult verification was not successful",
        )
    if verification.invalidated_at is not None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="adult verification was invalidated",
        )

    device = await db.get(Device, verification.device_id)
    if device is None or device.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="device not found")
    if device.status != "ACTIVE":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="device is not active",
        )
    if not device.holder_did:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="device has no holder_did. Register device and bind holder key first.",
        )

    vc_jwt, credential_id, expires_at = issue_vc(device.holder_did)

    vc_row = VcCredential(
        user_id=user.id,
        device_id=device.id,
        adult_verification_id=verification.id,
        credential_id=credential_id,
        holder_did=device.holder_did,
        issuer_did=ISSUER_DID,
        credential_format="JWT_VC",
        status="ACTIVE",
        expires_at=expires_at,
    )
    db.add(vc_row)
    await db.flush()  # audit의 aggregate_id로 쓸 vc_row.id 확보

    # 발급된 VC 본문(JWT)은 남기지 않는다. 감사 로그가 유출되면
    # 그대로 사용 가능한 자격증명이 되기 때문이다. 식별자만 남긴다.
    await record_audit_event(
        db,
        event_type=AuditEventType.VC_ISSUED.value,
        actor_type=AuditActorType.USER.value,
        actor_ref=str(user.id),
        aggregate_type=AuditAggregateType.VC_CREDENTIAL.value,
        aggregate_id=str(vc_row.id),
        payload={
            "credential_id": credential_id,
            "device_id": device.id,
            "adult_verification_id": verification.id,
            "holder_did": device.holder_did,
            "issuer_did": ISSUER_DID,
            "expires_at": expires_at.isoformat() if expires_at else None,
        },
    )
    await db.commit()

    return IssueVcResponse(
        credential=vc_jwt,
        credential_id=credential_id,
        holder_did=device.holder_did,
        issuer_did=ISSUER_DID,
        expires_at=expires_at,
    )


@router.get("/did/issuer")
async def get_issuer_did_document():
    """AgeTrust 발급자의 공개 DID Document를 반환한다."""
    return build_did_document(ISSUER_DID)


@router.get("/did/{did}")
async def resolve_did_document(did: str):
    """did:key DID를 공개키가 포함된 DID Document로 해석한다."""
    try:
        return build_did_document(did)
    except ValueError as error:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error
