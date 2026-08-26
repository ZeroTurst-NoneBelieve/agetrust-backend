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


@router.post(
    "/adult-verifications",
    response_model=AdultVerificationResponse,
    summary="온디바이스 성인 판정 결과 기록",
    responses={
        400: {"description": "기기가 ACTIVE 상태가 아님"},
        404: {"description": "기기를 찾을 수 없거나 본인 소유가 아님"},
    },
)
async def record_adult_verification(
    body: AdultVerificationRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """모바일에서 수행한 최초 성인·얼굴 대조 결과를 기록한다.

    얼굴 이미지나 임베딩은 서버로 전송되지 않으며, 판정 결과만 저장한다.

    검사 항목 중 하나라도 실패하면 result_status에 실패 지점에 대응하는
    FAIL_AGE, FAIL_FACE_MISMATCH, FAIL_LIVENESS 중 하나가 기록되고
    failure_code에 세부 사유가 담긴다. 실패한 기록으로는 VC를 발급할 수 없다.

    실패 판정 우선순위: 연령 → 얼굴 대조 → 라이브니스
    """
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


@router.post(
    "/did/issue",
    response_model=IssueVcResponse,
    summary="성인 인증 VC 발급",
    responses={
        400: {
            "description": (
                "판정이 SUCCESS가 아니거나 무효화됨 / "
                "기기가 ACTIVE가 아님 / holder_did 미등록"
            )
        },
        404: {"description": "판정 기록 또는 기기를 찾을 수 없거나 본인 소유가 아님"},
    },
)
async def issue_credential(
    body: IssueVcRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """성공한 최초 성인 인증 결과를 근거로 Holder에게 VC를 발급한다.

    발급 전 다음을 모두 확인한다.

    - 판정 기록이 요청자 본인의 것이고 result_status가 SUCCESS인가
    - 판정 기록이 무효화(invalidated_at)되지 않았는가
    - 해당 기기가 요청자 본인의 ACTIVE 기기인가
    - 기기에 holder_did가 바인딩되어 있는가

    holder_did가 없으면 먼저 POST /api/v1/auth/devices/bind-holder-key를
    호출해야 한다.

    발급된 VC(JWT) 원문은 서버에 저장하지 않으므로 클라이언트가 보관해야 한다.
    서버에는 credential_id, 상태, 만료 시각 등 메타데이터만 남는다.
    """
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


@router.get(
    "/did/issuer",
    summary="발급자 DID Document 조회",
)
async def get_issuer_did_document():
    """AgeTrust 발급자의 공개 DID Document를 반환한다.

    인증이 필요 없는 공개 엔드포인트다.
    반환되는 id가 발급된 VC의 issuer_did(JWT의 iss)와 일치한다.

    현재 검증 경로에서는 이 엔드포인트의 공개키를 사용할 수 있다.
    향후 Sepolia 컨트랙트 연동이 완료되면 키오스크가 컨트랙트에서 공개키를
    조회해 검증하도록 전환할 예정이다.
    """
    return build_did_document(ISSUER_DID)


@router.get(
    "/did/{did}",
    summary="did:key DID Document 해석",
    responses={400: {"description": "did:key 형식이 아니거나 파싱할 수 없는 DID"}},
)
async def resolve_did_document(did: str):
    """did:key DID를 공개키가 포함된 DID Document로 해석한다.

    did:key는 자기완결적이라 DID 문자열 자체에 공개키가 들어 있다.
    따라서 이 조회는 DB를 참조하지 않으며 인증도 필요 없다.

    did:key 이외의 DID method는 지원하지 않는다.
    """
    try:
        return build_did_document(did)
    except ValueError as error:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error
