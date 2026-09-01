"""최초 성인 인증 결과 기록, VC 발급 및 DID Document 조회."""

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.config import settings
from app.core.audit import record_audit_event
from app.core.status_list import (
    BITSTRING_SIZE,
    DB_PURPOSE_REVOCATION,
    PURPOSE_REVOCATION,
    build_credential_status,
    build_status_list_url,
    empty_encoded_list,
)
from app.core.vc import (
    ISSUER_DID,
    build_did_document,
    issue_status_list_vc,
    issue_vc,
)
from app.database import get_db
from app.models import (
    AdultVerification,
    CredentialStatusList,
    Device,
    User,
    VcCredential,
)
from app.schemas.audit import AuditActorType, AuditAggregateType, AuditEventType
from app.schemas.errors import AdultVerificationStatus
from app.schemas.vc import (
    AdultVerificationRequest,
    AdultVerificationResponse,
    IssueVcRequest,
    IssueVcResponse,
)

router = APIRouter(prefix="/api/v1", tags=["did-vc"])

# 상태 목록 생성 구간을 감싸는 advisory lock 키.
# 목록이 아직 하나도 없을 때는 잠글 행 자체가 없어서 with_for_update를 걸 수
# 없다. PostgreSQL의 트랜잭션 단위 advisory lock은 행이 없어도 "이름"에
# 자물쇠를 걸 수 있어, 첫 발급이 동시에 들어와도 목록이 두 개 생기지 않는다.
# 값 자체에 의미는 없고 다른 용도와 겹치지 않기만 하면 된다.
_STATUS_LIST_LOCK_KEY = 27_0001


async def _allocate_status_list_entry(
    db: AsyncSession,
) -> tuple[CredentialStatusList, int]:
    """발급할 VC에 배정할 (상태 목록, 인덱스)를 하나 확보한다.

    같은 인덱스가 두 VC에 배정되면, 한쪽을 폐기했을 때 관계없는 다른 VC까지
    키오스크에서 거부된다. 따라서 인덱스 배정은 반드시 한 번에 하나씩
    이루어져야 한다.

    흔한 실수는 MAX(status_list_index) + 1을 잠금 없이 읽는 것이다. 동시에
    들어온 두 요청이 같은 MAX를 보고 같은 번호를 가져간다. 여기서는 advisory
    lock으로 이 구간을 직렬화하고, 모델의
    UNIQUE(status_list_id, status_list_index)가 마지막 안전망이 된다.

    이 함수는 커밋하지 않는다. 호출부의 트랜잭션에 그대로 얹혀서, VC 저장이
    실패하면 배정도 같이 롤백된다.
    """
    await db.execute(select(func.pg_advisory_xact_lock(_STATUS_LIST_LOCK_KEY)))

    status_list = await db.scalar(
        select(CredentialStatusList)
        .where(
            CredentialStatusList.issuer_did == ISSUER_DID,
            CredentialStatusList.status_purpose == DB_PURPOSE_REVOCATION,
        )
        .order_by(CredentialStatusList.id)
        .limit(1)
    )

    if status_list is None:
        status_list = await _create_status_list(db)

    next_index = await db.scalar(
        select(func.coalesce(func.max(VcCredential.status_list_index), -1) + 1).where(
            VcCredential.status_list_id == status_list.id
        )
    )

    if next_index >= BITSTRING_SIZE:
        # 목록 하나가 13만 건을 담으므로 현실적으로 도달하지 않는다. 다만
        # 조용히 넘어가면 범위를 벗어난 인덱스가 배정되므로 명시적으로 막는다.
        # 목록을 여러 개로 넘기는 처리는 별도 이슈로 다룬다.
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="status list is full",
        )

    return status_list, next_index


async def _create_status_list(db: AsyncSession) -> CredentialStatusList:
    """첫 발급 시점에 폐기용 상태 목록을 하나 만든다.

    status_list_url에 목록의 id가 들어가는데 id는 INSERT 후에야 정해지므로,
    임시값으로 넣고 flush해 id를 받은 뒤 실제 URL로 채운다.

    encoded_list는 비워두지 않고 전부 0인 비트열로 채운다. NULL로 두면
    키오스크가 목록을 조회했을 때 해석할 값이 없어진다.
    """
    status_list = CredentialStatusList(
        issuer_did=ISSUER_DID,
        status_purpose=DB_PURPOSE_REVOCATION,
        status_list_url=f"pending:{DB_PURPOSE_REVOCATION}",
        encoded_list=empty_encoded_list(),
    )
    db.add(status_list)
    await db.flush()  # id 확보

    status_list.status_list_url = build_status_list_url(
        settings.public_base_url, status_list.id
    )
    await db.flush()
    return status_list


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

    # 상태 목록의 자리를 먼저 잡아야 VC 본문에 credentialStatus를 실을 수 있다.
    # did:key VC는 자기완결적이라 키오스크가 서버에 묻지 않고 검증하는데,
    # 이 한 줄이 없으면 폐기된 VC도 만료 전까지 그대로 통과한다.
    status_list, status_list_index = await _allocate_status_list_entry(db)
    credential_status = build_credential_status(
        status_list.status_list_url, status_list_index
    )

    vc_jwt, credential_id, expires_at = issue_vc(
        device.holder_did,
        credential_status=credential_status,
    )

    vc_row = VcCredential(
        user_id=user.id,
        device_id=device.id,
        adult_verification_id=verification.id,
        credential_id=credential_id,
        holder_did=device.holder_did,
        issuer_did=ISSUER_DID,
        credential_format="JWT_VC",
        status="ACTIVE",
        status_list_id=status_list.id,
        status_list_index=status_list_index,
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
    "/status/{status_list_id}",
    summary="StatusList2021 폐기 목록 조회",
    response_class=Response,
    responses={
        200: {
            "description": (
                "서명된 StatusList2021Credential (JWT). "
                "Content-Type은 application/jwt다."
            ),
            "content": {"application/jwt": {"schema": {"type": "string"}}},
        },
        404: {"description": "해당 상태 목록이 없음"},
    },
)
async def get_status_list(
    status_list_id: int,
    db: AsyncSession = Depends(get_db),
):
    """VC 폐기 목록을 서명된 StatusList2021Credential로 반환한다.

    키오스크가 호출하므로 로그인 인증이 필요 없는 공개 엔드포인트다.
    발급된 VC의 credentialStatus.statusListCredential이 이 주소를 가리킨다.

    키오스크는 "이 VC 유효한가?"를 한 건씩 묻지 않고 목록 전체를 받아간다.
    개별 조회 방식이면 서버가 누가 언제 어디서 인증을 시도했는지 모두 알게
    되기 때문이다. 목록에는 13만 개의 비트가 함께 들어 있어 어느 VC를
    확인하는지 서버가 알 수 없다.

    응답은 발급자 키로 서명된 JWT다. 서명이 없으면 중간에서 전부 0인 목록으로
    바꿔치기해 폐기된 VC를 되살릴 수 있다.
    """
    status_list = await db.get(CredentialStatusList, status_list_id)
    if status_list is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail="status list not found",
        )

    # 목록이 만들어진 직후라 비어 있을 수 있다. 폐기가 하나도 없는 상태와
    # 같으므로 전부 0인 비트열로 응답한다.
    encoded_list = status_list.encoded_list or empty_encoded_list()

    token = issue_status_list_vc(
        status_list_url=status_list.status_list_url,
        encoded_list=encoded_list,
        # DB는 'REVOCATION'이지만 규격상 VC 본문은 소문자다.
        status_purpose=(
            PURPOSE_REVOCATION
            if status_list.status_purpose == DB_PURPOSE_REVOCATION
            else status_list.status_purpose.lower()
        ),
    )

    return Response(
        content=token,
        media_type="application/jwt",
        headers={
            # 폐기 반영이 늦어지는 만큼이 위험 구간이므로 짧게 잡는다.
            "Cache-Control": "public, max-age=300",
            # 목록이 그대로면 키오스크가 본문을 다시 받지 않아도 된다.
            "ETag": f'W/"{status_list_id}-{status_list.version}"',
        },
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