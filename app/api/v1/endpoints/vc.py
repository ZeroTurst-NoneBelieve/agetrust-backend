"""최초 성인 인증 결과 기록, VC 발급 및 DID Document 조회."""

import hashlib
import json
import re
import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_kiosk, get_current_user
from app.api.errors import api_error
from app.config import settings
from app.core.audit import record_audit_event
from app.core.status_list import (
    BITSTRING_SIZE,
    DB_PURPOSE_REVOCATION,
    PURPOSE_REVOCATION,
    build_credential_status,
    build_status_list_url,
    decode_bitstring,
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
    Kiosk,
    User,
    VcCredential,
)
from app.schemas.audit import AuditActorType, AuditAggregateType, AuditEventType
from app.schemas.errors import (
    AdultVerificationStatus,
    AuthErrorResponse,
    VcError,
    VcErrorResponse,
)
from app.schemas.vc import (
    AdultVerificationRequest,
    AdultVerificationResponse,
    IssueVcRequest,
    IssueVcResponse,
)

router = APIRouter(prefix="/api/v1", tags=["did-vc"])

# 상태 목록 생성 및 인덱스 배정을 직렬화하는 advisory lock 키.
# 목록이 아직 하나도 없을 때는 잠글 행 자체가 없어서 with_for_update를 걸 수
# 없다. PostgreSQL의 트랜잭션 단위 advisory lock은 행이 없어도 "이름"에
# 자물쇠를 걸 수 있어, 첫 발급이 동시에 들어와도 목록이 두 개 생기지 않는다.
# 사용 여부 확인부터 VC INSERT·commit까지 유지해야 같은 빈자리의 중복
# 배정도 막는다. 생성 직후 잠금을 풀거나 기존 목록에서 생략하면 안 된다.
# 값 자체에 의미는 없고 다른 용도와 겹치지 않기만 하면 된다.
_STATUS_LIST_LOCK_KEY = 27_0001
_INDEX_PICK_ATTEMPTS = 32


async def _index_is_taken(db: AsyncSession, status_list_id: int, index: int) -> bool:
    """폐기·만료된 VC의 자리도 재사용하지 않는다."""
    return bool(await db.scalar(select(exists().where(
        VcCredential.status_list_id == status_list_id,
        VcCredential.status_list_index == index,
    ))))


async def _pick_unused_index(db: AsyncSession, status_list_id: int) -> int:
    """무작위 재시도 소진 시 실제 빈자리 중 하나를 무작위로 고른다.

    재시도 실패가 목록이 가득 찼다는 뜻은 아니다. 드문 fallback 경로에서만
    최대 131,072개의 자리를 훑어, 빈자리가 있는데 확률적으로 503을 내지 않는다.
    호출부의 advisory lock이 VC 저장까지 유지되는 것을 전제로 한다.
    """
    result = await db.execute(select(VcCredential.status_list_index).where(
        VcCredential.status_list_id == status_list_id,
    ))
    taken = set(result.scalars().all())
    available = [index for index in range(BITSTRING_SIZE) if index not in taken]
    if not available:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="status list is full")
    return secrets.choice(available)


async def _allocate_status_list_entry(
    db: AsyncSession,
) -> tuple[CredentialStatusList, int]:
    """발급할 VC에 배정할 (상태 목록, 인덱스)를 하나 확보한다.

    같은 인덱스가 두 VC에 배정되면, 한쪽을 폐기했을 때 관계없는 다른 VC까지
    키오스크에서 거부된다. 따라서 인덱스 배정은 반드시 한 번에 하나씩
    이루어져야 한다.

    인덱스는 무작위로 고른다. MAX + 1로 순차 배정하면 인덱스만 봐도 발급
    순서와 그때까지의 총 발급량이 드러나기 때문이다. W3C도 랜덤 배정을
    권고한다. 동시성은 advisory lock으로 이 구간을 직렬화해 막고, 모델의
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

    # 랜덤 배정에서는 최댓값으로 남은 자리를 알 수 없으므로 개수로 판단한다.
    used_count = await db.scalar(
        select(func.count()).where(VcCredential.status_list_id == status_list.id)
    )
    if used_count >= BITSTRING_SIZE:
        # 목록 하나가 13만 건을 담으므로 현실적으로 도달하지 않는다. 다만
        # 조용히 넘어가면 범위를 벗어난 인덱스가 배정되므로 명시적으로 막는다.
        # 목록을 여러 개로 넘기는 처리는 별도 이슈로 다룬다.
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="status list is full",
        )

    # 잠금은 동시 배정만 막는다. 이미 쓰인 후보는 직접 확인하고 다시 뽑는다.
    for _ in range(_INDEX_PICK_ATTEMPTS):
        next_index = secrets.randbelow(BITSTRING_SIZE)
        if not await _index_is_taken(db, status_list.id, next_index):
            break
    else:
        next_index = await _pick_unused_index(db, status_list.id)

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
        400: {
            "model": VcErrorResponse,
            "description": "기기가 ACTIVE 상태가 아님 (DEVICE_NOT_ACTIVE)",
        },
        404: {
            "model": VcErrorResponse,
            "description": "기기를 찾을 수 없거나 본인 소유가 아님 (DEVICE_NOT_FOUND)",
        },
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
        raise api_error(VcError.DEVICE_NOT_FOUND, status.HTTP_404_NOT_FOUND)
    if device.status != "ACTIVE":
        raise api_error(VcError.DEVICE_NOT_ACTIVE, status.HTTP_400_BAD_REQUEST)

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
            "model": VcErrorResponse,
            "description": (
                "판정이 SUCCESS가 아니거나(VERIFICATION_NOT_SUCCESSFUL) "
                "무효화됨(VERIFICATION_INVALIDATED) / "
                "기기가 ACTIVE가 아님(DEVICE_NOT_ACTIVE) / "
                "holder_did 미등록(HOLDER_DID_NOT_BOUND)"
            ),
        },
        404: {
            "model": VcErrorResponse,
            "description": (
                "판정 기록(VERIFICATION_NOT_FOUND) 또는 "
                "기기(DEVICE_NOT_FOUND)를 찾을 수 없거나 본인 소유가 아님"
            ),
        },
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
        raise api_error(VcError.VERIFICATION_NOT_FOUND, status.HTTP_404_NOT_FOUND)
    if verification.result_status != AdultVerificationStatus.SUCCESS.value:
        raise api_error(VcError.VERIFICATION_NOT_SUCCESSFUL, status.HTTP_400_BAD_REQUEST)
    if verification.invalidated_at is not None:
        raise api_error(VcError.VERIFICATION_INVALIDATED, status.HTTP_400_BAD_REQUEST)

    # 재바인딩(POST /auth/devices/bind-holder-key)과 같은 기기 행을 잠가 두
    # 요청을 직렬화한다. 잠금이 없으면 여기서 읽은 holder_did가 아래에서 VC를
    # 저장하기 전에 재바인딩으로 바뀔 수 있고, 그렇게 저장된 옛 키용 VC는
    # 이미 끝난 폐기를 피해 ACTIVE로 남는다. 폐기 목록에도 없으므로 분실
    # 기기가 키오스크를 그대로 통과한다.
    device = await db.get(Device, verification.device_id, with_for_update=True)
    if device is None or device.user_id != user.id:
        raise api_error(VcError.DEVICE_NOT_FOUND, status.HTTP_404_NOT_FOUND)
    if device.status != "ACTIVE":
        raise api_error(VcError.DEVICE_NOT_ACTIVE, status.HTTP_400_BAD_REQUEST)
    if not device.holder_did:
        raise api_error(VcError.HOLDER_DID_NOT_BOUND, status.HTTP_400_BAD_REQUEST)

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


def _status_list_etag(status_list: CredentialStatusList) -> str:
    # iat는 매 응답마다 바뀌므로 weak ETag를 쓴다. 버전뿐 아니라 URL 복구나
    # 발급자 키 변경도 반영해 이전 JWT를 잘못 304로 재검증하지 않는다.
    representation = json.dumps([
        ISSUER_DID,
        status_list.status_list_url,
        status_list.status_purpose,
        status_list.encoded_list,
    ], ensure_ascii=True, separators=(",", ":"))
    fingerprint = hashlib.sha256(representation.encode()).hexdigest()
    return f'W/"{status_list.id}-{status_list.version}-{fingerprint}"'


def _etag_matches(if_none_match: list[str] | None, etag: str) -> bool:
    """If-None-Match는 weak 비교를 사용한다 (RFC 9110 §13.1.2)."""
    if not if_none_match:
        return False
    value = ",".join(if_none_match).strip()
    if value == "*":
        return True
    # opaque-tag 안의 쉼표를 구분자로 오인하지 않는다. 잘못된 헤더는 무시한다.
    tag_pattern = r'(?:W/)?"[\x21\x23-\x7e\x80-\xff]*"'
    if not re.fullmatch(rf'\s*{tag_pattern}(?:\s*,\s*{tag_pattern})*\s*', value):
        return False
    return any(
        tag.removeprefix("W/") == etag.removeprefix("W/")
        for tag in re.findall(tag_pattern, value)
    )


@router.get("/status/{status_list_id}", response_class=Response, include_in_schema=False)
@router.get(
    "/status-lists/{status_list_id}",
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
        304: {"description": "If-None-Match와 일치하며 목록이 변경되지 않음"},
        401: {
            "description": "키오스크 키가 없거나 잘못됨 또는 키오스크가 비활성/폐기 상태임",
            "model": AuthErrorResponse,
        },
        404: {"description": "해당 상태 목록이 없음"},
        503: {"description": "상태 목록이 비어 있거나 손상되어 응답할 수 없음"},
    },
)
async def get_status_list(
    status_list_id: int,
    db: AsyncSession = Depends(get_db),
    if_none_match: Annotated[list[str] | None, Header()] = None,
    _kiosk: Kiosk = Depends(get_current_kiosk),
):
    """VC 폐기 목록을 서명된 StatusList2021Credential로 반환한다.

    Authorization: Bearer <api_key>로 등록된 ACTIVE 키오스크만 조회할 수 있다.
    목록 조회와 조건부 304 처리보다 먼저 인증한다. #42 계약과 헤더를 맞췄으며,
    키 발급/배포 후속 범위는 docs/status-list-review.md에 기록한다.
    발급된 VC의 credentialStatus.statusListCredential이 이 주소를 가리킨다.
    기존 VC의 /status/{id} 주소도 동일한 인증을 거치는 호환 별칭으로 유지한다.

    키오스크는 "이 VC 유효한가?"를 한 건씩 묻지 않고 목록 전체를 받아간다.
    개별 조회 방식이면 서버가 누가 언제 어디서 인증을 시도했는지 모두 알게
    되기 때문이다. 목록에는 13만 개의 비트가 함께 들어 있어 어느 VC를
    확인하는지 목록 조회만으로 특정할 수 없다. 일괄 조회의 프라이버시 이점은
    API Key 인증 유무와 별개다.

    응답은 발급자 키로 서명된 JWT다. 서명이 없으면 중간에서 전부 0인 목록으로
    바꿔치기해 폐기된 VC를 되살릴 수 있다.
    """
    status_list = await db.get(CredentialStatusList, status_list_id)
    if status_list is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail="status list not found",
            headers={"Cache-Control": "no-store"},
        )

    try:
        # 전부 0인 목록으로 대신 응답하면 안 된다. 그 서명은 "폐기된 VC가
        # 하나도 없다"는 발급자의 보증이라, 저장된 값이 손상된 경우에도
        # 폐기된 VC를 키오스크에서 되살리게 된다.
        # 비어 있지 않아도 gzip이나 길이가 잘못되면 서명·304 모두 금지한다.
        if not status_list.encoded_list:
            raise ValueError("empty status list")
        decode_bitstring(status_list.encoded_list)
    except ValueError as error:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="status list is not available",
            headers={"Cache-Control": "no-store"},
        ) from error

    headers = {
        # 공유 캐시는 저장하지 않고, HTTP 캐시 재사용도 서버 인증/재검증을
        # 거친다. 키오스크 앱의 별도 오프라인 저장·검증 정책과는 구분한다.
        "Cache-Control": "private, no-cache",
        "Vary": "Authorization",
        "ETag": _status_list_etag(status_list),
    }
    if _etag_matches(if_none_match, headers["ETag"]):
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers=headers)

    token = issue_status_list_vc(
        status_list_url=status_list.status_list_url,
        encoded_list=status_list.encoded_list,
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
        headers=headers,
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
    responses={
        400: {
            "model": VcErrorResponse,
            "description": (
                "did:key 형식이 아니거나 파싱할 수 없는 DID (INVALID_DID_FORMAT). "
                "실패 사유는 detail.message에 담긴다."
            ),
        },
    },
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
        # 파싱 실패 사유는 코드 하나로 뭉뚱그릴 수 없어 message로 함께 내려보낸다.
        # 분기는 code로 하고, message는 어디가 틀렸는지 사람이 읽는 용도다.
        raise api_error(
            VcError.INVALID_DID_FORMAT,
            status.HTTP_400_BAD_REQUEST,
            message=str(error),
        ) from error
