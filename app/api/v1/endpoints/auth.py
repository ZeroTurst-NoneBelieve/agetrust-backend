"""가입 / 로그인 / 기기 등록.

devices 관련 엔드포인트는 팀 endpoints 목록(auth/vc/verify/stores)에
별도 파일이 없어 계정 관리 성격이 가까운 이 파일에 포함했습니다.
(팀 컨벤션상 별도 devices.py로 분리해야 하면 옮기기만 하면 됩니다)
"""

import base64
import logging
import math
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.api.errors import AUTHENTICATED_RESPONSES, api_error
from app.config import settings
from app.core.audit import mask_phone, record_audit_event
from app.core.did_key import load_public_key_pem, public_key_to_did_key
from app.core.otp_rate_limit import (
    OtpSmsRateLimiter,
    OtpSmsReservationDenied,
)
from app.core.revocation import revoke_active_credentials_for_device
from app.core.security import (
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_login_token,
    generate_otp,
    hash_otp,
    hash_password,
    verify_otp,
    verify_password_or_dummy,
)
from app.core.sms import (
    SmsConfigurationError,
    SmsDeliveryError,
    send_otp_sms,
    validate_sms_configuration,
)
from app.database import get_db
from app.models import Device, PhoneVerificationRequest, User
from app.schemas.audit import (
    AuditActorType,
    AuditAggregateType,
    AuditEventType,
)
from app.schemas.device import BindHolderKeyRequest, DeviceResponse, RegisterDeviceRequest
from app.schemas.errors import AuthError, AuthErrorResponse, VcError, VcErrorResponse
from app.schemas.user import (
    LoginRequest,
    PhoneRequestBody,
    PhoneRequestResponse,
    PhoneVerifyBody,
    RefreshRequest,
    SignupRequest,
    TokenResponse,
    UserResponse,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
logger = logging.getLogger(__name__)
otp_sms_rate_limiter = OtpSmsRateLimiter(
    per_client_limit=settings.otp_request_limit_per_client,
    per_client_window_seconds=settings.otp_request_limit_window_seconds,
    per_recipient_limit=settings.otp_request_limit_per_recipient,
    per_recipient_window_seconds=settings.otp_request_recipient_window_seconds,
    global_limit=settings.otp_request_global_limit,
    global_window_seconds=settings.otp_request_global_window_seconds,
)


def _fail(
    code: AuthError,
    status_code: int = status.HTTP_401_UNAUTHORIZED,
    *,
    headers: dict[str, str] | None = None,
):
    """인증 실패가 기본이라 401을 기본값으로 둔다. 본문 형태는 공용 생성기가 정한다."""
    return api_error(code, status_code, headers=headers)


async def _find_active_phone_verification(
    db: AsyncSession,
    *,
    phone_number: str,
) -> tuple[PhoneVerificationRequest | None, datetime]:
    """같은 번호의 OTP 발급을 직렬화하고 아직 유효한 요청을 찾는다."""
    # 행이 아직 없는 최초 요청끼리도 동시에 문자를 보내지 못하도록 번호별
    # transaction advisory lock을 먼저 잡는다. 잠금은 commit/rollback 때 풀린다.
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:phone_number, 0))"),
        {"phone_number": phone_number},
    )
    # 잠금 대기 시간을 만료·쿨다운 시간에 포함하지 않는다.
    now = datetime.now(timezone.utc)
    row = await db.scalar(
        select(PhoneVerificationRequest)
        .where(
            PhoneVerificationRequest.phone_number == phone_number,
            PhoneVerificationRequest.purpose == "SIGN_UP",
            PhoneVerificationRequest.verified_at.is_(None),
            PhoneVerificationRequest.consumed_at.is_(None),
            PhoneVerificationRequest.expires_at > now,
        )
        .order_by(PhoneVerificationRequest.created_at.desc())
        .limit(1)
        .with_for_update()
    )
    return row, now


def _retry_after_until(expires_at: datetime, now: datetime) -> int:
    """활성 요청이 끝날 때까지 남은 초를 Retry-After 형식으로 반환한다."""
    return max(1, math.ceil((expires_at - now).total_seconds()))


async def _invalidate_failed_sms_request(
    db: AsyncSession,
    *,
    verification_id: UUID,
    prepared_digest: str,
    prepared_last_sent_at: datetime,
) -> None:
    """공급자가 거절한 OTP를 더 이상 검증할 수 없게 만든다.

    OTP 준비 트랜잭션은 외부 호출 전에 이미 커밋된다. 따라서 공급자 실패는
    별도의 짧은 트랜잭션으로 만료 처리한다. 이 정리 자체가 실패해도 원래의
    공급자 오류를 가리지 않는다.
    """
    try:
        result = await db.execute(
            update(PhoneVerificationRequest)
            .where(
                PhoneVerificationRequest.id == verification_id,
                PhoneVerificationRequest.otp_digest == prepared_digest,
                PhoneVerificationRequest.last_sent_at == prepared_last_sent_at,
                PhoneVerificationRequest.verified_at.is_(None),
                PhoneVerificationRequest.consumed_at.is_(None),
            )
            .values(
                expires_at=datetime.now(timezone.utc) - timedelta(microseconds=1)
            )
            .execution_options(synchronize_session=False)
        )
        await db.commit()
        if result.rowcount == 0:
            logger.info(
                "Skipped stale SMS failure cleanup for verification_id=%s",
                verification_id,
            )
    except Exception:
        await db.rollback()
        logger.exception("Failed to invalidate an OTP after SMS delivery failure")


# users의 UNIQUE 제약 이름 -> 클라이언트가 분기할 오류 코드.
# 사전 확인과 DB 제약이 같은 코드를 내도록 한 곳에 묶어 둔다.
_UNIQUE_CONFLICTS = {
    "users_phone_number_key": AuthError.PHONE_ALREADY_REGISTERED,
    "users_login_id_key": AuthError.USER_ALREADY_EXISTS,
}


def _conflicting_unique(error: IntegrityError) -> AuthError | None:
    """UNIQUE 위반이 어느 제약에서 났는지 보고 오류 코드를 고른다.

    제약 이름이 드라이버마다 다른 자리에 실린다. asyncpg 어댑터는 error.orig에
    constraint_name을 달지 않고 원래 예외를 __cause__로 걸어 두고(실측),
    psycopg2는 diag.constraint_name을 준다. 둘 다 없으면 메시지에 남은
    이름으로 떨어진다. 알 수 없는 제약이면 None을 주어 그대로 올라가게 한다.
    """
    orig = error.orig
    name = (
        getattr(orig, "constraint_name", None)
        or getattr(getattr(orig, "diag", None), "constraint_name", None)
        or getattr(getattr(orig, "__cause__", None), "constraint_name", None)
    )
    if name is None:
        rendered = str(orig)
        name = next((c for c in _UNIQUE_CONFLICTS if c in rendered), None)
    return _UNIQUE_CONFLICTS.get(name)


async def _record_phone_verification_failure(
    db: AsyncSession,
    *,
    reason: AuthError,
    row: PhoneVerificationRequest,
) -> bool:
    """OTP 검증 실패를 감사 로그에 남기고 커밋한다.

    실제로 발급된 인증 요청의 실패 경로에서 record_audit_event를 매번
    펼치면
    분기마다 인자를 빠뜨리기 쉬워 한 곳으로 모았다.

    소비·만료·시도 초과 상태를 같은 ID로 반복 호출해 감사 체인을 무한히
    늘리지 못하도록 attempt_count를 상한으로 사용한다. OTP_MAX_ATTEMPTS는
    상한에 처음 도달한 직후 한 번만 기록하고 이후 요청은 건너뛴다.
    """
    terminal_reason = reason in {
        AuthError.OTP_ALREADY_CONSUMED,
        AuthError.OTP_EXPIRED,
        AuthError.OTP_MAX_ATTEMPTS,
    }
    if terminal_reason:
        limit_reached = (
            row.attempt_count > settings.otp_max_attempts
            if reason is AuthError.OTP_MAX_ATTEMPTS
            else row.attempt_count >= settings.otp_max_attempts
        )
        if limit_reached:
            return False
        row.attempt_count += 1

    payload = {
        "reason": reason.value,
        "attempt_count": row.attempt_count,
    }

    await record_audit_event(
        db,
        event_type=AuditEventType.PHONE_VERIFICATION_FAILED.value,
        actor_type=AuditActorType.USER.value,
        actor_ref=mask_phone(row.phone_number),
        aggregate_type=AuditAggregateType.PHONE_VERIFICATION.value,
        aggregate_id=str(row.id),
        payload=payload,
    )
    # 실패 이력이 롤백되지 않도록 예외 이전에 커밋한다.
    # 이 경로에는 감사 로그 외에 롤백되어야 할 업무 변경이 없다.
    # (OTP_MISMATCH의 attempt_count 증가는 저장되어야 하는 값이다)
    await db.commit()
    return True


# ---------------------------------------------------------------------------
@router.post(
    "/phone/request",
    response_model=PhoneRequestResponse,
    summary="전화번호 인증번호 발송",
    responses={
        429: {
            "model": AuthErrorResponse,
            "description": (
                "재전송 대기·횟수 또는 발송량 제한. 검증 시도 소진으로 발급이 "
                "잠긴 경우 OTP_LOCKED_UNTIL_EXPIRY와 만료까지의 Retry-After 반환"
            ),
            "headers": {
                "Retry-After": {
                    "description": "다시 요청할 수 있을 때까지 남은 초",
                    "schema": {"type": "integer"},
                }
            },
        },
        502: {
            "model": AuthErrorResponse,
            "description": "SOLAPI가 SMS를 접수하지 못함",
        },
        503: {
            "model": AuthErrorResponse,
            "description": "서버에 SOLAPI 설정이 준비되지 않음",
        },
    },
)
async def request_phone_otp(
    body: PhoneRequestBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """전화번호로 인증번호를 발송하고 인증 요청 건을 생성한다.

    발급마다 새로운 verification_id를 반환한다. 재발급에 성공하면 이전의
    미검증 요청은 만료되며, 새 ID를 이후 phone/verify와 signup에 전달한다.
    인증번호는 expires_at까지만 유효하며, 이후에는 재요청이 필요하다.
    """
    if not settings.dev_mode:
        try:
            validate_sms_configuration()
        except SmsConfigurationError:
            logger.error("SOLAPI configuration is missing or invalid")
            raise _fail(
                AuthError.SMS_SERVICE_UNAVAILABLE,
                status.HTTP_503_SERVICE_UNAVAILABLE,
            )

    row, now = await _find_active_phone_verification(
        db,
        phone_number=body.phone_number,
    )

    if row is not None:
        if row.attempt_count >= settings.otp_max_attempts:
            raise _fail(
                AuthError.OTP_LOCKED_UNTIL_EXPIRY,
                status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": str(_retry_after_until(row.expires_at, now))},
            )
        if row.resend_count >= settings.otp_max_resends:
            raise _fail(
                AuthError.OTP_RESEND_LIMIT_REACHED,
                status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": str(_retry_after_until(row.expires_at, now))},
            )
        elapsed = (now - row.last_sent_at).total_seconds()
        retry_after = math.ceil(settings.otp_resend_cooldown_seconds - elapsed)
        if retry_after > 0:
            raise _fail(
                AuthError.OTP_RESEND_TOO_SOON,
                status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": str(retry_after)},
            )

    reservation_token = None
    if not settings.dev_mode:
        client_id = request.client.host if request.client is not None else "unknown"
        reservation = await otp_sms_rate_limiter.reserve(
            client_id,
            body.phone_number,
        )
        if isinstance(reservation, OtpSmsReservationDenied):
            raise _fail(
                AuthError.OTP_REQUEST_RATE_LIMITED,
                status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": str(reservation.retry_after_seconds)},
            )
        reservation_token = reservation.token

    try:
        attempt_count = row.attempt_count if row is not None else 0
        resend_count = row.resend_count + 1 if row is not None else 0
        if row is not None:
            # ID는 검증 후 회원가입에 쓰이는 비밀 식별자다. 전화번호만 아는
            # 새 요청자에게 기존 ID를 반환하면 인증 완료 상태가 공유된다.
            # 기존 요청을 만료시키되 번호별 실패·재발급 횟수는 이어받는다.
            # 위 row lock은 verify의 row lock과도 직렬화된다.
            row.expires_at = now
        row = PhoneVerificationRequest(
            phone_number=body.phone_number,
            otp_digest="",  # 아래서 id 확보 후 채움
            attempt_count=attempt_count,
            resend_count=resend_count,
            last_sent_at=now,
            expires_at=now + timedelta(minutes=settings.otp_expire_minutes),
        )
        db.add(row)
        await db.flush()  # 새 row.id(UUID)를 얻기 위해 flush

        otp = generate_otp()
        row.otp_digest = hash_otp(otp, str(row.id))
        verification_id = row.id
        prepared_digest = row.otp_digest
        prepared_last_sent_at = row.last_sent_at
        expires_at = row.expires_at

        # 먼저 OTP 상태를 확정해 문자만 도착하고 검증할 DB 상태는 없는 상황을
        # 막는다. 이 커밋으로 번호별 advisory/row lock과 DB connection도 외부
        # 네트워크 호출 전에 풀린다.
        await db.commit()
    except BaseException:
        if reservation_token is not None:
            await otp_sms_rate_limiter.release(
                reservation_token,
                retain_client_attempt=True,
            )
        raise

    if not settings.dev_mode:
        try:
            receipt = await send_otp_sms(body.phone_number, otp)
        except SmsConfigurationError:
            await otp_sms_rate_limiter.release(
                reservation_token,
                retain_client_attempt=True,
            )
            await _invalidate_failed_sms_request(
                db,
                verification_id=verification_id,
                prepared_digest=prepared_digest,
                prepared_last_sent_at=prepared_last_sent_at,
            )
            logger.error("SOLAPI configuration is missing or invalid")
            raise _fail(
                AuthError.SMS_SERVICE_UNAVAILABLE,
                status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except SmsDeliveryError as exc:
            if not exc.may_have_been_sent:
                await otp_sms_rate_limiter.release(
                    reservation_token,
                    retain_client_attempt=True,
                )
                await _invalidate_failed_sms_request(
                    db,
                    verification_id=verification_id,
                    prepared_digest=prepared_digest,
                    prepared_last_sent_at=prepared_last_sent_at,
                )
            logger.warning(
                "SOLAPI OTP SMS failed for %s (code=%s, outcome_unknown=%s)",
                mask_phone(body.phone_number),
                exc.provider_code,
                exc.may_have_been_sent,
            )
            raise _fail(AuthError.SMS_DELIVERY_FAILED, status.HTTP_502_BAD_GATEWAY)
        await otp_sms_rate_limiter.confirm(reservation_token)
        logger.info(
            "SOLAPI accepted OTP SMS for %s (group_id=%s, message_id=%s)",
            mask_phone(body.phone_number),
            receipt.group_id,
            receipt.message_id,
        )

    return PhoneRequestResponse(
        verification_id=str(verification_id), expires_at=expires_at,
        dev_otp=otp if settings.dev_mode else None,
    )


@router.post(
    "/phone/verify",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="인증번호 검증",
    responses={
        401: {
            "model": AuthErrorResponse,
            "description": "인증번호 불일치 / 이미 사용됨 / 만료 / 시도 횟수 초과",
        },
        404: {
            "model": AuthErrorResponse,
            "description": "해당 인증 요청을 찾을 수 없음",
        },
    },
)
async def verify_phone_otp(body: PhoneVerifyBody, db: AsyncSession = Depends(get_db)):
    """인증번호를 검증한다.

    성공 시 본문 없이 204를 반환한다. 인증 건은 이 시점에 소모되지 않으며,
    signup 요청에서 사용될 때 소모된다.

    실패 사유는 응답 본문의 detail.code로 구분된다.
    시도 횟수가 상한에 도달하면 이후 요청은 인증번호가 맞아도 거절된다.
    실제로 발급된 요청의 실패는 감사 로그에 남기고 사유는 payload.reason으로
    구분한다. 존재하지 않는 ID 조회는 인증 없이 감사 체인을 무한히 늘리는 통로가
    되지 않도록 애플리케이션 경고 로그만 남긴다.
    """
    # 같은 인증 요청에 대한 동시 검증을 직렬화한다. 잠금이 없으면 두 요청이
    # 같은 attempt_count를 읽고 각각 증가시켜 실패 횟수 하나가 유실될 수 있다.
    row = await db.get(
        PhoneVerificationRequest,
        body.verification_id,
        with_for_update=True,
    )
    if row is None:
        logger.warning(
            "OTP verification requested for an unknown verification ID"
        )
        raise _fail(AuthError.OTP_NOT_FOUND, status.HTTP_404_NOT_FOUND)

    if row.consumed_at is not None:
        await _record_phone_verification_failure(
            db,
            reason=AuthError.OTP_ALREADY_CONSUMED,
            row=row,
        )
        raise _fail(AuthError.OTP_ALREADY_CONSUMED)

    if datetime.now(timezone.utc) > row.expires_at:
        await _record_phone_verification_failure(
            db,
            reason=AuthError.OTP_EXPIRED,
            row=row,
        )
        raise _fail(AuthError.OTP_EXPIRED)

    if row.attempt_count >= settings.otp_max_attempts:
        await _record_phone_verification_failure(
            db,
            reason=AuthError.OTP_MAX_ATTEMPTS,
            row=row,
        )
        raise _fail(AuthError.OTP_MAX_ATTEMPTS)

    if not verify_otp(body.otp, str(row.id), row.otp_digest):
        row.attempt_count += 1
        await _record_phone_verification_failure(
            db,
            reason=AuthError.OTP_MISMATCH,
            row=row,
        )
        raise _fail(AuthError.OTP_MISMATCH)

    row.verified_at = datetime.now(timezone.utc)
    await record_audit_event(
        db,
        event_type=AuditEventType.PHONE_VERIFICATION_SUCCEEDED.value,
        actor_type=AuditActorType.USER.value,
        actor_ref=mask_phone(row.phone_number),
        aggregate_type=AuditAggregateType.PHONE_VERIFICATION.value,
        aggregate_id=str(row.id),
        payload={"attempt_count": row.attempt_count},
    )
    await db.commit()


@router.post(
    "/signup",
    response_model=UserResponse,
    summary="회원가입",
    responses={
        400: {
            "model": AuthErrorResponse,
            "description": "전화번호 미인증 또는 이미 사용된 인증 건",
        },
        404: {
            "model": AuthErrorResponse,
            "description": "해당 인증 요청을 찾을 수 없음",
        },
        409: {
            "model": AuthErrorResponse,
            "description": (
                "이미 존재하는 login_id (USER_ALREADY_EXISTS) 또는 "
                "이미 가입된 전화번호 (PHONE_ALREADY_REGISTERED)"
            ),
        },
    },
)
async def signup(body: SignupRequest, db: AsyncSession = Depends(get_db)):
    """전화번호 인증을 마친 건으로 회원가입한다.

    phone/verify를 통과한 verification_id가 필요하며, 해당 인증 건은
    이 시점에 소모되어 재사용할 수 없다.
    전화번호는 인증 건에서 가져오므로 요청 본문에 포함하지 않는다.
    """
    # 동시에 도착한 가입 요청도 같은 인증 건을 한 번만 소모해야 한다.
    verification = await db.get(
        PhoneVerificationRequest, body.verification_id, with_for_update=True,
    )
    if verification is None:
        raise _fail(AuthError.OTP_NOT_FOUND, status.HTTP_404_NOT_FOUND)
    if verification.verified_at is None:
        raise _fail(AuthError.PHONE_NOT_VERIFIED, status.HTTP_400_BAD_REQUEST)
    if verification.consumed_at is not None:
        raise _fail(AuthError.OTP_ALREADY_CONSUMED, status.HTTP_400_BAD_REQUEST)

    existing = await db.execute(select(User).where(User.login_id == body.login_id))
    if existing.scalar_one_or_none():
        raise _fail(AuthError.USER_ALREADY_EXISTS, status.HTTP_409_CONFLICT)

    # phone_number도 UNIQUE라 DB가 막지만, 걸러 두지 않으면 제약 위반이 그대로
    # 500으로 올라가 모바일이 "서버 오류"로 안내한다(#49). 탈퇴한 계정의 번호도
    # 제약에 남아 있으므로 status·withdrawn_at으로 좁히지 않는다.
    registered = await db.execute(
        select(User.id).where(User.phone_number == verification.phone_number)
    )
    if registered.scalar_one_or_none() is not None:
        raise _fail(AuthError.PHONE_ALREADY_REGISTERED, status.HTTP_409_CONFLICT)

    user = User(
        login_id=body.login_id,
        password_hash=hash_password(body.password),
        name=body.name,
        phone_number=verification.phone_number,
        phone_verified_at=verification.verified_at,
        platform_role="USER",
        status="ACTIVE",
    )
    db.add(user)
    verification.consumed_at = datetime.now(timezone.utc)
    try:
        # users INSERT가 나가는 지점이다. 같은 번호·아이디로 동시에 들어온
        # 가입(모바일 가입 버튼 이중 탭이 그렇다)은 위의 사전 확인을 둘 다
        # 통과한 뒤 여기서 UNIQUE 제약에 걸린다. 사전 확인과 같은 409로
        # 맞춰야 이 경로에서도 500이 나지 않는다.
        await db.flush()  # audit의 aggregate_id로 쓸 user.id 확보

        await record_audit_event(
            db,
            event_type=AuditEventType.USER_SIGNED_UP.value,
            actor_type=AuditActorType.USER.value,
            actor_ref=str(user.id),
            aggregate_type=AuditAggregateType.USER.value,
            aggregate_id=str(user.id),
            payload={"login_id": user.login_id, "phone": mask_phone(user.phone_number)},
        )
        # users INSERT + phone_verification_requests UPDATE + audit을 한 트랜잭션으로 커밋
        await db.commit()
    except IntegrityError as error:
        await db.rollback()
        conflict = _conflicting_unique(error)
        if conflict is None:
            raise
        raise _fail(conflict, status.HTTP_409_CONFLICT) from None
    await db.refresh(user)
    return user


# ---------------------------------------------------------------------------
@router.post(
    "/login",
    response_model=TokenResponse,
    summary="로그인",
    responses={
        401: {
            "model": AuthErrorResponse,
            "description": "아이디 또는 비밀번호가 올바르지 않음",
        }
    },
)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    """로그인하고 액세스·리프레시 토큰을 발급받는다.

    실패 사유는 계정 존재 여부를 드러내지 않도록 하나로 통일한다.
    """
    result = await db.execute(select(User).where(User.login_id == body.login_id))
    user = result.scalar_one_or_none()
    password_matches = verify_password_or_dummy(
        body.password,
        user.password_hash if user is not None else None,
    )
    if not password_matches:
        await record_audit_event(
            db,
            event_type=AuditEventType.LOGIN_FAILED.value,
            actor_type=AuditActorType.USER.value,
            actor_ref=body.login_id,
            aggregate_type=AuditAggregateType.USER.value,
            # 존재하지 않는 계정인지 비밀번호가 틀린 것인지는 남기지 않는다.
            # 감사 로그가 계정 존재 여부를 알려주는 통로가 되면 안 된다.
            #
            # aggregate_id도 비운다. 계정이 있을 때만 채우면 null 여부만으로
            # 계정 존재가 드러나고 user.id까지 특정되어, payload.reason을
            # 통일한 의미가 사라진다. 조사에는 actor_ref의 login_id로 충분하다.
            aggregate_id=None,
            payload={"reason": AuthError.INVALID_CREDENTIALS.value},
        )
        await db.commit()
        raise _fail(AuthError.INVALID_CREDENTIALS)

    await record_audit_event(
        db,
        event_type=AuditEventType.LOGIN_SUCCEEDED.value,
        actor_type=(
            AuditActorType.ADMIN.value
            if user.platform_role == "ADMIN"
            else AuditActorType.USER.value
        ),
        actor_ref=str(user.id),
        aggregate_type=AuditAggregateType.USER.value,
        aggregate_id=str(user.id),
        payload={"login_id": user.login_id, "platform_role": user.platform_role},
    )
    await db.commit()

    return TokenResponse(
        access_token=create_access_token(user.id, user.platform_role),
        refresh_token=create_refresh_token(user.id),
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="액세스 토큰 재발급",
    responses={
        401: {
            "model": AuthErrorResponse,
            "description": "리프레시 토큰이 유효하지 않거나 만료됨",
        }
    },
)
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """리프레시 토큰으로 액세스·리프레시 토큰을 재발급받는다.

    MVP 범위에서는 리프레시 토큰 블랙리스트를 두지 않으므로,
    재발급 후에도 이전 리프레시 토큰은 만료 전까지 유효하다.
    """
    try:
        claims = decode_login_token(body.refresh_token, expected_type="refresh")
    except TokenError as e:
        raise _fail(e.code)

    user = await db.get(User, claims["sub"])
    if user is None:
        raise _fail(AuthError.USER_NOT_FOUND)

    return TokenResponse(
        access_token=create_access_token(user.id, user.platform_role),
        refresh_token=create_refresh_token(user.id),
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="로그아웃",
)
async def logout():
    """로그아웃한다.

    MVP 범위에서는 서버가 토큰을 무효화하지 않으므로, 클라이언트가
    보관 중인 토큰을 폐기하는 것으로 로그아웃이 완료된다.
    """
    return None


@router.get(
    "/me",
    response_model=UserResponse,
    summary="내 정보 조회",
    responses=AUTHENTICATED_RESPONSES,
)
async def me(user: User = Depends(get_current_user)):
    """액세스 토큰으로 본인 정보를 조회한다."""
    return user


# ---------------------------------------------------------------------------
# 기기 등록
# ---------------------------------------------------------------------------
@router.post(
    "/devices",
    response_model=DeviceResponse,
    summary="기기 등록",
    responses=AUTHENTICATED_RESPONSES,
)
async def register_device(
    body: RegisterDeviceRequest, user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """기기를 등록한다.

    응답의 id가 이후 요청의 device_id다.
    이 시점에는 holder_did가 비어 있으며, VC를 발급받으려면
    bind-holder-key로 Holder 공개키를 먼저 등록해야 한다.
    """
    device = Device(user_id=user.id, device_identifier=body.device_identifier,
                    platform=body.platform, status="ACTIVE")
    db.add(device)
    await db.flush()  # audit의 aggregate_id로 쓸 device.id 확보

    await record_audit_event(
        db,
        event_type=AuditEventType.DEVICE_REGISTERED.value,
        actor_type=AuditActorType.USER.value,
        actor_ref=str(user.id),
        aggregate_type=AuditAggregateType.DEVICE.value,
        aggregate_id=str(device.id),
        payload={"device_identifier": device.device_identifier, "platform": device.platform},
    )
    await db.commit()
    await db.refresh(device)
    return device


@router.post(
    "/devices/bind-holder-key",
    response_model=DeviceResponse,
    summary="Holder 공개키 바인딩",
    responses={
        **AUTHENTICATED_RESPONSES,
        400: {
            "model": VcErrorResponse,
            "description": "소유 증명 서명 검증 실패 (HOLDER_KEY_PROOF_FAILED)",
        },
        404: {
            "model": VcErrorResponse,
            "description": "기기를 찾을 수 없거나 본인 소유가 아님 (DEVICE_NOT_FOUND)",
        },
    },
)
async def bind_holder_key(
    body: BindHolderKeyRequest, user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """기기에 Holder 공개키를 등록하고 did:key를 파생한다.

    공개키만 받는 것이 아니라, 대응하는 개인키를 실제로 보유하고 있는지
    서명으로 검증한다. 서명 대상은 device_id를 10진 문자열로 바꾼 바이트열이다.
    (예: device_id가 15이면 "15"의 UTF-8 바이트에 서명)

    재바인딩이 허용되며, holder_did가 실제로 바뀌는 경우 해당 기기로 발급된
    ACTIVE 상태 VC는 REVOKED로 전이되고, StatusList2021 폐기 목록의 해당
    비트도 함께 켜진다. 동일 키를 다시 바인딩하는 경우에는 소유자가
    그대로이므로 폐기하지 않는다.
    """
    # VC 발급(POST /did/issue)과 같은 기기 행을 잠가 두 요청을 직렬화한다.
    # 잠금이 없으면 발급이 옛 holder_did를 읽은 사이에 재바인딩이 폐기를
    # 끝내고, 뒤늦게 저장된 옛 키용 VC가 폐기를 피해 ACTIVE로 남는다.
    # 그 VC는 폐기 목록에도 없어 분실 기기가 키오스크를 그대로 통과한다.
    device = await db.get(Device, body.device_id, with_for_update=True)
    if device is None or device.user_id != user.id:
        raise api_error(VcError.DEVICE_NOT_FOUND, status.HTTP_404_NOT_FOUND)

    try:
        pub = load_public_key_pem(body.holder_public_key_pem)
        pub.verify(base64.b64decode(body.proof_signature_b64), str(body.device_id).encode())
    except Exception:
        raise api_error(VcError.HOLDER_KEY_PROOF_FAILED, status.HTTP_400_BAD_REQUEST)

    new_holder_did = public_key_to_did_key(pub)

    previous_holder_did = device.holder_did
    is_rebinding = previous_holder_did is not None and previous_holder_did != new_holder_did
    revoked_count = 0
    revoked_bit_count = 0

    # 재바인딩으로 holder_did가 바뀌면, 이전 DID로 발급된 VC는 더 이상
    # 이 기기의 현재 소유자를 가리키지 않는다. did:key는 자기완결적이라
    # 키오스크가 서버를 조회하지 않으므로, 서버 DB의 폐기만으로는 분실 기기의
    # VC가 만료 전까지 통과한다(#22에서 남겨둔 요구사항).
    # 이제 StatusList2021 비트까지 함께 켜서 키오스크도 거부하게 한다(#27).
    if is_rebinding:
        revoked_count, revoked_bit_count = await revoke_active_credentials_for_device(
            db, device.id
        )

    device.holder_did = new_holder_did
    device.holder_public_key = body.holder_public_key_pem

    # 기기 분실 후 재바인딩은 사후 조사에서 가장 중요한 이벤트다.
    # 몇 건의 VC가 폐기됐는지까지 남긴다.
    await record_audit_event(
        db,
        event_type=(
            AuditEventType.HOLDER_KEY_REBOUND.value
            if is_rebinding
            else AuditEventType.HOLDER_KEY_BOUND.value
        ),
        actor_type=AuditActorType.USER.value,
        actor_ref=str(user.id),
        aggregate_type=AuditAggregateType.DEVICE.value,
        aggregate_id=str(device.id),
        payload={
            "previous_holder_did": previous_holder_did,
            "new_holder_did": new_holder_did,
            "revoked_vc_count": revoked_count,
            # 폐기 목록에 실제로 반영된 수. revoked_vc_count와 다르면 상태
            # 목록 배정이 없는 옛 VC가 섞여 있다는 뜻이다.
            "revoked_status_list_bits": revoked_bit_count,
        },
    )

    await db.commit()
    await db.refresh(device)
    return device


@router.get(
    "/devices",
    response_model=list[DeviceResponse],
    summary="내 기기 목록 조회",
    responses=AUTHENTICATED_RESPONSES,
)
async def list_my_devices(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """본인이 등록한 기기 목록을 조회한다."""
    result = await db.execute(select(Device).where(Device.user_id == user.id))
    return result.scalars().all()
