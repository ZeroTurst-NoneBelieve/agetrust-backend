"""의존성(문지기). 비동기 DB 세션을 사용한다."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import MultipleResultsFound
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.errors import api_error
from app.core.audit import record_audit_event
from app.core.kiosk_key_cleanup import UNUSED_KEY_GRACE_PERIOD
from app.core.security import TokenError, decode_login_token
from app.database import get_db
from app.models import Kiosk, KioskApiKey, User
from app.schemas.errors import AuthError

bearer_scheme = HTTPBearer(auto_error=False)
kiosk_key_scheme = HTTPBearer(
    scheme_name="KioskApiKey",
    bearerFormat="API key",
    description=(
        "Authorization: Bearer <api_key>. 등록된 키오스크의 API Key 원문만 입력합니다. "
        "사용자 로그인 JWT나 kiosk_identifier:raw_key 형식이 아닙니다."
    ),
    auto_error=False,
)

# 회전 확인에 필요한 분 단위 사용 이력만 쓴다. 최초 사용은 즉시 기록한다.
KIOSK_KEY_USAGE_INTERVAL = timedelta(minutes=1)


def _deny(code: AuthError, status_code: int = status.HTTP_401_UNAUTHORIZED):
    """문지기가 막는 경우는 대부분 401이라 기본값으로 둔다."""
    return api_error(code, status_code)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    if credentials is None:
        raise _deny(AuthError.TOKEN_MISSING)
    try:
        payload = decode_login_token(credentials.credentials, expected_type="access")
    except TokenError as e:
        raise _deny(e.code)

    user = await db.get(User, payload["sub"])
    if user is None:
        raise _deny(AuthError.USER_NOT_FOUND)
    return user


async def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.platform_role != "ADMIN" or user.status != "ACTIVE":
        raise _deny(AuthError.PERMISSION_DENIED, status.HTTP_403_FORBIDDEN)
    return user


async def get_current_kiosk(
    credentials: HTTPAuthorizationCredentials | None = Depends(kiosk_key_scheme),
    db: AsyncSession = Depends(get_db),
) -> Kiosk:
    """Bearer API Key로 키오스크를 찾는다. 로그인 JWT를 디코딩하지 않는다.

    등록된 키의 해시와 접두사로 조회한다. 마이그레이션 전에 발급된 키는
    접두사를 복구할 수 없어 ``legacy__`` 표식으로 보존한다. #42에서도
    이 인증 주체와 요청 본문의 kiosk_identifier가 일치하는지 확인해야 한다.
    """
    if credentials is None:
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)
    raw_key = credentials.credentials
    if not raw_key:
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    # prefix는 후보를 좁히는 용도이며 비밀이 아니다. 해시가 같더라도 접두사가
    # 맞지 않으면 거부한다. 이전 키는 원문 접두사를 알 수 없으므로 별도 표식으로 찾는다.
    result = await db.execute(
        select(KioskApiKey)
        .where(
            KioskApiKey.key_hash == key_hash,
            KioskApiKey.key_prefix.in_((raw_key[:8], "legacy__")),
        )
        .limit(2)
    )
    try:
        key = result.scalar_one_or_none()
    except MultipleResultsFound:
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID) from None
    if key is None:
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)

    if not secrets.compare_digest(key_hash.encode("ascii"), key.key_hash.encode("utf-8")):
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)
    key = await _check_kiosk_key(db, key)

    kiosk = await db.get(Kiosk, key.kiosk_id)
    if kiosk is None:
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)
    if kiosk.status != "ACTIVE":
        raise _deny_kiosk(AuthError.KIOSK_INACTIVE)

    now = datetime.now(timezone.utc)
    if key.last_used_at is None or key.last_used_at <= now - KIOSK_KEY_USAGE_INTERVAL:
        # 같은 오래된 시각을 읽은 요청이 겹쳐도 첫 요청만 갱신한다.
        # UPDATE에서도 폐기·만료와 신규 키의 24시간 제한을 확인한다.
        # clock_timestamp()로 트랜잭션 시작 시각에 고정되는 now()를 피한다.
        touched = await db.execute(
            update(KioskApiKey)
            .where(
                KioskApiKey.id == key.id,
                KioskApiKey.status == "ACTIVE",
                KioskApiKey.revoked_at.is_(None),
                or_(KioskApiKey.expires_at.is_(None), KioskApiKey.expires_at > func.clock_timestamp()),
                or_(
                    KioskApiKey.key_prefix == "legacy__",
                    KioskApiKey.last_used_at.is_not(None),
                    KioskApiKey.created_at > func.clock_timestamp() - UNUSED_KEY_GRACE_PERIOD,
                ),
                or_(
                    KioskApiKey.last_used_at.is_(None),
                    KioskApiKey.last_used_at <= now - KIOSK_KEY_USAGE_INTERVAL,
                ),
            )
            .values(last_used_at=func.greatest(KioskApiKey.last_used_at, func.clock_timestamp()))
            .returning(KioskApiKey.id)
            .execution_options(synchronize_session=False)
        )
        if touched.scalar_one_or_none() is None:
            # 다른 인증이 먼저 기록했거나 폐기가 먼저 끝났을 수 있다.
            # identity map의 오래된 값 대신 최신 상태로 다시 판단한다.
            key = await db.get(KioskApiKey, key.id, populate_existing=True)
            await _check_kiosk_key(db, key)

    # 인증 의존성은 엔드포인트 본문보다 먼저 실행된다. 인증 트랜잭션을
    # 끝내 결과 기록 등 이후 업무 변경과 사용 이력의 저장을 분리한다.
    await db.commit()
    return kiosk


def _unused_key_expired(key: KioskApiKey, now: datetime) -> bool:
    return (
        key.key_prefix != "legacy__"
        and key.last_used_at is None
        and key.created_at <= now - UNUSED_KEY_GRACE_PERIOD
    )


def _validate_kiosk_key(key: KioskApiKey | None, now: datetime) -> None:
    if (
        key is None
        or key.status != "ACTIVE"
        or key.revoked_at is not None
        or (key.expires_at is not None and key.expires_at <= now)
    ):
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)


async def _check_kiosk_key(db: AsyncSession, key: KioskApiKey | None) -> KioskApiKey:
    now = datetime.now(timezone.utc)
    _validate_kiosk_key(key, now)
    if not _unused_key_expired(key, now):
        return key

    # 최초 사용·관리자 폐기·정리 루프와 경합해도 상태를 덮어쓰지 않는다.
    # 실제로 폐기한 요청만 감사/Outbox를 기록한다. legacy 키는 제외한다.
    result = await db.execute(
        update(KioskApiKey)
        .where(
            KioskApiKey.id == key.id,
            KioskApiKey.status == "ACTIVE",
            KioskApiKey.revoked_at.is_(None),
            KioskApiKey.key_prefix != "legacy__",
            KioskApiKey.last_used_at.is_(None),
            KioskApiKey.created_at <= now - UNUSED_KEY_GRACE_PERIOD,
        )
        .values(status="REVOKED", revoked_at=now)
        .returning(KioskApiKey.id)
        .execution_options(synchronize_session=False)
    )
    if result.scalar_one_or_none() is not None:
        await record_audit_event(
            db,
            event_type="KIOSK_KEY_AUTO_REVOKED",
            actor_type="SYSTEM",
            source_kiosk_id=key.kiosk_id,
            aggregate_type="KIOSK_KEY",
            aggregate_id=str(key.id),
            payload={"key_id": key.id, "reason": "UNUSED_24H"},
        )
        await db.commit()
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)

    key = await db.get(KioskApiKey, key.id, populate_existing=True)
    now = datetime.now(timezone.utc)
    _validate_kiosk_key(key, now)
    if _unused_key_expired(key, now):
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)
    return key


def _deny_kiosk(code: AuthError) -> HTTPException:
    error = _deny(code)
    error.headers = {
        "Cache-Control": "no-store",
        "Vary": "Authorization",
        "WWW-Authenticate": "Bearer",
    }
    return error
