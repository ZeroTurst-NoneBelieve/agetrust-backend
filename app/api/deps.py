"""의존성(문지기). 비동기 DB 세션을 사용한다."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.exc import MultipleResultsFound
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.errors import api_error
from app.core.audit import record_audit_event
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
        .with_for_update()
    )
    try:
        key = result.scalar_one_or_none()
    except MultipleResultsFound:
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID) from None
    if key is None:
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)

    if not secrets.compare_digest(key_hash.encode("ascii"), key.key_hash.encode("utf-8")):
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)
    now = datetime.now(timezone.utc)
    if (
        key.status != "ACTIVE"
        or key.revoked_at is not None
        or (key.expires_at is not None and key.expires_at <= now)
    ):
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)

    # 설치 중 유출된 신규 키가 장기간 남지 않도록, 한 번도 쓰이지 않은
    # 발급 키는 24시간 뒤 폐기한다. 이전 스키마에서 옮긴 키는 사용 이력을
    # 복원할 수 없으므로 별도 회전 대상으로 남긴다.
    if (
        key.key_prefix != "legacy__"
        and key.last_used_at is None
        and key.created_at <= now - timedelta(hours=24)
    ):
        key.status = "REVOKED"
        key.revoked_at = now
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

    kiosk = await db.get(Kiosk, key.kiosk_id)
    if kiosk is None:
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)
    if kiosk.status != "ACTIVE":
        raise _deny_kiosk(AuthError.KIOSK_INACTIVE)

    # 회전 후 구 키 사용이 멈췄는지 운영자가 확인할 수 있어야 한다.
    # 인증 의존성은 엔드포인트 본문보다 먼저 실행되므로 여기서 커밋해도
    # 이후 비즈니스 변경을 함께 저장하지 않는다.
    key.last_used_at = now
    await db.commit()
    return kiosk


def _deny_kiosk(code: AuthError) -> HTTPException:
    error = _deny(code)
    error.headers = {
        "Cache-Control": "no-store",
        "Vary": "Authorization",
        "WWW-Authenticate": "Bearer",
    }
    return error
