"""의존성(문지기). 비동기 DB 세션을 사용한다."""

import hashlib
import secrets

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import TokenError, decode_login_token
from app.database import get_db
from app.models import Kiosk, User
from app.schemas.errors import AuthError

bearer_scheme = HTTPBearer(auto_error=False)
kiosk_key_scheme = APIKeyHeader(
    name="X-Kiosk-Key",
    scheme_name="KioskApiKey",
    description="등록된 키오스크의 <kiosk_identifier>:<raw_key>. 로그인 Bearer 토큰과 다릅니다.",
    auto_error=False,
)


def _deny(code: AuthError, status_code: int = status.HTTP_401_UNAUTHORIZED):
    return HTTPException(status_code=status_code, detail={"code": code.value})


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
    if user.platform_role != "ADMIN":
        raise _deny(AuthError.PERMISSION_DENIED, status.HTTP_403_FORBIDDEN)
    return user


async def get_current_kiosk(
    x_kiosk_key: str | None = Depends(kiosk_key_scheme),
    db: AsyncSession = Depends(get_db),
) -> Kiosk:
    """기존 X-Kiosk-Key 계약으로 매 요청의 키와 ACTIVE 상태를 확인한다."""
    if not x_kiosk_key:
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)
    try:
        identifier, raw_key = x_kiosk_key.split(":", 1)
    except ValueError:
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)
    if not identifier or not raw_key:
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)

    result = await db.execute(select(Kiosk).where(Kiosk.kiosk_identifier == identifier))
    kiosk = result.scalar_one_or_none()
    if kiosk is None:
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)

    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    if not secrets.compare_digest(key_hash.encode("ascii"), kiosk.api_key_hash.encode("utf-8")):
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)
    if kiosk.status != "ACTIVE":
        raise _deny_kiosk(AuthError.KIOSK_INACTIVE)
    return kiosk


def _deny_kiosk(code: AuthError) -> HTTPException:
    error = _deny(code)
    error.headers = {"Cache-Control": "no-store", "Vary": "X-Kiosk-Key"}
    return error
