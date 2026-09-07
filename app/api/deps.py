"""의존성(문지기). 비동기 DB 세션을 사용한다."""

import hashlib

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import TokenError, decode_login_token
from app.database import get_db
from app.models import Kiosk, User
from app.schemas.errors import AuthError

bearer_scheme = HTTPBearer(auto_error=False)


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
    x_kiosk_key: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> Kiosk:
    if not x_kiosk_key:
        raise _deny(AuthError.KIOSK_KEY_INVALID)
    try:
        identifier, raw_key = x_kiosk_key.split(":", 1)
    except ValueError:
        raise _deny(AuthError.KIOSK_KEY_INVALID)

    result = await db.execute(select(Kiosk).where(Kiosk.kiosk_identifier == identifier))
    kiosk = result.scalar_one_or_none()
    if kiosk is None:
        raise _deny(AuthError.KIOSK_KEY_INVALID)

    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    if key_hash != kiosk.api_key_hash:
        raise _deny(AuthError.KIOSK_KEY_INVALID)
    if kiosk.status != "ACTIVE":
        raise _deny(AuthError.KIOSK_INACTIVE)
    return kiosk
