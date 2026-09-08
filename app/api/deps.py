"""의존성(문지기). 비동기 DB 세션을 사용한다."""

import hashlib
import secrets

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.exc import MultipleResultsFound
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import TokenError, decode_login_token
from app.database import get_db
from app.models import Kiosk, User
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
    credentials: HTTPAuthorizationCredentials | None = Depends(kiosk_key_scheme),
    db: AsyncSession = Depends(get_db),
) -> Kiosk:
    """Bearer API Key로 키오스크를 찾는다. 로그인 JWT를 디코딩하지 않는다.

    GET에는 식별자 본문이 없으므로 키 해시로 조회한다. #42에서도 이 인증 주체와
    요청 본문의 kiosk_identifier가 일치하는지 별도로 확인해야 한다.
    """
    if credentials is None:
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)
    raw_key = credentials.credentials
    if not raw_key:
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    # 아직 키별 테이블/UNIQUE가 없다. 동일 키가 여러 단말에 등록됐다면
    # 임의의 단말로 인증하지 않고 거부한다. 두 행이면 중복 판정에 충분하다.
    result = await db.execute(
        select(Kiosk).where(Kiosk.api_key_hash == key_hash).limit(2)
    )
    try:
        kiosk = result.scalar_one_or_none()
    except MultipleResultsFound:
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID) from None
    if kiosk is None:
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)

    if not secrets.compare_digest(key_hash.encode("ascii"), kiosk.api_key_hash.encode("utf-8")):
        raise _deny_kiosk(AuthError.KIOSK_KEY_INVALID)
    if kiosk.status != "ACTIVE":
        raise _deny_kiosk(AuthError.KIOSK_INACTIVE)
    return kiosk


def _deny_kiosk(code: AuthError) -> HTTPException:
    error = _deny(code)
    error.headers = {
        "Cache-Control": "no-store",
        "Vary": "Authorization",
        "WWW-Authenticate": "Bearer",
    }
    return error
