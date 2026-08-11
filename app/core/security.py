"""JWT / 비밀번호 - 로그인 관련 보안 유틸.

DID/VC 서명은 app/core/did_crypto.py 에 분리했다.
"""

import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.config import settings
from app.schemas.errors import AuthError


class TokenError(Exception):
    def __init__(self, code: AuthError):
        self.code = code
        super().__init__(code)


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8")[:72], bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8")[:72], hashed.encode("utf-8"))
    except ValueError:
        return False


def _create_login_token(subject: int, token_type: str, expires: timedelta,
                        extra: dict | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        # JWT 표준상 sub는 문자열이어야 한다. DB의 id(int)는 문자열로 변환해서 담는다.
        "sub": str(subject), "type": token_type, "jti": str(uuid.uuid4()),
        "iat": now, "exp": now + expires,
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def create_access_token(user_id: int, platform_role: str) -> str:
    return _create_login_token(
        subject=user_id, token_type="access",
        expires=timedelta(minutes=settings.access_token_expire_minutes),
        extra={"platform_role": platform_role},
    )


def create_refresh_token(user_id: int) -> str:
    return _create_login_token(
        subject=user_id, token_type="refresh",
        expires=timedelta(days=settings.refresh_token_expire_days),
    )


def decode_login_token(token: str, expected_type: str = "access") -> dict:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except jwt.ExpiredSignatureError:
        raise TokenError(AuthError.TOKEN_EXPIRED)
    except jwt.InvalidTokenError:
        raise TokenError(AuthError.TOKEN_INVALID)

    if payload.get("type") != expected_type:
        raise TokenError(AuthError.TOKEN_WRONG_TYPE)
    # sub는 문자열로 저장했으니 다시 int로 변환해서 돌려준다.
    payload["sub"] = int(payload["sub"])
    return payload


# ---------------------------------------------------------------------------
# OTP (SMS 인증번호)
# ---------------------------------------------------------------------------
import hashlib
import hmac
import secrets


def generate_otp() -> str:
    return f"{secrets.randbelow(10**settings.otp_length):0{settings.otp_length}d}"


def hash_otp(otp: str, verification_id: str) -> str:
    msg = f"{verification_id}:{otp}".encode()
    return hmac.new(settings.secret_key.encode(), msg, hashlib.sha256).hexdigest()


def verify_otp(otp: str, verification_id: str, digest: str) -> bool:
    return hmac.compare_digest(hash_otp(otp, verification_id), digest)