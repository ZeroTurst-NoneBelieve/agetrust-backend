"""가입 / 로그인 / 기기 등록.

devices 관련 엔드포인트는 팀 endpoints 목록(auth/vc/verify/stores)에
별도 파일이 없어 계정 관리 성격이 가까운 이 파일에 포함했습니다.
(팀 컨벤션상 별도 devices.py로 분리해야 하면 옮기기만 하면 됩니다)
"""

import base64
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.config import settings
from app.core.did_key import load_public_key_pem, public_key_to_did_key
from app.core.security import (
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_login_token,
    generate_otp,
    hash_otp,
    hash_password,
    verify_otp,
    verify_password,
)
from app.database import get_db
from app.models import Device, PhoneVerificationRequest, User
from app.schemas.device import BindHolderKeyRequest, DeviceResponse, RegisterDeviceRequest
from app.schemas.errors import AuthError
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


def _fail(code: AuthError, status_code: int = status.HTTP_401_UNAUTHORIZED):
    return HTTPException(status_code=status_code, detail={"code": code.value})


# ---------------------------------------------------------------------------
@router.post("/phone/request", response_model=PhoneRequestResponse)
async def request_phone_otp(body: PhoneRequestBody, db: AsyncSession = Depends(get_db)):
    otp = generate_otp()
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    row = PhoneVerificationRequest(
        phone_number=body.phone_number,
        otp_digest="",  # 아래서 id 확보 후 채움
        expires_at=now + timedelta(minutes=settings.otp_expire_minutes),
    )
    db.add(row)
    await db.flush()  # row.id(UUID)를 얻기 위해 flush

    row.otp_digest = hash_otp(otp, str(row.id))
    await db.commit()

    print(f"[SMS 시뮬레이터] {body.phone_number} 로 인증번호 발송: {otp}")

    return PhoneRequestResponse(
        verification_id=str(row.id), expires_at=row.expires_at,
        dev_otp=otp if settings.dev_mode else None,
    )


@router.post("/phone/verify", status_code=status.HTTP_204_NO_CONTENT)
async def verify_phone_otp(body: PhoneVerifyBody, db: AsyncSession = Depends(get_db)):
    row = await db.get(PhoneVerificationRequest, body.verification_id)
    if row is None:
        raise _fail(AuthError.OTP_NOT_FOUND, status.HTTP_404_NOT_FOUND)
    if row.consumed_at is not None:
        raise _fail(AuthError.OTP_ALREADY_CONSUMED)
    if datetime.now(timezone.utc) > row.expires_at:
        raise _fail(AuthError.OTP_EXPIRED)
    if row.attempt_count >= settings.otp_max_attempts:
        raise _fail(AuthError.OTP_MAX_ATTEMPTS)

    if not verify_otp(body.otp, str(row.id), row.otp_digest):
        row.attempt_count += 1
        await db.commit()
        raise _fail(AuthError.OTP_MISMATCH)

    row.verified_at = datetime.now(timezone.utc)
    await db.commit()


@router.post("/signup", response_model=UserResponse)
async def signup(body: SignupRequest, db: AsyncSession = Depends(get_db)):
    verification = await db.get(PhoneVerificationRequest, body.verification_id)
    if verification is None:
        raise _fail(AuthError.OTP_NOT_FOUND, status.HTTP_404_NOT_FOUND)
    if verification.verified_at is None:
        raise _fail(AuthError.PHONE_NOT_VERIFIED, status.HTTP_400_BAD_REQUEST)
    if verification.consumed_at is not None:
        raise _fail(AuthError.OTP_ALREADY_CONSUMED, status.HTTP_400_BAD_REQUEST)

    existing = await db.execute(select(User).where(User.login_id == body.login_id))
    if existing.scalar_one_or_none():
        raise _fail(AuthError.USER_ALREADY_EXISTS, status.HTTP_409_CONFLICT)

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
    # users INSERT + phone_verification_requests UPDATE를 한 트랜잭션으로 커밋
    await db.commit()
    await db.refresh(user)
    return user


# ---------------------------------------------------------------------------
@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.login_id == body.login_id))
    user = result.scalar_one_or_none()
    if user is None or not verify_password(body.password, user.password_hash):
        raise _fail(AuthError.INVALID_CREDENTIALS)

    return TokenResponse(
        access_token=create_access_token(user.id, user.platform_role),
        refresh_token=create_refresh_token(user.id),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
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


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout():
    return None


@router.get("/me", response_model=UserResponse)
async def me(user: User = Depends(get_current_user)):
    return user


# ---------------------------------------------------------------------------
# 기기 등록
# ---------------------------------------------------------------------------
@router.post("/devices", response_model=DeviceResponse)
async def register_device(
    body: RegisterDeviceRequest, user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    device = Device(user_id=user.id, device_identifier=body.device_identifier,
                    platform=body.platform, status="ACTIVE")
    db.add(device)
    await db.commit()
    await db.refresh(device)
    return device


@router.post("/devices/bind-holder-key", response_model=DeviceResponse)
async def bind_holder_key(
    body: BindHolderKeyRequest, user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    device = await db.get(Device, body.device_id)
    if device is None or device.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="device not found")

    try:
        pub = load_public_key_pem(body.holder_public_key_pem)
        pub.verify(base64.b64decode(body.proof_signature_b64), str(body.device_id).encode())
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="key ownership proof failed")

    device.holder_did = public_key_to_did_key(pub)
    device.holder_public_key = body.holder_public_key_pem
    await db.commit()
    await db.refresh(device)
    return device


@router.get("/devices", response_model=list[DeviceResponse])
async def list_my_devices(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Device).where(Device.user_id == user.id))
    return result.scalars().all()