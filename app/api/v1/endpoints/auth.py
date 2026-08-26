"""가입 / 로그인 / 기기 등록.

devices 관련 엔드포인트는 팀 endpoints 목록(auth/vc/verify/stores)에
별도 파일이 없어 계정 관리 성격이 가까운 이 파일에 포함했습니다.
(팀 컨벤션상 별도 devices.py로 분리해야 하면 옮기기만 하면 됩니다)
"""

import base64
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.config import settings
from app.core.audit import mask_phone, record_audit_event
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
from app.models import Device, PhoneVerificationRequest, User, VcCredential
from app.schemas.audit import (
    AuditActorType,
    AuditAggregateType,
    AuditEventType,
)
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

    if settings.dev_mode:
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
        await record_audit_event(
            db,
            event_type=AuditEventType.PHONE_VERIFICATION_FAILED.value,
            actor_type=AuditActorType.USER.value,
            actor_ref=mask_phone(row.phone_number),
            aggregate_type=AuditAggregateType.PHONE_VERIFICATION.value,
            aggregate_id=str(row.id),
            payload={"reason": AuthError.OTP_MISMATCH.value, "attempt_count": row.attempt_count},
        )
        # 실패 이력이 롤백되지 않도록 예외 이전에 커밋한다.
        await db.commit()
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
    await db.refresh(user)
    return user


# ---------------------------------------------------------------------------
@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.login_id == body.login_id))
    user = result.scalar_one_or_none()
    if user is None or not verify_password(body.password, user.password_hash):
        await record_audit_event(
            db,
            event_type=AuditEventType.LOGIN_FAILED.value,
            actor_type=AuditActorType.USER.value,
            actor_ref=body.login_id,
            aggregate_type=AuditAggregateType.USER.value,
            aggregate_id=str(user.id) if user else None,
            # 존재하지 않는 계정인지 비밀번호가 틀린 것인지는 남기지 않는다.
            # 감사 로그가 계정 존재 여부를 알려주는 통로가 되면 안 된다.
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

    new_holder_did = public_key_to_did_key(pub)

    previous_holder_did = device.holder_did
    is_rebinding = previous_holder_did is not None and previous_holder_did != new_holder_did
    revoked_count = 0

    # 재바인딩으로 holder_did가 바뀌면, 이전 DID로 발급된 VC는 더 이상
    # 이 기기의 현재 소유자를 가리키지 않는다. did:key는 자기완결적이라
    # 키오스크가 서버를 조회하지 않으므로, 최소한 서버 DB에 폐기 사실을 남긴다.
    # (실제 차단은 폐기 목록 동기화가 구현되어야 완성된다 — #22 참고)
    if is_rebinding:
        result = await db.execute(
            update(VcCredential)
            .where(
                VcCredential.device_id == device.id,
                VcCredential.status == "ACTIVE",
            )
            .values(status="REVOKED", revoked_at=datetime.now(timezone.utc))
        )
        revoked_count = result.rowcount or 0

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
        },
    )

    await db.commit()
    await db.refresh(device)
    return device


@router.get("/devices", response_model=list[DeviceResponse])
async def list_my_devices(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Device).where(Device.user_id == user.id))
    return result.scalars().all()