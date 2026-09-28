"""관리자용 키오스크 등록 및 API Key 수명 관리 (#46).

키 원문은 발급 응답에서만 한 번 반환한다. DB에는 SHA-256 해시만 남기고,
감사 로그/Outbox에도 원문과 해시를 넣지 않는다.
"""

import base64
import hashlib
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.api.errors import ADMIN_RESPONSES, api_error
from app.core.audit import record_audit_event
from app.database import get_db
from app.models import Kiosk, KioskApiKey, Store, User
from app.schemas.errors import AuthError, AuthErrorResponse
from app.schemas.kiosk_admin import (
    IssueKioskKeyRequest,
    KioskKeyIssuedResponse,
    KioskKeyResponse,
    KioskRegisteredResponse,
    KioskResponse,
    RegisterKioskRequest,
    SetKioskKeyExpiryRequest,
)

router = APIRouter(prefix="/api/v1/admin/kiosks", tags=["admin"])

_NO_STORE = {"Cache-Control": "no-store"}
_CROCKFORD_LOWER = "0123456789abcdefghjkmnpqrstvwxyz"
_RESPONSES = {
    **ADMIN_RESPONSES,
    400: {"model": AuthErrorResponse, "description": "키 만료일이 과거이거나 현재 시각임"},
    404: {"model": AuthErrorResponse, "description": "매장, 키오스크 또는 키가 없음"},
    409: {"model": AuthErrorResponse, "description": "비활성 매장·키오스크·키 또는 식별자 충돌"},
}


def _error(code: AuthError, status_code: int):
    return api_error(code, status_code, headers=_NO_STORE)


def _new_key(kiosk_id: int, *, expires_at: datetime | None = None) -> tuple[str, KioskApiKey]:
    raw_key = "ak_" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    row = KioskApiKey(
        kiosk_id=kiosk_id,
        key_prefix=raw_key[:8],
        key_hash=hashlib.sha256(raw_key.encode("ascii")).hexdigest(),
        status="ACTIVE",
        expires_at=expires_at,
    )
    return raw_key, row


def _new_kiosk_identifier() -> str:
    """ADR-0004: 128-bit CSPRNG을 26자리 lowercase Crockford base32로 인코딩."""
    value = int.from_bytes(secrets.token_bytes(16), "big")
    encoded = "".join(_CROCKFORD_LOWER[(value >> shift) & 31] for shift in range(125, -1, -5))
    return "ka_" + encoded


def _validate_future(expires_at: datetime | None) -> None:
    if expires_at is not None and expires_at <= datetime.now(timezone.utc):
        raise _error(AuthError.KIOSK_KEY_EXPIRY_INVALID, status.HTTP_400_BAD_REQUEST)


async def _find_kiosk(db: AsyncSession, kiosk_identifier: str, *, lock: bool = True) -> Kiosk:
    stmt = select(Kiosk).where(Kiosk.kiosk_identifier == kiosk_identifier)
    if lock:
        # 식별자/PK는 바꾸지 않으므로 NO KEY UPDATE로 상태 변경만 직렬화한다.
        # FOR UPDATE는 자동 폐기 감사 로그의 kiosk FK 확인(KEY SHARE)을 막아
        # 키 행 또는 감사 체인 잠금과 교착 상태를 만들 수 있다.
        stmt = stmt.with_for_update(key_share=True)
    result = await db.execute(stmt)
    kiosk = result.scalar_one_or_none()
    if kiosk is None:
        raise _error(AuthError.KIOSK_NOT_FOUND, status.HTTP_404_NOT_FOUND)
    return kiosk


async def _find_key(db: AsyncSession, kiosk_id: int, key_id: int) -> KioskApiKey:
    result = await db.execute(
        select(KioskApiKey)
        .where(KioskApiKey.id == key_id, KioskApiKey.kiosk_id == kiosk_id)
        .with_for_update()
    )
    key = result.scalar_one_or_none()
    if key is None:
        raise _error(AuthError.KIOSK_KEY_NOT_FOUND, status.HTTP_404_NOT_FOUND)
    return key


async def _audit(db: AsyncSession, admin: User, event_type: str, kiosk: Kiosk, payload: dict) -> None:
    await record_audit_event(
        db,
        event_type=event_type,
        actor_type="ADMIN",
        actor_ref=str(admin.id),
        source_kiosk_id=kiosk.id,
        aggregate_type="KIOSK",
        aggregate_id=kiosk.kiosk_identifier,
        payload=payload,
    )


@router.post(
    "",
    response_model=KioskRegisteredResponse,
    status_code=status.HTTP_201_CREATED,
    responses=_RESPONSES,
)
async def register_kiosk(
    body: RegisterKioskRequest,
    response: Response,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    response.headers["Cache-Control"] = "no-store"
    store = await db.get(Store, body.store_id)
    if store is None:
        raise _error(AuthError.STORE_NOT_FOUND, status.HTTP_404_NOT_FOUND)
    if store.status != "ACTIVE":
        raise _error(AuthError.STORE_INACTIVE, status.HTTP_409_CONFLICT)

    kiosk = Kiosk(
        store_id=body.store_id,
        kiosk_identifier=_new_kiosk_identifier(),
        status="ACTIVE",
        software_version=body.software_version,
    )
    try:
        db.add(kiosk)
        await db.flush()
        raw_key, key = _new_key(kiosk.id)
        db.add(key)
        await db.flush()
        await _audit(db, admin, "KIOSK_REGISTERED", kiosk, {"store_id": kiosk.store_id, "key_id": key.id})
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise _error(AuthError.KIOSK_IDENTIFIER_CONFLICT, status.HTTP_409_CONFLICT) from None

    return KioskRegisteredResponse(
        kiosk_identifier=kiosk.kiosk_identifier,
        store_id=kiosk.store_id,
        status=kiosk.status,
        key=KioskKeyIssuedResponse(
            key_id=key.id,
            api_key=raw_key,
            key_prefix=key.key_prefix,
            expires_at=key.expires_at,
        ),
    )


@router.post(
    "/{kiosk_identifier}/keys",
    response_model=KioskKeyIssuedResponse,
    status_code=status.HTTP_201_CREATED,
    responses=_RESPONSES,
)
async def issue_kiosk_key(
    kiosk_identifier: str,
    body: IssueKioskKeyRequest,
    response: Response,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    response.headers["Cache-Control"] = "no-store"
    _validate_future(body.expires_at)
    kiosk = await _find_kiosk(db, kiosk_identifier)
    if kiosk.status != "ACTIVE":
        raise _error(AuthError.KIOSK_INACTIVE, status.HTTP_409_CONFLICT)
    raw_key, key = _new_key(kiosk.id, expires_at=body.expires_at)
    try:
        db.add(key)
        await db.flush()
        await _audit(db, admin, "KIOSK_KEY_ISSUED", kiosk, {"key_id": key.id})
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise _error(AuthError.KIOSK_KEY_CONFLICT, status.HTTP_409_CONFLICT) from None
    return KioskKeyIssuedResponse(
        key_id=key.id,
        api_key=raw_key,
        key_prefix=key.key_prefix,
        expires_at=key.expires_at,
    )


@router.get(
    "/{kiosk_identifier}/keys",
    response_model=list[KioskKeyResponse],
    responses=_RESPONSES,
)
async def list_kiosk_keys(
    kiosk_identifier: str,
    response: Response,
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """키 회전 전 기존 키의 사용 정지를 확인할 수 있도록 메타데이터만 제공."""
    response.headers["Cache-Control"] = "no-store"
    kiosk = await _find_kiosk(db, kiosk_identifier, lock=False)
    result = await db.execute(
        select(KioskApiKey)
        .where(KioskApiKey.kiosk_id == kiosk.id)
        .order_by(KioskApiKey.created_at.desc(), KioskApiKey.id.desc())
    )
    return [KioskKeyResponse.model_validate(key) for key in result.scalars().all()]


@router.patch(
    "/{kiosk_identifier}/keys/{key_id}",
    response_model=KioskKeyResponse,
    responses=_RESPONSES,
)
async def set_kiosk_key_expiry(
    kiosk_identifier: str,
    key_id: int,
    body: SetKioskKeyExpiryRequest,
    response: Response,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    response.headers["Cache-Control"] = "no-store"
    _validate_future(body.expires_at)
    kiosk = await _find_kiosk(db, kiosk_identifier)
    key = await _find_key(db, kiosk.id, key_id)
    if key.status != "ACTIVE":
        raise _error(AuthError.KIOSK_KEY_REVOKED, status.HTTP_409_CONFLICT)
    key.expires_at = body.expires_at
    await _audit(db, admin, "KIOSK_KEY_EXPIRY_SET", kiosk, {"key_id": key.id, "expires_at": key.expires_at.isoformat()})
    await db.commit()
    return KioskKeyResponse.model_validate(key)


@router.post(
    "/{kiosk_identifier}/keys/{key_id}/revoke",
    response_model=KioskKeyResponse,
    responses=_RESPONSES,
)
async def revoke_kiosk_key(
    kiosk_identifier: str,
    key_id: int,
    response: Response,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    response.headers["Cache-Control"] = "no-store"
    kiosk = await _find_kiosk(db, kiosk_identifier)
    key = await _find_key(db, kiosk.id, key_id)
    if key.status != "REVOKED":
        key.status = "REVOKED"
        key.revoked_at = datetime.now(timezone.utc)
        await _audit(db, admin, "KIOSK_KEY_REVOKED", kiosk, {"key_id": key.id})
        await db.commit()
    return KioskKeyResponse.model_validate(key)


@router.post(
    "/{kiosk_identifier}/revoke",
    response_model=KioskResponse,
    responses=_RESPONSES,
)
async def revoke_kiosk(
    kiosk_identifier: str,
    response: Response,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    response.headers["Cache-Control"] = "no-store"
    kiosk = await _find_kiosk(db, kiosk_identifier)
    if kiosk.status != "REVOKED":
        kiosk.status = "REVOKED"
        kiosk.revoked_at = datetime.now(timezone.utc)
        kiosk.updated_at = kiosk.revoked_at
        await _audit(db, admin, "KIOSK_REVOKED", kiosk, {"store_id": kiosk.store_id})
        await db.commit()
    return KioskResponse.model_validate(kiosk)
