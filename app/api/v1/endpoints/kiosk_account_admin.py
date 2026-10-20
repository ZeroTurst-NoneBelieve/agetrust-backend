"""관리자용 KIOSK 계정 생성·관리 (#66).

KIOSK 계정은 전화번호 없이 관리자가 만든다. 임시 비밀번호는 서버가 만들어
생성·초기화 응답에서 한 번만 돌려준다. DB에는 bcrypt 해시만 남기고, 감사 로그에는
비밀번호를 넣지 않는다.

사업자 정보는 기존 businesses에 두고 business_memberships(OWNER)로 계정과 잇는다.
키오스크 단말의 API Key(/api/v1/admin/kiosks)와는 별개의 계정이다.
"""

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.api.errors import ADMIN_RESPONSES, api_error
from app.core.audit import record_audit_event
from app.core.security import hash_password
from app.database import get_db
from app.models import Business, BusinessMembership, User
from app.schemas.audit import AuditActorType, AuditAggregateType, AuditEventType
from app.schemas.errors import AuthError, AuthErrorResponse
from app.schemas.kiosk_account_admin import (
    CreateKioskAccountRequest,
    KioskAccountBusiness,
    KioskAccountCredentialResponse,
    KioskAccountResponse,
)

router = APIRouter(prefix="/api/v1/admin/kiosk-accounts", tags=["admin"])

# 매장에 전달해 첫 로그인할 때까지의 기한.
TEMP_PASSWORD_TTL = timedelta(hours=72)
MAX_PAGE_SIZE = 200

# 키오스크 화면에 옮겨 적기 쉽도록 헷갈리는 글자(0·O, 1·l·I)를 뺀다. 12자 ≈ 69비트.
_TEMP_PASSWORD_ALPHABET = "23456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
_TEMP_PASSWORD_LENGTH = 12

_NO_STORE = {"Cache-Control": "no-store"}
_NOT_FOUND = {"model": AuthErrorResponse, "description": "KIOSK 계정이 없음(KIOSK_ACCOUNT_NOT_FOUND)"}
_WITHDRAWN = {"model": AuthErrorResponse, "description": "탈퇴 처리된 계정이라 바꿀 수 없음(ACCOUNT_INACTIVE)"}
_CREATE_RESPONSES = {
    **ADMIN_RESPONSES,
    409: {
        "model": AuthErrorResponse,
        "description": "아이디 중복(USER_ALREADY_EXISTS) · 정지·해지된 사업자(BUSINESS_INACTIVE)",
    },
}
_DETAIL_RESPONSES = {**ADMIN_RESPONSES, 404: _NOT_FOUND}
_CHANGE_RESPONSES = {**ADMIN_RESPONSES, 404: _NOT_FOUND, 409: _WITHDRAWN}


def _error(code: AuthError, status_code: int):
    return api_error(code, status_code, headers=_NO_STORE)


def _new_temp_password() -> str:
    return "".join(secrets.choice(_TEMP_PASSWORD_ALPHABET) for _ in range(_TEMP_PASSWORD_LENGTH))


def _set_temp_password(account: User, now: datetime) -> str:
    """임시 비밀번호를 새로 정하고 원문을 돌려준다. 원문은 응답에만 싣는다."""
    raw = _new_temp_password()
    account.password_hash = hash_password(raw)
    account.must_change_password = True
    account.temp_password_expires_at = now + TEMP_PASSWORD_TTL
    return raw


def _to_response(account: User, business: Business | None) -> KioskAccountResponse:
    return KioskAccountResponse(
        id=account.id,
        login_id=account.login_id,
        name=account.name,
        status=account.status,
        must_change_password=account.must_change_password,
        temp_password_expires_at=account.temp_password_expires_at,
        created_at=account.created_at,
        business=KioskAccountBusiness.model_validate(business) if business is not None else None,
    )


async def _owner_businesses(db: AsyncSession, user_ids: list[int]) -> dict[int, Business]:
    if not user_ids:
        return {}
    rows = await db.execute(
        select(BusinessMembership.user_id, Business)
        .join(Business, Business.id == BusinessMembership.business_id)
        .where(BusinessMembership.user_id.in_(user_ids), BusinessMembership.business_role == "OWNER")
        .order_by(BusinessMembership.id)
    )
    found: dict[int, Business] = {}
    for user_id, business in rows.all():
        found.setdefault(user_id, business)
    return found


async def _find_account(db: AsyncSession, account_id: int, *, lock: bool) -> User:
    # 상태 변경·비밀번호 초기화는 같은 계정의 비밀번호 변경(POST /auth/password)과
    # 같은 행 잠금으로 직렬화한다.
    account = await db.get(User, account_id, with_for_update=lock, populate_existing=lock)
    if account is None or account.platform_role != "KIOSK":
        raise _error(AuthError.KIOSK_ACCOUNT_NOT_FOUND, status.HTTP_404_NOT_FOUND)
    return account


async def _audit(db: AsyncSession, admin: User, event_type: AuditEventType, account: User, payload: dict) -> None:
    await record_audit_event(
        db,
        event_type=event_type.value,
        actor_type=AuditActorType.ADMIN.value,
        actor_ref=str(admin.id),
        aggregate_type=AuditAggregateType.USER.value,
        aggregate_id=str(account.id),
        payload=payload,
    )


@router.post(
    "",
    response_model=KioskAccountCredentialResponse,
    status_code=status.HTTP_201_CREATED,
    summary="KIOSK 계정 생성",
    responses=_CREATE_RESPONSES,
)
async def create_kiosk_account(
    body: CreateKioskAccountRequest,
    response: Response,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """전화번호 없는 KIOSK 계정을 만들고 임시 비밀번호를 한 번만 돌려준다.

    사업자등록번호가 이미 있으면 그 사업자에, 없으면 새 사업자를 만들어 OWNER로 연결한다.
    임시 비밀번호는 72시간 안에 첫 로그인해서 바꿔야 한다.
    """
    response.headers["Cache-Control"] = "no-store"
    taken = await db.execute(select(User.id).where(User.login_id == body.login_id))
    if taken.scalar_one_or_none() is not None:
        raise _error(AuthError.USER_ALREADY_EXISTS, status.HTTP_409_CONFLICT)

    now = datetime.now(timezone.utc)
    try:
        # 같은 사업자로 동시에 만들어도 사업자 행은 하나만 생긴다.
        inserted = await db.execute(
            pg_insert(Business)
            .values(
                business_number=body.business_number,
                business_name=body.business_name,
                contact_number=body.contact_number,
                status="ACTIVE",
            )
            .on_conflict_do_nothing(index_elements=[Business.business_number])
        )
        business_created = inserted.rowcount == 1
        business = (
            await db.execute(select(Business).where(Business.business_number == body.business_number))
        ).scalar_one()
        if business.status != "ACTIVE":
            await db.rollback()
            raise _error(AuthError.BUSINESS_INACTIVE, status.HTTP_409_CONFLICT)

        account = User(
            login_id=body.login_id,
            password_hash="",
            name=body.name,
            platform_role="KIOSK",
            status="ACTIVE",
        )
        temporary_password = _set_temp_password(account, now)
        db.add(account)
        await db.flush()
        db.add(
            BusinessMembership(
                user_id=account.id, business_id=business.id, business_role="OWNER", status="ACTIVE"
            )
        )
        await db.flush()
        await _audit(
            db,
            admin,
            AuditEventType.KIOSK_ACCOUNT_CREATED,
            account,
            {
                "login_id": account.login_id,
                "business_id": business.id,
                "business_created": business_created,
                "temp_password_expires_at": account.temp_password_expires_at.isoformat(),
            },
        )
        await db.commit()
    except IntegrityError:
        # 사전 확인과 저장 사이에 같은 아이디가 먼저 들어온 경우.
        await db.rollback()
        taken = await db.execute(select(User.id).where(User.login_id == body.login_id))
        if taken.scalar_one_or_none() is not None:
            raise _error(AuthError.USER_ALREADY_EXISTS, status.HTTP_409_CONFLICT) from None
        raise

    await db.refresh(account)
    return KioskAccountCredentialResponse(
        account=_to_response(account, business),
        temporary_password=temporary_password,
    )


@router.get(
    "",
    response_model=list[KioskAccountResponse],
    summary="KIOSK 계정 목록",
    responses=ADMIN_RESPONSES,
)
async def list_kiosk_accounts(
    response: Response,
    account_status: str | None = Query(
        default=None, alias="status", pattern="^(ACTIVE|SUSPENDED|WITHDRAWN)$", description="계정 상태로 거른다."
    ),
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """KIOSK 계정을 최근 생성 순으로 돌려준다."""
    response.headers["Cache-Control"] = "no-store"
    stmt = select(User).where(User.platform_role == "KIOSK")
    if account_status is not None:
        stmt = stmt.where(User.status == account_status)
    accounts = (await db.execute(stmt.order_by(User.id.desc()).limit(limit).offset(offset))).scalars().all()
    businesses = await _owner_businesses(db, [account.id for account in accounts])
    return [_to_response(account, businesses.get(account.id)) for account in accounts]


@router.get(
    "/{account_id}",
    response_model=KioskAccountResponse,
    summary="KIOSK 계정 상세",
    responses=_DETAIL_RESPONSES,
)
async def get_kiosk_account(
    account_id: int,
    response: Response,
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    response.headers["Cache-Control"] = "no-store"
    account = await _find_account(db, account_id, lock=False)
    businesses = await _owner_businesses(db, [account.id])
    return _to_response(account, businesses.get(account.id))


@router.post(
    "/{account_id}/suspend",
    response_model=KioskAccountResponse,
    summary="KIOSK 계정 정지",
    responses=_CHANGE_RESPONSES,
)
async def suspend_kiosk_account(
    account_id: int,
    response: Response,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """계정을 정지한다. 이미 발급된 토큰은 token_version을 올려 즉시 무효로 만든다.

    이미 정지된 계정이면 아무것도 바꾸지 않는다.
    """
    response.headers["Cache-Control"] = "no-store"
    account = await _find_account(db, account_id, lock=True)
    if account.status == "WITHDRAWN":
        raise _error(AuthError.ACCOUNT_INACTIVE, status.HTTP_409_CONFLICT)
    if account.status != "SUSPENDED":
        account.status = "SUSPENDED"
        account.token_version += 1
        account.updated_at = datetime.now(timezone.utc)
        await _audit(db, admin, AuditEventType.KIOSK_ACCOUNT_SUSPENDED, account, {"login_id": account.login_id})
        await db.commit()
    businesses = await _owner_businesses(db, [account.id])
    return _to_response(account, businesses.get(account.id))


@router.post(
    "/{account_id}/activate",
    response_model=KioskAccountResponse,
    summary="KIOSK 계정 정지 해제",
    responses=_CHANGE_RESPONSES,
)
async def activate_kiosk_account(
    account_id: int,
    response: Response,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """정지된 계정을 다시 쓸 수 있게 한다. 정지 전에 받은 토큰은 계속 무효다.

    이미 활성 상태면 아무것도 바꾸지 않는다.
    """
    response.headers["Cache-Control"] = "no-store"
    account = await _find_account(db, account_id, lock=True)
    if account.status == "WITHDRAWN":
        raise _error(AuthError.ACCOUNT_INACTIVE, status.HTTP_409_CONFLICT)
    if account.status != "ACTIVE":
        account.status = "ACTIVE"
        account.updated_at = datetime.now(timezone.utc)
        await _audit(db, admin, AuditEventType.KIOSK_ACCOUNT_ACTIVATED, account, {"login_id": account.login_id})
        await db.commit()
    businesses = await _owner_businesses(db, [account.id])
    return _to_response(account, businesses.get(account.id))


@router.post(
    "/{account_id}/reset-password",
    response_model=KioskAccountCredentialResponse,
    summary="KIOSK 계정 임시 비밀번호 재발급",
    responses=_CHANGE_RESPONSES,
)
async def reset_kiosk_account_password(
    account_id: int,
    response: Response,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """새 임시 비밀번호를 발급한다. 기존 비밀번호와 이미 발급된 토큰은 모두 무효가 된다.

    매장이 비밀번호를 잊었거나 임시 비밀번호 기한이 지났을 때 쓴다.
    정지 상태는 그대로 두므로, 정지된 계정이면 정지 해제도 따로 해야 한다.
    """
    response.headers["Cache-Control"] = "no-store"
    account = await _find_account(db, account_id, lock=True)
    if account.status == "WITHDRAWN":
        raise _error(AuthError.ACCOUNT_INACTIVE, status.HTTP_409_CONFLICT)
    now = datetime.now(timezone.utc)
    temporary_password = _set_temp_password(account, now)
    account.token_version += 1
    account.updated_at = now
    await _audit(
        db,
        admin,
        AuditEventType.KIOSK_ACCOUNT_PASSWORD_RESET,
        account,
        {"login_id": account.login_id, "temp_password_expires_at": account.temp_password_expires_at.isoformat()},
    )
    await db.commit()
    businesses = await _owner_businesses(db, [account.id])
    return KioskAccountCredentialResponse(
        account=_to_response(account, businesses.get(account.id)),
        temporary_password=temporary_password,
    )
