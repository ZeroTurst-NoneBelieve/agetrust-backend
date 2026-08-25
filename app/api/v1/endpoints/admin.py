"""관리자용 감사 로그 조회 (#9).

`require_admin`으로 보호되며, platform_role이 ADMIN이 아니면 403이다.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.core.audit import recompute_hash_for
from app.database import get_db
from app.models import AuditLog, User
from app.schemas.audit import (
    AuditActorType,
    AuditLogPage,
    AuditLogResponse,
    ChainBreak,
    ChainVerificationResponse,
)

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])

MAX_PAGE_SIZE = 200
MAX_VERIFY_SCAN = 10_000


@router.get("/logs", response_model=AuditLogPage)
async def list_audit_logs(
    event_type: str | None = Query(default=None, description="정확히 일치하는 이벤트 타입"),
    actor_type: AuditActorType | None = Query(default=None),
    actor_ref: str | None = Query(default=None),
    aggregate_type: str | None = Query(default=None),
    aggregate_id: str | None = Query(default=None),
    source_kiosk_id: int | None = Query(default=None),
    occurred_from: datetime | None = Query(default=None, description="created_at >= (ISO8601)"),
    occurred_to: datetime | None = Query(default=None, description="created_at < (ISO8601)"),
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """감사 로그를 최신순으로 조회한다.

    `occurred_to`는 **미포함**(`<`)이다. 하루치를 조회할 때 자정 경계의
    이벤트가 양쪽 페이지에 중복으로 잡히지 않도록 한 것이다.
    """
    filters = []
    if event_type is not None:
        filters.append(AuditLog.event_type == event_type)
    if actor_type is not None:
        filters.append(AuditLog.actor_type == actor_type.value)
    if actor_ref is not None:
        filters.append(AuditLog.actor_ref == actor_ref)
    if aggregate_type is not None:
        filters.append(AuditLog.aggregate_type == aggregate_type)
    if aggregate_id is not None:
        filters.append(AuditLog.aggregate_id == aggregate_id)
    if source_kiosk_id is not None:
        filters.append(AuditLog.source_kiosk_id == source_kiosk_id)
    if occurred_from is not None:
        filters.append(AuditLog.created_at >= occurred_from)
    if occurred_to is not None:
        filters.append(AuditLog.created_at < occurred_to)

    total = await db.scalar(select(func.count()).select_from(AuditLog).where(*filters))

    result = await db.execute(
        select(AuditLog)
        .where(*filters)
        # created_at만으로 정렬하면 같은 트랜잭션에서 나온 이벤트의 순서가
        # 불안정해 페이지 경계에서 누락/중복이 생긴다. id를 tie-breaker로 둔다.
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = result.scalars().all()

    return AuditLogPage(
        items=[AuditLogResponse.model_validate(r) for r in rows],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get("/logs/chain-verification", response_model=ChainVerificationResponse)
async def verify_audit_chain(
    from_id: int | None = Query(default=None, description="이 id부터 (포함)"),
    to_id: int | None = Query(default=None, description="이 id까지 (포함)"),
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """해시 체인 무결성을 검증한다.

    저장된 `event_hash`를 본문으로부터 다시 계산해 비교하고(본문 변조 탐지),
    각 레코드의 `previous_hash`가 직전 레코드의 `event_hash`와 이어지는지
    확인한다(레코드 삭제·삽입 탐지).

    해시를 저장만 하고 검증 경로가 없으면 위·변조 방지가 성립하지 않으므로
    함께 제공한다.
    """
    filters = []
    if from_id is not None:
        filters.append(AuditLog.id >= from_id)
    if to_id is not None:
        filters.append(AuditLog.id <= to_id)

    result = await db.execute(
        select(AuditLog).where(*filters).order_by(AuditLog.id.asc()).limit(MAX_VERIFY_SCAN)
    )
    rows = result.scalars().all()

    previous_hash: str | None = None
    for index, row in enumerate(rows):
        # 구간 조회의 첫 레코드는 앞 레코드를 모르므로 연결 검사를 건너뛴다.
        if index > 0 and row.previous_hash != previous_hash:
            return ChainVerificationResponse(
                checked=index + 1,
                is_intact=False,
                first_break=ChainBreak(
                    audit_log_id=row.id,
                    event_id=row.event_id,
                    reason="LINK_MISMATCH",
                    expected=previous_hash or "",
                    stored=row.previous_hash or "",
                ),
                from_id=rows[0].id,
                to_id=rows[-1].id,
            )

        recomputed = recompute_hash_for(row)
        if recomputed != row.event_hash:
            return ChainVerificationResponse(
                checked=index + 1,
                is_intact=False,
                first_break=ChainBreak(
                    audit_log_id=row.id,
                    event_id=row.event_id,
                    reason="HASH_MISMATCH",
                    expected=recomputed,
                    stored=row.event_hash,
                ),
                from_id=rows[0].id,
                to_id=rows[-1].id,
            )
        previous_hash = row.event_hash

    return ChainVerificationResponse(
        checked=len(rows),
        is_intact=True,
        first_break=None,
        from_id=rows[0].id if rows else None,
        to_id=rows[-1].id if rows else None,
    )
