"""미사용 신규 키를 24시간 뒤 자동 폐기한다 (ADR-0010).

조건부 UPDATE와 감사·Outbox 기록을 하나의 DB 트랜잭션으로 묶는다.
``legacy__`` 키는 마이그레이션 전의 기존 키라 발급 시각을 알 수 없으므로
이 정책에서 제외한다. 키 원문·해시는 조회하거나 기록하지 않는다.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import record_audit_event
from app.models import KioskApiKey

logger = logging.getLogger(__name__)

UNUSED_KEY_GRACE_PERIOD = timedelta(hours=24)
CLEANUP_INTERVAL_SECONDS = 60
CLEANUP_BATCH_SIZE = 100


async def revoke_unused_keys_once(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    batch_size: int = CLEANUP_BATCH_SIZE,
) -> int:
    """한 배치의 미사용 키를 폐기하고, 동일 트랜잭션에 감사 이벤트를 남긴다.

    후보 행 잠금은 SKIP LOCKED라 다중 API 인스턴스가 겹쳐 돌더라도
    같은 키를 중복 처리하지 않는다. UPDATE에도 조건을 다시 걸어
    사용 시각·상태가 바뀐 키를 폐기하지 않는다.
    """
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    current = now or datetime.now(timezone.utc)
    cutoff = current - UNUSED_KEY_GRACE_PERIOD
    eligible = (
        select(KioskApiKey.id)
        .where(
            KioskApiKey.status == "ACTIVE",
            KioskApiKey.last_used_at.is_(None),
            KioskApiKey.created_at <= cutoff,
            KioskApiKey.key_prefix != "legacy__",
        )
        .order_by(KioskApiKey.id)
        .limit(batch_size)
        .with_for_update(skip_locked=True)
    )
    statement = (
        update(KioskApiKey)
        .where(
            KioskApiKey.id.in_(eligible),
            KioskApiKey.status == "ACTIVE",
            KioskApiKey.last_used_at.is_(None),
            KioskApiKey.created_at <= cutoff,
            KioskApiKey.key_prefix != "legacy__",
        )
        .values(status="REVOKED", revoked_at=current)
        .returning(KioskApiKey.id, KioskApiKey.kiosk_id)
    )

    try:
        result = await db.execute(statement)
        rows = result.all()
        for key_id, kiosk_id in rows:
            await record_audit_event(
                db,
                event_type="KIOSK_KEY_AUTO_REVOKED",
                actor_type="SYSTEM",
                source_kiosk_id=kiosk_id,
                aggregate_type="KIOSK_KEY",
                aggregate_id=str(key_id),
                payload={"key_id": key_id, "reason": "UNUSED_24H"},
            )
        await db.commit()
        return len(rows)
    except Exception:
        await db.rollback()
        raise


async def run_unused_key_cleanup_loop(
    session_factory,
    stop_event: asyncio.Event,
    *,
    interval_seconds: float = CLEANUP_INTERVAL_SECONDS,
) -> None:
    """앱 수명 동안 정리한다. 시작 직후 한 번 실행하고 이후 주기적으로 확인."""
    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be positive")
    while not stop_event.is_set():
        count = 0
        try:
            async with session_factory() as db:
                count = await revoke_unused_keys_once(db)
            if count:
                logger.info("24시간 미사용 키 %d건 자동 폐기", count)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            # SQL 예외 문자열에는 바인딩 값이 포함될 수 있으므로 타입만 기록한다.
            logger.warning("미사용 키 정리 실패 (%s). 다음 주기에 재시도한다.", type(error).__name__)

        # 배치가 꽉 찼다면 적체를 바로 이어서 처리한다.
        if count == CLEANUP_BATCH_SIZE:
            continue
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
        except asyncio.TimeoutError:
            pass
