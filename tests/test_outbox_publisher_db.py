"""실제 PostgreSQL에서 Outbox Publisher의 조회·트랜잭션 의미를 검증한다 (#53).

`tests/test_kafka_publisher.py`의 가짜 세션은 SQL을 보지 않는다. 그래서
`_claim_pending`의 조건·정렬·`SKIP LOCKED`를 통째로 들어내도 그쪽은 초록이다
(#39 5번). 이 파일은 같은 함수를 실제 DB에 대고 돌린다.

E2E_DATABASE_URL로 명시적으로 켠다. 각 테스트는 자신이 만든 행만 제거한다.
Publisher가 떠 있는 개발 DB가 아니라 별도 테스트 DB를 권장한다.

## 다른 테스트가 남긴 미발행 행 가리기

`_claim_pending`은 테이블의 미발행 행 전부를 대상으로 한다. 같은 DB에서 먼저
도는 E2E 테스트가 미발행 이벤트를 남기므로(로컬 실측 33건) 그대로 두면 결과에
섞인다. 그래서 테스트 행을 만들기 전에 기존 미발행 행을 별도 연결에서
`FOR UPDATE`로 잡아 둔다. 검증 대상 세션에는 `SKIP LOCKED`로 보이지 않는다.

`SKIP LOCKED`가 빠지면 이 잠금 때문에 조회가 기다리게 된다. 연결마다
`lock_timeout`을 걸어 두었으므로 CI가 멈추지 않고 실패로 끝난다.
"""

import asyncio
import base64
import os
import unittest
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

E2E_DB_URL = os.environ.get("E2E_DATABASE_URL")

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from sqlalchemy import delete, func, literal_column, select, update  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402

from app.config import settings  # noqa: E402
from app.core.audit import record_audit_event  # noqa: E402
from app.core.kafka_publisher import (  # noqa: E402
    PublishFailed,
    _claim_pending,
    count_exhausted,
    publish_pending_once,
    run_publisher_loop,
)
from app.models import AuditLog, OutboxEvent  # noqa: E402
from tests.fakes import FakeProducer  # noqa: E402

# 잠긴 행을 기다리는 조회가 CI를 붙잡지 않게 한다.
LOCK_TIMEOUT = "3s"
AGGREGATE_TYPE = "OUTBOX_DB_TEST"


async def _claim_ids(db, limit=100):
    return [event.id for event in await _claim_pending(db, limit)]


def _position(row):
    return (row.kafka_topic, row.kafka_partition, row.kafka_offset)


@unittest.skipUnless(E2E_DB_URL, "실제 PostgreSQL 검증에는 E2E_DATABASE_URL이 필요하다")
class OutboxPublisherDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = create_async_engine(
            E2E_DB_URL,
            echo=False,
            connect_args={"server_settings": {"lock_timeout": LOCK_TIMEOUT}},
        )
        self.addAsyncCleanup(self.engine.dispose)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self.event_ids = []
        self.addAsyncCleanup(self._remove_owned_rows)

        # 테스트 행을 만들기 전에 잡아야 테스트 행이 잠기지 않는다 (모듈 docstring).
        self.fence = await self.engine.connect()
        self.addAsyncCleanup(self._release_fence)
        await self.fence.begin()
        await self.fence.execute(
            select(OutboxEvent.id).where(OutboxEvent.published_at.is_(None)).with_for_update()
        )

    async def _release_fence(self):
        await self.fence.rollback()
        await self.fence.close()

    async def _remove_owned_rows(self):
        if not self.event_ids:
            return
        async with self.session_factory() as db:
            await db.execute(delete(OutboxEvent).where(OutboxEvent.event_id.in_(self.event_ids)))
            await db.execute(delete(AuditLog).where(AuditLog.event_id.in_(self.event_ids)))
            await db.commit()

    def _new_event(self, *, retry_count=0, published=False, **fields):
        event = OutboxEvent(
            event_id=uuid.uuid4(),
            aggregate_type=AGGREGATE_TYPE,
            event_type="TEST_EVENT",
            payload={},
            retry_count=retry_count,
            published_at=datetime.now(timezone.utc) if published else None,
            **fields,
        )
        self.event_ids.append(event.event_id)
        return event

    async def _add_event(self, **options):
        """outbox 행 하나를 커밋하고 id를 돌려준다. 호출 순서대로 id가 커진다."""
        event = self._new_event(**options)
        async with self.session_factory() as db:
            db.add(event)
            await db.commit()
        return event.id

    async def _add_audited_event(self, *, emit_outbox=True):
        """실제 기록 경로로 감사 원장(과 outbox)에 이벤트를 남기고 event_id를 돌려준다."""
        async with self.session_factory() as db:
            row = await record_audit_event(
                db,
                event_type="TEST_EVENT",
                actor_type="SYSTEM",
                aggregate_type=AGGREGATE_TYPE,
                payload={},
                emit_outbox=emit_outbox,
            )
            self.event_ids.append(row.event_id)
            await db.commit()
        return row.event_id

    async def _outbox_rows(self, ids):
        async with self.session_factory() as db:
            rows = await db.scalars(select(OutboxEvent).where(OutboxEvent.id.in_(ids)))
            return {row.id: row for row in rows}

    # ── _claim_pending ───────────────────────────────────────────────

    async def test_claims_only_unpublished_events_under_the_retry_limit(self):
        limit = settings.outbox_max_retry_count
        fresh = await self._add_event()
        last_try = await self._add_event(retry_count=limit - 1)
        await self._add_event(retry_count=limit)  # 포기된 이벤트
        await self._add_event(published=True)

        async with self.session_factory() as db:
            self.assertEqual(await _claim_ids(db), [fresh, last_try])

    async def test_claims_in_id_order_not_physical_order(self):
        # id를 시퀀스에서 먼저 받아 두고 한 트랜잭션에서 거꾸로 넣는다. ORDER BY가
        # 빠지면 순차 스캔이 넣은 순서(물리 순서)대로 돌려주므로 정렬 누락이 드러난다.
        sequence = func.pg_get_serial_sequence(OutboxEvent.__tablename__, "id")
        async with self.session_factory() as db:
            ids = [await db.scalar(select(func.nextval(sequence))) for _ in range(3)]
            for event_id in reversed(ids):
                db.add(self._new_event(id=event_id))
                await db.flush()
            await db.commit()

            physical = await db.scalars(
                select(OutboxEvent.id).where(OutboxEvent.id.in_(ids)).order_by(literal_column("ctid"))
            )
            self.assertEqual(list(physical), ids[::-1], "전제: 물리 순서가 id 역순이어야 한다")

        async with self.session_factory() as db:
            self.assertEqual(await _claim_ids(db), ids)

    async def test_claims_at_most_limit_oldest_first(self):
        first = await self._add_event()
        second = await self._add_event()
        await self._add_event()

        async with self.session_factory() as db:
            self.assertEqual(await _claim_ids(db, limit=2), [first, second])

    async def test_concurrent_claims_do_not_overlap(self):
        """Publisher가 둘이어도 같은 이벤트를 두 번 집지 않는다."""
        events = [await self._add_event() for _ in range(3)]

        async with self.session_factory() as first, self.session_factory() as second:
            self.assertEqual(await _claim_ids(first), events)
            # 첫 세션이 잠근 채로 있는 동안, 두 번째는 기다리지 않고 빈손으로 돌아온다.
            self.assertEqual(await _claim_ids(second), [])

    async def test_locked_event_is_skipped_and_the_rest_are_claimed(self):
        busy = await self._add_event()
        free = await self._add_event()

        async with self.session_factory() as holder, self.session_factory() as claimer:
            await holder.execute(select(OutboxEvent.id).where(OutboxEvent.id == busy).with_for_update())
            self.assertEqual(await _claim_ids(claimer), [free])

    # ── 포기된 이벤트 집계 ─────────────────────────────────────────────

    async def test_count_exhausted_counts_unpublished_events_at_or_over_the_limit(self):
        limit = settings.outbox_max_retry_count
        async with self.session_factory() as db:
            before = await count_exhausted(db)

        await self._add_event(retry_count=limit)
        await self._add_event(retry_count=limit + 3)
        await self._add_event(retry_count=limit - 1)  # 아직 재시도 대상
        await self._add_event(retry_count=limit, published=True)  # 수동 조치로 발행 처리된 행

        async with self.session_factory() as db:
            self.assertEqual(await count_exhausted(db) - before, 2)

    async def test_loop_reports_exhausted_events_when_it_connects(self):
        """포기된 이벤트는 조회 대상에서 빠지므로, 연결 시 보고가 유일한 흔적이다."""
        await self._add_event(retry_count=settings.outbox_max_retry_count)
        async with self.session_factory() as db:
            stuck = await count_exhausted(db)

        async def reported(records):
            while not records:
                await asyncio.sleep(0.05)

        stop = asyncio.Event()
        with self.assertLogs("app.core.kafka_publisher", level="ERROR") as logs:
            loop = asyncio.create_task(
                run_publisher_loop(self.session_factory, stop, producer_factory=FakeProducer)
            )
            try:
                await asyncio.wait_for(reported(logs.records), timeout=5)
            except asyncio.TimeoutError:
                self.fail("연결 뒤 5초 안에 포기된 이벤트 보고가 없었다")
            finally:
                stop.set()
                await asyncio.wait_for(loop, timeout=5)

        self.assertIn(f"{stuck}건", logs.records[0].getMessage())

    # ── 발행 배치의 트랜잭션 ───────────────────────────────────────────

    async def test_send_failure_commits_progress_before_raising(self):
        """배치 중간에 전송이 실패해도, 앞 이벤트의 발행 기록과 실패 횟수는 남는다."""
        sent = await self._add_event()
        failed = await self._add_event()
        untouched = await self._add_event()
        producer = FakeProducer(fail_after=1, fail_with=ConnectionError("broker down"))

        with self.assertLogs("app.core.kafka_publisher", level="WARNING"):
            async with self.session_factory() as db:
                with self.assertRaises(PublishFailed):
                    await publish_pending_once(db, producer)

        rows = await self._outbox_rows([sent, failed, untouched])
        self.assertIsNotNone(rows[sent].published_at)
        self.assertEqual((rows[failed].published_at, rows[failed].retry_count), (None, 1))
        self.assertEqual((rows[untouched].published_at, rows[untouched].retry_count), (None, 0))

    async def test_position_collision_does_not_undo_the_batch(self):
        """좌표 하나가 유니크 제약에 걸려도 그 UPDATE만 되돌리고 나머지는 커밋한다."""
        topic = f"outbox-db-test-{uuid.uuid4().hex}"
        # FakeProducer는 offset을 0부터 매긴다. 첫 이벤트가 받을 좌표를 다른 감사 행이 이미 쓰고 있다.
        holder = await self._add_audited_event(emit_outbox=False)
        async with self.session_factory() as db:
            await db.execute(
                update(AuditLog)
                .where(AuditLog.event_id == holder)
                .values(kafka_topic=topic, kafka_partition=0, kafka_offset=0)
            )
            await db.commit()
        colliding = await self._add_audited_event()
        clean = await self._add_audited_event()

        with patch.object(settings, "kafka_audit_topic", topic):
            with self.assertLogs("app.core.kafka_publisher", level="WARNING"):
                async with self.session_factory() as db:
                    self.assertEqual(await publish_pending_once(db, FakeProducer()), 2)

        ids = [colliding, clean, holder]
        async with self.session_factory() as db:
            outbox = {row.event_id: row for row in await db.scalars(
                select(OutboxEvent).where(OutboxEvent.event_id.in_(ids))
            )}
            audit = {row.event_id: row for row in await db.scalars(
                select(AuditLog).where(AuditLog.event_id.in_(ids))
            )}
        self.assertIsNotNone(outbox[colliding].published_at)
        self.assertIsNotNone(outbox[clean].published_at)
        self.assertEqual(_position(audit[colliding]), (None, None, None))
        self.assertEqual(_position(audit[clean]), (topic, 0, 1))
        self.assertEqual(_position(audit[holder]), (topic, 0, 0))


if __name__ == "__main__":
    unittest.main()
