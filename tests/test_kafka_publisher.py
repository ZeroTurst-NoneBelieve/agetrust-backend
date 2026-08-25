"""#9 — Outbox → Kafka Publisher 테스트.

DB와 Kafka 없이 도는 단위 테스트다. 발행 성공/실패 시 outbox 상태가 어떻게
바뀌는지, 원장(audit_logs)에 Kafka 좌표가 되채워지는지를 확인한다.
"""

import base64
import json
import os
import unittest
import uuid
from datetime import datetime, timezone

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from sqlalchemy.exc import IntegrityError  # noqa: E402

from app.config import settings  # noqa: E402
from app.core.kafka_publisher import (  # noqa: E402
    build_message,
    partition_key,
    publish_pending_once,
)
from app.models import OutboxEvent  # noqa: E402
from tests.fakes import FakeOutboxDb, FakeProducer  # noqa: E402

BASE_TIME = datetime(2026, 8, 25, 9, 0, 0, tzinfo=timezone.utc)


def _event(*, index=0, aggregate_id="5", payload=None, retry_count=0):
    return OutboxEvent(
        id=index + 1,
        event_id=uuid.UUID(int=index + 1),
        aggregate_type="USER",
        aggregate_id=aggregate_id,
        event_type="LOGIN_SUCCEEDED",
        payload=payload if payload is not None else {"login_id": f"user{index}"},
        created_at=BASE_TIME,
        published_at=None,
        retry_count=retry_count,
    )


class BuildMessageTests(unittest.TestCase):
    def test_message_carries_event_fields(self):
        body = json.loads(build_message(_event()).decode())
        self.assertEqual(body["event_type"], "LOGIN_SUCCEEDED")
        self.assertEqual(body["aggregate_type"], "USER")
        self.assertEqual(body["aggregate_id"], "5")
        self.assertEqual(body["payload"], {"login_id": "user0"})
        self.assertEqual(body["created_at"], BASE_TIME.isoformat())

    def test_message_is_deterministic(self):
        """같은 이벤트면 항상 같은 바이트열이어야 재발행 비교가 가능하다."""
        self.assertEqual(build_message(_event()), build_message(_event()))

    def test_missing_created_at_does_not_crash(self):
        event = _event()
        event.created_at = None
        self.assertIsNone(json.loads(build_message(event).decode())["created_at"])


class PartitionKeyTests(unittest.TestCase):
    def test_same_aggregate_shares_a_key(self):
        """같은 대상의 이벤트는 같은 파티션으로 가야 순서가 유지된다."""
        self.assertEqual(
            partition_key(_event(index=0, aggregate_id="5")),
            partition_key(_event(index=1, aggregate_id="5")),
        )

    def test_different_aggregates_differ(self):
        self.assertNotEqual(
            partition_key(_event(aggregate_id="5")),
            partition_key(_event(aggregate_id="6")),
        )

    def test_falls_back_to_event_id(self):
        event = _event(aggregate_id=None)
        self.assertEqual(partition_key(event), str(event.event_id).encode())


class PublishSuccessTests(unittest.IsolatedAsyncioTestCase):
    async def test_nothing_pending_sends_nothing(self):
        db, producer = FakeOutboxDb(), FakeProducer()
        self.assertEqual(await publish_pending_once(db, producer), 0)
        self.assertEqual(producer.sent, [])

    async def test_pending_events_are_sent(self):
        events = [_event(index=0), _event(index=1)]
        db, producer = FakeOutboxDb(events), FakeProducer()

        self.assertEqual(await publish_pending_once(db, producer), 2)
        self.assertEqual(len(producer.sent), 2)
        self.assertEqual(producer.sent[0]["topic"], settings.kafka_audit_topic)

    async def test_published_at_is_stamped(self):
        events = [_event(index=0)]
        db, producer = FakeOutboxDb(events), FakeProducer()

        await publish_pending_once(db, producer)
        self.assertIsNotNone(events[0].published_at)

    async def test_kafka_position_is_backfilled_to_ledger(self):
        """원장에 '이 이벤트가 Kafka 어디에 실렸는지'가 기록되어야 한다."""
        events = [_event(index=0), _event(index=1)]
        db, producer = FakeOutboxDb(events), FakeProducer()

        await publish_pending_once(db, producer)
        self.assertEqual(len(db.backfills), 2)

    async def test_success_is_committed(self):
        db, producer = FakeOutboxDb([_event()]), FakeProducer()
        await publish_pending_once(db, producer)
        self.assertEqual(db.commits, 1)


class BackfillFailureTests(unittest.IsolatedAsyncioTestCase):
    """좌표 기록 실패가 발행 성공을 취소시키면 안 된다.

    Kafka 토픽이 재생성되어 offset이 되감기면 uq_audit_logs_kafka_position에
    충돌한다. 이때 배치 전체가 롤백되면 이미 Kafka로 나간 이벤트의
    published_at까지 사라져 다음 주기에 같은 메시지를 중복 발행하게 된다.
    """

    @staticmethod
    def _collision():
        return IntegrityError("UPDATE audit_logs", {}, Exception("duplicate key"))

    async def test_event_stays_published_despite_backfill_collision(self):
        events = [_event(index=0)]
        db = FakeOutboxDb(events, backfill_error=self._collision())
        producer = FakeProducer()

        self.assertEqual(await publish_pending_once(db, producer), 1)
        self.assertIsNotNone(
            events[0].published_at,
            "좌표 기록 실패로 published_at이 사라지면 중복 발행된다",
        )

    async def test_backfill_collision_does_not_stop_the_batch(self):
        events = [_event(index=0), _event(index=1)]
        db = FakeOutboxDb(events, backfill_error=self._collision())
        producer = FakeProducer()

        self.assertEqual(await publish_pending_once(db, producer), 2)
        self.assertEqual(len(producer.sent), 2)

    async def test_backfill_runs_inside_a_savepoint(self):
        """SAVEPOINT 없이 실행하면 실패가 바깥 트랜잭션까지 오염시킨다."""
        db = FakeOutboxDb([_event()])
        await publish_pending_once(db, FakeProducer())
        self.assertEqual(db.savepoints, 1)


class PublishFailureTests(unittest.IsolatedAsyncioTestCase):
    """브로커가 죽었을 때 이벤트를 잃지 않는지 확인한다."""

    async def test_failure_increments_retry_count(self):
        events = [_event(index=0)]
        db = FakeOutboxDb(events)
        producer = FakeProducer(fail_with=ConnectionError("broker down"))

        self.assertEqual(await publish_pending_once(db, producer), 0)
        self.assertEqual(events[0].retry_count, 1)

    async def test_failure_leaves_event_unpublished(self):
        """published_at이 남으면 이벤트가 영영 발행되지 않고 유실된다."""
        events = [_event(index=0)]
        db = FakeOutboxDb(events)
        producer = FakeProducer(fail_with=ConnectionError("broker down"))

        await publish_pending_once(db, producer)
        self.assertIsNone(events[0].published_at)

    async def test_failure_is_committed(self):
        """롤백하면 retry_count가 남지 않아 같은 이벤트를 영원히 재시도한다."""
        db = FakeOutboxDb([_event()])
        producer = FakeProducer(fail_with=ConnectionError("broker down"))

        await publish_pending_once(db, producer)
        self.assertEqual(db.commits, 1)

    async def test_failure_stops_the_batch(self):
        """브로커가 죽었으면 나머지도 실패한다. 배치 전체를 낭비하지 않는다."""
        events = [_event(index=i) for i in range(5)]
        db = FakeOutboxDb(events)
        producer = FakeProducer(fail_with=ConnectionError("broker down"))

        await publish_pending_once(db, producer)

        self.assertEqual(events[0].retry_count, 1)
        # 뒤 이벤트는 시도조차 하지 않았어야 한다.
        self.assertEqual([e.retry_count for e in events[1:]], [0, 0, 0, 0])

    async def test_retry_count_none_does_not_crash(self):
        """server_default라 DB를 거치지 않은 행은 retry_count가 None이다."""
        event = _event()
        event.retry_count = None
        db = FakeOutboxDb([event])
        producer = FakeProducer(fail_with=ConnectionError("broker down"))

        await publish_pending_once(db, producer)
        self.assertEqual(event.retry_count, 1)

    async def test_no_backfill_when_publish_failed(self):
        """발행되지 않은 이벤트의 Kafka 좌표를 원장에 적으면 거짓말이 된다."""
        db = FakeOutboxDb([_event()])
        producer = FakeProducer(fail_with=ConnectionError("broker down"))

        await publish_pending_once(db, producer)
        self.assertEqual(db.backfills, [])


if __name__ == "__main__":
    unittest.main()
