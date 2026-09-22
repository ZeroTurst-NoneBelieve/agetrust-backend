"""ADR-0010 미사용 키 자동 폐기 조건과 감사 트랜잭션 검증."""

import asyncio
import base64
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from sqlalchemy.dialects import postgresql

os.environ["DATABASE_URL"] = "postgresql+asyncpg://test:test@localhost/test"
os.environ["SECRET_KEY"] = "test-secret-key-at-least-32-bytes"
os.environ["ISSUER_PRIVATE_KEY"] = base64.b64encode(bytes(range(32))).decode()

from app.core import kiosk_key_cleanup  # noqa: E402
from app import main as app_main  # noqa: E402


class _Result:
    def __init__(self, rows):
        self.rows = rows

    def all(self):
        return self.rows


class _Db:
    def __init__(self, rows):
        self.rows = rows
        self.statement = None
        self.commits = 0
        self.rollbacks = 0

    async def execute(self, statement):
        self.statement = statement
        return _Result(self.rows)

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1


class KioskKeyCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_conditional_update_and_audit_share_one_commit(self):
        db = _Db([(11, 7), (12, 8)])
        now = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)
        audit = AsyncMock()
        with patch.object(kiosk_key_cleanup, "record_audit_event", audit):
            count = await kiosk_key_cleanup.revoke_unused_keys_once(db, now=now)

        self.assertEqual(count, 2)
        self.assertEqual(db.commits, 1)
        self.assertEqual(db.rollbacks, 0)
        self.assertEqual(audit.await_count, 2)
        first = audit.await_args_list[0].kwargs
        self.assertEqual(first["event_type"], "KIOSK_KEY_AUTO_REVOKED")
        self.assertEqual(first["actor_type"], "SYSTEM")
        self.assertEqual(first["source_kiosk_id"], 7)
        self.assertEqual(first["aggregate_type"], "KIOSK_KEY")
        self.assertEqual(first["aggregate_id"], "11")
        self.assertEqual(first["payload"], {"key_id": 11, "reason": "UNUSED_24H"})
        self.assertNotIn("key_hash", repr(audit.await_args_list))
        self.assertNotIn("raw_key", repr(audit.await_args_list))

        compiled = db.statement.compile(dialect=postgresql.dialect())
        sql = str(compiled)
        self.assertIn("UPDATE kiosk_api_keys", sql)
        self.assertIn("FOR UPDATE SKIP LOCKED", sql)
        self.assertIn("RETURNING kiosk_api_keys.id, kiosk_api_keys.kiosk_id", sql)
        self.assertGreaterEqual(sql.count("kiosk_api_keys.last_used_at IS NULL"), 2)
        self.assertGreaterEqual(sql.count("kiosk_api_keys.created_at <="), 2)
        self.assertGreaterEqual(sql.count("kiosk_api_keys.key_prefix !="), 2)
        self.assertIn("legacy__", compiled.params.values())
        self.assertIn("REVOKED", compiled.params.values())
        self.assertIn(now, compiled.params.values())
        self.assertIn(now - kiosk_key_cleanup.UNUSED_KEY_GRACE_PERIOD, compiled.params.values())

    async def test_audit_failure_rolls_back_key_revocation(self):
        db = _Db([(11, 7)])
        with patch.object(
            kiosk_key_cleanup,
            "record_audit_event",
            new=AsyncMock(side_effect=RuntimeError("audit unavailable")),
        ):
            with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
                await kiosk_key_cleanup.revoke_unused_keys_once(db)
        self.assertEqual(db.commits, 0)
        self.assertEqual(db.rollbacks, 1)

    async def test_empty_batch_commits_without_audit_event(self):
        db = _Db([])
        audit = AsyncMock()
        with patch.object(kiosk_key_cleanup, "record_audit_event", audit):
            count = await kiosk_key_cleanup.revoke_unused_keys_once(db)
        self.assertEqual(count, 0)
        self.assertEqual(db.commits, 1)
        audit.assert_not_awaited()

    async def test_app_lifespan_starts_and_stops_cleanup_task(self):
        started = asyncio.Event()
        stopped = asyncio.Event()

        async def fake_cleanup(_session_factory, stop_event):
            started.set()
            await stop_event.wait()
            stopped.set()

        with (
            patch.object(app_main, "run_unused_key_cleanup_loop", fake_cleanup),
            patch.object(app_main.settings, "kafka_publisher_enabled", False),
        ):
            async with app_main.lifespan(app_main.app):
                await asyncio.wait_for(started.wait(), timeout=1)
            self.assertTrue(stopped.is_set())
