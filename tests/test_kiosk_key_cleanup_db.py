"""전용 PostgreSQL에서 24시간 미사용 키 자동 폐기와 감사 원자성을 검증한다.

전용 테스트 DB의 E2E_DATABASE_URL이 설정되어 있으면 실행한다. 외부 트랜잭션을
마지막에 롤백하므로 키·감사·Outbox 행이 테스트 DB에 남지 않는다.
"""

import asyncio
import base64
import hashlib
import json
import os
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

E2E_DB_URL = os.environ.get("E2E_DATABASE_URL")

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from app import main as app_main  # noqa: E402
from app.core import kiosk_key_cleanup  # noqa: E402
from app.core.kiosk_key_cleanup import revoke_unused_keys_once  # noqa: E402
from app.models import AuditLog, Business, Kiosk, KioskApiKey, OutboxEvent, Store  # noqa: E402


@unittest.skipUnless(E2E_DB_URL, "실제 PostgreSQL 검증에는 전용 E2E_DATABASE_URL이 필요하다")
class KioskKeyCleanupDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = create_async_engine(E2E_DB_URL, echo=False)
        self.addAsyncCleanup(self.engine.dispose)
        self.connection = await self.engine.connect()
        self.addAsyncCleanup(self.connection.close)
        self.outer_transaction = await self.connection.begin()
        self.addAsyncCleanup(self.outer_transaction.rollback)
        self.session_factory = async_sessionmaker(
            self.connection,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        )

    async def test_only_unseen_nonlegacy_keys_older_than_24h_are_revoked(self):
        now = datetime.now(timezone.utc)
        token = uuid.uuid4().hex
        async with self.session_factory() as db:
            business = Business(
                business_number=f"cleanup-e2e-{token}",
                business_name="cleanup E2E business",
                status="ACTIVE",
            )
            db.add(business)
            await db.flush()
            store = Store(
                business_id=business.id,
                store_code=f"cleanup-e2e-{token}",
                store_name="cleanup E2E store",
                store_type_code="E2E",
                address="E2E only",
                status="ACTIVE",
            )
            db.add(store)
            await db.flush()
            kiosk = Kiosk(
                store_id=store.id,
                kiosk_identifier=f"ka_{token[:26]}",
                status="ACTIVE",
            )
            db.add(kiosk)
            await db.flush()
            key_specs = {
                "stale": (now - timedelta(hours=25), None, "ak_stale", "ACTIVE"),
                "boundary": (now - timedelta(hours=24), None, "ak_border", "ACTIVE"),
                "used": (now - timedelta(hours=25), now - timedelta(hours=1), "ak_used", "ACTIVE"),
                "legacy": (now - timedelta(hours=25), None, "legacy__", "ACTIVE"),
                "recent": (now - timedelta(hours=1), None, "ak_recent", "ACTIVE"),
                "revoked": (now - timedelta(hours=25), None, "ak_revoked", "REVOKED"),
            }
            key_ids = {}
            key_hashes = {}
            for name, (created_at, last_used_at, prefix, key_status) in key_specs.items():
                key_hash = hashlib.sha256(f"cleanup-test-{token}-{name}".encode()).hexdigest()
                key = KioskApiKey(
                    kiosk_id=kiosk.id,
                    key_prefix=prefix,
                    key_hash=key_hash,
                    status=key_status,
                    created_at=created_at,
                    last_used_at=last_used_at,
                )
                db.add(key)
                await db.flush()
                key_ids[name] = key.id
                key_hashes[name] = key_hash
            await db.commit()

        async with self.session_factory() as db:
            changed = await revoke_unused_keys_once(db, now=now)
        self.assertEqual(changed, 2)

        async with self.session_factory() as db:
            rows = (
                await db.execute(select(KioskApiKey).where(KioskApiKey.id.in_(key_ids.values())))
            ).scalars().all()
            by_id = {row.id: row for row in rows}
            self.assertEqual(by_id[key_ids["stale"]].status, "REVOKED")
            self.assertEqual(by_id[key_ids["boundary"]].status, "REVOKED")
            self.assertEqual(by_id[key_ids["stale"]].revoked_at, now)
            for name in ("used", "legacy", "recent"):
                self.assertEqual(by_id[key_ids[name]].status, "ACTIVE", name)
                self.assertIsNone(by_id[key_ids[name]].revoked_at, name)

            audits = (
                await db.execute(
                    select(AuditLog).where(
                        AuditLog.event_type == "KIOSK_KEY_AUTO_REVOKED",
                        AuditLog.aggregate_id.in_((str(key_ids["stale"]), str(key_ids["boundary"]))),
                    )
                )
            ).scalars().all()
            self.assertEqual(len(audits), 2)
            outbox = (
                await db.execute(
                    select(OutboxEvent).where(
                        OutboxEvent.event_type == "KIOSK_KEY_AUTO_REVOKED",
                        OutboxEvent.aggregate_id.in_((str(key_ids["stale"]), str(key_ids["boundary"]))),
                    )
                )
            ).scalars().all()
            self.assertEqual(len(outbox), 2)
            for audit in audits:
                self.assertEqual(audit.actor_type, "SYSTEM")
                self.assertEqual(audit.aggregate_type, "KIOSK_KEY")
                self.assertEqual(audit.source_kiosk_id, kiosk.id)
                self.assertEqual(audit.payload["reason"], "UNUSED_24H")
                self.assertNotIn("key_hash", audit.payload)
                self.assertNotIn("raw_key", audit.payload)
                serialized = json.dumps(audit.payload)
                for key_hash in key_hashes.values():
                    self.assertNotIn(key_hash, serialized)
            for event in outbox:
                serialized = json.dumps(event.payload)
                for key_hash in key_hashes.values():
                    self.assertNotIn(key_hash, serialized)

        # 앱 부팅 시 시작되는 실제 정리 루프도 전용 DB의 이 키들을 건드리지 않아야 한다.
        cleanup_ran = asyncio.Event()
        original_cleanup = kiosk_key_cleanup.revoke_unused_keys_once

        async def observed_cleanup(db):
            result = await original_cleanup(db)
            cleanup_ran.set()
            return result

        with (
            patch.object(app_main, "AsyncSessionLocal", self.session_factory),
            patch.object(app_main.settings, "kafka_publisher_enabled", False),
            patch.object(kiosk_key_cleanup, "revoke_unused_keys_once", observed_cleanup),
        ):
            async with app_main.lifespan(app_main.app):
                await asyncio.wait_for(cleanup_ran.wait(), timeout=3)

        async with self.session_factory() as db:
            rows = (
                await db.execute(select(KioskApiKey).where(KioskApiKey.id.in_(key_ids.values())))
            ).scalars().all()
            statuses = {row.id: row.status for row in rows}
            self.assertEqual(statuses[key_ids["stale"]], "REVOKED")
            self.assertEqual(statuses[key_ids["boundary"]], "REVOKED")
            for name in ("used", "legacy", "recent"):
                self.assertEqual(statuses[key_ids[name]], "ACTIVE", name)
