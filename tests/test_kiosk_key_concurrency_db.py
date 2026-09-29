"""관리자 폐기와 자동 폐기가 겹쳐도 서로의 잠금을 기다리며 교착하지 않는다.

서로 다른 DB 연결이 필요하므로 전용 E2E DB에 합성 fixture를 커밋한다.
종료 시 이 테스트의 키오스크와 관련 감사/Outbox 행만 제거한다.
"""

import asyncio
import base64
import hashlib
import os
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException, Response
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.sql.dml import Update

E2E_DB_URL = os.environ.get("E2E_DATABASE_URL")

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from app.api.v1.endpoints import kiosk_admin  # noqa: E402
from app.api.deps import get_current_kiosk  # noqa: E402
from app.core import kiosk_key_cleanup  # noqa: E402
from app.models import AuditLog, Business, Kiosk, KioskApiKey, OutboxEvent, Store  # noqa: E402
from app.schemas.kiosk_admin import IssueKioskKeyRequest  # noqa: E402


class _AuthSession(AsyncSession):
    """실제 인증 조회/UPDATE 사이를 제어한다. 프로덕션에 테스트 훅을 넣지 않는다."""

    async def execute(self, statement, *args, **kwargs):
        key_update = isinstance(statement, Update) and statement.table.name == "kiosk_api_keys"
        if key_update:
            gate = self.info.pop("before_key_update", None)
            if gate:
                await asyncio.wait_for(gate(), timeout=5)
        result = await super().execute(statement, *args, **kwargs)
        if key_update:
            frozen = result.freeze()
            self.info.setdefault("updated_keys", []).extend(frozen().scalars().all())
            return frozen()
        if any(
            item.get("expr") is KioskApiKey
            for item in getattr(statement, "column_descriptions", [])
        ):
            gate = self.info.pop("after_key_read", None)
            if gate:
                await asyncio.wait_for(gate(), timeout=5)
        return result


@unittest.skipUnless(E2E_DB_URL, "잠금 경합 검증에는 전용 E2E_DATABASE_URL이 필요하다")
class KioskKeyConcurrencyDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = create_async_engine(E2E_DB_URL, echo=False)
        self.addAsyncCleanup(self.engine.dispose)
        self.session_factory = async_sessionmaker(self.engine, class_=_AuthSession, expire_on_commit=False)
        # 정리 함수는 전역 스캔하므로 기존 미사용 키를 다른 연결에서 잠가
        # SKIP LOCKED 대상에서 제외한다. 경계 시각을 막 넘는 키도 보호한다.
        self.guard_connection = await self.engine.connect()
        self.addAsyncCleanup(self.guard_connection.close)
        self.guard_transaction = await self.guard_connection.begin()
        self.addAsyncCleanup(self.guard_transaction.rollback)
        await self.guard_connection.execute(
            select(KioskApiKey.id)
            .where(
                KioskApiKey.status == "ACTIVE",
                KioskApiKey.last_used_at.is_(None),
                KioskApiKey.key_prefix != "legacy__",
            )
            .with_for_update()
        )
        token = uuid.uuid4().hex
        self.raw_key = "ak_lock_" + token
        async with self.session_factory() as db:
            business = Business(
                business_number=f"lock-e2e-{token}", business_name="Lock E2E", status="ACTIVE"
            )
            db.add(business)
            await db.flush()
            store = Store(
                business_id=business.id,
                store_code=f"lock-e2e-{token}",
                store_name="Lock E2E",
                store_type_code="E2E",
                address="E2E only",
                status="ACTIVE",
            )
            db.add(store)
            await db.flush()
            kiosk = Kiosk(
                store_id=store.id, kiosk_identifier=f"ka_{token[:26]}", status="ACTIVE"
            )
            db.add(kiosk)
            await db.flush()
            key = KioskApiKey(
                kiosk_id=kiosk.id,
                key_prefix="ak_lock_",
                key_hash=hashlib.sha256(self.raw_key.encode()).hexdigest(),
                status="ACTIVE",
                created_at=datetime.now(timezone.utc) - timedelta(hours=25),
            )
            db.add(key)
            await db.flush()
            self.business_id, self.store_id = business.id, store.id
            self.kiosk_id, self.identifier, self.key_id = kiosk.id, kiosk.kiosk_identifier, key.id
            await db.commit()
        self.addAsyncCleanup(self._remove_fixture)

    async def _remove_fixture(self):
        async with self.session_factory() as db:
            events = select(AuditLog.event_id).where(AuditLog.source_kiosk_id == self.kiosk_id)
            await db.execute(delete(OutboxEvent).where(OutboxEvent.event_id.in_(events)))
            await db.execute(delete(AuditLog).where(AuditLog.source_kiosk_id == self.kiosk_id))
            await db.execute(delete(KioskApiKey).where(KioskApiKey.kiosk_id == self.kiosk_id))
            await db.execute(delete(Kiosk).where(Kiosk.id == self.kiosk_id))
            await db.execute(delete(Store).where(Store.id == self.store_id))
            await db.execute(delete(Business).where(Business.id == self.business_id))
            await db.commit()

    async def _race_cleanup_with_admin(self, *, revoke_device: bool):
        cleanup_holds_key_and_audit = asyncio.Event()
        admin_holds_kiosk = asyncio.Event()
        original_audit = kiosk_key_cleanup.record_audit_event
        original_find_kiosk = kiosk_admin._find_kiosk

        async def pause_cleanup_before_audit_flush(db, **kwargs):
            row = await original_audit(db, **kwargs)
            if kwargs["source_kiosk_id"] == self.kiosk_id:
                # 자동 폐기는 키 행 + 감사 advisory lock을 보유한다. 아직
                # AuditLog INSERT의 kiosk FK 잠금은 획득하지 않은 시점이다.
                cleanup_holds_key_and_audit.set()
                await asyncio.wait_for(admin_holds_kiosk.wait(), timeout=5)
            return row

        async def observe_kiosk_lock(db, identifier, **kwargs):
            row = await original_find_kiosk(db, identifier, **kwargs)
            if identifier == self.identifier:
                admin_holds_kiosk.set()
            return row

        async def cleanup():
            async with self.session_factory() as db:
                return await kiosk_key_cleanup.revoke_unused_keys_once(db)

        async def admin():
            await asyncio.wait_for(cleanup_holds_key_and_audit.wait(), timeout=5)
            async with self.session_factory() as db:
                kwargs = {
                    "kiosk_identifier": self.identifier,
                    "response": Response(),
                    "admin": SimpleNamespace(id=1),
                    "db": db,
                }
                if revoke_device:
                    return await kiosk_admin.revoke_kiosk(**kwargs)
                return await kiosk_admin.revoke_kiosk_key(key_id=self.key_id, **kwargs)

        with (
            patch.object(kiosk_key_cleanup, "record_audit_event", pause_cleanup_before_audit_flush),
            patch.object(kiosk_admin, "_find_kiosk", observe_kiosk_lock),
        ):
            tasks = [asyncio.create_task(cleanup()), asyncio.create_task(admin())]
            try:
                results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=10)
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

        self.assertEqual(results[0], 1)
        self.assertEqual(results[1].status, "REVOKED")
        async with self.session_factory() as db:
            key = await db.get(KioskApiKey, self.key_id)
            self.assertEqual(key.status, "REVOKED")
            audits = (
                await db.execute(select(AuditLog).where(AuditLog.source_kiosk_id == self.kiosk_id))
            ).scalars().all()
            self.assertEqual(
                sum(row.event_type == "KIOSK_KEY_AUTO_REVOKED" for row in audits), 1
            )
            if revoke_device:
                self.assertEqual(sum(row.event_type == "KIOSK_REVOKED" for row in audits), 1)

    async def test_cleanup_and_admin_key_revocation_do_not_deadlock(self):
        await self._race_cleanup_with_admin(revoke_device=False)

    async def test_cleanup_and_admin_device_revocation_do_not_deadlock(self):
        await self._race_cleanup_with_admin(revoke_device=True)

    async def _set_key_usage(self, *, recent=False):
        async with self.session_factory() as db:
            key = await db.get(KioskApiKey, self.key_id)
            key.created_at = datetime.now(timezone.utc) - timedelta(hours=1)
            key.last_used_at = datetime.now(timezone.utc) if recent else None
            await db.commit()

    async def _authenticate(self, db):
        return await get_current_kiosk(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials=self.raw_key), db
        )

    async def _revoke_device(self):
        async with self.session_factory() as db:
            return await kiosk_admin.revoke_kiosk(
                self.identifier, Response(), SimpleNamespace(id=1), db
            )

    async def test_recent_authentication_does_not_wait_for_a_key_row_write_lock(self):
        await self._set_key_usage(recent=True)
        async with self.session_factory() as blocker:
            key = (await blocker.execute(
                select(KioskApiKey).where(KioskApiKey.id == self.key_id).with_for_update()
            )).scalar_one()
            previous_used = key.last_used_at
            async with self.session_factory() as reader:
                kiosk = await asyncio.wait_for(self._authenticate(reader), timeout=2)
                self.assertEqual(kiosk.id, self.kiosk_id)
                self.assertEqual(reader.info.get("updated_keys", []), [])
            await blocker.rollback()
        async with self.session_factory() as db:
            self.assertEqual((await db.get(KioskApiKey, self.key_id)).last_used_at, previous_used)

    async def test_concurrent_first_use_updates_the_key_only_once(self):
        await self._set_key_usage()
        barrier = asyncio.Barrier(2)
        infos = [{"before_key_update": barrier.wait} for _ in range(2)]

        async def authenticate(info):
            async with self.session_factory(info=info) as db:
                kiosk = await self._authenticate(db)
                return kiosk.id, db.info["updated_keys"]

        results = await asyncio.wait_for(asyncio.gather(*(authenticate(info) for info in infos)), timeout=10)
        self.assertEqual([kiosk_id for kiosk_id, _ in results], [self.kiosk_id] * 2)
        self.assertEqual(sum(key is not None for _, changes in results for key in changes), 1)
        async with self.session_factory() as db:
            key = await db.get(KioskApiKey, self.key_id)
            self.assertEqual(key.status, "ACTIVE")
            self.assertIsNotNone(key.last_used_at)

    async def test_revocation_after_lookup_is_rechecked_before_recording_first_use(self):
        await self._set_key_usage()
        key_read = asyncio.Event()
        revoked = asyncio.Event()

        async def pause():
            key_read.set()
            await revoked.wait()

        async def authenticate():
            async with self.session_factory(info={"after_key_read": pause}) as db:
                with self.assertRaises(HTTPException) as caught:
                    await self._authenticate(db)
                self.assertEqual(caught.exception.detail["code"], "KIOSK_KEY_INVALID")

        async def revoke():
            await asyncio.wait_for(key_read.wait(), timeout=5)
            async with self.session_factory() as db:
                await kiosk_admin.revoke_kiosk_key(
                    self.identifier, self.key_id, Response(), SimpleNamespace(id=1), db
                )
            revoked.set()

        await asyncio.wait_for(asyncio.gather(authenticate(), revoke()), timeout=10)
        async with self.session_factory() as db:
            key = await db.get(KioskApiKey, self.key_id)
            self.assertEqual(key.status, "REVOKED")
            self.assertIsNone(key.last_used_at)

    async def test_cleanup_winning_after_auth_lookup_does_not_duplicate_audit(self):
        key_read = asyncio.Event()
        cleaned = asyncio.Event()

        async def pause():
            key_read.set()
            await cleaned.wait()

        async def authenticate():
            async with self.session_factory(info={"after_key_read": pause}) as db:
                with self.assertRaises(HTTPException) as caught:
                    await self._authenticate(db)
                self.assertEqual(caught.exception.detail["code"], "KIOSK_KEY_INVALID")

        async def cleanup():
            await asyncio.wait_for(key_read.wait(), timeout=5)
            async with self.session_factory() as db:
                self.assertEqual(await kiosk_key_cleanup.revoke_unused_keys_once(db), 1)
            cleaned.set()

        await asyncio.wait_for(asyncio.gather(authenticate(), cleanup()), timeout=10)
        async with self.session_factory() as db:
            audits = (await db.scalars(select(AuditLog).where(AuditLog.source_kiosk_id == self.kiosk_id))).all()
            self.assertEqual([row.event_type for row in audits], ["KIOSK_KEY_AUTO_REVOKED"])

    async def test_concurrent_unused_key_authentication_emits_one_revocation(self):
        barrier = asyncio.Barrier(2)

        async def authenticate():
            async with self.session_factory(info={"before_key_update": barrier.wait}) as db:
                with self.assertRaises(HTTPException) as caught:
                    await self._authenticate(db)
                self.assertEqual(caught.exception.detail["code"], "KIOSK_KEY_INVALID")

        await asyncio.wait_for(asyncio.gather(authenticate(), authenticate()), timeout=10)
        async with self.session_factory() as db:
            audits = (await db.scalars(select(AuditLog).where(AuditLog.source_kiosk_id == self.kiosk_id))).all()
            self.assertEqual([row.event_type for row in audits], ["KIOSK_KEY_AUTO_REVOKED"])
            outbox = (await db.scalars(select(OutboxEvent).where(OutboxEvent.event_id == audits[0].event_id))).all()
            self.assertEqual(len(outbox), 1)

    async def test_concurrent_device_revocation_preserves_one_transition_per_key(self):
        barrier = asyncio.Barrier(2)
        original_find = kiosk_admin._find_kiosk

        async def synchronized_find(*args, **kwargs):
            await asyncio.wait_for(barrier.wait(), timeout=5)
            return await original_find(*args, **kwargs)

        with patch.object(kiosk_admin, "_find_kiosk", synchronized_find):
            results = await asyncio.wait_for(
                asyncio.gather(self._revoke_device(), self._revoke_device()), timeout=10
            )
        self.assertEqual(results[0].revoked_at, results[1].revoked_at)
        async with self.session_factory() as db:
            key = await db.get(KioskApiKey, self.key_id)
            self.assertEqual(key.status, "REVOKED")
            self.assertEqual(key.revoked_at, results[0].revoked_at)
            audits = (await db.scalars(select(AuditLog).where(AuditLog.source_kiosk_id == self.kiosk_id))).all()
            self.assertCountEqual([row.event_type for row in audits], ["KIOSK_REVOKED", "KIOSK_KEY_REVOKED"])

    async def test_key_issuance_waiting_for_device_revocation_is_rejected(self):
        device_locked = asyncio.Event()
        issuance_started = asyncio.Event()
        original_find = kiosk_admin._find_kiosk

        async def pause_revoker(db, identifier, **kwargs):
            if db.info.get("issuing"):
                issuance_started.set()
                return await original_find(db, identifier, **kwargs)
            kiosk = await original_find(db, identifier, **kwargs)
            device_locked.set()
            await asyncio.wait_for(issuance_started.wait(), timeout=5)
            return kiosk

        async def issue():
            await asyncio.wait_for(device_locked.wait(), timeout=5)
            async with self.session_factory(info={"issuing": True}) as db:
                with self.assertRaises(HTTPException) as caught:
                    await kiosk_admin.issue_kiosk_key(
                        self.identifier, IssueKioskKeyRequest(), Response(), SimpleNamespace(id=1), db
                    )
                self.assertEqual(caught.exception.detail["code"], "KIOSK_INACTIVE")

        with patch.object(kiosk_admin, "_find_kiosk", pause_revoker):
            await asyncio.wait_for(asyncio.gather(self._revoke_device(), issue()), timeout=10)
        async with self.session_factory() as db:
            keys = (await db.scalars(select(KioskApiKey).where(KioskApiKey.kiosk_id == self.kiosk_id))).all()
            self.assertEqual(len(keys), 1)
            self.assertEqual(keys[0].status, "REVOKED")
