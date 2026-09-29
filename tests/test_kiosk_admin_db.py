"""전용 PostgreSQL에서 키오스크 발급·인증·회전·폐기를 실제 HTTP로 검증한다.

전용 테스트 DB의 E2E_DATABASE_URL이 설정되어 있으면 실행한다. 모든 요청은 외부
트랜잭션의 SAVEPOINT에서 실행하고 테스트 끝에 외부 트랜잭션을 롤백한다.
따라서 키오스크·키·감사 로그·Outbox 등 이 테스트가 만든 행이 남지 않는다.
"""

import base64
import hashlib
import os
import re
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

E2E_DB_URL = os.environ.get("E2E_DATABASE_URL")

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from app.core.security import create_access_token  # noqa: E402
from app.api.v1.endpoints import kiosk_admin  # noqa: E402
from app.core.status_list import empty_encoded_list  # noqa: E402
from app.database import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import (  # noqa: E402
    AuditLog,
    Business,
    CredentialStatusList,
    Kiosk,
    KioskApiKey,
    OutboxEvent,
    Store,
    User,
)


@unittest.skipUnless(E2E_DB_URL, "키 관리 E2E에는 전용 E2E_DATABASE_URL이 필요하다")
class KioskAdminDatabaseTests(unittest.IsolatedAsyncioTestCase):
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

        token = uuid.uuid4().hex
        async with self.session_factory() as db:
            admin = User(
                login_id=f"kiosk-e2e-{token}",
                password_hash="not-used-for-e2e-token",
                name="kiosk E2E admin",
                phone_number=f"e2e-{token[:24]}",
                phone_verified_at=datetime.now(timezone.utc),
                platform_role="ADMIN",
                status="ACTIVE",
            )
            business = Business(
                business_number=f"kiosk-e2e-{token}",
                business_name="Kiosk E2E business",
                status="ACTIVE",
            )
            db.add_all((admin, business))
            await db.flush()
            self.admin_id = admin.id
            store = Store(
                business_id=business.id,
                store_code=f"kiosk-e2e-{token}",
                store_name="Kiosk E2E store",
                store_type_code="E2E",
                address="E2E only",
                status="ACTIVE",
            )
            status_list = CredentialStatusList(
                issuer_did=f"did:example:kiosk-e2e-{token}",
                status_purpose="REVOCATION",
                status_list_url=f"https://kiosk-e2e.invalid/status-lists/{token}",
                encoded_list=empty_encoded_list(),
            )
            db.add_all((store, status_list))
            await db.flush()
            self.store_id = store.id
            self.status_path = f"/api/v1/status-lists/{status_list.id}"
            self.admin_headers = {"Authorization": f"Bearer {create_access_token(admin.id, 'ADMIN')}"}
            await db.commit()

        async def override_db():
            async with self.session_factory() as session:
                yield session

        self.old_overrides = app.dependency_overrides.copy()
        app.dependency_overrides[get_db] = override_db
        self.addCleanup(self._restore_overrides)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://kiosk-e2e")
        self.addAsyncCleanup(self.client.aclose)

    def _restore_overrides(self):
        app.dependency_overrides.clear()
        app.dependency_overrides.update(self.old_overrides)

    async def _status(self, raw_key):
        return await self.client.get(self.status_path, headers={"Authorization": f"Bearer {raw_key}"})

    async def _register(self):
        response = await self.client.post(
            "/api/v1/admin/kiosks", json={"store_id": self.store_id}, headers=self.admin_headers
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    async def _revoke(self, identifier):
        return await self.client.post(
            f"/api/v1/admin/kiosks/{identifier}/revoke", headers=self.admin_headers
        )

    async def _events(self, kiosk_id):
        async with self.session_factory() as db:
            audits = (await db.scalars(
                select(AuditLog).where(AuditLog.source_kiosk_id == kiosk_id).order_by(AuditLog.id)
            )).all()
            outbox = (await db.scalars(
                select(OutboxEvent).where(OutboxEvent.event_id.in_([row.event_id for row in audits]))
            )).all()
            return audits, outbox

    async def test_device_revocation_covers_all_active_keys_and_is_idempotent(self):
        first = await self._register()
        other = await self._register()
        identifier = first["kiosk_identifier"]
        keys = [first["key"]]
        for _ in range(4):
            response = await self.client.post(
                f"/api/v1/admin/kiosks/{identifier}/keys", json={}, headers=self.admin_headers
            )
            self.assertEqual(response.status_code, 201)
            keys.append(response.json())
        old = datetime.now(timezone.utc) - timedelta(days=2)
        async with self.session_factory() as db:
            rows = [await db.get(KioskApiKey, key["key_id"]) for key in keys]
            rows[0].last_used_at = old
            rows[1].created_at = old  # 24시간 미사용 키
            rows[2].key_prefix = "legacy__"
            rows[3].expires_at = old
            rows[4].status, rows[4].revoked_at = "REVOKED", old
            kiosk_id = rows[0].kiosk_id
            await db.commit()
        before, _ = await self._events(kiosk_id)

        response = await self._revoke(identifier)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        async with self.session_factory() as db:
            kiosk = await db.get(Kiosk, kiosk_id)
            rows = [await db.get(KioskApiKey, key["key_id"]) for key in keys]
            self.assertTrue(all(row.status == "REVOKED" for row in rows))
            self.assertTrue(all(row.revoked_at == kiosk.revoked_at for row in rows[:4]))
            self.assertEqual(rows[4].revoked_at, old)
            other_key = await db.get(KioskApiKey, other["key"]["key_id"])
            self.assertEqual(other_key.status, "ACTIVE")
            revoked_at, updated_at = kiosk.revoked_at, kiosk.updated_at
        after, outbox = await self._events(kiosk_id)
        events = after[len(before):]
        self.assertEqual([row.event_type for row in events], ["KIOSK_REVOKED"] + ["KIOSK_KEY_REVOKED"] * 4)
        self.assertEqual({row.payload["key_id"] for row in events[1:]}, {key["key_id"] for key in keys[:4]})
        self.assertTrue(all(row.payload["reason"] == "KIOSK_REVOKED" for row in events[1:]))
        self.assertEqual({row.event_id for row in after}, {row.event_id for row in outbox})
        for key in keys:
            payloads = repr([row.payload for row in (*after, *outbox)])
            self.assertNotIn(key["api_key"], payloads)
            self.assertNotIn(hashlib.sha256(key["api_key"].encode()).hexdigest(), payloads)

        self.assertEqual((await self._revoke(identifier)).status_code, 200)
        repeated, _ = await self._events(kiosk_id)
        self.assertEqual([row.event_id for row in repeated], [row.event_id for row in after])
        async with self.session_factory() as db:
            kiosk = await db.get(Kiosk, kiosk_id)
            self.assertEqual((kiosk.revoked_at, kiosk.updated_at), (revoked_at, updated_at))
        listed = await self.client.get(
            f"/api/v1/admin/kiosks/{identifier}/keys", headers=self.admin_headers
        )
        self.assertTrue(all(key["status"] == "REVOKED" for key in listed.json()))
        self.assertEqual((await self._status(keys[0]["api_key"])).json()["detail"]["code"], "KIOSK_KEY_INVALID")

    async def test_repeated_device_revocation_repairs_legacy_residual_keys(self):
        first = await self._register()
        old = datetime.now(timezone.utc) - timedelta(days=1)
        async with self.session_factory() as db:
            key = await db.get(KioskApiKey, first["key"]["key_id"])
            kiosk = await db.get(Kiosk, key.kiosk_id)
            kiosk.status, kiosk.revoked_at, kiosk.updated_at = "REVOKED", old, old
            kiosk_id = kiosk.id
            await db.commit()
        before, _ = await self._events(kiosk_id)
        response = await self._revoke(first["kiosk_identifier"])
        self.assertEqual(response.status_code, 200)
        async with self.session_factory() as db:
            key = await db.get(KioskApiKey, first["key"]["key_id"])
            kiosk = await db.get(Kiosk, kiosk_id)
            self.assertEqual(key.status, "REVOKED")
            self.assertEqual((kiosk.revoked_at, kiosk.updated_at), (old, old))
        after, _ = await self._events(kiosk_id)
        self.assertEqual([row.event_type for row in after[len(before):]], ["KIOSK_KEY_REVOKED"])

    async def test_audit_failure_rolls_back_device_keys_and_events(self):
        first = await self._register()
        async with self.session_factory() as db:
            key = await db.get(KioskApiKey, first["key"]["key_id"])
            kiosk_id = key.kiosk_id
        before, _ = await self._events(kiosk_id)
        original_audit = kiosk_admin.record_audit_event

        async def fail_after_event_flush(db, **kwargs):
            await original_audit(db, **kwargs)
            # 키와 단말 UPDATE에 이어 감사/Outbox INSERT까지 수행한 뒤 실패한다.
            await db.flush()
            raise RuntimeError("injected audit failure")

        with patch.object(kiosk_admin, "record_audit_event", fail_after_event_flush):
            with self.assertRaisesRegex(RuntimeError, "injected audit failure"):
                await self._revoke(first["kiosk_identifier"])
        async with self.session_factory() as db:
            kiosk = await db.get(Kiosk, kiosk_id)
            key = await db.get(KioskApiKey, first["key"]["key_id"])
            self.assertEqual((kiosk.status, key.status), ("ACTIVE", "ACTIVE"))
            self.assertIsNone(kiosk.revoked_at)
            self.assertIsNone(key.revoked_at)
        after, outbox = await self._events(kiosk_id)
        self.assertEqual([row.event_id for row in before], [row.event_id for row in after])
        self.assertEqual({row.event_id for row in after}, {row.event_id for row in outbox})

    async def test_usage_is_recorded_on_first_use_then_at_minute_intervals(self):
        first = await self._register()
        key_id, raw = first["key"]["key_id"], first["key"]["api_key"]
        self.assertEqual((await self._status(raw)).status_code, 200)
        async with self.session_factory() as db:
            first_used = (await db.get(KioskApiKey, key_id)).last_used_at
        self.assertIsNotNone(first_used)
        self.assertEqual((await self._status(raw)).status_code, 200)
        async with self.session_factory() as db:
            key = await db.get(KioskApiKey, key_id)
            self.assertEqual(key.last_used_at, first_used)
            key.last_used_at = first_used - timedelta(minutes=2)
            key.created_at = first_used - timedelta(days=2)
            await db.commit()
        self.assertEqual((await self._status(raw)).status_code, 200)
        async with self.session_factory() as db:
            self.assertGreater((await db.get(KioskApiKey, key_id)).last_used_at, first_used)

    async def test_expired_unused_key_is_revoked_once_and_legacy_key_remains_usable(self):
        first = await self._register()
        legacy = await self._register()
        async with self.session_factory() as db:
            first_key = await db.get(KioskApiKey, first["key"]["key_id"])
            legacy_key = await db.get(KioskApiKey, legacy["key"]["key_id"])
            first_key.created_at = legacy_key.created_at = datetime.now(timezone.utc) - timedelta(days=2)
            legacy_key.key_prefix = "legacy__"
            kiosk_id = first_key.kiosk_id
            await db.commit()
        for _ in range(2):
            response = await self._status(first["key"]["api_key"])
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json()["detail"]["code"], "KIOSK_KEY_INVALID")
        self.assertEqual((await self._status(legacy["key"]["api_key"])).status_code, 200)
        audits, _ = await self._events(kiosk_id)
        self.assertEqual(sum(row.event_type == "KIOSK_KEY_AUTO_REVOKED" for row in audits), 1)

    async def test_admin_issuance_rotation_expiry_and_revocation(self):
        registered = await self.client.post(
            "/api/v1/admin/kiosks", json={"store_id": self.store_id}, headers=self.admin_headers
        )
        self.assertEqual(registered.status_code, 201)
        self.assertEqual(registered.headers["cache-control"], "no-store")
        first_payload = registered.json()
        identifier = first_payload["kiosk_identifier"]
        first_key = first_payload["key"]["api_key"]
        first_id = first_payload["key"]["key_id"]
        self.assertTrue(bool(re.fullmatch(r"ak_[A-Za-z0-9_-]{43}", first_key)), "invalid key format")

        # 이미 발급된 ADMIN JWT가 있어도 계정 정지 중에는 키를 더 만들 수 없다.
        async with self.session_factory() as db:
            admin = await db.get(User, self.admin_id)
            admin.status = "SUSPENDED"
            await db.commit()
        denied = await self.client.post(
            f"/api/v1/admin/kiosks/{identifier}/keys", json={}, headers=self.admin_headers
        )
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.json()["detail"]["code"], "PERMISSION_DENIED")
        async with self.session_factory() as db:
            admin = await db.get(User, self.admin_id)
            admin.status = "ACTIVE"
            await db.commit()

        first_read = await self._status(first_key)
        self.assertEqual(first_read.status_code, 200)
        self.assertEqual(first_read.headers["content-type"], "application/jwt")
        wrong_read = await self._status(first_key + "x")
        self.assertEqual(wrong_read.status_code, 401)

        second_issued = await self.client.post(
            f"/api/v1/admin/kiosks/{identifier}/keys", json={}, headers=self.admin_headers
        )
        self.assertEqual(second_issued.status_code, 201)
        second_key = second_issued.json()["api_key"]
        second_id = second_issued.json()["key_id"]
        self.assertNotEqual(first_id, second_id)
        self.assertTrue(bool(re.fullmatch(r"ak_[A-Za-z0-9_-]{43}", second_key)), "invalid key format")
        self.assertEqual((await self._status(first_key)).status_code, 200)
        self.assertEqual((await self._status(second_key)).status_code, 200)
        listed = await self.client.get(
            f"/api/v1/admin/kiosks/{identifier}/keys", headers=self.admin_headers
        )
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.headers["cache-control"], "no-store")
        self.assertEqual({item["key_id"] for item in listed.json()}, {first_id, second_id})
        self.assertTrue(all(item["last_used_at"] is not None for item in listed.json()))
        self.assertNotIn(first_key, listed.text)
        self.assertNotIn(second_key, listed.text)
        self.assertNotIn("key_hash", listed.text)

        future = datetime.now(timezone.utc) + timedelta(hours=1)
        expiry_set = await self.client.patch(
            f"/api/v1/admin/kiosks/{identifier}/keys/{first_id}",
            json={"expires_at": future.isoformat()},
            headers=self.admin_headers,
        )
        self.assertEqual(expiry_set.status_code, 200)
        self.assertNotIn("api_key", expiry_set.json())
        self.assertNotIn("key_hash", expiry_set.json())
        self.assertEqual((await self._status(first_key)).status_code, 200)

        first_revoked = await self.client.post(
            f"/api/v1/admin/kiosks/{identifier}/keys/{first_id}/revoke", headers=self.admin_headers
        )
        self.assertEqual(first_revoked.status_code, 200)
        self.assertEqual(first_revoked.json()["status"], "REVOKED")
        self.assertEqual((await self._status(first_key)).status_code, 401)
        self.assertEqual((await self._status(second_key)).status_code, 200)

        # 관리자 API는 과거 만료 시각을 받지 않으므로, 지난 시간을 DB에 직접
        # 설정해 인증 의존성의 만료 판정을 검증한다.
        async with self.session_factory() as db:
            second_row = await db.get(KioskApiKey, second_id)
            second_row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            await db.commit()
        self.assertEqual((await self._status(second_key)).status_code, 401)

        third_issued = await self.client.post(
            f"/api/v1/admin/kiosks/{identifier}/keys", json={}, headers=self.admin_headers
        )
        self.assertEqual(third_issued.status_code, 201)
        third_key = third_issued.json()["api_key"]
        self.assertEqual((await self._status(third_key)).status_code, 200)
        kiosk_revoked = await self.client.post(
            f"/api/v1/admin/kiosks/{identifier}/revoke", headers=self.admin_headers
        )
        self.assertEqual(kiosk_revoked.status_code, 200)
        self.assertEqual(kiosk_revoked.json()["status"], "REVOKED")
        final_read = await self._status(third_key)
        self.assertEqual(final_read.status_code, 401)
        # 단말과 함께 키 자체도 폐기되므로 키 우선 검사에서 거절한다.
        self.assertEqual(final_read.json()["detail"]["code"], "KIOSK_KEY_INVALID")

        async with self.session_factory() as db:
            kiosk = (await db.execute(select(Kiosk).where(Kiosk.kiosk_identifier == identifier))).scalar_one()
            first_row = await db.get(KioskApiKey, first_id)
            second_row = await db.get(KioskApiKey, second_id)
            audit_result = await db.execute(select(AuditLog).where(AuditLog.source_kiosk_id == kiosk.id))
            outbox_result = await db.execute(select(OutboxEvent).where(OutboxEvent.aggregate_id == identifier))
            audit_rows = audit_result.scalars().all()
            outbox_rows = outbox_result.scalars().all()
            self.assertEqual(first_row.status, "REVOKED")
            self.assertIsNotNone(first_row.last_used_at)
            self.assertIsNotNone(second_row.last_used_at)
            self.assertTrue(
                hashlib.sha256(first_key.encode()).hexdigest() == first_row.key_hash,
                "stored hash mismatch",
            )
            self.assertEqual(first_row.key_prefix, first_key[:8])
            self.assertGreaterEqual(len(audit_rows), 4)
            self.assertEqual(len(audit_rows), len(outbox_rows))
            persisted = repr([row.payload for row in (*audit_rows, *outbox_rows)])
            for raw in (first_key, second_key, third_key):
                self.assertFalse(raw in persisted, "raw key leaked into audit or outbox")

        # 관제 웹이 사용하는 기존 감사 조회 API에서도 새 키 관리 이벤트가
        # 직렬화되고, 키 원문/해시는 응답에 노출되지 않아야 한다.
        log_response = await self.client.get(
            "/api/v1/admin/logs",
            params={"source_kiosk_id": kiosk.id},
            headers=self.admin_headers,
        )
        self.assertEqual(log_response.status_code, 200)
        events = {item["event_type"] for item in log_response.json()["items"]}
        self.assertTrue({"KIOSK_REGISTERED", "KIOSK_KEY_ISSUED", "KIOSK_REVOKED"} <= events)
        for raw in (first_key, second_key, third_key):
            self.assertNotIn(raw, log_response.text)
            self.assertNotIn(hashlib.sha256(raw.encode()).hexdigest(), log_response.text)


if __name__ == "__main__":
    unittest.main()
