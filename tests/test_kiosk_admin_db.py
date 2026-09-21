"""전용 PostgreSQL에서 키오스크 발급·인증·회전·폐기를 실제 HTTP로 검증한다.

E2E_DATABASE_URL의 DB 이름에 ``e2e``가 있어야 실행한다. 모든 요청은 외부
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

import httpx
from sqlalchemy import select
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

E2E_DB_URL = os.environ.get("E2E_DATABASE_URL")
E2E_DB_NAME = make_url(E2E_DB_URL).database if E2E_DB_URL else ""
RUN_E2E = bool(E2E_DB_URL and E2E_DB_NAME and "e2e" in E2E_DB_NAME.lower())

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from app.core.security import create_access_token  # noqa: E402
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


@unittest.skipUnless(RUN_E2E, "키 관리 E2E는 이름에 e2e가 포함된 전용 E2E_DATABASE_URL이 필요하다")
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
        self.assertEqual(final_read.json()["detail"]["code"], "KIOSK_INACTIVE")

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
