"""키오스크 관리자 API의 권한, 키 비밀성, 발급·폐기 계약."""

import base64
import hashlib
import os
import re
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from sqlalchemy.exc import IntegrityError

os.environ["DATABASE_URL"] = "postgresql+asyncpg://test:test@localhost/test"
os.environ["SECRET_KEY"] = "test-secret-key-at-least-32-bytes"
os.environ["ISSUER_PRIVATE_KEY"] = base64.b64encode(bytes(range(32))).decode()

from app.api.deps import get_current_user  # noqa: E402
from app.api.v1.endpoints import kiosk_admin  # noqa: E402
from app.database import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Kiosk, KioskApiKey, Store  # noqa: E402


class _Result:
    def __init__(self, value, rows=None):
        self.value = value
        self.rows = rows or []

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return self

    def all(self):
        return self.rows


class _Db:
    def __init__(self):
        self.store = SimpleNamespace(id=7, status="ACTIVE")
        self.kiosk = None
        self.keys = []
        self.pending = []
        self.commits = 0
        self.rollbacks = 0
        self._next_id = 20

    async def get(self, model, key):
        if model is Store and key == 7:
            return self.store
        return None

    async def execute(self, statement):
        entity = statement.column_descriptions[0]["entity"]
        params = statement.compile().params
        if entity is Kiosk:
            identifier = next((v for v in params.values() if isinstance(v, str)), None)
            return _Result(self.kiosk if self.kiosk and self.kiosk.kiosk_identifier == identifier else None)
        if entity is KioskApiKey:
            ints = [v for v in params.values() if isinstance(v, int)]
            if len(ints) == 1:
                return _Result(None, [k for k in self.keys if k.kiosk_id == ints[0]])
            key = next((k for k in self.keys if k.id in ints and k.kiosk_id in ints), None)
            return _Result(key)
        raise AssertionError(f"unexpected select: {entity}")

    def add(self, row):
        self.pending.append(row)
        if isinstance(row, Kiosk):
            self.kiosk = row
        elif isinstance(row, KioskApiKey):
            self.keys.append(row)

    async def flush(self):
        for row in self.pending:
            if row.id is None:
                row.id = self._next_id
                self._next_id += 1
            if isinstance(row, KioskApiKey) and row.created_at is None:
                row.created_at = datetime.now(timezone.utc)

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1


class KioskAdminTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.db = _Db()
        self.admin = SimpleNamespace(id=1, platform_role="ADMIN", status="ACTIVE")
        self.audit_calls = []
        self.old_overrides = app.dependency_overrides.copy()

        async def override_db():
            yield self.db

        async def override_user():
            return self.admin

        async def fake_audit(_db, **kwargs):
            self.audit_calls.append(kwargs)

        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides[get_current_user] = override_user
        self.audit_patch = patch.object(kiosk_admin, "record_audit_event", side_effect=fake_audit)
        self.audit_patch.start()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")

    async def asyncTearDown(self):
        await self.client.aclose()
        self.audit_patch.stop()
        app.dependency_overrides.clear()
        app.dependency_overrides.update(self.old_overrides)

    async def _register(self):
        return await self.client.post("/api/v1/admin/kiosks", json={"store_id": 7})

    async def test_only_admin_can_register_and_see_raw_key_once(self):
        self.admin.platform_role = "USER"
        denied = await self._register()
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.json(), {"detail": {"code": "PERMISSION_DENIED"}})
        self.assertEqual(self.db.commits, 0)

        self.admin.platform_role = "ADMIN"
        issued = await self._register()
        self.assertEqual(issued.status_code, 201)
        self.assertEqual(issued.headers["cache-control"], "no-store")
        payload = issued.json()
        self.assertRegex(payload["kiosk_identifier"], r"^ka_[0123456789abcdefghjkmnpqrstvwxyz]{26}$")
        raw = payload["key"]["api_key"]
        self.assertRegex(raw, r"^ak_[A-Za-z0-9_-]{43}$")
        self.assertEqual(payload["key"]["key_prefix"], raw[:8])
        self.assertEqual(self.db.keys[0].key_hash, hashlib.sha256(raw.encode()).hexdigest())
        self.assertNotEqual(self.db.keys[0].key_hash, raw)
        self.assertEqual(self.db.kiosk.store_id, 7)
        self.assertEqual(self.db.keys[0].kiosk_id, self.db.kiosk.id)
        self.assertEqual(self.db.commits, 1)
        self.assertEqual(len(self.audit_calls), 1)
        self.assertNotIn(raw, repr(self.audit_calls))
        self.assertNotIn(self.db.keys[0].key_hash, repr(self.audit_calls))

    async def test_suspended_or_withdrawn_admin_cannot_manage_kiosk_keys(self):
        for account_status in ("SUSPENDED", "WITHDRAWN"):
            with self.subTest(status=account_status):
                self.admin.status = account_status
                denied = await self._register()
                self.assertEqual(denied.status_code, 403)
                self.assertEqual(denied.json(), {"detail": {"code": "PERMISSION_DENIED"}})
        self.assertEqual(self.db.commits, 0)
        self.assertIsNone(self.db.kiosk)

    def test_identifier_crockford_encoding_uses_128_random_bits(self):
        with patch.object(kiosk_admin.secrets, "token_bytes", return_value=b"\x00" * 16) as generator:
            self.assertEqual(kiosk_admin._new_kiosk_identifier(), "ka_" + "0" * 26)
            generator.assert_called_once_with(16)
        with patch.object(kiosk_admin.secrets, "token_bytes", return_value=b"\xff" * 16):
            identifier = kiosk_admin._new_kiosk_identifier()
        self.assertTrue(re.fullmatch(r"ka_[0123456789abcdefghjkmnpqrstvwxyz]{26}", identifier))
        self.assertEqual(identifier[:4], "ka_7")  # 128 bits need only 3 of the first 5 bits.

    async def test_missing_and_inactive_store_do_not_create_kiosk(self):
        missing = await self.client.post("/api/v1/admin/kiosks", json={"store_id": 8})
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.json()["detail"]["code"], "STORE_NOT_FOUND")
        self.db.store.status = "SUSPENDED"
        inactive = await self._register()
        self.assertEqual(inactive.status_code, 409)
        self.assertEqual(inactive.json()["detail"]["code"], "STORE_INACTIVE")
        self.assertIsNone(self.db.kiosk)
        self.assertEqual(self.db.commits, 0)

    async def test_add_key_keeps_old_key_active_and_expiry_can_be_set(self):
        registered = (await self._register()).json()
        identifier = registered["kiosk_identifier"]
        first = self.db.keys[0]
        expires_at = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        second_response = await self.client.post(
            f"/api/v1/admin/kiosks/{identifier}/keys", json={"expires_at": expires_at}
        )
        self.assertEqual(second_response.status_code, 201)
        self.assertEqual(second_response.headers["cache-control"], "no-store")
        second = self.db.keys[1]
        self.assertEqual(first.status, "ACTIVE")
        self.assertEqual(second.status, "ACTIVE")
        self.assertNotEqual(first.key_hash, second.key_hash)
        self.assertEqual(second_response.json()["api_key"][:8], second.key_prefix)

        new_expiry = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
        updated = await self.client.patch(
            f"/api/v1/admin/kiosks/{identifier}/keys/{second.id}", json={"expires_at": new_expiry}
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["key_id"], second.id)
        self.assertNotIn("api_key", updated.json())
        self.assertNotIn("key_hash", updated.json())
        self.assertEqual(second.expires_at.isoformat(), new_expiry)

    async def test_list_shows_active_keys_and_usage_metadata_without_secrets(self):
        registered = (await self._register()).json()
        identifier = registered["kiosk_identifier"]
        first_raw = registered["key"]["api_key"]
        second_response = await self.client.post(f"/api/v1/admin/kiosks/{identifier}/keys", json={})
        second_raw = second_response.json()["api_key"]
        self.db.keys[0].last_used_at = datetime.now(timezone.utc)

        listed = await self.client.get(f"/api/v1/admin/kiosks/{identifier}/keys")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.headers["cache-control"], "no-store")
        items = listed.json()
        self.assertEqual(len(items), 2)
        self.assertEqual({item["key_id"] for item in items}, {key.id for key in self.db.keys})
        self.assertTrue(all(item["status"] == "ACTIVE" for item in items))
        self.assertTrue(all("created_at" in item and "last_used_at" in item for item in items))
        self.assertNotIn(first_raw, listed.text)
        self.assertNotIn(second_raw, listed.text)
        for key in self.db.keys:
            self.assertNotIn(key.key_hash, listed.text)
        self.assertNotIn("api_key", listed.text)
        self.assertNotIn("key_hash", listed.text)

    async def test_non_admin_cannot_list_keys(self):
        identifier = (await self._register()).json()["kiosk_identifier"]
        self.admin.platform_role = "USER"
        listed = await self.client.get(f"/api/v1/admin/kiosks/{identifier}/keys")
        self.assertEqual(listed.status_code, 403)
        self.assertEqual(listed.json()["detail"]["code"], "PERMISSION_DENIED")

    async def test_key_and_device_revocation_never_echo_raw_or_hash(self):
        registered = (await self._register()).json()
        identifier = registered["kiosk_identifier"]
        raw = registered["key"]["api_key"]
        key = self.db.keys[0]
        revoked_key = await self.client.post(f"/api/v1/admin/kiosks/{identifier}/keys/{key.id}/revoke")
        self.assertEqual(revoked_key.status_code, 200)
        self.assertEqual(revoked_key.json()["status"], "REVOKED")
        self.assertEqual(revoked_key.headers["cache-control"], "no-store")
        self.assertNotIn(raw, revoked_key.text)
        self.assertNotIn(key.key_hash, revoked_key.text)
        revoked_kiosk = await self.client.post(f"/api/v1/admin/kiosks/{identifier}/revoke")
        self.assertEqual(revoked_kiosk.status_code, 200)
        self.assertEqual(revoked_kiosk.json()["status"], "REVOKED")
        self.assertNotIn(raw, repr(self.audit_calls))
        self.assertNotIn(key.key_hash, repr(self.audit_calls))

    async def test_wrong_key_and_past_expiry_are_rejected(self):
        identifier = (await self._register()).json()["kiosk_identifier"]
        missing = await self.client.post(f"/api/v1/admin/kiosks/{identifier}/keys/999/revoke")
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.json()["detail"]["code"], "KIOSK_KEY_NOT_FOUND")
        self.assertEqual(missing.headers["cache-control"], "no-store")
        old_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        expired = await self.client.post(
            f"/api/v1/admin/kiosks/{identifier}/keys", json={"expires_at": old_date}
        )
        self.assertEqual(expired.status_code, 400)
        self.assertEqual(expired.json()["detail"]["code"], "KIOSK_KEY_EXPIRY_INVALID")
        self.assertEqual(len(self.db.keys), 1)

    async def test_key_hash_collision_rolls_back_without_exposing_key(self):
        identifier = (await self._register()).json()["kiosk_identifier"]
        with patch.object(self.db, "flush", side_effect=IntegrityError("insert", {}, Exception())):
            conflict = await self.client.post(f"/api/v1/admin/kiosks/{identifier}/keys", json={})
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json(), {"detail": {"code": "KIOSK_KEY_CONFLICT"}})
        self.assertEqual(conflict.headers["cache-control"], "no-store")
        self.assertEqual(self.db.rollbacks, 1)
        self.assertEqual(self.db.commits, 1)

    async def test_missing_token_is_denied_before_database_work(self):
        app.dependency_overrides.pop(get_current_user)
        response = await self._register()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"]["code"], "TOKEN_MISSING")
        self.assertEqual(self.db.commits, 0)
        self.assertIsNone(self.db.kiosk)
