"""전용 PostgreSQL에서 관리자의 KIOSK 계정 생성·정지·임시 비밀번호 재발급을 실제 HTTP로 검증한다 (#66).

E2E_DATABASE_URL이 설정되어 있으면 실행한다. 모든 요청은 외부 트랜잭션의
SAVEPOINT에서 실행하고 테스트 끝에 롤백하므로 만든 계정·사업자·감사 로그가 남지 않는다.
"""

import base64
import os
import re
import unittest
import uuid
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

E2E_DB_URL = os.environ.get("E2E_DATABASE_URL")

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from app.core.security import create_access_token  # noqa: E402
from app.database import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import AuditLog, Business, BusinessMembership, User  # noqa: E402

NEW_PASSWORD = "kiosk-own-pass-1"


@unittest.skipUnless(E2E_DB_URL, "KIOSK 계정 관리 E2E에는 전용 E2E_DATABASE_URL이 필요하다")
class KioskAccountAdminDatabaseTests(unittest.IsolatedAsyncioTestCase):
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

        self.token = uuid.uuid4().hex
        async with self.session_factory() as db:
            admin = User(
                login_id=f"acct-admin-{self.token}",
                password_hash="not-used-for-e2e-token",
                name="account E2E admin",
                phone_number=f"e2e-{self.token[:24]}",
                phone_verified_at=datetime.now(timezone.utc),
                platform_role="ADMIN",
                status="ACTIVE",
            )
            db.add(admin)
            await db.commit()
            self.admin_headers = {"Authorization": f"Bearer {create_access_token(admin.id, 'ADMIN')}"}

        async def override_db():
            async with self.session_factory() as session:
                yield session

        self.old_overrides = app.dependency_overrides.copy()
        app.dependency_overrides[get_db] = override_db
        self.addCleanup(self._restore_overrides)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://acct-e2e")
        self.addAsyncCleanup(self.client.aclose)

    def _restore_overrides(self):
        app.dependency_overrides.clear()
        app.dependency_overrides.update(self.old_overrides)

    def _body(self, suffix: str = "a", business_number: str | None = None) -> dict:
        return {
            "login_id": f"kiosk-{suffix}-{self.token}",
            "name": "E2E 매장 키오스크",
            "business_number": business_number or f"biz-{self.token}",
            "business_name": "E2E 사업자",
        }

    async def _create(self, body: dict) -> httpx.Response:
        return await self.client.post("/api/v1/admin/kiosk-accounts", json=body, headers=self.admin_headers)

    async def _login(self, login_id: str, password: str) -> httpx.Response:
        return await self.client.post("/api/v1/auth/login", json={"login_id": login_id, "password": password})

    def _assert_error(self, response: httpx.Response, status_code: int, code: str):
        self.assertEqual(response.status_code, status_code, response.text)
        self.assertEqual(response.json()["detail"]["code"], code)

    async def _audit_rows(self, account_id: int) -> list[AuditLog]:
        async with self.session_factory() as db:
            result = await db.execute(
                select(AuditLog).where(AuditLog.aggregate_id == str(account_id)).order_by(AuditLog.id)
            )
            return list(result.scalars().all())

    async def test_create_returns_temp_password_once_and_links_business_as_owner(self):
        created = await self._create(self._body())
        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(created.headers["cache-control"], "no-store")
        payload = created.json()
        temp_password = payload["temporary_password"]
        self.assertTrue(re.fullmatch(r"[2-9a-km-zA-HJ-NP-Z]{12}", temp_password), temp_password)
        account = payload["account"]
        self.assertEqual(account["status"], "ACTIVE")
        self.assertTrue(account["must_change_password"])
        self.assertIsNotNone(account["temp_password_expires_at"])
        self.assertEqual(account["business"]["business_number"], f"biz-{self.token}")
        self.assertNotIn("temporary_password", account)

        async with self.session_factory() as db:
            stored = await db.get(User, account["id"])
            self.assertEqual(stored.platform_role, "KIOSK")
            self.assertIsNone(stored.phone_number)
            self.assertNotEqual(stored.password_hash, temp_password)
            membership = (
                await db.execute(select(BusinessMembership).where(BusinessMembership.user_id == stored.id))
            ).scalar_one()
            self.assertEqual(membership.business_role, "OWNER")
            self.assertEqual(membership.business_id, account["business"]["business_id"])

        # 조회 응답에는 임시 비밀번호가 없다.
        detail = await self.client.get(f"/api/v1/admin/kiosk-accounts/{account['id']}", headers=self.admin_headers)
        self.assertEqual(detail.status_code, 200, detail.text)
        self.assertNotIn(temp_password, detail.text)

        # 매장은 임시 비밀번호로 로그인해 바로 비밀번호를 바꾼다.
        login = await self._login(account["login_id"], temp_password)
        self.assertEqual(login.status_code, 200, login.text)
        changed = await self.client.post(
            "/api/v1/auth/password",
            json={"current_password": temp_password, "new_password": NEW_PASSWORD},
            headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        )
        self.assertEqual(changed.status_code, 200, changed.text)
        me = await self.client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {changed.json()['access_token']}"}
        )
        self.assertEqual(me.json()["platform_role"], "KIOSK")
        self.assertFalse(me.json()["must_change_password"])

        # 감사 로그 어디에도 비밀번호 원문이 남지 않는다.
        rows = await self._audit_rows(account["id"])
        self.assertIn("KIOSK_ACCOUNT_CREATED", [row.event_type for row in rows])
        created_row = next(row for row in rows if row.event_type == "KIOSK_ACCOUNT_CREATED")
        self.assertEqual(created_row.actor_type, "ADMIN")
        self.assertTrue(created_row.payload["business_created"])
        for row in rows:
            self.assertNotIn(temp_password, str(row.payload))
            self.assertNotIn(NEW_PASSWORD, str(row.payload))

    async def test_same_business_number_reuses_business_and_duplicate_login_id_conflicts(self):
        first = await self._create(self._body("a"))
        self.assertEqual(first.status_code, 201, first.text)
        second = await self._create(self._body("b"))
        self.assertEqual(second.status_code, 201, second.text)
        self.assertEqual(
            first.json()["account"]["business"]["business_id"],
            second.json()["account"]["business"]["business_id"],
        )
        rows = await self._audit_rows(second.json()["account"]["id"])
        self.assertFalse(rows[0].payload["business_created"])

        self._assert_error(await self._create(self._body("a")), 409, "USER_ALREADY_EXISTS")

    async def test_inactive_business_is_refused(self):
        async with self.session_factory() as db:
            db.add(Business(business_number=f"closed-{self.token}", business_name="해지 사업자", status="TERMINATED"))
            await db.commit()
        refused = await self._create(self._body(business_number=f"closed-{self.token}"))
        self._assert_error(refused, 409, "BUSINESS_INACTIVE")
        async with self.session_factory() as db:
            leftover = await db.execute(select(User).where(User.login_id == f"kiosk-a-{self.token}"))
            self.assertIsNone(leftover.scalar_one_or_none())

    async def test_suspend_revokes_tokens_and_blocks_login_until_activated(self):
        created = (await self._create(self._body())).json()
        account_id = created["account"]["id"]
        login_id = created["account"]["login_id"]
        temp_password = created["temporary_password"]
        tokens = (await self._login(login_id, temp_password)).json()

        suspended = await self.client.post(
            f"/api/v1/admin/kiosk-accounts/{account_id}/suspend", headers=self.admin_headers
        )
        self.assertEqual(suspended.status_code, 200, suspended.text)
        self.assertEqual(suspended.json()["status"], "SUSPENDED")
        again = await self.client.post(
            f"/api/v1/admin/kiosk-accounts/{account_id}/suspend", headers=self.admin_headers
        )
        self.assertEqual(again.status_code, 200, again.text)

        me = await self.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
        self._assert_error(me, 401, "TOKEN_REVOKED")
        self._assert_error(await self._login(login_id, temp_password), 403, "ACCOUNT_INACTIVE")

        activated = await self.client.post(
            f"/api/v1/admin/kiosk-accounts/{account_id}/activate", headers=self.admin_headers
        )
        self.assertEqual(activated.status_code, 200, activated.text)
        self.assertEqual(activated.json()["status"], "ACTIVE")
        self.assertEqual((await self._login(login_id, temp_password)).status_code, 200)
        # 정지 전 토큰은 정지 해제 뒤에도 무효다.
        me = await self.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
        self._assert_error(me, 401, "TOKEN_REVOKED")

        events = [row.event_type for row in await self._audit_rows(account_id)]
        self.assertEqual(events.count("KIOSK_ACCOUNT_SUSPENDED"), 1)
        self.assertEqual(events.count("KIOSK_ACCOUNT_ACTIVATED"), 1)

    async def test_reset_password_issues_new_temp_password_and_revokes_old_sessions(self):
        created = (await self._create(self._body())).json()
        account_id = created["account"]["id"]
        login_id = created["account"]["login_id"]
        first_temp = created["temporary_password"]
        login = (await self._login(login_id, first_temp)).json()
        changed = await self.client.post(
            "/api/v1/auth/password",
            json={"current_password": first_temp, "new_password": NEW_PASSWORD},
            headers={"Authorization": f"Bearer {login['access_token']}"},
        )
        own_tokens = changed.json()

        reset = await self.client.post(
            f"/api/v1/admin/kiosk-accounts/{account_id}/reset-password", headers=self.admin_headers
        )
        self.assertEqual(reset.status_code, 200, reset.text)
        self.assertEqual(reset.headers["cache-control"], "no-store")
        new_temp = reset.json()["temporary_password"]
        self.assertNotEqual(new_temp, first_temp)
        self.assertTrue(reset.json()["account"]["must_change_password"])

        self._assert_error(await self._login(login_id, NEW_PASSWORD), 401, "INVALID_CREDENTIALS")
        refresh = await self.client.post("/api/v1/auth/refresh", json={"refresh_token": own_tokens["refresh_token"]})
        self._assert_error(refresh, 401, "TOKEN_REVOKED")

        relogin = await self._login(login_id, new_temp)
        self.assertEqual(relogin.status_code, 200, relogin.text)
        blocked = await self.client.get(
            "/api/v1/auth/devices", headers={"Authorization": f"Bearer {relogin.json()['access_token']}"}
        )
        self._assert_error(blocked, 403, "PASSWORD_CHANGE_REQUIRED")

        rows = await self._audit_rows(account_id)
        self.assertIn("KIOSK_ACCOUNT_PASSWORD_RESET", [row.event_type for row in rows])
        for row in rows:
            self.assertNotIn(new_temp, str(row.payload))

    async def test_list_detail_and_access_control(self):
        created = (await self._create(self._body())).json()
        account_id = created["account"]["id"]

        listed = await self.client.get("/api/v1/admin/kiosk-accounts", headers=self.admin_headers)
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertIn(account_id, [item["id"] for item in listed.json()])
        self.assertNotIn(created["temporary_password"], listed.text)

        suspended_only = await self.client.get(
            "/api/v1/admin/kiosk-accounts", params={"status": "SUSPENDED"}, headers=self.admin_headers
        )
        self.assertNotIn(account_id, [item["id"] for item in suspended_only.json()])

        # USER·ADMIN 계정은 이 API로 보거나 바꿀 수 없다.
        async with self.session_factory() as db:
            wallet_user = User(
                login_id=f"wallet-{self.token}",
                password_hash="not-used",
                name="E2E 사용자",
                phone_number=f"w-{self.token[:24]}",
                phone_verified_at=datetime.now(timezone.utc),
                platform_role="USER",
                status="ACTIVE",
            )
            db.add(wallet_user)
            await db.commit()
        for method, path in (
            ("GET", f"/api/v1/admin/kiosk-accounts/{wallet_user.id}"),
            ("POST", f"/api/v1/admin/kiosk-accounts/{wallet_user.id}/suspend"),
            ("POST", f"/api/v1/admin/kiosk-accounts/{wallet_user.id}/reset-password"),
        ):
            response = await self.client.request(method, path, headers=self.admin_headers)
            self._assert_error(response, 404, "KIOSK_ACCOUNT_NOT_FOUND")

        # ADMIN이 아니면 403, 토큰이 없으면 401.
        user_headers = {"Authorization": f"Bearer {create_access_token(wallet_user.id, 'USER')}"}
        self._assert_error(
            await self.client.get("/api/v1/admin/kiosk-accounts", headers=user_headers), 403, "PERMISSION_DENIED"
        )
        self._assert_error(await self.client.get("/api/v1/admin/kiosk-accounts"), 401, "TOKEN_MISSING")


if __name__ == "__main__":
    unittest.main()
