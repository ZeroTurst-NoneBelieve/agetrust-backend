"""전용 PostgreSQL에서 KIOSK 계정 로그인·임시 비밀번호·토큰 무효화를 실제 HTTP로 검증한다 (#66).

E2E_DATABASE_URL이 설정되어 있으면 실행한다. 모든 요청은 외부 트랜잭션의
SAVEPOINT에서 실행하고 테스트 끝에 롤백하므로 만든 계정·감사 로그가 남지 않는다.
"""

import base64
import os
import unittest
import uuid
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

E2E_DB_URL = os.environ.get("E2E_DATABASE_URL")

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from app.core.security import hash_password  # noqa: E402
from app.database import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import AuditLog, User  # noqa: E402

TEMP_PASSWORD = "temp-pass-1234"
NEW_PASSWORD = "new-pass-5678"
USER_PASSWORD = "user-pass-1234"


@unittest.skipUnless(E2E_DB_URL, "계정 세션 E2E에는 전용 E2E_DATABASE_URL이 필요하다")
class AccountSessionDatabaseTests(unittest.IsolatedAsyncioTestCase):
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

        async def override_db():
            async with self.session_factory() as session:
                yield session

        self.old_overrides = app.dependency_overrides.copy()
        app.dependency_overrides[get_db] = override_db
        self.addCleanup(self._restore_overrides)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://account-e2e")
        self.addAsyncCleanup(self.client.aclose)

    def _restore_overrides(self):
        app.dependency_overrides.clear()
        app.dependency_overrides.update(self.old_overrides)

    async def _create_kiosk_account(self, *, expires_in: timedelta = timedelta(hours=1)) -> User:
        """관리자가 막 만든 KIOSK 계정처럼 전화번호 없이 임시 비밀번호 상태로 둔다."""
        async with self.session_factory() as db:
            user = User(
                login_id=f"kiosk-acct-{self.token}",
                password_hash=hash_password(TEMP_PASSWORD),
                name="E2E 매장",
                platform_role="KIOSK",
                status="ACTIVE",
                must_change_password=True,
                temp_password_expires_at=datetime.now(timezone.utc) + expires_in,
            )
            db.add(user)
            await db.commit()
            return user

    async def _create_wallet_user(self) -> User:
        async with self.session_factory() as db:
            user = User(
                login_id=f"wallet-acct-{self.token}",
                password_hash=hash_password(USER_PASSWORD),
                name="E2E 사용자",
                phone_number=f"e2e-{self.token[:24]}",
                phone_verified_at=datetime.now(timezone.utc),
                platform_role="USER",
                status="ACTIVE",
            )
            db.add(user)
            await db.commit()
            return user

    async def _login(self, login_id: str, password: str) -> httpx.Response:
        return await self.client.post("/api/v1/auth/login", json={"login_id": login_id, "password": password})

    @staticmethod
    def _bearer(access_token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {access_token}"}

    def _assert_error(self, response: httpx.Response, status_code: int, code: str):
        self.assertEqual(response.status_code, status_code, response.text)
        self.assertEqual(response.json()["detail"]["code"], code)

    async def test_kiosk_account_must_change_temp_password_then_is_kept_out_of_wallet_api(self):
        kiosk = await self._create_kiosk_account()

        login = await self._login(kiosk.login_id, TEMP_PASSWORD)
        self.assertEqual(login.status_code, 200, login.text)
        temp_tokens = login.json()

        me = await self.client.get("/api/v1/auth/me", headers=self._bearer(temp_tokens["access_token"]))
        self.assertEqual(me.status_code, 200, me.text)
        self.assertEqual(me.json()["platform_role"], "KIOSK")
        self.assertIsNone(me.json()["phone_number"])
        self.assertTrue(me.json()["must_change_password"])

        # 비밀번호를 바꾸기 전에는 /me·/password 외의 API를 쓸 수 없다.
        blocked = await self.client.get("/api/v1/auth/devices", headers=self._bearer(temp_tokens["access_token"]))
        self._assert_error(blocked, 403, "PASSWORD_CHANGE_REQUIRED")

        wrong = await self.client.post(
            "/api/v1/auth/password",
            json={"current_password": "wrong-pass", "new_password": NEW_PASSWORD},
            headers=self._bearer(temp_tokens["access_token"]),
        )
        self._assert_error(wrong, 400, "INVALID_CREDENTIALS")
        reused = await self.client.post(
            "/api/v1/auth/password",
            json={"current_password": TEMP_PASSWORD, "new_password": TEMP_PASSWORD},
            headers=self._bearer(temp_tokens["access_token"]),
        )
        self._assert_error(reused, 400, "PASSWORD_REUSED")
        too_short = await self.client.post(
            "/api/v1/auth/password",
            json={"current_password": TEMP_PASSWORD, "new_password": "short"},
            headers=self._bearer(temp_tokens["access_token"]),
        )
        self.assertEqual(too_short.status_code, 422)

        changed = await self.client.post(
            "/api/v1/auth/password",
            json={"current_password": TEMP_PASSWORD, "new_password": NEW_PASSWORD},
            headers=self._bearer(temp_tokens["access_token"]),
        )
        self.assertEqual(changed.status_code, 200, changed.text)
        new_tokens = changed.json()

        # 바꾸기 전에 받은 토큰은 액세스·리프레시 모두 무효다.
        old_me = await self.client.get("/api/v1/auth/me", headers=self._bearer(temp_tokens["access_token"]))
        self._assert_error(old_me, 401, "TOKEN_REVOKED")
        old_refresh = await self.client.post(
            "/api/v1/auth/refresh", json={"refresh_token": temp_tokens["refresh_token"]}
        )
        self._assert_error(old_refresh, 401, "TOKEN_REVOKED")

        me = await self.client.get("/api/v1/auth/me", headers=self._bearer(new_tokens["access_token"]))
        self.assertEqual(me.status_code, 200, me.text)
        self.assertFalse(me.json()["must_change_password"])

        # KIOSK 계정은 지갑 API(기기 등록·조회 등)를 쓸 수 없다.
        devices = await self.client.get("/api/v1/auth/devices", headers=self._bearer(new_tokens["access_token"]))
        self._assert_error(devices, 403, "PERMISSION_DENIED")

        refreshed = await self.client.post(
            "/api/v1/auth/refresh", json={"refresh_token": new_tokens["refresh_token"]}
        )
        self.assertEqual(refreshed.status_code, 200, refreshed.text)

        self._assert_error(await self._login(kiosk.login_id, TEMP_PASSWORD), 401, "INVALID_CREDENTIALS")
        self.assertEqual((await self._login(kiosk.login_id, NEW_PASSWORD)).status_code, 200)

        async with self.session_factory() as db:
            stored = await db.get(User, kiosk.id)
            self.assertFalse(stored.must_change_password)
            self.assertIsNone(stored.temp_password_expires_at)
            self.assertEqual(stored.token_version, 1)
            audit = (
                await db.execute(
                    select(AuditLog).where(
                        AuditLog.event_type == "PASSWORD_CHANGED",
                        AuditLog.aggregate_id == str(kiosk.id),
                    )
                )
            ).scalar_one()
            self.assertEqual(audit.payload, {"was_temporary": True})

    async def test_expired_temp_password_blocks_login_and_refresh(self):
        kiosk = await self._create_kiosk_account()
        tokens = (await self._login(kiosk.login_id, TEMP_PASSWORD)).json()

        async with self.session_factory() as db:
            stored = await db.get(User, kiosk.id)
            stored.temp_password_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            await db.commit()

        # 틀린 비밀번호는 기존처럼 401 하나로 통일하고, 상태는 비밀번호가 맞을 때만 알려준다.
        self._assert_error(await self._login(kiosk.login_id, "wrong-pass"), 401, "INVALID_CREDENTIALS")
        self._assert_error(await self._login(kiosk.login_id, TEMP_PASSWORD), 403, "TEMP_PASSWORD_EXPIRED")
        refresh = await self.client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        self._assert_error(refresh, 401, "TEMP_PASSWORD_EXPIRED")

        async with self.session_factory() as db:
            audit = (
                await db.execute(
                    select(AuditLog).where(
                        AuditLog.event_type == "LOGIN_FAILED",
                        AuditLog.aggregate_id == str(kiosk.id),
                    )
                )
            ).scalar_one()
            self.assertEqual(audit.payload, {"reason": "TEMP_PASSWORD_EXPIRED"})

    async def test_suspended_account_cannot_log_in_and_version_bump_revokes_tokens(self):
        kiosk = await self._create_kiosk_account()
        tokens = (await self._login(kiosk.login_id, TEMP_PASSWORD)).json()

        # 정지 API(다음 단계)가 할 일을 그대로 흉내 낸다: 상태 변경 + token_version 증가.
        async with self.session_factory() as db:
            stored = await db.get(User, kiosk.id)
            stored.status = "SUSPENDED"
            stored.token_version += 1
            await db.commit()

        self._assert_error(await self._login(kiosk.login_id, TEMP_PASSWORD), 403, "ACCOUNT_INACTIVE")
        me = await self.client.get("/api/v1/auth/me", headers=self._bearer(tokens["access_token"]))
        self._assert_error(me, 401, "TOKEN_REVOKED")
        refresh = await self.client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        self._assert_error(refresh, 401, "TOKEN_REVOKED")

    async def test_suspended_account_refresh_is_refused_even_without_version_bump(self):
        kiosk = await self._create_kiosk_account()
        tokens = (await self._login(kiosk.login_id, TEMP_PASSWORD)).json()

        async with self.session_factory() as db:
            stored = await db.get(User, kiosk.id)
            stored.status = "SUSPENDED"
            await db.commit()

        refresh = await self.client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        self._assert_error(refresh, 401, "ACCOUNT_INACTIVE")
        changed = await self.client.post(
            "/api/v1/auth/password",
            json={"current_password": TEMP_PASSWORD, "new_password": NEW_PASSWORD},
            headers=self._bearer(tokens["access_token"]),
        )
        self._assert_error(changed, 403, "ACCOUNT_INACTIVE")

    async def test_wallet_user_flow_is_unchanged(self):
        user = await self._create_wallet_user()
        login = await self._login(user.login_id, USER_PASSWORD)
        self.assertEqual(login.status_code, 200, login.text)
        access = login.json()["access_token"]

        me = await self.client.get("/api/v1/auth/me", headers=self._bearer(access))
        self.assertEqual(me.status_code, 200, me.text)
        self.assertEqual(me.json()["platform_role"], "USER")
        self.assertFalse(me.json()["must_change_password"])

        devices = await self.client.get("/api/v1/auth/devices", headers=self._bearer(access))
        self.assertEqual(devices.status_code, 200, devices.text)
        self.assertEqual(devices.json(), [])


if __name__ == "__main__":
    unittest.main()
