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

from app.api.v1.endpoints.auth import password_attempt_limiter  # noqa: E402
from app.config import settings  # noqa: E402
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
        # 비밀번호 시도 제한은 프로세스 메모리에 남으므로 테스트마다 비운다 (#68).
        await password_attempt_limiter.reset()
        self.addAsyncCleanup(password_attempt_limiter.reset)

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
        self._assert_error(refresh, 403, "TEMP_PASSWORD_EXPIRED")

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

    async def test_temp_password_expired_after_login_cannot_be_changed(self):
        kiosk = await self._create_kiosk_account()
        login = await self._login(kiosk.login_id, TEMP_PASSWORD)
        self.assertEqual(login.status_code, 200, login.text)
        tokens = login.json()

        async with self.session_factory() as db:
            stored = await db.get(User, kiosk.id)
            original_hash = stored.password_hash
            original_version = stored.token_version
            stored.temp_password_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            await db.commit()

        # 액세스 토큰은 아직 유효하지만 임시 비밀번호 변경 기한은 지났다.
        me = await self.client.get("/api/v1/auth/me", headers=self._bearer(tokens["access_token"]))
        self.assertEqual(me.status_code, 200, me.text)
        changed = await self.client.post(
            "/api/v1/auth/password",
            json={"current_password": TEMP_PASSWORD, "new_password": NEW_PASSWORD},
            headers=self._bearer(tokens["access_token"]),
        )
        self._assert_error(changed, 403, "TEMP_PASSWORD_EXPIRED")
        # 만료 뒤에는 현재 비밀번호가 틀려도 같은 403이라, 이 API로 비밀번호를 확인해 볼 수 없다.
        wrong = await self.client.post(
            "/api/v1/auth/password",
            json={"current_password": "wrong-pass", "new_password": NEW_PASSWORD},
            headers=self._bearer(tokens["access_token"]),
        )
        self._assert_error(wrong, 403, "TEMP_PASSWORD_EXPIRED")
        async with self.session_factory() as db:
            stored = await db.get(User, kiosk.id)
            self.assertEqual(stored.password_hash, original_hash)
            self.assertEqual(stored.token_version, original_version)
            self.assertTrue(stored.must_change_password)
            self.assertIsNotNone(stored.temp_password_expires_at)
            audit = await db.execute(
                select(AuditLog).where(
                    AuditLog.event_type == "PASSWORD_CHANGED",
                    AuditLog.aggregate_id == str(kiosk.id),
                )
            )
            self.assertIsNone(audit.scalar_one_or_none())

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
        self._assert_error(refresh, 403, "ACCOUNT_INACTIVE")
        changed = await self.client.post(
            "/api/v1/auth/password",
            json={"current_password": TEMP_PASSWORD, "new_password": NEW_PASSWORD},
            headers=self._bearer(tokens["access_token"]),
        )
        self._assert_error(changed, 403, "ACCOUNT_INACTIVE")
        me = await self.client.get("/api/v1/auth/me", headers=self._bearer(tokens["access_token"]))
        self._assert_error(me, 403, "ACCOUNT_INACTIVE")

    async def test_suspended_wallet_user_access_token_is_refused_without_version_bump(self):
        """token_version을 올리지 않고 정지돼도 남은 액세스 토큰으로 지갑 API를 쓸 수 없다."""
        user = await self._create_wallet_user()
        access = (await self._login(user.login_id, USER_PASSWORD)).json()["access_token"]

        async with self.session_factory() as db:
            stored = await db.get(User, user.id)
            stored.status = "SUSPENDED"
            await db.commit()

        devices = await self.client.get("/api/v1/auth/devices", headers=self._bearer(access))
        self._assert_error(devices, 403, "ACCOUNT_INACTIVE")

    async def test_wrong_current_password_on_change_is_audited(self):
        user = await self._create_wallet_user()
        access = (await self._login(user.login_id, USER_PASSWORD)).json()["access_token"]

        wrong = await self.client.post(
            "/api/v1/auth/password",
            json={"current_password": "wrong-pass", "new_password": NEW_PASSWORD},
            headers=self._bearer(access),
        )
        self._assert_error(wrong, 400, "INVALID_CREDENTIALS")

        async with self.session_factory() as db:
            audit = (
                await db.execute(
                    select(AuditLog).where(
                        AuditLog.event_type == "PASSWORD_CHANGE_FAILED",
                        AuditLog.aggregate_id == str(user.id),
                    )
                )
            ).scalar_one()
            self.assertEqual(audit.actor_type, "USER")
            self.assertEqual(audit.payload, {"reason": "INVALID_CREDENTIALS"})
            self.assertNotIn("wrong-pass", str(audit.payload))

    async def test_blocked_admin_login_is_audited_as_admin(self):
        async with self.session_factory() as db:
            admin = User(
                login_id=f"blocked-admin-{self.token}",
                password_hash=hash_password(USER_PASSWORD),
                name="E2E 정지 관리자",
                phone_number=f"adm-{self.token[:24]}",
                phone_verified_at=datetime.now(timezone.utc),
                platform_role="ADMIN",
                status="SUSPENDED",
            )
            db.add(admin)
            await db.commit()

        self._assert_error(await self._login(admin.login_id, USER_PASSWORD), 403, "ACCOUNT_INACTIVE")
        async with self.session_factory() as db:
            audit = (
                await db.execute(
                    select(AuditLog).where(
                        AuditLog.event_type == "LOGIN_FAILED",
                        AuditLog.aggregate_id == str(admin.id),
                    )
                )
            ).scalar_one()
            self.assertEqual(audit.actor_type, "ADMIN")

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

    async def test_logout_revokes_every_token_of_the_account(self):
        """로그아웃 전에 빼돌린 토큰도, 다른 기기의 토큰도 더는 쓸 수 없다 (#73)."""
        user = await self._create_wallet_user()
        this_device = (await self._login(user.login_id, USER_PASSWORD)).json()
        other_device = (await self._login(user.login_id, USER_PASSWORD)).json()

        logout = await self.client.post("/api/v1/auth/logout", headers=self._bearer(this_device["access_token"]))
        self.assertEqual(logout.status_code, 204, logout.text)

        for tokens in (this_device, other_device):
            me = await self.client.get("/api/v1/auth/me", headers=self._bearer(tokens["access_token"]))
            self._assert_error(me, 401, "TOKEN_REVOKED")
            refresh = await self.client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
            self._assert_error(refresh, 401, "TOKEN_REVOKED")

        async with self.session_factory() as db:
            audit = (
                await db.execute(
                    select(AuditLog).where(AuditLog.event_type == "LOGOUT", AuditLog.aggregate_id == str(user.id))
                )
            ).scalar_one()
            self.assertEqual(audit.actor_type, "USER")

        # 다시 로그인하면 새 토큰은 정상이다.
        relogin = await self._login(user.login_id, USER_PASSWORD)
        self.assertEqual(relogin.status_code, 200, relogin.text)
        me = await self.client.get("/api/v1/auth/me", headers=self._bearer(relogin.json()["access_token"]))
        self.assertEqual(me.status_code, 200, me.text)

    async def test_logout_requires_a_live_access_token(self):
        user = await self._create_wallet_user()
        tokens = (await self._login(user.login_id, USER_PASSWORD)).json()

        self._assert_error(await self.client.post("/api/v1/auth/logout"), 401, "TOKEN_MISSING")
        # 리프레시 토큰으로는 로그아웃할 수 없다.
        by_refresh = await self.client.post("/api/v1/auth/logout", headers=self._bearer(tokens["refresh_token"]))
        self._assert_error(by_refresh, 401, "TOKEN_WRONG_TYPE")

        first = await self.client.post("/api/v1/auth/logout", headers=self._bearer(tokens["access_token"]))
        self.assertEqual(first.status_code, 204, first.text)
        again = await self.client.post("/api/v1/auth/logout", headers=self._bearer(tokens["access_token"]))
        self._assert_error(again, 401, "TOKEN_REVOKED")

    async def test_kiosk_account_can_log_out_before_changing_temp_password(self):
        kiosk = await self._create_kiosk_account()
        tokens = (await self._login(kiosk.login_id, TEMP_PASSWORD)).json()

        logout = await self.client.post("/api/v1/auth/logout", headers=self._bearer(tokens["access_token"]))
        self.assertEqual(logout.status_code, 204, logout.text)
        refresh = await self.client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        self._assert_error(refresh, 401, "TOKEN_REVOKED")

        async with self.session_factory() as db:
            audit = (
                await db.execute(
                    select(AuditLog).where(AuditLog.event_type == "LOGOUT", AuditLog.aggregate_id == str(kiosk.id))
                )
            ).scalar_one()
            self.assertEqual(audit.actor_type, "USER")

    async def _locked_audit_rows(self, login_id: str) -> list[AuditLog]:
        async with self.session_factory() as db:
            result = await db.execute(
                select(AuditLog).where(
                    AuditLog.event_type == "PASSWORD_ATTEMPTS_LOCKED",
                    AuditLog.actor_ref == login_id,
                )
            )
            return list(result.scalars().all())

    async def test_repeated_wrong_logins_lock_the_account_even_for_the_right_password(self):
        user = await self._create_wallet_user()
        limit = settings.password_failure_limit
        for _ in range(limit):
            self._assert_error(await self._login(user.login_id, "wrong-pass"), 401, "INVALID_CREDENTIALS")

        # 한도에 걸리면 맞는 비밀번호도 검사하지 않고 막는다.
        locked = await self._login(user.login_id, USER_PASSWORD)
        self._assert_error(locked, 429, "TOO_MANY_PASSWORD_ATTEMPTS")
        self.assertGreater(int(locked.headers["retry-after"]), 0)
        self._assert_error(await self._login(user.login_id, "wrong-pass"), 429, "TOO_MANY_PASSWORD_ATTEMPTS")

        # 막히기 시작할 때 한 번만 남기고, 계정 존재 여부는 남기지 않는다.
        rows = await self._locked_audit_rows(user.login_id)
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0].aggregate_id)
        self.assertEqual(rows[0].payload["endpoint"], "login")

        # 다른 계정은 영향이 없다.
        other = await self._create_kiosk_account()
        self.assertEqual((await self._login(other.login_id, TEMP_PASSWORD)).status_code, 200)

    async def test_unknown_login_id_is_limited_the_same_way(self):
        ghost = f"ghost-{self.token}"
        for _ in range(settings.password_failure_limit):
            self._assert_error(await self._login(ghost, "wrong-pass"), 401, "INVALID_CREDENTIALS")
        self._assert_error(await self._login(ghost, "wrong-pass"), 429, "TOO_MANY_PASSWORD_ATTEMPTS")

    async def test_successful_login_clears_earlier_failures(self):
        user = await self._create_wallet_user()
        for _ in range(settings.password_failure_limit - 1):
            await self._login(user.login_id, "wrong-pass")
        self.assertEqual((await self._login(user.login_id, USER_PASSWORD)).status_code, 200)

        # 성공으로 기록이 지워져 다시 한도만큼 틀릴 수 있다.
        for _ in range(settings.password_failure_limit - 1):
            self._assert_error(await self._login(user.login_id, "wrong-pass"), 401, "INVALID_CREDENTIALS")
        self.assertEqual((await self._login(user.login_id, USER_PASSWORD)).status_code, 200)

    async def test_password_change_failures_share_the_login_limit(self):
        """탈취한 토큰으로 /auth/password에서 대입해도 로그인과 같은 한도에 걸린다."""
        user = await self._create_wallet_user()
        access = (await self._login(user.login_id, USER_PASSWORD)).json()["access_token"]

        for _ in range(settings.password_failure_limit):
            wrong = await self.client.post(
                "/api/v1/auth/password",
                json={"current_password": "wrong-pass", "new_password": NEW_PASSWORD},
                headers=self._bearer(access),
            )
            self._assert_error(wrong, 400, "INVALID_CREDENTIALS")

        right = await self.client.post(
            "/api/v1/auth/password",
            json={"current_password": USER_PASSWORD, "new_password": NEW_PASSWORD},
            headers=self._bearer(access),
        )
        self._assert_error(right, 429, "TOO_MANY_PASSWORD_ATTEMPTS")
        self._assert_error(await self._login(user.login_id, USER_PASSWORD), 429, "TOO_MANY_PASSWORD_ATTEMPTS")

        async with self.session_factory() as db:
            stored = await db.get(User, user.id)
            self.assertEqual(stored.token_version, 0)  # 비밀번호는 바뀌지 않았다.
        rows = await self._locked_audit_rows(user.login_id)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].aggregate_id, str(user.id))
        self.assertEqual(rows[0].payload["endpoint"], "password")


if __name__ == "__main__":
    unittest.main()
