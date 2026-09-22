"""OTP request isolation and single-use signup against a dedicated PostgreSQL DB.

Enable only with E2E_DATABASE_URL. Each test owns a UUID schema; all credentials
and phone data are synthetic. DEV_MODE is forced on and the SMS sender is blocked.
"""

import asyncio
import base64
import os
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

E2E_DB_URL = os.environ.get("E2E_DATABASE_URL")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

import httpx  # noqa: E402
from sqlalchemy import func, select, text  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.schema import CreateSchema, DropSchema  # noqa: E402

from app.config import settings  # noqa: E402
from app.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import PhoneVerificationRequest, User  # noqa: E402


@unittest.skipUnless(E2E_DB_URL, "OTP isolation integration requires E2E_DATABASE_URL")
class OtpIsolationE2ETests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.schema = f"otp_isolation_{uuid.uuid4().hex}"
        self.phone = "+821000000000"
        self.engine = create_async_engine(
            E2E_DB_URL,
            echo=False,
            connect_args={"server_settings": {
                "search_path": self.schema,
                "application_name": self.schema,
                "statement_timeout": "10000",
                "lock_timeout": "7000",
            }},
        )
        self.addAsyncCleanup(self.engine.dispose)
        self.addAsyncCleanup(self._drop_schema)
        async with self.engine.begin() as connection:
            await connection.execute(CreateSchema(self.schema))
            self.assertEqual(await connection.scalar(text("SELECT current_schema()")), self.schema)
            await connection.run_sync(Base.metadata.create_all)
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)

        async def override_get_db():
            async with self.sessions() as db:
                yield db

        overrides = patch.dict(app.dependency_overrides, {get_db: override_get_db})
        overrides.start()
        self.addCleanup(overrides.stop)
        configuration = patch.multiple(
            settings, dev_mode=True, solapi_api_key=None, solapi_api_secret=None,
            solapi_sender=None, otp_resend_cooldown_seconds=120,
            otp_max_attempts=2, otp_max_resends=2, otp_expire_minutes=5,
        )
        configuration.start()
        self.addCleanup(configuration.stop)
        sender = patch("app.api.v1.endpoints.auth.send_otp_sms", new_callable=AsyncMock)
        no_sms = sender.start()
        no_sms.side_effect = AssertionError("Isolation tests must never send SMS")
        self.addCleanup(sender.stop)
        self.addCleanup(no_sms.assert_not_awaited)
        # ASGITransport does not start lifespan or the Kafka publisher.
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://otp-isolation-test",
        )
        self.addAsyncCleanup(self.client.aclose)

    async def _drop_schema(self):
        async with self.engine.begin() as connection:
            await connection.execute(DropSchema(self.schema, cascade=True, if_exists=True))

    async def _request(self):
        response = await self.client.post("/api/v1/auth/phone/request", json={"phone_number": self.phone})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        uuid.UUID(body["verification_id"])
        self.assertRegex(body["dev_otp"], r"^\d{6}$")
        return body

    async def _row(self, request):
        async with self.sessions() as db:
            return await db.get(PhoneVerificationRequest, uuid.UUID(request["verification_id"]))

    async def _request_count(self):
        async with self.sessions() as db:
            return await db.scalar(select(func.count()).select_from(PhoneVerificationRequest))

    async def _allow_resend(self, request):
        # Advance only this synthetic request's cooldown, without real-time sleeps.
        async with self.sessions() as db:
            row = await db.get(PhoneVerificationRequest, uuid.UUID(request["verification_id"]))
            row.last_sent_at = datetime.now(timezone.utc) - timedelta(seconds=121)
            await db.commit()

    async def _verify(self, request, *, wrong=False):
        otp = request["dev_otp"]
        if wrong:
            otp = "000001" if otp == "000000" else "000000"
        return await self.client.post("/api/v1/auth/phone/verify", json={
            "verification_id": request["verification_id"], "otp": otp,
        })

    async def _signup(self, request, suffix):
        return await self.client.post("/api/v1/auth/signup", json={
            "verification_id": request["verification_id"],
            "login_id": f"isolation-{suffix}",
            "password": "Synthetic-test-password!",
            "name": "Isolation test",
        })

    def _assert_error(self, response, status_code, code):
        self.assertEqual(response.status_code, status_code)
        self.assertEqual(response.json(), {"detail": {"code": code}})

    async def test_malformed_otp_strings_count_as_mismatches(self):
        for otp in ("", "12345", "1234567", "12a456", "１２３４５６", "١٢٣٤٥٦"):
            with self.subTest(otp=otp):
                request = await self._request()
                response = await self.client.post("/api/v1/auth/phone/verify", json={
                    "verification_id": request["verification_id"], "otp": otp,
                })
                self._assert_error(response, 401, "OTP_MISMATCH")
                row = await self._row(request)
                self.assertEqual(row.attempt_count, 1)
                self.assertIsNone(row.verified_at)
                self.assertEqual((await self._verify(request)).status_code, 204)

    async def test_resend_rotates_id_expires_previous_and_carries_counts(self):
        first = await self._request()
        self._assert_error(await self._verify(first, wrong=True), 401, "OTP_MISMATCH")
        await self._allow_resend(first)
        second = await self._request()

        self.assertNotEqual(first["verification_id"], second["verification_id"])
        self.assertEqual(await self._request_count(), 2)
        old, new = await self._row(first), await self._row(second)
        self.assertLessEqual(old.expires_at, datetime.now(timezone.utc))
        self.assertIsNone(old.verified_at)
        self.assertEqual(new.attempt_count, 1)
        self.assertEqual(new.resend_count, 1)
        self._assert_error(await self._verify(first), 401, "OTP_EXPIRED")
        self.assertEqual((await self._verify(second)).status_code, 204)
        self.assertIsNone((await self._row(first)).verified_at)
        self.assertIsNotNone((await self._row(second)).verified_at)

    async def test_cooldown_and_failed_attempt_budget_survive_resend(self):
        first = await self._request()
        self._assert_error(await self._verify(first, wrong=True), 401, "OTP_MISMATCH")
        response = await self.client.post("/api/v1/auth/phone/request", json={"phone_number": self.phone})
        self._assert_error(response, 429, "OTP_RESEND_TOO_SOON")
        self.assertGreater(int(response.headers["Retry-After"]), 0)
        self.assertEqual(await self._request_count(), 1)
        self.assertEqual((await self._row(first)).attempt_count, 1)

        await self._allow_resend(first)
        second = await self._request()
        self._assert_error(await self._verify(second, wrong=True), 401, "OTP_MISMATCH")
        await self._allow_resend(second)
        response = await self.client.post("/api/v1/auth/phone/request", json={"phone_number": self.phone})
        self._assert_error(response, 429, "OTP_LOCKED_UNTIL_EXPIRY")
        self.assertGreater(int(response.headers["Retry-After"]), 0)
        self.assertEqual(await self._request_count(), 2)
        self.assertEqual((await self._row(second)).attempt_count, 2)
        self._assert_error(await self._verify(second), 401, "OTP_MAX_ATTEMPTS")

    async def test_resend_budget_is_not_reset_by_new_ids(self):
        current = await self._request()
        identifiers = {current["verification_id"]}
        for expected_resends in (1, 2):
            await self._allow_resend(current)
            current = await self._request()
            self.assertNotIn(current["verification_id"], identifiers)
            identifiers.add(current["verification_id"])
            self.assertEqual((await self._row(current)).resend_count, expected_resends)
        await self._allow_resend(current)
        response = await self.client.post("/api/v1/auth/phone/request", json={"phone_number": self.phone})
        self._assert_error(response, 429, "OTP_RESEND_LIMIT_REACHED")
        self.assertGreater(int(response.headers["Retry-After"]), 0)
        self.assertEqual(await self._request_count(), 3)

    async def test_new_request_does_not_inherit_completed_verification(self):
        completed = await self._request()
        self.assertEqual((await self._verify(completed)).status_code, 204)
        original_verified_at = (await self._row(completed)).verified_at
        new = await self._request()

        self.assertNotEqual(new["verification_id"], completed["verification_id"])
        self.assertIsNone((await self._row(new)).verified_at)
        self._assert_error(await self._signup(new, "unverified"), 400, "PHONE_NOT_VERIFIED")
        old = await self._row(completed)
        self.assertEqual(old.verified_at, original_verified_at)
        self.assertIsNone(old.consumed_at)
        async with self.sessions() as db:
            self.assertEqual(await db.scalar(select(func.count()).select_from(User)), 0)

    async def _wait_for_two_blocked_requests(self):
        # Observe only this test's DB sessions; each query gets a fresh stats snapshot.
        while True:
            async with self.sessions() as db:
                blocked = await db.scalar(text(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE application_name = :name AND wait_event_type = 'Lock'"
                ), {"name": self.schema})
            if blocked >= 2:
                return
            await asyncio.sleep(0.02)

    async def _competing_signups(self, blocker, submissions):
        tasks = [asyncio.create_task(self._signup(request, suffix)) for request, suffix in submissions]
        try:
            # Both real requests reach the held DB lock before either can finish.
            await asyncio.wait_for(self._wait_for_two_blocked_requests(), timeout=5)
            await blocker.rollback()
            return await asyncio.wait_for(asyncio.gather(*tasks), timeout=10)
        finally:
            await blocker.rollback()
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def test_concurrent_signups_consume_verification_exactly_once(self):
        verified = await self._request()
        self.assertEqual((await self._verify(verified)).status_code, 204)
        async with self.sessions() as blocker:
            await blocker.get(
                PhoneVerificationRequest, uuid.UUID(verified["verification_id"]), with_for_update=True,
            )
            responses = await self._competing_signups(blocker, [(verified, "one"), (verified, "two")])

        self.assertEqual(sorted(response.status_code for response in responses), [200, 400])
        rejected = next(response for response in responses if response.status_code == 400)
        self._assert_error(rejected, 400, "OTP_ALREADY_CONSUMED")
        self.assertIsNotNone((await self._row(verified)).consumed_at)
        async with self.sessions() as db:
            self.assertEqual(await db.scalar(select(func.count()).select_from(User)), 1)

    async def test_existing_phone_conflict_does_not_consume_new_verification(self):
        first = await self._request()
        self.assertEqual((await self._verify(first)).status_code, 204)
        self.assertEqual((await self._signup(first, "existing-phone")).status_code, 200)

        second = await self._request()
        self.assertNotEqual(first["verification_id"], second["verification_id"])
        self.assertEqual((await self._verify(second)).status_code, 204)
        response = await self._signup(second, "duplicate-phone")
        self._assert_error(response, 409, "PHONE_ALREADY_REGISTERED")
        retained = await self._row(second)
        self.assertIsNotNone(retained.verified_at)
        self.assertIsNone(retained.consumed_at)
        async with self.sessions() as db:
            self.assertEqual(await db.scalar(select(func.count()).select_from(User)), 1)

    async def test_concurrent_login_id_conflict_preserves_losing_verification(self):
        first = await self._request()
        self.assertEqual((await self._verify(first)).status_code, 204)
        self.phone = "+821000000001"
        second = await self._request()
        self.assertEqual((await self._verify(second)).status_code, 204)

        async with self.sessions() as blocker:
            # SELECT prechecks can both pass; INSERTs wait until this lock is released.
            # search_path confines the table lock to this test's UUID schema.
            await blocker.execute(text("LOCK TABLE users IN SHARE MODE"))
            responses = await self._competing_signups(blocker, [(first, "shared"), (second, "shared")])

        self.assertEqual(sorted(response.status_code for response in responses), [200, 409])
        for request, response in zip((first, second), responses):
            row = await self._row(request)
            self.assertIsNotNone(row.verified_at)
            if response.status_code == 409:
                self._assert_error(response, 409, "USER_ALREADY_EXISTS")
                self.assertIsNone(row.consumed_at)
            else:
                self.assertIsNotNone(row.consumed_at)
        async with self.sessions() as db:
            self.assertEqual(await db.scalar(select(func.count()).select_from(User)), 1)
