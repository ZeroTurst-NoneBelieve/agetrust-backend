"""Real PostgreSQL + ASGI + SOLAPI SDK HTTP integration, with no live SMS.

Enable with E2E_DATABASE_URL (postgresql+asyncpg). Each test creates and removes
its own UUID schema, including its audit chain, so existing rows are untouched.
The database account needs CREATE SCHEMA permission. Only the SDK factory's
base_url is redirected: serialization, HMAC, HTTP, and response parsing are real.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import threading
import unittest
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

E2E_DB_URL = os.environ.get("E2E_DATABASE_URL")

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

import httpx  # noqa: E402
from pydantic import SecretStr  # noqa: E402
from solapi import SolapiMessageService  # noqa: E402
from sqlalchemy import select, text  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.schema import CreateSchema, DropSchema  # noqa: E402

from app.api.v1.endpoints import auth  # noqa: E402
from app.config import settings  # noqa: E402
from app.core.otp_rate_limit import OtpSmsRateLimiter  # noqa: E402
from app.core.security import verify_otp  # noqa: E402
from app.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import AuditLog, OutboxEvent, PhoneVerificationRequest, User  # noqa: E402

_DUMMY_KEY = "loopback-test-key"
_DUMMY_SECRET = "loopback-test-secret"
_SENDER = "01011112222"


def _accepted_response():
    """Required JSON fields in the pinned SOLAPI 5.0.3 response models."""
    cash = {"requested": 0, "replacement": 0, "refund": 0, "sum": 0}
    return {
        "groupInfo": {
            "count": {
                "total": 1, "sentTotal": 0, "sentSuccess": 0, "sentPending": 0,
                "sentReplacement": 0, "refund": 0, "registeredFailed": 0, "registeredSuccess": 1,
            },
            "countForCharge": {}, "balance": cash, "point": cash, "app": {},
            "log": [], "status": "SENDING", "allowDuplicates": False, "isRefunded": False,
            "accountId": "loopback-account", "masterAccountId": None, "apiVersion": "4",
            "groupId": "GLOOPBACK", "price": {}, "dateCreated": None, "dateUpdated": None,
        },
        "failedMessageList": [],
        "messageList": [{"messageId": "MLOOPBACK", "statusCode": "2000", "statusMessage": "Accepted"}],
    }


def _valid_authorization(header):
    match = re.fullmatch(
        r"HMAC-SHA256 ApiKey=([^,]+), Date=([^,]+), salt=([^,]+), signature=([0-9a-f]{64})",
        header,
    )
    if match is None:
        return False
    key, date, salt, signature = match.groups()
    expected = hmac.new(_DUMMY_SECRET.encode(), (date + salt).encode(), hashlib.sha256).hexdigest()
    try:
        age = abs((datetime.now(timezone.utc) - datetime.fromisoformat(date)).total_seconds())
    except (ValueError, TypeError):
        return False
    return key == _DUMMY_KEY and age < 60 and hmac.compare_digest(signature, expected)


class _LoopbackSolapi:
    """Keep OTPs in test memory only; never log requests or authentication."""

    def __init__(self):
        self.requests = []
        self.reject = False
        provider = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):  # noqa: N802
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                authorized = _valid_authorization(self.headers.get("Authorization", ""))
                provider.requests.append({"path": self.path, "authorized": authorized, "payload": payload})
                status_code = 200
                body = _accepted_response()
                if not authorized or provider.reject:
                    status_code = 403
                    body = {"errorCode": "InvalidSenderId", "errorMessage": "provider-detail-must-stay-internal"}
                encoded = json.dumps(body).encode()
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    async def close(self):
        await asyncio.to_thread(self.server.shutdown)
        self.server.server_close()
        self.thread.join(timeout=2)
        self.requests.clear()

    def service_factory(self, *, api_key, api_secret):
        service = SolapiMessageService(api_key=api_key, api_secret=api_secret)
        service.base_url = self.base_url
        return service


@unittest.skipUnless(E2E_DB_URL, "Real PostgreSQL integration requires E2E_DATABASE_URL")
class SmsHttpE2ETests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.run_id = uuid.uuid4()
        self.schema = f"sms_http_{self.run_id.hex}"
        self.phone = f"+8210{self.run_id.int % 10**8:08d}"
        self.engine = create_async_engine(
            E2E_DB_URL,
            echo=False,
            connect_args={"server_settings": {
                "search_path": self.schema,
                "application_name": self.schema,
            }},
        )
        self.addAsyncCleanup(self.engine.dispose)
        self.addAsyncCleanup(self._drop_owned_schema)
        async with self.engine.begin() as connection:
            await connection.execute(CreateSchema(self.schema))
            self.assertEqual(await connection.scalar(text("SELECT current_schema()")), self.schema)
            await connection.run_sync(Base.metadata.create_all)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

        async def override_get_db():
            async with self.session_factory() as session:
                yield session

        # patch.dict restores existing overrides, including preexisting get_db.
        overrides = patch.dict(app.dependency_overrides, {get_db: override_get_db})
        overrides.start()
        self.addCleanup(overrides.stop)
        configuration = patch.multiple(
            settings, dev_mode=False, solapi_api_key=SecretStr(_DUMMY_KEY),
            solapi_api_secret=SecretStr(_DUMMY_SECRET), solapi_sender="010-1111-2222",
            otp_resend_cooldown_seconds=120, otp_max_resends=5, otp_expire_minutes=3,
        )
        configuration.start()
        self.addCleanup(configuration.stop)
        # A fresh real limiter isolates process state; limits make release observable.
        limiter = patch.object(auth, "otp_sms_rate_limiter", OtpSmsRateLimiter(
            per_client_limit=1, per_client_window_seconds=300,
            per_recipient_limit=1, per_recipient_window_seconds=300,
            global_limit=1, global_window_seconds=300,
        ))
        limiter.start()
        self.addCleanup(limiter.stop)

        self.provider = _LoopbackSolapi()
        self.addAsyncCleanup(self.provider.close)
        factory = patch("app.core.sms.SolapiMessageService", new=self.provider.service_factory)
        factory.start()
        self.addCleanup(factory.stop)
        self.client = self._client("198.51.100.1")
        self.addAsyncCleanup(self.client.aclose)

    def _client(self, client_ip):
        # ASGITransport does not run lifespan, so no background publisher starts.
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=(client_ip, 12345)),
            base_url="http://sms-e2e",
        )

    async def _drop_owned_schema(self):
        async with self.engine.begin() as connection:
            await connection.execute(DropSchema(self.schema, cascade=True, if_exists=True))

    async def _challenges(self):
        async with self.session_factory() as db:
            return list((await db.scalars(
                select(PhoneVerificationRequest).where(PhoneVerificationRequest.phone_number == self.phone)
                .order_by(PhoneVerificationRequest.created_at)
            )).all())

    async def _wait_for_two_blocked_requests(self):
        # Each request must reach the real PostgreSQL advisory lock before the
        # blocker is released. This prevents scheduler timing from making the
        # concurrency regression test pass through a sequential execution.
        while True:
            async with self.session_factory() as db:
                blocked = await db.scalar(text(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE application_name = :name AND wait_event_type = 'Lock'"
                ), {"name": self.schema})
            if blocked >= 2:
                return
            await asyncio.sleep(0.02)

    def _captured_otp(self, index=0):
        captured = self.provider.requests[index]
        self.assertEqual(captured["path"], "/messages/v4/send-many/detail")
        self.assertTrue(captured["authorized"], "The SDK must send a valid HMAC using dummy credentials")
        payload = captured["payload"]
        self.assertIs(payload["showMessageList"], True)
        self.assertEqual(len(payload["messages"]), 1)
        message = payload["messages"][0]
        self.assertEqual(message["to"], "0" + self.phone[3:])
        self.assertEqual(message["from"], _SENDER)
        self.assertEqual(message["type"], "SMS")
        self.assertIs(message["autoTypeDetect"], False)
        self.assertEqual(message["country"], "82")
        match = re.search(r"(?<!\d)\d{6}(?!\d)", message["text"])
        self.assertTrue(match is not None, "The provider must receive one six-digit OTP")
        return match.group()

    def _assert_request_response(self, response):
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(set(body), {"verification_id", "expires_at", "dev_otp"})
        self.assertIsNone(body["dev_otp"], "DEV_MODE=false must hide the OTP")
        return uuid.UUID(body["verification_id"])

    async def test_concurrent_first_requests_send_only_one_sms(self):
        async with self.session_factory() as blocker:
            await blocker.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:phone_number, 0))"),
                {"phone_number": self.phone},
            )
            tasks = [
                asyncio.create_task(self.client.post(
                    "/api/v1/auth/phone/request",
                    json={"phone_number": self.phone},
                ))
                for _ in range(2)
            ]
            try:
                await asyncio.wait_for(self._wait_for_two_blocked_requests(), timeout=5)
                await blocker.rollback()
                responses = await asyncio.wait_for(asyncio.gather(*tasks), timeout=10)
            finally:
                await blocker.rollback()
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

        self.assertEqual(sorted(response.status_code for response in responses), [200, 429])
        accepted = next(response for response in responses if response.status_code == 200)
        rejected = next(response for response in responses if response.status_code == 429)
        self._assert_request_response(accepted)
        self.assertEqual(rejected.json(), {"detail": {"code": "OTP_RESEND_TOO_SOON"}})
        self.assertGreater(int(rejected.headers["Retry-After"]), 0)
        self.assertEqual(len(self.provider.requests), 1, "Concurrent requests must dispatch one SMS")
        self._captured_otp()
        self.assertEqual(len(await self._challenges()), 1)

    async def test_live_mode_http_sms_through_signup_login_and_me(self):
        response = await self.client.post("/api/v1/auth/phone/request", json={"phone_number": self.phone})
        verification_id = self._assert_request_response(response)
        self.assertEqual(len(self.provider.requests), 1)
        otp = self._captured_otp()
        before, = await self._challenges()
        self.assertEqual(before.id, verification_id)
        self.assertEqual(before.phone_number, self.phone)
        self.assertTrue(verify_otp(otp, str(before.id), before.otp_digest), "Only the digest belongs in PostgreSQL")

        response = await self.client.post("/api/v1/auth/phone/request", json={"phone_number": self.phone})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.json(), {"detail": {"code": "OTP_RESEND_TOO_SOON"}})
        self.assertGreater(int(response.headers["Retry-After"]), 0)
        self.assertEqual(len(self.provider.requests), 1, "Cooldown must not dispatch another SMS")
        after, = await self._challenges()
        self.assertTrue(
            (after.id, after.otp_digest, after.last_sent_at, after.expires_at, after.resend_count)
            == (before.id, before.otp_digest, before.last_sent_at, before.expires_at, before.resend_count),
            "Cooldown must retain the original usable challenge",
        )

        response = await self.client.post(
            "/api/v1/auth/phone/verify", json={"verification_id": str(verification_id), "otp": otp},
        )
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.content, b"")
        login_id = f"sms-http-{self.run_id.hex}"
        password = f"Test-password-{self.run_id.hex}"
        response = await self.client.post("/api/v1/auth/signup", json={
            "verification_id": str(verification_id), "login_id": login_id,
            "password": password, "name": "SMS HTTP integration",
        })
        self.assertEqual(response.status_code, 200)
        user_id = response.json()["id"]
        self.assertEqual(response.json()["phone_number"], self.phone)
        response = await self.client.post("/api/v1/auth/login", json={"login_id": login_id, "password": password})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["token_type"], "bearer")
        response = await self.client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {response.json()['access_token']}"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["id"], user_id)
        self.assertEqual(response.json()["login_id"], login_id)
        self.assertEqual(response.json()["phone_number"], self.phone)
        self.assertEqual(set(response.json()), {"id", "login_id", "name", "phone_number", "platform_role"})
        async with self.session_factory() as db:
            challenge = await db.get(PhoneVerificationRequest, verification_id)
            self.assertIsNotNone(challenge.verified_at)
            self.assertIsNotNone(challenge.consumed_at)
            self.assertIsNotNone(await db.get(User, user_id))
            events = set((await db.scalars(select(AuditLog.event_type))).all())
            self.assertEqual(events, {"PHONE_VERIFICATION_SUCCEEDED", "USER_SIGNED_UP", "LOGIN_SUCCEEDED"})
            self.assertEqual(set((await db.scalars(select(OutboxEvent.event_type))).all()), events)

    async def test_provider_4xx_invalidates_otp_and_releases_dispatch_quota(self):
        self.provider.reject = True
        response = await self.client.post("/api/v1/auth/phone/request", json={"phone_number": self.phone})
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json(), {"detail": {"code": "SMS_DELIVERY_FAILED"}})
        self.assertEqual(len(self.provider.requests), 1)
        otp = self._captured_otp()
        failed, = await self._challenges()
        self.assertLess(failed.expires_at, datetime.now(timezone.utc))
        response = await self.client.post(
            "/api/v1/auth/phone/verify", json={"verification_id": str(failed.id), "otp": otp},
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": {"code": "OTP_EXPIRED"}})

        # A definitive provider rejection still counts against the originating client.
        self.provider.reject = False
        response = await self.client.post("/api/v1/auth/phone/request", json={"phone_number": self.phone})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.json(), {"detail": {"code": "OTP_REQUEST_RATE_LIMITED"}})
        self.assertGreater(int(response.headers["Retry-After"]), 0)
        self.assertEqual(len(self.provider.requests), 1)
        self.assertEqual(len(await self._challenges()), 1)

        # A different client can reuse the one-slot recipient and global quotas.
        async with self._client("198.51.100.2") as other_client:
            response = await other_client.post("/api/v1/auth/phone/request", json={"phone_number": self.phone})
        new_id = self._assert_request_response(response)
        self.assertNotEqual(new_id, failed.id)
        self.assertEqual(len(self.provider.requests), 2)
        self._captured_otp(1)
        self.assertEqual(len(await self._challenges()), 2)
