"""SOLAPI OTP 발송과 인증 요청 재전송 정책 테스트."""

import asyncio
import base64
import os
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from pydantic import SecretStr

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from app.api.v1.endpoints.auth import request_phone_otp  # noqa: E402
from app.config import settings  # noqa: E402
from app.core.otp_rate_limit import (  # noqa: E402
    OtpSmsReservationDenied,
    OtpSmsReservationGranted,
    OtpSmsReservationToken,
)
from app.core.security import verify_otp  # noqa: E402
from app.core.sms import (  # noqa: E402
    SmsConfigurationError,
    SmsDeliveryError,
    SmsReceipt,
    send_otp_sms,
)
from app.models import PhoneVerificationRequest  # noqa: E402
from app.schemas.errors import AuthError  # noqa: E402
from app.schemas.user import PhoneRequestBody  # noqa: E402
from tests.fakes import FakeDb  # noqa: E402


def fake_request(ip: str = "203.0.113.10"):
    return SimpleNamespace(client=SimpleNamespace(host=ip))


def granted_reservation() -> OtpSmsReservationGranted:
    return OtpSmsReservationGranted(OtpSmsReservationToken(uuid.uuid4()))


class SolapiSmsGatewayTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.previous = (
            settings.solapi_api_key,
            settings.solapi_api_secret,
            settings.solapi_sender,
        )
        settings.solapi_api_key = SecretStr("test-api-key")
        settings.solapi_api_secret = SecretStr("test-api-secret")
        settings.solapi_sender = "010-1111-2222"

    def tearDown(self):
        (
            settings.solapi_api_key,
            settings.solapi_api_secret,
            settings.solapi_sender,
        ) = self.previous

    @staticmethod
    def _accepted_response():
        return SimpleNamespace(
            group_info=SimpleNamespace(
                group_id="GTEST",
                count=SimpleNamespace(total=1, registered_success=1),
            ),
            message_list=[SimpleNamespace(message_id="MTEST")],
        )

    async def test_sends_korean_e164_number_as_domestic_sms(self):
        with patch("app.core.sms.SolapiMessageService") as service_type:
            service = service_type.return_value
            service.send.return_value = self._accepted_response()

            receipt = await send_otp_sms("+821012345678", "123456")

        service_type.assert_called_once_with(
            api_key="test-api-key",
            api_secret="test-api-secret",
        )
        message, request_config = service.send.call_args.args
        self.assertEqual(message.from_, "01011112222")
        self.assertEqual(message.to, "01012345678")
        self.assertEqual(message.type, "SMS")
        self.assertIs(message.model_dump(exclude_none=True, by_alias=True)["autoTypeDetect"], False)
        self.assertIn("123456", message.text)
        self.assertTrue(request_config.show_message_list)
        self.assertEqual(receipt, SmsReceipt(group_id="GTEST", message_id="MTEST"))

    async def test_provider_failure_exposes_only_provider_code(self):
        with patch("app.core.sms.SolapiMessageService") as service_type:
            service_type.return_value.send.side_effect = Exception(
                "InvalidApiKey",
                "provider detail must stay internal",
            )

            with self.assertRaises(SmsDeliveryError) as caught:
                await send_otp_sms("+821012345678", "123456")

        self.assertEqual(caught.exception.provider_code, "InvalidApiKey")
        self.assertFalse(caught.exception.may_have_been_sent)
        self.assertNotIn("provider detail", str(caught.exception))

    async def test_provider_server_error_keeps_unknown_delivery_outcome(self):
        with patch("app.core.sms.SolapiMessageService") as service_type:
            service_type.return_value.send.side_effect = Exception(
                "UnknownError",
                "provider detail must stay internal",
            )

            with self.assertRaises(SmsDeliveryError) as caught:
                await send_otp_sms("+821012345678", "123456")

        self.assertTrue(caught.exception.may_have_been_sent)

    async def test_missing_credentials_fail_before_network_call(self):
        settings.solapi_api_secret = SecretStr("   ")
        with patch("app.core.sms.SolapiMessageService") as service_type:
            with self.assertRaises(SmsConfigurationError):
                await send_otp_sms("+821012345678", "123456")
        service_type.assert_not_called()

    async def test_malformed_provider_response_is_a_delivery_error(self):
        with patch("solapi.services.message_service.default_fetcher", return_value={}):
            with self.assertRaises(SmsDeliveryError) as caught:
                await send_otp_sms("+821012345678", "123456")

        self.assertEqual(caught.exception.provider_code, "ValidationError")
        self.assertTrue(caught.exception.may_have_been_sent)

    async def test_unregistered_message_is_a_definitive_rejection(self):
        response = self._accepted_response()
        response.group_info.count.registered_success = 0
        with patch("app.core.sms.SolapiMessageService") as service_type:
            service_type.return_value.send.return_value = response

            with self.assertRaises(SmsDeliveryError) as caught:
                await send_otp_sms("+821012345678", "123456")

        self.assertEqual(caught.exception.provider_code, "NOT_REGISTERED")
        self.assertFalse(caught.exception.may_have_been_sent)


class PhoneOtpRequestTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.previous = (
            settings.dev_mode,
            settings.otp_resend_cooldown_seconds,
            settings.otp_max_resends,
            settings.solapi_api_key,
            settings.solapi_api_secret,
            settings.solapi_sender,
        )
        settings.otp_resend_cooldown_seconds = 30
        settings.otp_max_resends = 5
        settings.solapi_api_key = SecretStr("test-api-key")
        settings.solapi_api_secret = SecretStr("test-api-secret")
        settings.solapi_sender = "01011112222"

    def tearDown(self):
        (
            settings.dev_mode,
            settings.otp_resend_cooldown_seconds,
            settings.otp_max_resends,
            settings.solapi_api_key,
            settings.solapi_api_secret,
            settings.solapi_sender,
        ) = self.previous

    async def test_live_mode_commits_before_sending_and_hides_otp(self):
        settings.dev_mode = False
        db = FakeDb()
        receipt = SmsReceipt(group_id="GTEST", message_id="MTEST")
        reservation = granted_reservation()

        async def accepted_after_commit(*_args):
            self.assertEqual(db.commits, 1)
            return receipt

        with patch(
            "app.api.v1.endpoints.auth.send_otp_sms",
            new=AsyncMock(side_effect=accepted_after_commit),
        ) as send:
            with patch(
                "app.api.v1.endpoints.auth.otp_sms_rate_limiter.reserve",
                new=AsyncMock(return_value=reservation),
            ), patch(
                "app.api.v1.endpoints.auth.otp_sms_rate_limiter.confirm",
                new=AsyncMock(return_value=True),
            ) as confirm:
                response = await request_phone_otp(
                    PhoneRequestBody(phone_number="+821012345678"),
                    fake_request(),
                    db,
                )

        send.assert_awaited_once()
        sent_phone, sent_otp = send.await_args.args
        self.assertEqual(sent_phone, "+821012345678")
        self.assertRegex(sent_otp, r"^\d{6}$")
        row = next(item for item in db.added if isinstance(item, PhoneVerificationRequest))
        self.assertTrue(verify_otp(sent_otp, str(row.id), row.otp_digest))
        self.assertEqual(db.commits, 1)
        self.assertEqual(db.rollbacks, 0)
        self.assertIsNone(response.dev_otp)
        confirm.assert_awaited_once_with(reservation.token)

    async def test_delivery_failure_conditionally_expires_request_and_returns_502(self):
        settings.dev_mode = False
        db = FakeDb(rowcount=1)
        reservation = granted_reservation()

        with patch(
            "app.api.v1.endpoints.auth.send_otp_sms",
            new=AsyncMock(
                side_effect=SmsDeliveryError(
                    "NOT_REGISTERED",
                    may_have_been_sent=False,
                )
            ),
        ):
            with patch(
                "app.api.v1.endpoints.auth.otp_sms_rate_limiter.reserve",
                new=AsyncMock(return_value=reservation),
            ), patch(
                "app.api.v1.endpoints.auth.otp_sms_rate_limiter.release",
                new=AsyncMock(return_value=True),
            ) as release:
                with self.assertRaises(HTTPException) as caught:
                    await request_phone_otp(
                        PhoneRequestBody(phone_number="+821012345678"),
                        fake_request(),
                        db,
                    )

        self.assertEqual(caught.exception.status_code, 502)
        self.assertEqual(
            caught.exception.detail["code"],
            AuthError.SMS_DELIVERY_FAILED.value,
        )
        self.assertEqual(db.commits, 2)
        self.assertEqual(db.rollbacks, 0)
        self.assertEqual(len(db.statements_touching("phone_verification_requests")), 1)
        release.assert_awaited_once_with(
            reservation.token,
            retain_client_attempt=True,
        )

    async def test_unknown_delivery_outcome_keeps_request_and_quota(self):
        settings.dev_mode = False
        db = FakeDb()
        reservation = granted_reservation()

        with patch(
            "app.api.v1.endpoints.auth.send_otp_sms",
            new=AsyncMock(side_effect=SmsDeliveryError("ConnectTimeout")),
        ):
            with patch(
                "app.api.v1.endpoints.auth.otp_sms_rate_limiter.reserve",
                new=AsyncMock(return_value=reservation),
            ), patch(
                "app.api.v1.endpoints.auth.otp_sms_rate_limiter.release",
                new=AsyncMock(return_value=True),
            ) as release, patch(
                "app.api.v1.endpoints.auth.otp_sms_rate_limiter.confirm",
                new=AsyncMock(return_value=True),
            ) as confirm:
                with self.assertRaises(HTTPException) as caught:
                    await request_phone_otp(
                        PhoneRequestBody(phone_number="+821012345678"),
                        fake_request(),
                        db,
                    )

        self.assertEqual(caught.exception.status_code, 502)
        self.assertEqual(db.commits, 1)
        self.assertEqual(len(db.statements_touching("phone_verification_requests")), 0)
        release.assert_not_awaited()
        confirm.assert_not_awaited()

    async def test_commit_failure_never_calls_provider(self):
        settings.dev_mode = False
        db = FakeDb()
        db.commit = AsyncMock(side_effect=RuntimeError("database unavailable"))
        reservation = granted_reservation()

        with patch(
            "app.api.v1.endpoints.auth.send_otp_sms",
            new=AsyncMock(),
        ) as send:
            with patch(
                "app.api.v1.endpoints.auth.otp_sms_rate_limiter.reserve",
                new=AsyncMock(return_value=reservation),
            ), patch(
                "app.api.v1.endpoints.auth.otp_sms_rate_limiter.release",
                new=AsyncMock(return_value=True),
            ) as release:
                with self.assertRaisesRegex(RuntimeError, "database unavailable"):
                    await request_phone_otp(
                        PhoneRequestBody(phone_number="+821012345678"),
                        fake_request(),
                        db,
                    )

        send.assert_not_awaited()
        release.assert_awaited_once_with(
            reservation.token,
            retain_client_attempt=True,
        )

    async def test_flush_failure_releases_unsent_reservation(self):
        settings.dev_mode = False
        db = FakeDb()
        db.flush = AsyncMock(side_effect=RuntimeError("flush failed"))
        reservation = granted_reservation()

        with patch(
            "app.api.v1.endpoints.auth.send_otp_sms",
            new=AsyncMock(),
        ) as send:
            with patch(
                "app.api.v1.endpoints.auth.otp_sms_rate_limiter.reserve",
                new=AsyncMock(return_value=reservation),
            ), patch(
                "app.api.v1.endpoints.auth.otp_sms_rate_limiter.release",
                new=AsyncMock(return_value=True),
            ) as release:
                with self.assertRaisesRegex(RuntimeError, "flush failed"):
                    await request_phone_otp(
                        PhoneRequestBody(phone_number="+821012345678"),
                        fake_request(),
                        db,
                    )

        send.assert_not_awaited()
        release.assert_awaited_once_with(
            reservation.token,
            retain_client_attempt=True,
        )

    async def test_cancellation_leaves_precommitted_request_valid(self):
        settings.dev_mode = False
        db = FakeDb()
        reservation = granted_reservation()

        with patch(
            "app.api.v1.endpoints.auth.send_otp_sms",
            new=AsyncMock(side_effect=asyncio.CancelledError),
        ):
            with patch(
                "app.api.v1.endpoints.auth.otp_sms_rate_limiter.reserve",
                new=AsyncMock(return_value=reservation),
            ), patch(
                "app.api.v1.endpoints.auth.otp_sms_rate_limiter.release",
                new=AsyncMock(return_value=True),
            ) as release, patch(
                "app.api.v1.endpoints.auth.otp_sms_rate_limiter.confirm",
                new=AsyncMock(return_value=True),
            ) as confirm:
                with self.assertRaises(asyncio.CancelledError):
                    await request_phone_otp(
                        PhoneRequestBody(phone_number="+821012345678"),
                        fake_request(),
                        db,
                    )

        self.assertEqual(db.commits, 1)
        self.assertEqual(len(db.statements_touching("phone_verification_requests")), 0)
        release.assert_not_awaited()
        confirm.assert_not_awaited()

    async def test_dev_mode_skips_provider_and_returns_otp(self):
        settings.dev_mode = True
        db = FakeDb()

        with patch(
            "app.api.v1.endpoints.auth.send_otp_sms",
            new=AsyncMock(),
        ) as send:
            response = await request_phone_otp(
                PhoneRequestBody(phone_number="+821012345678"),
                fake_request(),
                db,
            )

        send.assert_not_awaited()
        self.assertRegex(response.dev_otp, r"^\d{6}$")
        self.assertEqual(db.commits, 1)

    async def test_resend_replaces_request_and_keeps_attempt_count(self):
        settings.dev_mode = True
        now = datetime.now(timezone.utc)
        row = SimpleNamespace(
            id=uuid.uuid4(),
            phone_number="+821012345678",
            otp_digest="old-digest",
            purpose="SIGN_UP",
            attempt_count=3,
            resend_count=1,
            created_at=now - timedelta(minutes=1),
            last_sent_at=now - timedelta(seconds=31),
            expires_at=now + timedelta(minutes=4),
            verified_at=None,
            consumed_at=None,
        )
        db = FakeDb(scalar_results={PhoneVerificationRequest: row})

        response = await request_phone_otp(
            PhoneRequestBody(phone_number=row.phone_number),
            fake_request(),
            db,
        )

        replacement = next(
            item for item in db.added if isinstance(item, PhoneVerificationRequest)
        )
        self.assertNotEqual(response.verification_id, str(row.id))
        self.assertEqual(response.verification_id, str(replacement.id))
        self.assertEqual(replacement.resend_count, 2)
        self.assertEqual(replacement.attempt_count, 3)
        self.assertTrue(
            verify_otp(response.dev_otp, str(replacement.id), replacement.otp_digest)
        )
        self.assertGreater(replacement.expires_at, now + timedelta(minutes=4))
        self.assertEqual(row.resend_count, 1)
        self.assertEqual(row.attempt_count, 3)
        self.assertEqual(row.otp_digest, "old-digest")
        self.assertLessEqual(row.expires_at, datetime.now(timezone.utc))
        self.assertEqual(db.commits, 1)

    async def test_resend_during_cooldown_returns_retry_after(self):
        settings.dev_mode = True
        now = datetime.now(timezone.utc)
        row = SimpleNamespace(
            id=uuid.uuid4(),
            phone_number="+821012345678",
            otp_digest="old-digest",
            purpose="SIGN_UP",
            attempt_count=0,
            resend_count=0,
            created_at=now,
            last_sent_at=now,
            expires_at=now + timedelta(minutes=5),
            verified_at=None,
            consumed_at=None,
        )
        db = FakeDb(scalar_results={PhoneVerificationRequest: row})

        with self.assertRaises(HTTPException) as caught:
            await request_phone_otp(
                PhoneRequestBody(phone_number=row.phone_number),
                fake_request(),
                db,
            )

        self.assertEqual(caught.exception.status_code, 429)
        self.assertEqual(
            caught.exception.detail["code"],
            AuthError.OTP_RESEND_TOO_SOON.value,
        )
        self.assertGreater(int(caught.exception.headers["Retry-After"]), 0)
        self.assertEqual(row.resend_count, 0)
        self.assertEqual(db.commits, 0)

    async def test_max_attempts_rejects_without_sending_or_extending(self):
        settings.dev_mode = True
        now = datetime.now(timezone.utc)
        original_expiry = now + timedelta(minutes=4)
        row = SimpleNamespace(
            id=uuid.uuid4(),
            phone_number="+821012345678",
            otp_digest="old-digest",
            purpose="SIGN_UP",
            attempt_count=settings.otp_max_attempts,
            resend_count=0,
            created_at=now - timedelta(minutes=1),
            last_sent_at=now - timedelta(seconds=31),
            expires_at=original_expiry,
            verified_at=None,
            consumed_at=None,
        )
        db = FakeDb(scalar_results={PhoneVerificationRequest: row})

        with patch(
            "app.api.v1.endpoints.auth.send_otp_sms",
            new=AsyncMock(),
        ) as send:
            with self.assertRaises(HTTPException) as caught:
                await request_phone_otp(
                    PhoneRequestBody(phone_number=row.phone_number),
                    fake_request(),
                    db,
                )

        self.assertEqual(caught.exception.status_code, 429)
        self.assertEqual(caught.exception.detail["code"], AuthError.OTP_LOCKED_UNTIL_EXPIRY.value)
        self.assertGreater(int(caught.exception.headers["Retry-After"]), 0)
        self.assertEqual(row.expires_at, original_expiry)
        self.assertEqual(row.resend_count, 0)
        self.assertEqual(db.commits, 0)
        send.assert_not_awaited()

    async def test_max_resends_rejects_without_sending_or_extending(self):
        settings.dev_mode = True
        now = datetime.now(timezone.utc)
        original_expiry = now + timedelta(minutes=4)
        row = SimpleNamespace(
            id=uuid.uuid4(),
            phone_number="+821012345678",
            otp_digest="old-digest",
            purpose="SIGN_UP",
            attempt_count=0,
            resend_count=settings.otp_max_resends,
            created_at=now - timedelta(minutes=1),
            last_sent_at=now - timedelta(seconds=31),
            expires_at=original_expiry,
            verified_at=None,
            consumed_at=None,
        )
        db = FakeDb(scalar_results={PhoneVerificationRequest: row})

        with self.assertRaises(HTTPException) as caught:
            await request_phone_otp(
                PhoneRequestBody(phone_number=row.phone_number),
                fake_request(),
                db,
            )

        self.assertEqual(caught.exception.status_code, 429)
        self.assertEqual(
            caught.exception.detail["code"],
            AuthError.OTP_RESEND_LIMIT_REACHED.value,
        )
        self.assertEqual(row.expires_at, original_expiry)
        self.assertEqual(row.resend_count, settings.otp_max_resends)
        self.assertEqual(db.commits, 0)

    async def test_live_rate_limit_rejects_before_otp_state_is_changed(self):
        settings.dev_mode = False
        db = FakeDb()

        with patch(
            "app.api.v1.endpoints.auth.otp_sms_rate_limiter.reserve",
            new=AsyncMock(
                return_value=OtpSmsReservationDenied(retry_after_seconds=42)
            ),
        ):
            with self.assertRaises(HTTPException) as caught:
                await request_phone_otp(
                    PhoneRequestBody(phone_number="+821012345678"),
                    fake_request(),
                    db,
                )

        self.assertEqual(caught.exception.status_code, 429)
        self.assertEqual(
            caught.exception.detail["code"],
            AuthError.OTP_REQUEST_RATE_LIMITED.value,
        )
        self.assertEqual(caught.exception.headers["Retry-After"], "42")
        self.assertEqual(db.added, [])
        self.assertEqual(db.commits, 0)

    async def test_missing_live_configuration_returns_503_before_db_work(self):
        settings.dev_mode = False
        settings.solapi_api_secret = SecretStr(" ")
        db = FakeDb()

        with patch(
            "app.api.v1.endpoints.auth.send_otp_sms",
            new=AsyncMock(),
        ) as send:
            with self.assertRaises(HTTPException) as caught:
                await request_phone_otp(
                    PhoneRequestBody(phone_number="+821012345678"),
                    fake_request(),
                    db,
                )

        self.assertEqual(caught.exception.status_code, 503)
        self.assertEqual(
            caught.exception.detail["code"],
            AuthError.SMS_SERVICE_UNAVAILABLE.value,
        )
        self.assertEqual(db.executed, [])
        self.assertEqual(db.commits, 0)
        send.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
