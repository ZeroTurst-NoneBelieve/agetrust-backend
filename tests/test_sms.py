"""SOLAPI SMS 게이트웨이 직렬화·오류 처리 검증."""

import base64
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pydantic import SecretStr

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from app.config import settings  # noqa: E402
from app.core.sms import SmsConfigurationError, SmsDeliveryError, SmsReceipt, send_otp_sms  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
