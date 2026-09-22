"""인증 요청 스키마 회귀 테스트."""

import unittest
import uuid

from pydantic import ValidationError

from app.schemas.user import LoginRequest, PhoneRequestBody, PhoneVerifyBody, SignupRequest


class VerificationIdSchemaTests(unittest.TestCase):
    def test_phone_verify_parses_valid_uuid(self):
        verification_id = uuid.uuid4()

        body = PhoneVerifyBody(
            verification_id=str(verification_id),
            otp="123456",
        )

        self.assertEqual(body.verification_id, verification_id)

    def test_phone_verify_rejects_malformed_uuid(self):
        with self.assertRaises(ValidationError):
            PhoneVerifyBody(verification_id="not-a-uuid", otp="123456")

    def test_signup_rejects_malformed_uuid(self):
        with self.assertRaises(ValidationError):
            SignupRequest(
                verification_id="not-a-uuid",
                login_id="schema-user",
                password="password123",
                name="테스트 사용자",
            )


class OtpSchemaTests(unittest.TestCase):
    def test_accepts_exactly_six_digits(self):
        body = PhoneVerifyBody(
            verification_id=uuid.uuid4(),
            otp="012345",
        )

        self.assertEqual(body.otp, "012345")

    def test_mistyped_otp_reaches_verification_unchanged(self):
        for otp in ("", "12345", "1234567", "12a456", "１２３４５６", "١٢٣٤٥٦"):
            with self.subTest(otp=otp):
                body = PhoneVerifyBody(
                    verification_id=uuid.uuid4(),
                    otp=otp,
                )
                self.assertEqual(body.otp, otp)

    def test_rejects_excessively_long_otp_input(self):
        with self.assertRaises(ValidationError):
            PhoneVerifyBody(verification_id=uuid.uuid4(), otp="1" * 65)


class PhoneNumberSchemaTests(unittest.TestCase):
    def test_accepts_korean_mobile_e164(self):
        body = PhoneRequestBody(phone_number="+821012345678")

        self.assertEqual(body.phone_number, "+821012345678")

    def test_rejects_non_korean_mobile_number(self):
        with self.assertRaises(ValidationError):
            PhoneRequestBody(phone_number="+12025550123")


class LoginIdSchemaTests(unittest.TestCase):
    def test_login_rejects_id_longer_than_database_column(self):
        with self.assertRaises(ValidationError):
            LoginRequest(login_id="x" * 101, password="password")

    def test_signup_rejects_id_longer_than_database_column(self):
        with self.assertRaises(ValidationError):
            SignupRequest(
                verification_id=uuid.uuid4(),
                login_id="x" * 101,
                password="password123",
                name="테스트 사용자",
            )

    def test_login_accepts_id_at_database_column_limit(self):
        body = LoginRequest(login_id="x" * 100, password="password")

        self.assertEqual(len(body.login_id), 100)


if __name__ == "__main__":
    unittest.main()
