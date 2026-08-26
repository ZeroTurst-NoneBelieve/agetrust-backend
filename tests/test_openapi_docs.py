"""Swagger/OpenAPI 문서 계약 회귀 테스트."""

import base64
import os
import unittest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault(
    "ISSUER_PRIVATE_KEY",
    base64.b64encode(bytes(range(32))).decode(),
)

from app.main import app  # noqa: E402


class OpenApiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openapi = app.openapi()
        cls.schemas = cls.openapi["components"]["schemas"]

    def test_nullable_response_fields_remain_required(self):
        expected = {
            "DeviceResponse": "holder_did",
            "AdultVerificationResponse": "failure_code",
            "IssueVcResponse": "expires_at",
        }

        for schema_name, field_name in expected.items():
            with self.subTest(schema=schema_name, field=field_name):
                self.assertIn(field_name, self.schemas[schema_name]["required"])

    def test_adult_verification_values_match_runtime_contract(self):
        statuses = self.schemas["AdultVerificationStatus"]["enum"]
        failure_codes = self.schemas["AdultVerificationFailureCode"]["enum"]

        self.assertNotIn("FAILURE", statuses)
        self.assertEqual(
            statuses,
            [
                "SUCCESS",
                "FAIL_AGE",
                "FAIL_FACE_MISMATCH",
                "FAIL_LIVENESS",
                "ERROR",
            ],
        )
        self.assertEqual(
            failure_codes,
            [
                "AGE_POLICY_FAILED",
                "ID_SELFIE_MISMATCH",
                "LIVENESS_FAILED",
            ],
        )

    def test_auth_error_responses_expose_detail_code_schema(self):
        responses = (
            ("/api/v1/auth/phone/verify", "401"),
            ("/api/v1/auth/phone/verify", "404"),
            ("/api/v1/auth/signup", "409"),
            ("/api/v1/auth/login", "401"),
            ("/api/v1/auth/refresh", "401"),
        )

        for path, status_code in responses:
            with self.subTest(path=path, status_code=status_code):
                schema = self.openapi["paths"][path]["post"]["responses"][status_code][
                    "content"
                ]["application/json"]["schema"]
                self.assertEqual(
                    schema["$ref"],
                    "#/components/schemas/AuthErrorResponse",
                )

        detail = self.schemas["AuthErrorResponse"]["properties"]["detail"]
        code = self.schemas["AuthErrorDetail"]["properties"]["code"]
        self.assertEqual(detail["$ref"], "#/components/schemas/AuthErrorDetail")
        self.assertEqual(code["$ref"], "#/components/schemas/AuthError")


if __name__ == "__main__":
    unittest.main()
