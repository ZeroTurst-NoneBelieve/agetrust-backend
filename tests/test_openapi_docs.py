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


    def test_vc_error_responses_expose_detail_code_schema(self):
        responses = (
            ("/api/v1/adult-verifications", "post", "400"),
            ("/api/v1/adult-verifications", "post", "404"),
            ("/api/v1/did/issue", "post", "400"),
            ("/api/v1/did/issue", "post", "404"),
            ("/api/v1/did/{did}", "get", "400"),
            ("/api/v1/auth/devices/bind-holder-key", "post", "400"),
            ("/api/v1/auth/devices/bind-holder-key", "post", "404"),
        )

        for path, method, status_code in responses:
            with self.subTest(path=path, status_code=status_code):
                schema = self.openapi["paths"][path][method]["responses"][status_code][
                    "content"
                ]["application/json"]["schema"]
                self.assertEqual(
                    schema["$ref"],
                    "#/components/schemas/VcErrorResponse",
                )

        detail = self.schemas["VcErrorResponse"]["properties"]["detail"]
        code = self.schemas["VcErrorDetail"]["properties"]["code"]
        self.assertEqual(detail["$ref"], "#/components/schemas/VcErrorDetail")
        self.assertEqual(code["$ref"], "#/components/schemas/VcError")

    def test_documented_errors_never_return_a_bare_string_body(self):
        """에러 본문이 다시 평문 문자열로 돌아가지 않도록 잠근다(#38).

        문서화한 4xx·5xx는 전부 detail.code 형태여야 한다. 422는 FastAPI가
        요청 검증용으로 직접 만드는 응답이라 제외한다.
        """
        allowed = {
            "#/components/schemas/AuthErrorResponse",
            "#/components/schemas/VcErrorResponse",
        }
        offenders = []

        for path, methods in self.openapi["paths"].items():
            for method, operation in methods.items():
                for status_code, response in operation.get("responses", {}).items():
                    if status_code[0] not in "45" or status_code == "422":
                        continue
                    schema = (
                        response.get("content", {})
                        .get("application/json", {})
                        .get("schema", {})
                    )
                    if schema.get("$ref") not in allowed:
                        offenders.append(f"{status_code} {method.upper()} {path}")

        self.assertEqual(offenders, [])


    def test_protected_endpoints_document_their_401(self):
        """문지기가 던지는 401은 FastAPI가 자동 문서화하지 않아 손으로 얹는다.

        보호된 엔드포인트를 새로 추가하면서 공용 responses를 빠뜨리면
        여기서 걸린다. 클라이언트가 가장 자주 만나는 오류다.
        """
        missing = []

        for path, methods in self.openapi["paths"].items():
            for method, operation in methods.items():
                if operation.get("security") is None:
                    continue
                schema = (
                    operation.get("responses", {})
                    .get("401", {})
                    .get("content", {})
                    .get("application/json", {})
                    .get("schema", {})
                )
                if schema.get("$ref") != "#/components/schemas/AuthErrorResponse":
                    missing.append(f"{method.upper()} {path}")

        self.assertEqual(missing, [])

    def test_admin_endpoints_document_their_403(self):
        """require_admin이 걸린 경로는 403도 함께 문서화한다."""
        admin_paths = [p for p in self.openapi["paths"] if p.startswith("/api/v1/admin/")]
        self.assertTrue(admin_paths, "admin 엔드포인트가 하나도 없다")

        for path in admin_paths:
            for method, operation in self.openapi["paths"][path].items():
                with self.subTest(path=path, method=method):
                    schema = operation["responses"]["403"]["content"]["application/json"][
                        "schema"
                    ]
                    self.assertEqual(
                        schema["$ref"],
                        "#/components/schemas/AuthErrorResponse",
                    )


if __name__ == "__main__":
    unittest.main()
