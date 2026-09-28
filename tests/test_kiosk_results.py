"""키오스크 결과 업로드의 입력·오류·OpenAPI 계약 (#42)."""

import base64
import os
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from app.api.deps import get_current_kiosk  # noqa: E402
from app.database import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.schemas.kiosk import KioskVerificationResultRequest  # noqa: E402

RESULT_PATH = "/api/v1/kiosk/verification-results"


def _payload(**changes):
    body = {
        "kiosk_identifier": "kiosk-test-01",
        "nonce": "opaque-session-nonce",
        "verified_at": "2026-09-22T10:30:00+09:00",
        "result_status": "PASS",
        "is_vc_valid": True,
        "is_face_matched": True,
        "transport_type": "QR_BLE",
    }
    body.update(changes)
    return body


class KioskResultSchemaTests(unittest.TestCase):
    def test_issue_payload_accepts_optional_field_defaults(self):
        body = KioskVerificationResultRequest.model_validate(_payload())

        self.assertEqual(body.result_status, "PASS")
        self.assertEqual(body.verified_at.utcoffset().total_seconds(), 9 * 3600)
        self.assertFalse(body.is_vp_valid)
        self.assertIsNone(body.is_liveness_valid)
        self.assertIsNone(body.failure_code)
        self.assertIsNone(body.face_model_version)
        self.assertIsNone(body.threshold_version)
        self.assertIsNone(body.status_list_age_seconds)

    def test_optional_reported_values_are_preserved(self):
        body = KioskVerificationResultRequest.model_validate(_payload(
            result_status="FAIL_FACE_MISMATCH",
            is_face_matched=False,
            is_vp_valid=True,
            is_liveness_valid=False,
            failure_code="FACE_MISMATCH",
            face_model_version="face-v1",
            threshold_version="threshold-v2",
            status_list_age_seconds=0,
        ))

        self.assertTrue(body.is_vp_valid)
        self.assertFalse(body.is_face_matched)
        self.assertFalse(body.is_liveness_valid)
        self.assertEqual(body.failure_code, "FACE_MISMATCH")
        self.assertEqual(body.face_model_version, "face-v1")
        self.assertEqual(body.threshold_version, "threshold-v2")
        self.assertEqual(body.status_list_age_seconds, 0)

    def test_booleans_are_not_coerced(self):
        for field in ("is_vc_valid", "is_face_matched", "is_vp_valid", "is_liveness_valid"):
            for value in (0, 1, "true", "false"):
                with self.subTest(field=field, value=value), self.assertRaises(ValidationError):
                    KioskVerificationResultRequest.model_validate(_payload(**{field: value}))

    def test_status_list_age_requires_nonnegative_database_sized_integer(self):
        for value in (-1, 2**31, True, 1.5, "30"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                KioskVerificationResultRequest.model_validate(_payload(status_list_age_seconds=value))

    def test_timestamp_requires_timezone_and_rejects_unix_number(self):
        for value in (
            "2026-09-22T10:30:00", "2026-09-22", 1758501000,
            "1758501000", "1758501000.5", datetime(2026, 9, 22),
        ):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                KioskVerificationResultRequest.model_validate(_payload(verified_at=value))

        for value in ("2026-09-22T01:30:00Z", datetime(2026, 9, 22, tzinfo=timezone.utc)):
            with self.subTest(value=value):
                body = KioskVerificationResultRequest.model_validate(_payload(verified_at=value))
                self.assertIsNotNone(body.verified_at.utcoffset())

    def test_timestamp_must_be_representable_after_utc_conversion(self):
        for value in ("0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                KioskVerificationResultRequest.model_validate(_payload(verified_at=value))

    def test_only_documented_status_and_transport_are_accepted(self):
        for changes in (
            {"result_status": "SUCCESS"},
            {"result_status": "pass"},
            {"result_status": "UNKNOWN"},
            {"transport_type": "BLE"},
            {"transport_type": "NFC"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                KioskVerificationResultRequest.model_validate(_payload(**changes))

    def test_text_fields_reject_blank_nul_and_excessive_length(self):
        limits = {
            "kiosk_identifier": 255,
            "nonce": 128,
            "failure_code": 100,
            "face_model_version": 100,
            "threshold_version": 100,
        }
        for field, limit in limits.items():
            for value in ("", "   ", "value\x00suffix", "x" * (limit + 1), 123):
                with self.subTest(field=field, value=value), self.assertRaises(ValidationError):
                    KioskVerificationResultRequest.model_validate(_payload(**{field: value}))

    def test_nonce_is_not_trimmed(self):
        body = KioskVerificationResultRequest.model_validate(_payload(nonce=" nonce bytes "))
        self.assertEqual(body.nonce, " nonce bytes ")

    def test_required_fields_cannot_be_omitted(self):
        for field in _payload():
            body = _payload()
            del body[field]
            with self.subTest(field=field), self.assertRaises(ValidationError):
                KioskVerificationResultRequest.model_validate(body)


class _NoDatabaseAccess:
    def __getattr__(self, name):
        raise AssertionError(f"Input/auth rejection must not use DB method: {name}")


class KioskResultHttpTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        previous_overrides = app.dependency_overrides.copy()

        def restore_overrides():
            app.dependency_overrides.clear()
            app.dependency_overrides.update(previous_overrides)

        self.addCleanup(restore_overrides)

        async def no_database():
            yield _NoDatabaseAccess()

        async def authenticated_kiosk():
            return SimpleNamespace(id=42, kiosk_identifier="kiosk-test-01")

        app.dependency_overrides[get_db] = no_database
        app.dependency_overrides[get_current_kiosk] = authenticated_kiosk
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test",
        )
        self.addAsyncCleanup(self.client.aclose)

    def assert_invalid_result(self, response):
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"detail": {"code": "INVALID_VERIFICATION_RESULT"}})
        self.assertEqual(response.headers["cache-control"], "no-store")

    async def test_sensitive_unknown_fields_are_rejected_without_echo(self):
        for field in ("user_id", "holder_did", "vc", "vp", "embedding", "face_embedding"):
            with self.subTest(field=field):
                response = await self.client.post(
                    RESULT_PATH,
                    json=_payload(**{field: "private-value-must-not-be-echoed"}),
                )
                self.assert_invalid_result(response)
                self.assertNotIn("private-value", response.text)
                self.assertNotIn("opaque-session-nonce", response.text)

    async def test_invalid_fields_use_400_detail_code(self):
        for changes in (
            {"is_vc_valid": "true"},
            {"status_list_age_seconds": -1},
            {"verified_at": "2026-09-22T10:30:00"},
            {"verified_at": "1758501000"},
            {"verified_at": "1758501000.5"},
            {"verified_at": "0001-01-01T00:00:00+01:00"},
            {"verified_at": "9999-12-31T23:59:59-01:00"},
            {"result_status": "SUCCESS"},
            {"nonce": "sensitive-nonce-" * 20},
        ):
            with self.subTest(changes=changes):
                response = await self.client.post(RESULT_PATH, json=_payload(**changes))
                self.assert_invalid_result(response)

    async def test_missing_and_malformed_json_use_400(self):
        response = await self.client.post(RESULT_PATH)
        self.assert_invalid_result(response)
        response = await self.client.post(
            RESULT_PATH,
            content='{"nonce":"private-json-value",',
            headers={"Content-Type": "application/json"},
        )
        self.assert_invalid_result(response)
        self.assertNotIn("private-json-value", response.text)

    async def test_invalid_json_encoding_uses_400_detail_code(self):
        for content in (b"\xff", b'{"nonce":"private-value-\xff"}'):
            with self.subTest(content=content):
                response = await self.client.post(
                    RESULT_PATH,
                    content=content,
                    headers={"Content-Type": "application/json"},
                )
                self.assert_invalid_result(response)
                self.assertNotIn("private-value", response.text)

    async def test_missing_or_non_bearer_key_is_401(self):
        del app.dependency_overrides[get_current_kiosk]
        for headers in ({}, {"Authorization": "Basic private-value"}):
            with self.subTest(headers=headers):
                response = await self.client.post(RESULT_PATH, json=_payload(), headers=headers)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json(), {"detail": {"code": "KIOSK_KEY_INVALID"}})
                self.assertEqual(response.headers["www-authenticate"], "Bearer")
                self.assertEqual(response.headers["cache-control"], "no-store")

    async def test_other_kiosk_identifier_is_403_before_storage(self):
        response = await self.client.post(RESULT_PATH, json=_payload(kiosk_identifier="another-kiosk"))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {"detail": {"code": "KIOSK_IDENTIFIER_MISMATCH"}})
        self.assertEqual(response.headers["cache-control"], "no-store")

    async def test_authentication_database_failure_returns_safe_503(self):
        class UnavailableDatabase:
            async def execute(self, statement):
                raise error_type("private-db-marker")

        async def unavailable_database():
            yield UnavailableDatabase()

        del app.dependency_overrides[get_current_kiosk]
        app.dependency_overrides[get_db] = unavailable_database
        for error_type in (SQLAlchemyError, ConnectionRefusedError, TimeoutError):
            with self.subTest(error_type=error_type.__name__):
                response = await self.client.post(
                    RESULT_PATH,
                    json=_payload(),
                    headers={"Authorization": "Bearer private-api-key"},
                )

                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.json(), {"detail": {"code": "VERIFICATION_RESULT_UNAVAILABLE"}})
                self.assertEqual(response.headers["cache-control"], "no-store")
                self.assertNotIn("private-db-marker", response.text)
                self.assertNotIn("private-api-key", response.text)
                self.assertNotIn("opaque-session-nonce", response.text)

    async def test_unrelated_endpoint_keeps_422_validation_contract(self):
        response = await self.client.post("/api/v1/auth/login", json={})
        self.assertEqual(response.status_code, 422)
        self.assertIsInstance(response.json()["detail"], list)


class KioskResultOpenApiTests(unittest.TestCase):
    def test_responses_document_receipts_and_structured_errors_without_422(self):
        document = app.openapi()
        operation = document["paths"][RESULT_PATH]["post"]
        responses = operation["responses"]
        expected = {
            "200": "KioskVerificationResultResponse",
            "201": "KioskVerificationResultResponse",
            "400": "KioskResultErrorResponse",
            "401": "AuthErrorResponse",
            "403": "KioskResultErrorResponse",
            "503": "KioskResultErrorResponse",
        }
        for status_code, schema in expected.items():
            with self.subTest(status_code=status_code):
                self.assertEqual(
                    responses[status_code]["content"]["application/json"]["schema"]["$ref"],
                    f"#/components/schemas/{schema}",
                )
        self.assertNotIn("422", responses)
        self.assertIn("422", document["paths"]["/api/v1/auth/login"]["post"]["responses"])

    def test_authentication_and_closed_request_schema_are_documented(self):
        document = app.openapi()
        operation = document["paths"][RESULT_PATH]["post"]
        self.assertEqual(operation["security"], [{"KioskApiKey": []}])
        scheme = document["components"]["securitySchemes"]["KioskApiKey"]
        self.assertEqual(scheme["type"], "http")
        self.assertEqual(scheme["scheme"], "bearer")
        schema = document["components"]["schemas"]["KioskVerificationResultRequest"]
        self.assertFalse(schema["additionalProperties"])
        self.assertCountEqual(schema["required"], _payload().keys())


if __name__ == "__main__":
    unittest.main()
