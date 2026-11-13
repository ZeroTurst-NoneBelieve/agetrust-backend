"""Request validation responses must never echo credentials or request bodies."""

import base64
import json
import os
import unittest
from unittest.mock import AsyncMock

import httpx
from fastapi.exceptions import RequestValidationError

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from app.api.errors import safe_validation_error_handler  # noqa: E402
from app.database import get_db  # noqa: E402
from app.main import app  # noqa: E402


class ValidationPrivacyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.original_overrides = app.dependency_overrides.copy()

        async def fake_db():
            yield AsyncMock()

        app.dependency_overrides[get_db] = fake_db
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")

    async def asyncTearDown(self):
        await self.client.aclose()
        app.dependency_overrides.clear()
        app.dependency_overrides.update(self.original_overrides)

    async def test_sensitive_fields_and_missing_field_body_are_not_reflected(self):
        cases = [
            ("signup", {"verification_id": "00000000-0000-0000-0000-000000000001",
                        "login_id": "review", "password": "FAKE123", "name": "Review"}, "password", "FAKE123"),
            ("phone/request", {"phone_number": "01000000000"}, "phone_number", "01000000000"),
            ("phone/verify", {"verification_id": "00000000-0000-0000-0000-000000000001",
                              "otp": "9" * 65}, "otp", "9" * 65),
            ("login", {"password": "FAKE-password-secret"}, "login_id", "FAKE-password-secret"),
            ("refresh", {"refresh_token": {"secret": "FAKE-token-secret"}},
             "refresh_token", "FAKE-token-secret"),
        ]
        for path, body, field, secret in cases:
            with self.subTest(path=path):
                response = await self.client.post("/api/v1/auth/" + path, json=body)
                self.assertEqual(response.status_code, 422)
                self.assertNotIn(secret, response.text)
                self.assertEqual(response.headers["cache-control"], "no-store")
                errors = response.json()["detail"]
                self.assertTrue(any(error["loc"] == ["body", field] for error in errors))
                for error in errors:
                    self.assertEqual(set(error), {"type", "loc", "msg"})

    async def test_malformed_json_does_not_echo_partial_body(self):
        response = await self.client.post(
            "/api/v1/auth/login", content='{"password":"FAKE-json-secret",',
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("FAKE-json-secret", response.text)
        self.assertEqual(response.json()["detail"][0]["type"], "json_invalid")

    async def test_validator_message_and_context_are_not_reflected(self):
        secret = "FAKE-validator-secret"
        exc = RequestValidationError([{
            "type": "value_error", "loc": ("body", "password"),
            "msg": secret, "input": secret, "ctx": {"error": ValueError(secret)},
        }])
        response = await safe_validation_error_handler(None, exc)
        self.assertNotIn(secret, response.body.decode())
        self.assertEqual(json.loads(response.body)["detail"][0]["type"], "value_error")
