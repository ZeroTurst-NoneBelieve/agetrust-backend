"""StatusList의 신규/이전 경로 모두 실제 키오스크 인증 의존성을 통과해야 한다."""

import base64
import hashlib
import os
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.exc import MultipleResultsFound

_ISSUER_KEY_BYTES = bytes(range(32))
os.environ["DATABASE_URL"] = "postgresql+asyncpg://test:test@localhost/test"
os.environ["SECRET_KEY"] = "test-secret-key-at-least-32-bytes"
os.environ["ISSUER_PRIVATE_KEY"] = base64.b64encode(_ISSUER_KEY_BYTES).decode()

from app.core.security import create_access_token  # noqa: E402
from app.core.status_list import empty_encoded_list  # noqa: E402
from app.database import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import CredentialStatusList, Kiosk  # noqa: E402
from tests.fakes import FakeDb  # noqa: E402


class StatusListAuthenticationTests(unittest.IsolatedAsyncioTestCase):
    PATHS = ("/api/v1/status-lists/7", "/api/v1/status/7")
    IDENTIFIER = "registered-test-kiosk"
    RAW_KEY = "test-only-random-kiosk-key"

    def setUp(self):
        self.kiosk = SimpleNamespace(
            id=5,
            kiosk_identifier=self.IDENTIFIER,
            api_key_hash=hashlib.sha256(self.RAW_KEY.encode()).hexdigest(),
            status="ACTIVE",
        )
        self.row = SimpleNamespace(
            id=7,
            status_list_url="http://localhost:8000/api/v1/status-lists/7",
            status_purpose="REVOCATION",
            encoded_list=empty_encoded_list(),
            version=1,
        )
        self.db = FakeDb(
            {(CredentialStatusList, 7): self.row}, scalar_results={Kiosk: self.kiosk}
        )

    def _key_headers(self, raw_key=None):
        key = self.RAW_KEY if raw_key is None else raw_key
        return {"Authorization": f"Bearer {key}"}

    async def _get(self, path, headers=None):
        async def override_db():
            yield self.db

        previous_overrides = app.dependency_overrides.copy()
        # get_current_kiosk is deliberately NOT overridden: exercise real hashing,
        # kiosk status checks, and dependency ordering through ASGI.
        app.dependency_overrides[get_db] = override_db
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://testserver"
            ) as client:
                return await client.get(path, headers=headers)
        finally:
            app.dependency_overrides.clear()
            app.dependency_overrides.update(previous_overrides)

    async def _assert_denied(self, path, headers=None, code="KIOSK_KEY_INVALID"):
        prior_gets = list(self.db.get_calls)
        with patch("app.api.v1.endpoints.vc.issue_status_list_vc") as signer:
            response = await self._get(path, headers)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": {"code": code}})
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["vary"], "Authorization")
        self.assertEqual(response.headers["www-authenticate"], "Bearer")
        self.assertNotIn("etag", response.headers)
        self.assertNotIn(self.RAW_KEY, response.text)
        # Neither an existence check nor signing may run before authentication.
        self.assertEqual(self.db.get_calls, prior_gets)
        signer.assert_not_called()
        return response

    async def test_active_registered_key_receives_signed_list_on_both_routes(self):
        public_key = Ed25519PrivateKey.from_private_bytes(_ISSUER_KEY_BYTES).public_key()
        for path in self.PATHS:
            with self.subTest(path=path):
                response = await self._get(path, self._key_headers())

                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers["content-type"], "application/jwt")
                self.assertEqual(response.headers["cache-control"], "private, no-cache")
                self.assertEqual(response.headers["vary"], "Authorization")
                payload = jwt.decode(response.text, public_key, algorithms=["EdDSA"])
                self.assertEqual(payload["vc"]["id"], self.row.status_list_url)

    async def test_missing_and_malformed_headers_are_denied_on_both_routes(self):
        header_values = (
            None, "", "without-separator", "Bearer", "Bearer ", "Bearer  ",
            f"Basic {self.RAW_KEY}", f"Digest {self.RAW_KEY}", f"Token {self.RAW_KEY}",
        )
        for path in self.PATHS:
            for header in header_values:
                with self.subTest(path=path, header=header):
                    headers = {} if header is None else {"Authorization": header}
                    await self._assert_denied(path, headers)

    async def test_empty_raw_key_is_denied_even_if_empty_hash_is_stored(self):
        self.kiosk.api_key_hash = hashlib.sha256(b"").hexdigest()
        for path in self.PATHS:
            with self.subTest(path=path):
                await self._assert_denied(path, self._key_headers(""))

    async def test_unknown_kiosk_is_denied(self):
        self.db.scalar_results[Kiosk] = None
        for path in self.PATHS:
            with self.subTest(path=path):
                await self._assert_denied(path, self._key_headers("unknown-kiosk-key"))

    async def test_wrong_raw_key_is_denied_without_disclosing_list(self):
        for stored_hash in (self.kiosk.api_key_hash, "not-a-hash", "잘못된-해시"):
            self.kiosk.api_key_hash = stored_hash
            for path in self.PATHS:
                with self.subTest(path=path, stored_hash=stored_hash):
                    await self._assert_denied(path, self._key_headers("wrong-key"))

    async def test_inactive_and_revoked_kiosks_are_denied(self):
        for kiosk_status in ("INACTIVE", "REVOKED"):
            self.kiosk.status = kiosk_status
            for path in self.PATHS:
                with self.subTest(path=path, kiosk_status=kiosk_status):
                    await self._assert_denied(path, self._key_headers(), code="KIOSK_INACTIVE")

    async def test_user_or_admin_login_bearer_cannot_replace_kiosk_key(self):
        for role in ("USER", "ADMIN"):
            token = create_access_token(123, role)
            for path in self.PATHS:
                with self.subTest(path=path, role=role):
                    await self._assert_denied(path, {"Authorization": f"Bearer {token}"})

    async def test_conditional_request_cannot_bypass_authentication(self):
        initial = await self._get(self.PATHS[0], self._key_headers())
        self.assertEqual(initial.status_code, 200)
        for path in self.PATHS:
            for etag in (initial.headers["etag"], "*"):
                for credentials in ({}, self._key_headers("wrong-key")):
                    with self.subTest(path=path, etag=etag, credentials=bool(credentials)):
                        await self._assert_denied(path, {**credentials, "If-None-Match": etag})

    async def test_missing_list_does_not_reveal_existence_before_authentication(self):
        self.db.rows.clear()
        for path in self.PATHS:
            with self.subTest(path=path):
                await self._assert_denied(path)
                response = await self._get(path, self._key_headers())
                self.assertEqual(response.status_code, 404)
                self.assertEqual(response.headers["cache-control"], "no-store")

    async def test_key_rotation_rejects_old_key_even_with_current_etag(self):
        initial = await self._get(self.PATHS[0], self._key_headers())
        self.assertEqual(initial.status_code, 200)
        new_raw_key = "test-only-rotated-kiosk-key"
        self.kiosk.api_key_hash = hashlib.sha256(new_raw_key.encode()).hexdigest()
        for path in self.PATHS:
            with self.subTest(path=path):
                condition = {"If-None-Match": initial.headers["etag"]}
                await self._assert_denied(path, {**self._key_headers(), **condition})
                response = await self._get(path, {**self._key_headers(new_raw_key), **condition})
                self.assertEqual(response.status_code, 304)
                self.assertEqual(response.content, b"")
                self.assertEqual(response.headers["cache-control"], "private, no-cache")
                self.assertEqual(response.headers["vary"], "Authorization")

    async def test_revocation_after_fetch_rejects_conditional_revalidation(self):
        initial = await self._get(self.PATHS[0], self._key_headers())
        self.assertEqual(initial.status_code, 200)
        self.kiosk.status = "REVOKED"
        for path in self.PATHS:
            with self.subTest(path=path):
                await self._assert_denied(
                    path,
                    {**self._key_headers(), "If-None-Match": initial.headers["etag"]},
                    code="KIOSK_INACTIVE",
                )

    async def test_legacy_header_is_not_an_authentication_fallback(self):
        legacy = {"X-Kiosk-Key": f"{self.IDENTIFIER}:{self.RAW_KEY}"}
        for path in self.PATHS:
            for headers in (legacy, {**legacy, **self._key_headers("wrong-key")},
                            {**legacy, "Authorization": f"Basic {self.RAW_KEY}"}):
                with self.subTest(path=path, header_names=tuple(headers)):
                    await self._assert_denied(path, headers)

    async def test_valid_bearer_does_not_take_identity_from_legacy_header(self):
        for path in self.PATHS:
            with self.subTest(path=path):
                response = await self._get(
                    path,
                    {**self._key_headers(), "X-Kiosk-Key": "another-kiosk:unrelated-key"},
                )
                self.assertEqual(response.status_code, 200)

    async def test_bearer_contains_only_raw_key_not_identifier_prefix(self):
        for path in self.PATHS:
            with self.subTest(path=path):
                await self._assert_denied(path, self._key_headers(f"{self.IDENTIFIER}:{self.RAW_KEY}"))

    async def test_kiosk_query_uses_key_hash_not_identifier_and_detects_duplicates(self):
        for path in self.PATHS:
            with self.subTest(path=path):
                with patch.object(self.db, "execute", wraps=self.db.execute) as execute:
                    response = await self._get(path, self._key_headers())
                self.assertEqual(response.status_code, 200)
                execute.assert_awaited_once()
                query = execute.await_args.args[0]
                sql = str(query.compile(compile_kwargs={"literal_binds": True}))
                where_clause = sql.split("WHERE", 1)[1]
                digest = hashlib.sha256(self.RAW_KEY.encode()).hexdigest()
                self.assertIn(f"kiosks.api_key_hash = '{digest}'", where_clause)
                self.assertNotIn("kiosks.kiosk_identifier", where_clause)
                self.assertNotIn(self.RAW_KEY, sql)
                self.assertIn("LIMIT 2", where_clause)

    async def test_duplicate_key_hash_is_rejected_instead_of_selecting_one_kiosk(self):
        duplicate_result = SimpleNamespace(
            scalar_one_or_none=Mock(side_effect=MultipleResultsFound("duplicate test key"))
        )
        for path in self.PATHS:
            with self.subTest(path=path):
                with patch.object(self.db, "execute", new=AsyncMock(return_value=duplicate_result)):
                    await self._assert_denied(path, self._key_headers())


if __name__ == "__main__":
    unittest.main()
