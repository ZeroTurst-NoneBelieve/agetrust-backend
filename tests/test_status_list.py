"""StatusList URL 및 무작위 인덱스 배정 보조 함수의 회귀 테스트."""

import base64
import os
import unittest
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from app.api.v1.endpoints.vc import _index_is_taken, _pick_unused_index  # noqa: E402
from app.schemas.errors import VcError  # noqa: E402
from app.core.status_list import (  # noqa: E402
    BITSTRING_BYTES,
    build_status_list_url,
    decode_bitstring,
    empty_encoded_list,
    encode_bitstring,
)
from tests.fakes import FakeResult  # noqa: E402


class StatusListEncodingTests(unittest.TestCase):
    def test_valid_unpadded_base64url_round_trips(self):
        for raw in (bytes(BITSTRING_BYTES), bytes(range(256)) * (BITSTRING_BYTES // 256)):
            with self.subTest(prefix=raw[:8]):
                encoded = encode_bitstring(raw)
                self.assertNotIn("=", encoded)
                self.assertEqual(decode_bitstring(encoded), bytearray(raw))

    def test_invalid_base64url_characters_are_not_silently_ignored(self):
        encoded = empty_encoded_list()
        malformed = (
            None, b"not-a-string", "", "A",
            encoded + "!!!!", encoded + " ", encoded + "\n",
            encoded[:4] + "\t" + encoded[4:], encoded + "+", encoded + "/",
            encoded + "=", encoded + "한",
        )
        for value in malformed:
            with self.subTest(encoded=value):
                with self.assertRaises(ValueError):
                    decode_bitstring(value)


class StatusListUrlTests(unittest.TestCase):
    def test_new_urls_use_canonical_resource_path(self):
        for base_url in ("https://issuer.example", "https://issuer.example/"):
            with self.subTest(base_url=base_url):
                self.assertEqual(
                    build_status_list_url(base_url, 7),
                    "https://issuer.example/api/v1/status-lists/7",
                )


class StatusListAllocationTests(unittest.IsolatedAsyncioTestCase):
    async def test_index_lookup_checks_both_list_and_index_without_status_filter(self):
        for occupied in (False, True):
            with self.subTest(occupied=occupied):
                db = AsyncMock()
                db.scalar.return_value = occupied

                self.assertIs(await _index_is_taken(db, 7, 4), occupied)

                query = db.scalar.await_args.args[0]
                sql = str(query.compile(compile_kwargs={"literal_binds": True}))
                self.assertIn("EXISTS", sql)
                self.assertIn("vc_credentials.status_list_id = 7", sql)
                self.assertIn("vc_credentials.status_list_index = 4", sql)
                self.assertNotIn("vc_credentials.status =", sql)

    async def test_fallback_selects_only_an_actually_unused_index(self):
        db = AsyncMock()
        db.execute.return_value = FakeResult(rows=[0, 1, 2, 4, 5, 6, 7])
        with (
            patch("app.api.v1.endpoints.vc.BITSTRING_SIZE", 8),
            patch("app.api.v1.endpoints.vc.secrets.choice", side_effect=lambda choices: choices[0]) as pick,
        ):
            result = await _pick_unused_index(db, 7)

        self.assertEqual(result, 3)
        pick.assert_called_once_with([3])
        query = db.execute.await_args.args[0]
        sql = str(query.compile(compile_kwargs={"literal_binds": True}))
        self.assertIn("vc_credentials.status_list_id = 7", sql)
        self.assertNotIn("vc_credentials.status =", sql)

    async def test_fallback_randomizes_across_all_remaining_places(self):
        db = AsyncMock()
        db.execute.return_value = FakeResult(rows=[0, 3, 5])
        with (
            patch("app.api.v1.endpoints.vc.BITSTRING_SIZE", 8),
            patch("app.api.v1.endpoints.vc.secrets.choice", return_value=6) as pick,
        ):
            result = await _pick_unused_index(db, 7)

        self.assertEqual(result, 6)
        pick.assert_called_once_with([1, 2, 4, 6, 7])

    async def test_fallback_returns_503_only_when_no_unused_place_remains(self):
        db = AsyncMock()
        db.execute.return_value = FakeResult(rows=list(range(8)))
        with (
            patch("app.api.v1.endpoints.vc.BITSTRING_SIZE", 8),
            patch("app.api.v1.endpoints.vc.secrets.choice") as pick,
        ):
            with self.assertRaises(HTTPException) as raised:
                await _pick_unused_index(db, 7)

        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(raised.exception.detail, {"code": VcError.STATUS_LIST_FULL.value})
        pick.assert_not_called()


if __name__ == "__main__":
    unittest.main()
