import asyncio
import base64
import gzip
import hashlib
import os
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException

_ISSUER_KEY_BYTES = bytes(range(32))
os.environ["DATABASE_URL"] = "postgresql+asyncpg://test:test@localhost/test"
os.environ["SECRET_KEY"] = "test-secret-key-at-least-32-bytes"
os.environ["ISSUER_PRIVATE_KEY"] = base64.b64encode(_ISSUER_KEY_BYTES).decode()

from app.core.vc import (  # noqa: E402
    ADULT_CREDENTIAL_TYPE,
    ISSUER_DID,
    VC_TYPE,
    _load_issuer_private_key,
    build_did_document,
    issue_vc,
)
from app.api.v1.endpoints.vc import (  # noqa: E402
    _INDEX_PICK_ATTEMPTS,
    get_status_list,
    issue_credential,
    record_adult_verification,
)
from app.main import app  # noqa: E402
from app.database import get_db  # noqa: E402
from app.core.status_list import (  # noqa: E402
    BITSTRING_SIZE,
    decode_bitstring,
    empty_encoded_list,
    encode_bitstring,
    get_bit,
    new_bitstring,
    set_bit,
)
from app.models import (  # noqa: E402
    AdultVerification,
    CredentialStatusList,
    Device,
    Kiosk,
    VcCredential,
)
from app.schemas.vc import AdultVerificationRequest, IssueVcRequest  # noqa: E402
from tests.fakes import FakeDb as _FakeDb  # noqa: E402


class VcCoreTests(unittest.TestCase):
    def test_issue_vc_uses_fixed_issuer_key_and_minimum_claims(self):
        holder_did = ISSUER_DID
        token, credential_id, expires_at = issue_vc(holder_did, expires_days=1)

        public_key = Ed25519PrivateKey.from_private_bytes(
            _ISSUER_KEY_BYTES
        ).public_key()
        payload = jwt.decode(token, public_key, algorithms=["EdDSA"])

        self.assertEqual(payload["iss"], ISSUER_DID)
        self.assertEqual(payload["sub"], holder_did)
        self.assertEqual(payload["jti"], credential_id)
        self.assertEqual(
            payload["vc"]["type"],
            [VC_TYPE, ADULT_CREDENTIAL_TYPE],
        )
        self.assertEqual(
            payload["vc"]["credentialSubject"],
            {"id": holder_did, "isOver19": True},
        )
        self.assertIn("exp", payload)
        self.assertEqual(
            datetime.fromtimestamp(payload["exp"], timezone.utc),
            expires_at,
        )

    def test_issue_vc_embeds_credential_status_inside_vc(self):
        credential_status = {
            "id": "http://localhost:8000/api/v1/status/1#7",
            "type": "StatusList2021Entry",
            "statusPurpose": "revocation",
            "statusListIndex": "7",
            "statusListCredential": "http://localhost:8000/api/v1/status/1",
        }
        token, _, _ = issue_vc(ISSUER_DID, credential_status=credential_status)
        payload = jwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=["EdDSA"],
        )

        # JWT VC에서 credentialStatus는 payload 최상단이 아니라 vc 안에 있어야
        # 키오스크가 규격대로 찾을 수 있다.
        self.assertEqual(payload["vc"]["credentialStatus"], credential_status)
        self.assertNotIn("credentialStatus", payload)

    def test_issue_vc_omits_credential_status_when_not_given(self):
        token, _, _ = issue_vc(ISSUER_DID)
        payload = jwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=["EdDSA"],
        )

        self.assertNotIn("credentialStatus", payload["vc"])

    def test_issue_vc_can_omit_expiration(self):
        token, _, expires_at = issue_vc(ISSUER_DID, expires_days=0)
        payload = jwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=["EdDSA"],
        )

        self.assertNotIn("exp", payload)
        self.assertIsNone(expires_at)

    def test_build_did_document_exposes_same_did_key(self):
        document = build_did_document(ISSUER_DID)
        multibase = ISSUER_DID.removeprefix("did:key:")

        self.assertEqual(document["id"], ISSUER_DID)
        self.assertEqual(
            document["verificationMethod"][0]["publicKeyMultibase"],
            multibase,
        )
        self.assertEqual(
            document["assertionMethod"],
            [f"{ISSUER_DID}#{multibase}"],
        )

    def test_build_did_document_rejects_unsupported_method(self):
        with self.assertRaisesRegex(ValueError, "only did:key"):
            build_did_document("did:web:example.com")

    def test_issuer_private_key_requires_32_decoded_bytes(self):
        short_key = base64.b64encode(b"too-short").decode()

        with self.assertRaisesRegex(ValueError, "exactly 32 bytes"):
            _load_issuer_private_key(short_key)


class VcRouteTests(unittest.TestCase):
    @staticmethod
    def _get(path: str) -> httpx.Response:
        async def request() -> httpx.Response:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as client:
                return await client.get(path)

        return asyncio.run(request())

    def test_revised_issue_7_routes_are_registered(self):
        paths = set(app.openapi()["paths"])

        self.assertIn("/api/v1/adult-verifications", paths)
        self.assertIn("/api/v1/did/issue", paths)
        self.assertIn("/api/v1/did/issuer", paths)
        self.assertIn("/api/v1/did/{did}", paths)
        self.assertIn("/api/v1/status-lists/{status_list_id}", paths)
        self.assertNotIn("/api/v1/status/{status_list_id}", paths)
        self.assertNotIn("/api/v1/did/verify", paths)

    def test_status_list_route_documents_kiosk_api_key_authentication(self):
        operation = app.openapi()["paths"]["/api/v1/status-lists/{status_list_id}"]["get"]

        self.assertEqual(operation["security"], [{"KioskApiKey": []}])
        scheme = app.openapi()["components"]["securitySchemes"]["KioskApiKey"]
        self.assertEqual(scheme["type"], "apiKey")
        self.assertEqual(scheme["in"], "header")
        self.assertEqual(scheme["name"], "X-Kiosk-Key")
        self.assertEqual(
            operation["responses"]["401"]["content"]["application/json"]["schema"],
            {"$ref": "#/components/schemas/AuthErrorResponse"},
        )

    def test_issuer_did_document_endpoint(self):
        response = self._get("/api/v1/did/issuer")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["id"], ISSUER_DID)

    def test_did_resolver_rejects_unsupported_method(self):
        response = self._get("/api/v1/did/did:web:example.com")

        self.assertEqual(response.status_code, 400)
        self.assertIn("only did:key", response.json()["detail"])


class VcEndpointTests(unittest.IsolatedAsyncioTestCase):
    user = SimpleNamespace(id=1)

    async def test_record_adult_verification_persists_success(self):
        device = SimpleNamespace(id=2, user_id=1, status="ACTIVE")
        db = _FakeDb({(Device, 2): device})
        body = AdultVerificationRequest(
            device_id=2,
            age_check_passed=True,
            id_face_match_passed=True,
            liveness_passed=True,
            age_policy_version="2026-KR-19",
            model_version="MobileFaceNet-v1.0",
            threshold_version="th-2026-08",
        )

        row = await record_adult_verification(body, self.user, db)

        self.assertEqual(row.user_id, self.user.id)
        self.assertEqual(row.device_id, device.id)
        self.assertEqual(row.result_status, "SUCCESS")
        self.assertIsNone(row.failure_code)
        self.assertIn(row, db.added)
        self.assertEqual(db.commits, 1)
        # 성인 인증은 성공·실패 모두 감사 로그로 남아야 한다 (#9).
        self.assertEqual(len(db.audit_logs), 1)
        self.assertEqual(db.audit_logs[0].event_type, "ADULT_VERIFICATION_RECORDED")
        self.assertEqual(db.audit_logs[0].payload["result_status"], "SUCCESS")

    async def test_record_adult_verification_rejects_inactive_device(self):
        device = SimpleNamespace(id=2, user_id=1, status="LOST")
        db = _FakeDb({(Device, 2): device})
        body = AdultVerificationRequest(
            device_id=2,
            age_check_passed=True,
            id_face_match_passed=True,
        )

        with self.assertRaises(HTTPException) as raised:
            await record_adult_verification(body, self.user, db)

        self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(raised.exception.detail, "device is not active")
        self.assertEqual(db.commits, 0)

    async def test_issue_credential_rejects_invalidated_verification(self):
        verification = SimpleNamespace(
            id=3,
            user_id=1,
            device_id=2,
            result_status="SUCCESS",
            invalidated_at=datetime.now(timezone.utc),
        )
        db = _FakeDb({(AdultVerification, 3): verification})

        with self.assertRaises(HTTPException) as raised:
            await issue_credential(IssueVcRequest(adult_verification_id=3), self.user, db)

        self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(
            raised.exception.detail,
            "adult verification was invalidated",
        )
        self.assertEqual(db.commits, 0)

    async def test_issue_credential_rejects_inactive_device(self):
        verification = SimpleNamespace(
            id=3,
            user_id=1,
            device_id=2,
            result_status="SUCCESS",
            invalidated_at=None,
        )
        device = SimpleNamespace(
            id=2,
            user_id=1,
            status="REVOKED",
            holder_did=ISSUER_DID,
        )
        db = _FakeDb(
            {
                (AdultVerification, 3): verification,
                (Device, 2): device,
            }
        )

        with self.assertRaises(HTTPException) as raised:
            await issue_credential(IssueVcRequest(adult_verification_id=3), self.user, db)

        self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(raised.exception.detail, "device is not active")
        self.assertEqual(db.commits, 0)

    async def test_issue_credential_persists_signed_expiration(self):
        verification = SimpleNamespace(
            id=3,
            user_id=1,
            device_id=2,
            result_status="SUCCESS",
            invalidated_at=None,
        )
        device = SimpleNamespace(
            id=2,
            user_id=1,
            status="ACTIVE",
            holder_did=ISSUER_DID,
        )
        db = _FakeDb(
            {
                (AdultVerification, 3): verification,
                (Device, 2): device,
            }
        )

        response = await issue_credential(
            IssueVcRequest(adult_verification_id=3),
            self.user,
            db,
        )
        payload = jwt.decode(
            response.credential,
            options={"verify_signature": False},
            algorithms=["EdDSA"],
        )

        self.assertEqual(db.commits, 1)
        vc_rows = [r for r in db.added if isinstance(r, VcCredential)]
        self.assertEqual(len(vc_rows), 1)
        self.assertEqual(vc_rows[0].expires_at, response.expires_at)
        # VC 발급도 감사 대상이다. 단, JWT 본문은 남기지 않는다 (#9).
        self.assertEqual(len(db.audit_logs), 1)
        self.assertEqual(db.audit_logs[0].event_type, "VC_ISSUED")
        self.assertNotIn("credential", db.audit_logs[0].payload)
        self.assertEqual(
            datetime.fromtimestamp(payload["exp"], timezone.utc),
            response.expires_at,
        )

    @staticmethod
    def _issuable_rows():
        verification = SimpleNamespace(
            id=3,
            user_id=1,
            device_id=2,
            result_status="SUCCESS",
            invalidated_at=None,
        )
        device = SimpleNamespace(
            id=2,
            user_id=1,
            status="ACTIVE",
            holder_did=ISSUER_DID,
        )
        return {
            (AdultVerification, 3): verification,
            (Device, 2): device,
        }

    @staticmethod
    def _credential_status_of(response):
        payload = jwt.decode(
            response.credential,
            options={"verify_signature": False},
            algorithms=["EdDSA"],
        )
        return payload["vc"]["credentialStatus"]

    async def test_issue_credential_creates_first_status_list(self):
        """상태 목록이 하나도 없는 첫 발급은 목록을 만들고 인덱스를 배정한다."""
        db = _FakeDb(self._issuable_rows())

        await issue_credential(
            IssueVcRequest(adult_verification_id=3),
            self.user,
            db,
        )

        status_lists = [r for r in db.added if isinstance(r, CredentialStatusList)]
        self.assertEqual(len(status_lists), 1)
        status_list = status_lists[0]
        self.assertEqual(status_list.status_purpose, "REVOCATION")
        self.assertEqual(status_list.issuer_did, ISSUER_DID)
        # 비어 있으면 키오스크가 해석할 값이 없다. 전부 0인 비트열이어야 한다.
        self.assertTrue(status_list.encoded_list)
        # id가 정해진 뒤 실제 URL로 채워져야 한다.
        self.assertNotIn("pending", status_list.status_list_url)
        self.assertTrue(
            status_list.status_list_url.endswith(f"/api/v1/status-lists/{status_list.id}")
        )

        vc_row = next(r for r in db.added if isinstance(r, VcCredential))
        self.assertEqual(vc_row.status_list_id, status_list.id)
        # 인덱스는 무작위로 배정되므로 특정 값이 아니라 범위를 확인한다.
        self.assertIsNotNone(vc_row.status_list_index)
        self.assertTrue(0 <= vc_row.status_list_index < BITSTRING_SIZE)

    async def test_issue_credential_embeds_matching_credential_status(self):
        """VC 본문의 credentialStatus가 DB에 저장된 배정과 일치해야 한다."""
        status_list = SimpleNamespace(
            id=7,
            status_list_url="http://localhost:8000/api/v1/status/7",
        )
        db = _FakeDb(
            self._issuable_rows(),
            scalar_results={CredentialStatusList: status_list},
        )

        response = await issue_credential(
            IssueVcRequest(adult_verification_id=3),
            self.user,
            db,
        )

        vc_row = next(r for r in db.added if isinstance(r, VcCredential))
        self.assertEqual(vc_row.status_list_id, 7)
        # 인덱스는 무작위다. 값 자체가 아니라 DB와 VC 본문이 같은 값을
        # 쓰는지가 이 테스트의 목적이다.
        assigned_index = vc_row.status_list_index
        self.assertTrue(0 <= assigned_index < BITSTRING_SIZE)
        # 이미 목록이 있으므로 새로 만들지 않는다.
        self.assertEqual(
            [r for r in db.added if isinstance(r, CredentialStatusList)], []
        )

        credential_status = self._credential_status_of(response)
        self.assertEqual(
            credential_status,
            {
                "id": f"http://localhost:8000/api/v1/status/7#{assigned_index}",
                "type": "StatusList2021Entry",
                # DB는 'REVOCATION'이지만 VC 본문은 규격대로 소문자다.
                "statusPurpose": "revocation",
                # 규격상 정수가 아니라 문자열이다.
                "statusListIndex": str(assigned_index),
                "statusListCredential": "http://localhost:8000/api/v1/status/7",
            },
        )
        self.assertIsInstance(credential_status["statusListIndex"], str)

    async def test_issue_credential_rejects_full_status_list(self):
        """범위를 벗어난 인덱스를 조용히 배정하지 않는다."""
        status_list = SimpleNamespace(
            id=7,
            status_list_url="http://localhost:8000/api/v1/status/7",
        )
        db = _FakeDb(
            self._issuable_rows(),
            scalar_results={CredentialStatusList: status_list},
            scalar_default=BITSTRING_SIZE,
        )

        with self.assertRaises(HTTPException) as raised:
            await issue_credential(
                IssueVcRequest(adult_verification_id=3),
                self.user,
                db,
            )

        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(raised.exception.detail, "status list is full")
        self.assertEqual(db.commits, 0)

    async def test_issue_credential_retries_an_already_assigned_index(self):
        status_list = SimpleNamespace(
            id=7,
            status_list_url="http://localhost:8000/api/v1/status-lists/7",
        )
        db = _FakeDb(
            self._issuable_rows(),
            scalar_results={CredentialStatusList: status_list},
        )

        with (
            patch("app.api.v1.endpoints.vc.secrets.randbelow", side_effect=[4, 9]) as pick,
            patch(
                "app.api.v1.endpoints.vc._index_is_taken",
                new_callable=AsyncMock,
                side_effect=[True, False],
            ) as is_taken,
        ):
            response = await issue_credential(
                IssueVcRequest(adult_verification_id=3), self.user, db
            )

        self.assertEqual(pick.call_count, 2)
        self.assertEqual(is_taken.await_args_list[0].args, (db, 7, 4))
        self.assertEqual(is_taken.await_args_list[1].args, (db, 7, 9))
        self.assertEqual(self._credential_status_of(response)["statusListIndex"], "9")
        vc_row = next(row for row in db.added if isinstance(row, VcCredential))
        self.assertEqual(vc_row.status_list_index, 9)
        self.assertEqual(db.commits, 1)

    async def test_repeated_collisions_use_fallback_instead_of_claiming_list_is_full(self):
        status_list = SimpleNamespace(
            id=7,
            status_list_url="http://localhost:8000/api/v1/status-lists/7",
        )
        db = _FakeDb(
            self._issuable_rows(),
            scalar_results={CredentialStatusList: status_list},
        )

        with (
            patch("app.api.v1.endpoints.vc.secrets.randbelow", return_value=4) as pick,
            patch("app.api.v1.endpoints.vc._index_is_taken", new=AsyncMock(return_value=True)),
            patch(
                "app.api.v1.endpoints.vc._pick_unused_index",
                new_callable=AsyncMock,
                return_value=9,
            ) as fallback,
        ):
            response = await issue_credential(
                IssueVcRequest(adult_verification_id=3), self.user, db
            )

        self.assertEqual(pick.call_count, _INDEX_PICK_ATTEMPTS)
        fallback.assert_awaited_once_with(db, 7)
        self.assertEqual(self._credential_status_of(response)["statusListIndex"], "9")
        self.assertEqual(db.commits, 1)


class StatusListEndpointTests(unittest.IsolatedAsyncioTestCase):
    """#27 — 등록된 키오스크가 인증 후 받아가는 폐기 목록."""

    URL = "http://localhost:8000/api/v1/status/7"

    def _status_list(self, **overrides):
        values = {
            "id": 7,
            "status_list_url": self.URL,
            "status_purpose": "REVOCATION",
            "encoded_list": empty_encoded_list(),
            "version": 1,
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    @staticmethod
    async def _http_get(db, path="/api/v1/status-lists/7", headers=None):
        raw_key = "test-status-list-reader-key"
        db.scalar_results[Kiosk] = SimpleNamespace(
            id=5,
            kiosk_identifier="test-status-list-reader",
            api_key_hash=hashlib.sha256(raw_key.encode()).hexdigest(),
            status="ACTIVE",
        )
        request_headers = httpx.Headers(headers)
        request_headers["X-Kiosk-Key"] = f"test-status-list-reader:{raw_key}"

        async def override_db():
            yield db

        previous_overrides = app.dependency_overrides.copy()
        app.dependency_overrides[get_db] = override_db
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://testserver"
            ) as client:
                return await client.get(path, headers=request_headers)
        finally:
            app.dependency_overrides.clear()
            app.dependency_overrides.update(previous_overrides)

    @staticmethod
    def _public_key():
        return Ed25519PrivateKey.from_private_bytes(_ISSUER_KEY_BYTES).public_key()

    def _decode(self, response):
        """키오스크가 하는 일: 발급자 공개키로 서명을 검증하고 내용을 읽는다."""
        return jwt.decode(
            response.body.decode(),
            self._public_key(),
            algorithms=["EdDSA"],
        )

    async def test_returns_signed_status_list_credential(self):
        status_list = SimpleNamespace(
            id=7,
            status_list_url=self.URL,
            status_purpose="REVOCATION",
            encoded_list=empty_encoded_list(),
            version=1,
        )
        db = _FakeDb({(CredentialStatusList, 7): status_list})

        response = await get_status_list(7, db)

        self.assertEqual(response.media_type, "application/jwt")
        payload = self._decode(response)

        self.assertEqual(payload["iss"], ISSUER_DID)
        credential = payload["vc"]
        self.assertIn("StatusList2021Credential", credential["type"])
        self.assertEqual(credential["id"], self.URL)

        subject = credential["credentialSubject"]
        self.assertEqual(subject["type"], "StatusList2021")
        # DB는 'REVOCATION'이지만 규격상 VC 본문은 소문자다.
        self.assertEqual(subject["statusPurpose"], "revocation")

        # 오프라인 정책상 exp는 없다. 이 자체가 목록의 최신성을 보장하지는 않는다.
        self.assertNotIn("exp", payload)

    async def test_tampered_list_fails_signature_check(self):
        """서명이 없으면 전부 0인 가짜 목록으로 바꿔치기할 수 있다."""
        status_list = SimpleNamespace(
            id=7,
            status_list_url=self.URL,
            status_purpose="REVOCATION",
            encoded_list=empty_encoded_list(),
            version=1,
        )
        db = _FakeDb({(CredentialStatusList, 7): status_list})

        response = await get_status_list(7, db)
        attacker_key = Ed25519PrivateKey.generate().public_key()

        with self.assertRaises(jwt.InvalidSignatureError):
            jwt.decode(
                response.body.decode(), attacker_key, algorithms=["EdDSA"]
            )

    async def test_revoked_bits_are_visible_to_kiosk(self):
        """폐기된 VC의 비트가 키오스크가 받는 목록에 그대로 나타나야 한다."""
        bitstring = new_bitstring()
        set_bit(bitstring, 3)
        set_bit(bitstring, 94567)
        status_list = SimpleNamespace(
            id=7,
            status_list_url=self.URL,
            status_purpose="REVOCATION",
            encoded_list=encode_bitstring(bitstring),
            version=3,
        )
        db = _FakeDb({(CredentialStatusList, 7): status_list})

        response = await get_status_list(7, db)
        subject = self._decode(response)["vc"]["credentialSubject"]
        received = decode_bitstring(subject["encodedList"])

        self.assertTrue(get_bit(received, 3))
        self.assertTrue(get_bit(received, 94567))
        # 폐기되지 않은 VC는 계속 통과해야 한다.
        for untouched in (0, 2, 4, 94566, 94568, BITSTRING_SIZE - 1):
            self.assertFalse(get_bit(received, untouched))

    async def test_empty_encoded_list_is_not_signed_as_empty(self):
        """비어 있는 목록을 "폐기 없음"으로 서명해 주면 안 된다.

        전부 0인 목록에 발급자 서명을 붙이는 것은 "폐기된 VC가 하나도 없다"는
        보증이다. 저장된 값이 손상됐을 때 그 보증을 해주면 폐기된 VC가
        키오스크에서 되살아난다. 조회를 실패시키는 편이 안전하다.
        """
        status_list = SimpleNamespace(
            id=7,
            status_list_url=self.URL,
            status_purpose="REVOCATION",
            encoded_list=None,
            version=1,
        )
        db = _FakeDb({(CredentialStatusList, 7): status_list})

        with self.assertRaises(HTTPException) as raised:
            await get_status_list(7, db)

        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(raised.exception.detail, "status list is not available")

    async def test_invalid_nonempty_lists_are_rejected_before_signing(self):
        short_gzip = base64.urlsafe_b64encode(gzip.compress(b"\x00")).decode().rstrip("=")
        for encoded in (
            "", "not-a-gzip-bitstring", short_gzip,
            empty_encoded_list() + "!!!!", empty_encoded_list() + "\n",
        ):
            with self.subTest(encoded=encoded):
                row = self._status_list(encoded_list=encoded)
                db = _FakeDb({(CredentialStatusList, 7): row})
                with patch("app.api.v1.endpoints.vc.issue_status_list_vc") as signer:
                    with self.assertRaises(HTTPException) as raised:
                        await get_status_list(7, db)

                self.assertEqual(raised.exception.status_code, 503)
                self.assertEqual(raised.exception.headers["Cache-Control"], "no-store")
                signer.assert_not_called()

    async def test_canonical_and_legacy_routes_serve_existing_signed_url(self):
        row = self._status_list()
        db = _FakeDb({(CredentialStatusList, 7): row})

        canonical = await self._http_get(db)
        legacy = await self._http_get(db, "/api/v1/status/7")

        for response in (canonical, legacy):
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["content-type"], "application/jwt")
            self.assertEqual(response.headers["cache-control"], "private, no-cache")
            self.assertEqual(response.headers["vary"], "X-Kiosk-Key")
            payload = jwt.decode(response.text, self._public_key(), algorithms=["EdDSA"])
            self.assertEqual(payload["vc"]["id"], self.URL)
        self.assertEqual(canonical.headers["etag"], legacy.headers["etag"])
        self.assertEqual(row.status_list_url, self.URL)

    async def test_matching_etags_return_bodyless_304_with_cache_headers(self):
        row = self._status_list()
        db = _FakeDb({(CredentialStatusList, 7): row})
        initial = await self._http_get(db)
        etag = initial.headers["etag"]
        strong_etag = etag.removeprefix("W/")
        variants = (
            {"If-None-Match": etag},
            {"If-None-Match": strong_etag},
            {"If-None-Match": f'"unrelated", {etag}'},
            {"If-None-Match": "*"},
            [("If-None-Match", '"unrelated"'), ("If-None-Match", strong_etag)],
        )
        for headers in variants:
            with self.subTest(headers=headers):
                with patch("app.api.v1.endpoints.vc.issue_status_list_vc") as signer:
                    response = await self._http_get(db, headers=headers)

                self.assertEqual(response.status_code, 304)
                self.assertEqual(response.content, b"")
                self.assertEqual(response.headers["etag"], etag)
                self.assertEqual(
                    response.headers["cache-control"], initial.headers["cache-control"]
                )
                self.assertEqual(response.headers["cache-control"], "private, no-cache")
                self.assertEqual(response.headers["vary"], "X-Kiosk-Key")
                signer.assert_not_called()

    async def test_nonmatching_etags_return_signed_body(self):
        row = self._status_list()
        db = _FakeDb({(CredentialStatusList, 7): row})
        initial = await self._http_get(db)

        for header in ('"other"', 'W/"other", "another"', "invalid-unquoted-etag"):
            with self.subTest(header=header):
                response = await self._http_get(db, headers={"If-None-Match": header})

                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers["etag"], initial.headers["etag"])
                payload = jwt.decode(response.text, self._public_key(), algorithms=["EdDSA"])
                self.assertEqual(payload["vc"]["id"], self.URL)

    async def test_corrupt_list_is_not_hidden_by_matching_conditional_request(self):
        row = self._status_list()
        db = _FakeDb({(CredentialStatusList, 7): row})
        initial = await self._http_get(db)
        short_gzip = base64.urlsafe_b64encode(gzip.compress(b"\x00")).decode().rstrip("=")

        for encoded in (
            None, "", "not-a-gzip-bitstring", short_gzip,
            empty_encoded_list() + "!!!!", empty_encoded_list() + "\n",
        ):
            for header in (initial.headers["etag"], "*"):
                with self.subTest(encoded=encoded, header=header):
                    row.encoded_list = encoded
                    with patch("app.api.v1.endpoints.vc.issue_status_list_vc") as signer:
                        response = await self._http_get(db, headers={"If-None-Match": header})

                    self.assertEqual(response.status_code, 503)
                    self.assertEqual(response.headers["cache-control"], "no-store")
                    self.assertNotIn("etag", response.headers)
                    signer.assert_not_called()

    async def test_content_version_and_url_changes_invalidate_old_etag(self):
        for change in ("bits", "version", "url"):
            with self.subTest(change=change):
                row = self._status_list()
                db = _FakeDb({(CredentialStatusList, 7): row})
                initial = await self._http_get(db)
                if change == "bits":
                    bitstring = new_bitstring()
                    set_bit(bitstring, 94567)
                    row.encoded_list = encode_bitstring(bitstring)
                elif change == "version":
                    row.version += 1
                else:
                    row.status_list_url = "http://localhost:8000/api/v1/status-lists/7"

                response = await self._http_get(db, headers={"If-None-Match": initial.headers["etag"]})

                self.assertEqual(response.status_code, 200)
                self.assertNotEqual(response.headers["etag"], initial.headers["etag"])
                payload = jwt.decode(response.text, self._public_key(), algorithms=["EdDSA"])
                self.assertEqual(payload["vc"]["id"], row.status_list_url)
                if change == "bits":
                    received = decode_bitstring(payload["vc"]["credentialSubject"]["encodedList"])
                    self.assertTrue(get_bit(received, 94567))

    async def test_missing_status_list_returns_404(self):
        db = _FakeDb()

        with self.assertRaises(HTTPException) as raised:
            await get_status_list(999, db)

        self.assertEqual(raised.exception.status_code, 404)
        self.assertEqual(raised.exception.detail, "status list not found")


if __name__ == "__main__":
    unittest.main()
