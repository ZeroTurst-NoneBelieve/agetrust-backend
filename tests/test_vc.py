import asyncio
import base64
import os
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace

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
    get_status_list,
    issue_credential,
    record_adult_verification,
)
from app.main import app  # noqa: E402
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
        self.assertIn("/api/v1/status/{status_list_id}", paths)
        self.assertNotIn("/api/v1/did/verify", paths)

    def test_status_list_endpoint_requires_no_auth(self):
        """키오스크가 호출하므로 로그인 없이 열려 있어야 한다."""
        operation = app.openapi()["paths"]["/api/v1/status/{status_list_id}"]["get"]

        self.assertNotIn("security", operation)

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
        """상태 목록이 하나도 없는 첫 발급은 목록을 만들고 0번을 배정한다."""
        db = _FakeDb(self._issuable_rows())

        response = await issue_credential(
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
            status_list.status_list_url.endswith(f"/api/v1/status/{status_list.id}")
        )

        vc_row = next(r for r in db.added if isinstance(r, VcCredential))
        self.assertEqual(vc_row.status_list_id, status_list.id)
        self.assertEqual(vc_row.status_list_index, 0)

    async def test_issue_credential_embeds_matching_credential_status(self):
        """VC 본문의 credentialStatus가 DB에 저장된 배정과 일치해야 한다."""
        status_list = SimpleNamespace(
            id=7,
            status_list_url="http://localhost:8000/api/v1/status/7",
        )
        db = _FakeDb(
            self._issuable_rows(),
            scalar_results={CredentialStatusList: status_list},
            scalar_default=42,  # MAX(index) + 1
        )

        response = await issue_credential(
            IssueVcRequest(adult_verification_id=3),
            self.user,
            db,
        )

        vc_row = next(r for r in db.added if isinstance(r, VcCredential))
        self.assertEqual(vc_row.status_list_id, 7)
        self.assertEqual(vc_row.status_list_index, 42)
        # 이미 목록이 있으므로 새로 만들지 않는다.
        self.assertEqual(
            [r for r in db.added if isinstance(r, CredentialStatusList)], []
        )

        credential_status = self._credential_status_of(response)
        self.assertEqual(
            credential_status,
            {
                "id": "http://localhost:8000/api/v1/status/7#42",
                "type": "StatusList2021Entry",
                # DB는 'REVOCATION'이지만 VC 본문은 규격대로 소문자다.
                "statusPurpose": "revocation",
                # 규격상 정수가 아니라 문자열이다.
                "statusListIndex": "42",
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


class StatusListEndpointTests(unittest.IsolatedAsyncioTestCase):
    """#27 — 키오스크가 받아가는 공개 폐기 목록."""

    URL = "http://localhost:8000/api/v1/status/7"

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

        # 목록은 최신 상태 그 자체이므로 만료를 두지 않는다.
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

    async def test_empty_encoded_list_falls_back_to_all_zero(self):
        """목록이 아직 비어 있어도 해석 가능한 비트열을 돌려준다."""
        status_list = SimpleNamespace(
            id=7,
            status_list_url=self.URL,
            status_purpose="REVOCATION",
            encoded_list=None,
            version=1,
        )
        db = _FakeDb({(CredentialStatusList, 7): status_list})

        response = await get_status_list(7, db)
        subject = self._decode(response)["vc"]["credentialSubject"]
        received = decode_bitstring(subject["encodedList"])

        self.assertEqual(len(received) * 8, BITSTRING_SIZE)
        self.assertFalse(any(received))

    async def test_missing_status_list_returns_404(self):
        db = _FakeDb()

        with self.assertRaises(HTTPException) as raised:
            await get_status_list(999, db)

        self.assertEqual(raised.exception.status_code, 404)
        self.assertEqual(raised.exception.detail, "status list not found")


if __name__ == "__main__":
    unittest.main()