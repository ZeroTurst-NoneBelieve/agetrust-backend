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
    issue_credential,
    record_adult_verification,
)
from app.main import app  # noqa: E402
from app.models import AdultVerification, Device, VcCredential  # noqa: E402
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
        self.assertNotIn("/api/v1/did/verify", paths)

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


if __name__ == "__main__":
    unittest.main()
