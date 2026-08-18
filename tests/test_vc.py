import asyncio
import base64
import os
import unittest

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
from app.main import app  # noqa: E402


class VcCoreTests(unittest.TestCase):
    def test_issue_vc_uses_fixed_issuer_key_and_minimum_claims(self):
        holder_did = ISSUER_DID
        token, credential_id = issue_vc(holder_did, expires_days=1)

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

    def test_issue_vc_can_omit_expiration(self):
        token, _ = issue_vc(ISSUER_DID, expires_days=0)
        payload = jwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=["EdDSA"],
        )

        self.assertNotIn("exp", payload)

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


if __name__ == "__main__":
    unittest.main()
