"""#22 — Holder 키 재바인딩 시 기존 ACTIVE VC 폐기 처리 회귀 테스트.

did:key는 자기완결적이라 키오스크가 서버를 조회하지 않는다.
따라서 이 테스트는 "서버 DB에 폐기 사실이 남는지"까지만 보장하며,
실제 차단은 폐기 목록 동기화가 구현되어야 완성된다.
"""

import base64
import os
import unittest
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from app.api.v1.endpoints.auth import bind_holder_key  # noqa: E402
from app.core.did_key import public_key_to_did_key  # noqa: E402
from app.models import Device  # noqa: E402
from app.schemas.device import BindHolderKeyRequest  # noqa: E402
from tests.fakes import FakeDb as _FakeDb  # noqa: E402


def _make_key_material(device_id: int):
    """테스트용 Holder 키쌍과 소유증명 서명을 만든다."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()
    signature = base64.b64encode(private_key.sign(str(device_id).encode())).decode()
    return pem, signature, public_key_to_did_key(public_key)


class BindHolderKeyRevocationTests(unittest.IsolatedAsyncioTestCase):
    user = SimpleNamespace(id=1)

    async def test_rebinding_new_key_revokes_existing_credentials(self):
        """holder_did가 바뀌면 기존 ACTIVE VC에 폐기 UPDATE가 나가야 한다."""
        pem, signature, new_did = _make_key_material(2)
        device = SimpleNamespace(
            id=2, user_id=1, status="ACTIVE",
            holder_did="did:key:zOldKeyFromLostPhone", holder_public_key=None,
        )
        db = _FakeDb({(Device, 2): device})
        body = BindHolderKeyRequest(
            device_id=2, holder_public_key_pem=pem, proof_signature_b64=signature
        )

        await bind_holder_key(body, self.user, db)

        self.assertEqual(device.holder_did, new_did)
        self.assertEqual(len(db.executed), 1, "폐기 UPDATE가 실행되지 않았다")

        compiled = str(db.executed[0].compile(compile_kwargs={"literal_binds": True}))
        self.assertIn("UPDATE vc_credentials", compiled)
        self.assertIn("REVOKED", compiled)
        self.assertEqual(db.commits, 1)

    async def test_first_binding_does_not_revoke(self):
        """최초 바인딩(holder_did가 None)은 폐기 대상이 없다."""
        pem, signature, new_did = _make_key_material(2)
        device = SimpleNamespace(
            id=2, user_id=1, status="ACTIVE",
            holder_did=None, holder_public_key=None,
        )
        db = _FakeDb({(Device, 2): device})
        body = BindHolderKeyRequest(
            device_id=2, holder_public_key_pem=pem, proof_signature_b64=signature
        )

        await bind_holder_key(body, self.user, db)

        self.assertEqual(device.holder_did, new_did)
        self.assertEqual(db.executed, [], "최초 바인딩인데 폐기가 실행됐다")

    async def test_rebinding_same_key_does_not_revoke(self):
        """같은 키를 다시 바인딩하면 소유자가 그대로이므로 폐기하지 않는다."""
        pem, signature, same_did = _make_key_material(2)
        device = SimpleNamespace(
            id=2, user_id=1, status="ACTIVE",
            holder_did=same_did, holder_public_key=pem,
        )
        db = _FakeDb({(Device, 2): device})
        body = BindHolderKeyRequest(
            device_id=2, holder_public_key_pem=pem, proof_signature_b64=signature
        )

        await bind_holder_key(body, self.user, db)

        self.assertEqual(db.executed, [], "동일 키 재바인딩인데 폐기가 실행됐다")


if __name__ == "__main__":
    unittest.main()