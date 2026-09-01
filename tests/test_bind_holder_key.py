"""Holder 키 재바인딩 시 기존 ACTIVE VC 폐기 처리 회귀 테스트.

did:key는 자기완결적이라 키오스크가 서버를 조회하지 않는다. #22에서는
"서버 DB에 폐기 사실이 남는지"까지만 보장했고, 실제 차단은 폐기 목록
동기화가 필요하다는 요구사항만 남겨두었다.

#27에서 StatusList2021을 연결했으므로, 이제 폐기 목록의 비트까지 켜지는지도
함께 확인한다.
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
from app.core.status_list import (  # noqa: E402
    decode_bitstring,
    empty_encoded_list,
    get_bit,
)
from app.models import CredentialStatusList, Device  # noqa: E402
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
        # 어떤 VC가 폐기됐는지 알아야 폐기 목록의 비트를 켤 수 있다.
        self.assertIn("RETURNING", compiled.upper())
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

    async def test_rebinding_flips_status_list_bits(self):
        """#27 — 폐기된 VC의 비트가 실제로 켜지고 version이 오른다."""
        pem, signature, _ = _make_key_material(2)
        device = SimpleNamespace(
            id=2, user_id=1, status="ACTIVE",
            holder_did="did:key:zOldKeyFromLostPhone", holder_public_key=None,
        )
        status_list = SimpleNamespace(
            id=7, encoded_list=empty_encoded_list(), version=1
        )
        db = _FakeDb(
            {(Device, 2): device},
            scalar_results={CredentialStatusList: status_list},
            # 폐기된 VC 두 건이 7번 목록의 3번과 5번을 쓰고 있었다.
            returning_rows=[(7, 3), (7, 5)],
        )
        body = BindHolderKeyRequest(
            device_id=2, holder_public_key_pem=pem, proof_signature_b64=signature
        )

        await bind_holder_key(body, self.user, db)

        bitstring = decode_bitstring(status_list.encoded_list)
        self.assertTrue(get_bit(bitstring, 3))
        self.assertTrue(get_bit(bitstring, 5))
        # 옆 비트는 건드리지 않아야 한다. 잘못 켜면 관계없는 사람이 거부된다.
        for untouched in (0, 2, 4, 6, 7, 8):
            self.assertFalse(get_bit(bitstring, untouched), f"{untouched}번이 켜졌다")
        # 키오스크가 캐시를 갱신할 근거가 된다.
        self.assertEqual(status_list.version, 2)

        audit = db.audit_logs[0]
        self.assertEqual(audit.payload["revoked_vc_count"], 2)
        self.assertEqual(audit.payload["revoked_status_list_bits"], 2)

    async def test_rebinding_skips_credentials_without_status_list(self):
        """상태 목록 도입 전에 발급된 VC는 켤 비트가 없어도 폐기는 진행된다."""
        pem, signature, _ = _make_key_material(2)
        device = SimpleNamespace(
            id=2, user_id=1, status="ACTIVE",
            holder_did="did:key:zOldKeyFromLostPhone", holder_public_key=None,
        )
        db = _FakeDb(
            {(Device, 2): device},
            # 배정이 없던 옛 VC 한 건 + 배정이 있는 VC는 없음.
            returning_rows=[(None, None)],
        )
        body = BindHolderKeyRequest(
            device_id=2, holder_public_key_pem=pem, proof_signature_b64=signature
        )

        await bind_holder_key(body, self.user, db)

        audit = db.audit_logs[0]
        self.assertEqual(audit.payload["revoked_vc_count"], 1)
        # 켤 자리가 없으므로 0이다. 두 값이 다르다는 것 자체가 감사 정보다.
        self.assertEqual(audit.payload["revoked_status_list_bits"], 0)
        self.assertEqual(db.commits, 1)

    async def test_missing_status_list_aborts_instead_of_skipping(self):
        """VC가 가리키는 목록이 없으면 폐기를 성공으로 끝내면 안 된다.

        조용히 넘어가면 DB에는 REVOKED로 남지만 키오스크는 계속 통과시킨다.
        폐기한 줄 알았는데 안 된 상태가 가장 위험하므로 전체를 되돌린다.
        """
        pem, signature, _ = _make_key_material(2)
        device = SimpleNamespace(
            id=2, user_id=1, status="ACTIVE",
            holder_did="did:key:zOldKeyFromLostPhone", holder_public_key=None,
        )
        db = _FakeDb(
            {(Device, 2): device},
            # 배정은 있는데 그 목록을 찾을 수 없는 상황.
            returning_rows=[(7, 3)],
        )
        body = BindHolderKeyRequest(
            device_id=2, holder_public_key_pem=pem, proof_signature_b64=signature
        )

        with self.assertRaises(RuntimeError):
            await bind_holder_key(body, self.user, db)

        self.assertEqual(db.commits, 0, "실패했는데 커밋됐다")

    async def test_corrupted_status_list_aborts(self):
        """encoded_list가 비어 있으면 빈 목록으로 새로 시작하면 안 된다.

        목록은 생성 시점에 채워지므로 비어 있다는 것은 손상됐다는 뜻이다.
        새 비트열로 덮어쓰면 이전에 폐기된 VC들이 모두 되살아난다.
        """
        pem, signature, _ = _make_key_material(2)
        device = SimpleNamespace(
            id=2, user_id=1, status="ACTIVE",
            holder_did="did:key:zOldKeyFromLostPhone", holder_public_key=None,
        )
        status_list = SimpleNamespace(id=7, encoded_list=None, version=1)
        db = _FakeDb(
            {(Device, 2): device},
            scalar_results={CredentialStatusList: status_list},
            returning_rows=[(7, 3)],
        )
        body = BindHolderKeyRequest(
            device_id=2, holder_public_key_pem=pem, proof_signature_b64=signature
        )

        with self.assertRaises(RuntimeError):
            await bind_holder_key(body, self.user, db)

        self.assertEqual(db.commits, 0, "실패했는데 커밋됐다")


if __name__ == "__main__":
    unittest.main()
