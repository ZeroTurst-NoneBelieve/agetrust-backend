"""#9 — 감사 로그 해시 체인 및 관리자 조회 API 테스트.

DB 없이 도는 단위 테스트다. 체인 계산·검증 로직은 순수 함수라
`compute_event_hash` / `recompute_hash_for`만으로 전부 덮을 수 있다.
"""

import base64
import os
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from app.core.audit import (  # noqa: E402
    GENESIS_HASH,
    canonical_json,
    compute_event_hash,
    mask_phone,
    recompute_hash_for,
)

BASE_TIME = datetime(2026, 8, 24, 9, 0, 0, tzinfo=timezone.utc)


def _event(previous_hash, *, index=0, payload=None, event_type="LOGIN_SUCCEEDED"):
    """결정적인 값으로 감사 이벤트 레코드를 만든다."""
    return SimpleNamespace(
        id=index + 1,
        event_id=uuid.UUID(int=index + 1),
        event_type=event_type,
        actor_type="USER",
        actor_ref=str(index + 1),
        aggregate_type="USER",
        aggregate_id=str(index + 1),
        payload=payload if payload is not None else {"login_id": f"user{index}"},
        previous_hash=previous_hash,
        created_at=BASE_TIME + timedelta(seconds=index),
        event_hash=None,
    )


def _seal(row):
    """레코드의 event_hash를 계산해 채운다."""
    row.event_hash = recompute_hash_for(row)
    return row


def _build_chain(length):
    rows, previous = [], None
    for i in range(length):
        row = _seal(_event(previous, index=i))
        rows.append(row)
        previous = row.event_hash
    return rows


class CanonicalJsonTests(unittest.TestCase):
    def test_key_order_does_not_change_output(self):
        """dict 삽입 순서가 달라도 같은 바이트열이어야 한다."""
        self.assertEqual(
            canonical_json({"b": 1, "a": 2}),
            canonical_json({"a": 2, "b": 1}),
        )

    def test_non_ascii_is_preserved(self):
        """한글이 유니코드 이스케이프로 변환되지 않아야 한다."""
        self.assertIn("성인", canonical_json({"k": "성인"}))


class EventHashTests(unittest.TestCase):
    def test_hash_is_deterministic(self):
        row = _event(None)
        self.assertEqual(recompute_hash_for(row), recompute_hash_for(row))

    def test_hash_is_sha256_hex(self):
        row = _seal(_event(None))
        self.assertEqual(len(row.event_hash), 64)
        int(row.event_hash, 16)  # 16진수가 아니면 ValueError

    def test_previous_hash_changes_the_hash(self):
        """직전 해시가 다르면 같은 내용이라도 다른 해시가 나와야 한다.

        이게 성립하지 않으면 체인이 아니라 그냥 독립된 해시 목록이다.
        """
        a = _seal(_event(None))
        b = _seal(_event("f" * 64))
        self.assertNotEqual(a.event_hash, b.event_hash)

    def test_none_previous_hash_uses_genesis(self):
        """체인의 첫 이벤트는 previous_hash=None과 GENESIS가 같게 취급된다."""
        self.assertEqual(
            compute_event_hash(
                previous_hash=None, event_id=uuid.UUID(int=1), event_type="T",
                actor_type="USER", actor_ref=None, aggregate_type=None,
                aggregate_id=None, payload={}, created_at=BASE_TIME,
            ),
            compute_event_hash(
                previous_hash=GENESIS_HASH, event_id=uuid.UUID(int=1), event_type="T",
                actor_type="USER", actor_ref=None, aggregate_type=None,
                aggregate_id=None, payload={}, created_at=BASE_TIME,
            ),
        )


class TamperDetectionTests(unittest.TestCase):
    """DB 쓰기 권한이 있어도 과거 기록을 조용히 못 고치는지 확인한다."""

    def test_intact_chain_verifies(self):
        rows = _build_chain(5)
        previous = None
        for i, row in enumerate(rows):
            self.assertEqual(recompute_hash_for(row), row.event_hash)
            if i > 0:
                self.assertEqual(row.previous_hash, previous)
            previous = row.event_hash

    def test_payload_tampering_breaks_own_hash(self):
        """본문을 고치면 그 레코드의 저장된 해시와 어긋난다."""
        rows = _build_chain(5)
        rows[2].payload = {"login_id": "attacker"}
        self.assertNotEqual(recompute_hash_for(rows[2]), rows[2].event_hash)

    def test_tampering_also_breaks_following_links(self):
        """공격자가 고친 레코드의 해시까지 다시 계산해도, 뒤 레코드와의 연결이 끊긴다."""
        rows = _build_chain(5)
        rows[2].payload = {"login_id": "attacker"}
        rows[2].event_hash = recompute_hash_for(rows[2])  # 자기 해시는 맞춰놨다

        # 그래도 다음 레코드의 previous_hash와는 어긋난다.
        self.assertNotEqual(rows[3].previous_hash, rows[2].event_hash)

    def test_deleting_a_record_breaks_the_link(self):
        """중간 레코드를 지우면 연결이 끊긴다."""
        rows = _build_chain(5)
        remaining = rows[:2] + rows[3:]
        self.assertNotEqual(remaining[2].previous_hash, remaining[1].event_hash)

    def test_timestamp_tampering_is_detected(self):
        """created_at을 고쳐도 해시가 깨진다 (시각 조작 방지)."""
        rows = _build_chain(3)
        rows[1].created_at = BASE_TIME + timedelta(days=30)
        self.assertNotEqual(recompute_hash_for(rows[1]), rows[1].event_hash)


class MaskPhoneTests(unittest.TestCase):
    def test_masks_middle_digits(self):
        self.assertEqual(mask_phone("010-1234-5678"), "010****5678")

    def test_keeps_enough_to_trace(self):
        """앞 3자리와 뒤 4자리는 남아 추적은 가능해야 한다."""
        masked = mask_phone("01012345678")
        self.assertTrue(masked.startswith("010"))
        self.assertTrue(masked.endswith("5678"))

    def test_original_number_is_not_present(self):
        self.assertNotIn("1234567", mask_phone("010-1234-5678"))

    def test_none_and_short_input(self):
        self.assertIsNone(mask_phone(None))
        self.assertIsNone(mask_phone(""))
        self.assertEqual(mask_phone("1234"), "****")

    def test_masks_seven_digit_number_without_exposing_original(self):
        self.assertEqual(mask_phone("+1234567"), "***4567")

    def test_masks_five_and_six_digit_inputs(self):
        self.assertEqual(mask_phone("12345"), "*2345")
        self.assertEqual(mask_phone("123456"), "**3456")


class PayloadSecretsTests(unittest.TestCase):
    """감사 로그에 그대로 재사용 가능한 비밀이 들어가면 안 된다."""

    def test_hash_input_accepts_nested_payload(self):
        """중첩 dict/list도 정규화되어 해시에 들어가야 한다."""
        row = _seal(_event(None, payload={"a": [1, {"b": "c"}], "d": None}))
        self.assertEqual(recompute_hash_for(row), row.event_hash)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# 엔드포인트 연동 — 가짜 세션 위에서 체인이 실제로 이어지는지 확인한다.
# ---------------------------------------------------------------------------
from app.api.v1.endpoints.auth import bind_holder_key, login  # noqa: E402
from app.core.audit import record_audit_event  # noqa: E402
from app.schemas.device import BindHolderKeyRequest  # noqa: E402
from app.schemas.user import LoginRequest  # noqa: E402
from tests.fakes import FakeDb  # noqa: E402


class RecordAuditEventTests(unittest.IsolatedAsyncioTestCase):
    async def test_first_event_has_no_previous_hash(self):
        db = FakeDb()
        row = await record_audit_event(
            db, event_type="LOGIN_SUCCEEDED", actor_type="USER", payload={"a": 1}
        )
        self.assertIsNone(row.previous_hash)
        self.assertEqual(len(row.event_hash), 64)

    async def test_events_chain_together(self):
        """두 번째 이벤트의 previous_hash가 첫 이벤트의 event_hash여야 한다."""
        db = FakeDb()
        first = await record_audit_event(
            db, event_type="LOGIN_SUCCEEDED", actor_type="USER", payload={"n": 1}
        )
        second = await record_audit_event(
            db, event_type="VC_ISSUED", actor_type="USER", payload={"n": 2}
        )
        self.assertEqual(second.previous_hash, first.event_hash)
        self.assertNotEqual(first.event_hash, second.event_hash)

    async def test_outbox_event_is_emitted(self):
        """설계서 14번 outbox 패턴 — 같은 트랜잭션에 발행 이벤트도 들어간다."""
        db = FakeDb()
        row = await record_audit_event(
            db, event_type="VC_ISSUED", actor_type="USER",
            aggregate_type="VC_CREDENTIAL", aggregate_id="7", payload={"n": 1},
        )
        self.assertEqual(len(db.outbox_events), 1)
        outbox = db.outbox_events[0]
        self.assertEqual(outbox.event_id, row.event_id)
        self.assertEqual(outbox.aggregate_type, "VC_CREDENTIAL")
        self.assertEqual(outbox.payload["event_hash"], row.event_hash)

    async def test_outbox_can_be_suppressed(self):
        db = FakeDb()
        await record_audit_event(
            db, event_type="LOGIN_FAILED", actor_type="USER",
            payload={}, emit_outbox=False,
        )
        self.assertEqual(db.outbox_events, [])
        self.assertEqual(len(db.audit_logs), 1)

    async def test_kafka_coordinates_are_left_for_publisher(self):
        db = FakeDb()
        row = await record_audit_event(
            db, event_type="LOGIN_SUCCEEDED", actor_type="USER", payload={}
        )
        self.assertIsNone(row.kafka_topic)
        self.assertIsNone(row.kafka_partition)
        self.assertIsNone(row.kafka_offset)


class LoginAuditTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_login_is_recorded_and_committed(self):
        """실패 이력이 롤백되면 감사 추적이 성립하지 않는다.

        예외를 던지기 *전에* 커밋되어야 한다.
        """
        from fastapi import HTTPException

        db = FakeDb()  # execute()가 사용자를 못 찾으므로 로그인 실패 경로
        body = LoginRequest(login_id="attacker", password="wrong-password")

        with self.assertRaises(HTTPException):
            await login(body, db)

        self.assertEqual(len(db.audit_logs), 1)
        self.assertEqual(db.audit_logs[0].event_type, "LOGIN_FAILED")
        self.assertEqual(db.commits, 1, "실패 감사 로그가 커밋되지 않았다")

    async def test_failed_login_payload_has_no_password(self):
        """비밀번호가 감사 로그로 새면 안 된다."""
        from fastapi import HTTPException

        db = FakeDb()
        body = LoginRequest(login_id="victim", password="super-secret-pw")

        with self.assertRaises(HTTPException):
            await login(body, db)

        serialized = canonical_json(db.audit_logs[0].payload)
        self.assertNotIn("super-secret-pw", serialized)

    async def test_failed_login_does_not_reveal_account_existence(self):
        """계정이 없는 건지 비밀번호가 틀린 건지 구분되면 계정 열거에 쓰인다."""
        from fastapi import HTTPException

        db = FakeDb()
        with self.assertRaises(HTTPException):
            await login(LoginRequest(login_id="nobody", password="x"), db)

        self.assertEqual(db.audit_logs[0].payload, {"reason": "INVALID_CREDENTIALS"})


class BindHolderKeyAuditTests(unittest.IsolatedAsyncioTestCase):
    """재바인딩이 감사 로그에 남는지 (#22 / #9 접점, #27에서 비트 수 추가)."""

    @staticmethod
    def _key_material(device_id):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        from app.core.did_key import public_key_to_did_key

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        signature = base64.b64encode(private_key.sign(str(device_id).encode())).decode()
        return pem, signature, public_key_to_did_key(public_key)

    async def test_rebinding_records_revoked_count(self):
        from app.core.status_list import empty_encoded_list
        from app.models import CredentialStatusList, Device

        pem, signature, new_did = self._key_material(2)
        device = SimpleNamespace(
            id=2, user_id=1, status="ACTIVE",
            holder_did="did:key:zOldKeyFromLostPhone", holder_public_key=None,
        )
        status_list = SimpleNamespace(
            id=7, encoded_list=empty_encoded_list(), version=1
        )
        # 폐기 건수는 UPDATE ... RETURNING이 돌려준 행으로 센다(#27).
        # 상태 목록 배정이 있는 VC 2건 + 배정 전에 발급된 VC 1건.
        db = FakeDb(
            {(Device, 2): device},
            scalar_results={CredentialStatusList: status_list},
            returning_rows=[(7, 3), (7, 5), (None, None)],
        )

        await bind_holder_key(
            BindHolderKeyRequest(
                device_id=2, holder_public_key_pem=pem, proof_signature_b64=signature
            ),
            SimpleNamespace(id=1),
            db,
        )

        self.assertEqual(len(db.audit_logs), 1)
        event = db.audit_logs[0]
        self.assertEqual(event.event_type, "HOLDER_KEY_REBOUND")
        self.assertEqual(event.payload["revoked_vc_count"], 3)
        # 배정이 없던 1건은 켤 비트가 없다. 두 값이 갈리는 것 자체가
        # 사후 조사에 필요한 정보다.
        self.assertEqual(event.payload["revoked_status_list_bits"], 2)
        self.assertEqual(event.payload["previous_holder_did"], "did:key:zOldKeyFromLostPhone")
        self.assertEqual(event.payload["new_holder_did"], new_did)

    async def test_first_binding_is_bound_not_rebound(self):
        from app.models import Device

        pem, signature, _ = self._key_material(2)
        device = SimpleNamespace(
            id=2, user_id=1, status="ACTIVE", holder_did=None, holder_public_key=None,
        )
        db = FakeDb({(Device, 2): device})

        await bind_holder_key(
            BindHolderKeyRequest(
                device_id=2, holder_public_key_pem=pem, proof_signature_b64=signature
            ),
            SimpleNamespace(id=1),
            db,
        )

        self.assertEqual(db.audit_logs[0].event_type, "HOLDER_KEY_BOUND")
        self.assertEqual(db.audit_logs[0].payload["revoked_vc_count"], 0)
        self.assertEqual(db.audit_logs[0].payload["revoked_status_list_bits"], 0)
