"""#9 후속 — 감사 로그 누락·누출 회귀 테스트.

두 가지를 고정한다.

1. 로그인 실패 시 aggregate_id가 계정 존재 여부와 무관하게 None이다.
   payload.reason만 통일하고 aggregate_id를 계정이 있을 때만 채우면,
   null 여부만으로 계정 존재가 드러나고 user.id까지 특정된다.
2. 실제로 발급된 OTP의 검증 실패 네 갈래가 기록되고 payload.reason으로
   구분된다. 존재하지 않는 ID 조회는 감사 체인을 무제한 늘릴 수 없도록
   애플리케이션 경고 로그만 남긴다.
"""

import base64
import os
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from app.api.v1.endpoints.auth import login, verify_phone_otp  # noqa: E402
from app.config import settings  # noqa: E402
from app.core.security import hash_otp, hash_password  # noqa: E402
from app.models import PhoneVerificationRequest, User  # noqa: E402
from app.schemas.audit import AuditEventType  # noqa: E402
from app.schemas.errors import AuthError  # noqa: E402
from app.schemas.user import LoginRequest, PhoneVerifyBody  # noqa: E402
from tests.fakes import FakeDb  # noqa: E402


class LoginFailureAuditTests(unittest.IsolatedAsyncioTestCase):
    """로그인 실패 로그가 계정 존재 여부를 드러내지 않아야 한다."""

    async def _login_failure_log(self, user):
        db = FakeDb(scalar_results={User: user})
        body = LoginRequest(login_id="gayeon123", password="wrong-password")

        with self.assertRaises(HTTPException):
            await login(body, db)

        self.assertEqual(
            db.scalar_query_hits.get(User),
            1,
            "사용자 조회 결과 주입이 사용되지 않으면 테스트가 공허하게 통과한다",
        )
        self.assertEqual(len(db.audit_logs), 1)
        return db.audit_logs[0]

    async def test_existing_account_failure_has_no_aggregate_id(self):
        user = User(
            id=15,
            login_id="gayeon123",
            password_hash=hash_password("correct-password"),
            platform_role="USER",
            status="ACTIVE",
        )
        log = await self._login_failure_log(user)

        self.assertEqual(log.event_type, AuditEventType.LOGIN_FAILED.value)
        self.assertIsNone(
            log.aggregate_id,
            "계정이 존재할 때 aggregate_id가 채워지면 계정 존재 여부가 드러난다",
        )
        self.assertEqual(log.payload["reason"], AuthError.INVALID_CREDENTIALS.value)

    async def test_missing_account_failure_is_indistinguishable(self):
        log = await self._login_failure_log(None)

        self.assertIsNone(log.aggregate_id)
        self.assertEqual(log.payload["reason"], AuthError.INVALID_CREDENTIALS.value)

    async def test_missing_account_still_runs_bcrypt_verification(self):
        db = FakeDb(scalar_results={User: None})
        body = LoginRequest(login_id="missing-user", password="wrong-password")

        with patch("app.core.security.verify_password", return_value=False) as verify:
            with self.assertRaises(HTTPException):
                await login(body, db)

        verify.assert_called_once()
        self.assertEqual(verify.call_args.args[0], body.password)
        self.assertTrue(verify.call_args.args[1].startswith("$2b$"))

    async def test_both_cases_produce_identical_distinguishing_fields(self):
        """존재하는 계정과 없는 계정의 로그가 구분 불가능해야 한다."""
        user = User(
            id=15,
            login_id="gayeon123",
            password_hash=hash_password("correct-password"),
            platform_role="USER",
            status="ACTIVE",
        )
        existing = await self._login_failure_log(user)
        missing = await self._login_failure_log(None)

        self.assertEqual(existing.aggregate_id, missing.aggregate_id)
        self.assertEqual(existing.payload, missing.payload)
        self.assertEqual(existing.actor_ref, missing.actor_ref)


class PhoneVerificationFailureAuditTests(unittest.IsolatedAsyncioTestCase):
    """발급된 OTP의 실패만 제한적으로 감사 체인에 기록해야 한다."""

    OTP = "123456"

    def _make_row(self, **overrides):
        row_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        defaults = dict(
            id=row_id,
            phone_number="+821012345678",
            otp_digest=hash_otp(self.OTP, str(row_id)),
            expires_at=now + timedelta(minutes=5),
            consumed_at=None,
            verified_at=None,
            attempt_count=0,
        )
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    async def _verify_failure_log(self, row, otp=None, verification_id=None):
        key = verification_id or (row.id if row else uuid.uuid4())
        rows = {(PhoneVerificationRequest, key): row} if row is not None else {}
        db = FakeDb(rows)
        body = PhoneVerifyBody(verification_id=key, otp=otp or self.OTP)

        with self.assertRaises(HTTPException):
            await verify_phone_otp(body, db)

        self.assertEqual(
            len(db.audit_logs), 1, "실패 경로에서 감사 로그가 남지 않았다"
        )
        log = db.audit_logs[0]
        self.assertEqual(log.event_type, AuditEventType.PHONE_VERIFICATION_FAILED.value)
        self.assertEqual(db.commits, 1, "실패 이력이 커밋되지 않으면 롤백된다")
        return log

    async def test_not_found_is_warning_only(self):
        attempted = uuid.uuid4()
        db = FakeDb()
        body = PhoneVerifyBody(verification_id=attempted, otp=self.OTP)

        with self.assertLogs("app.api.v1.endpoints.auth", level="WARNING"):
            with self.assertRaises(HTTPException) as caught:
                await verify_phone_otp(body, db)

        self.assertEqual(caught.exception.detail["code"], AuthError.OTP_NOT_FOUND.value)
        self.assertEqual(db.audit_logs, [])
        self.assertEqual(db.outbox_events, [])
        self.assertEqual(db.commits, 0)

    async def test_already_consumed_is_logged(self):
        row = self._make_row(consumed_at=datetime.now(timezone.utc))
        log = await self._verify_failure_log(row)

        self.assertEqual(log.payload["reason"], AuthError.OTP_ALREADY_CONSUMED.value)

    async def test_expired_is_logged(self):
        row = self._make_row(
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)
        )
        log = await self._verify_failure_log(row)

        self.assertEqual(log.payload["reason"], AuthError.OTP_EXPIRED.value)

    async def test_max_attempts_is_logged(self):
        """무차별 대입이 상한에 닿는 순간 — 가장 중요한 신호다."""
        row = self._make_row(attempt_count=settings.otp_max_attempts)
        log = await self._verify_failure_log(row)

        self.assertEqual(log.payload["reason"], AuthError.OTP_MAX_ATTEMPTS.value)
        self.assertEqual(
            log.payload["attempt_count"], settings.otp_max_attempts + 1
        )

    async def test_terminal_states_stop_writing_audit_chain_at_limit(self):
        """같은 종단 상태를 반복 호출해 감사 체인을 무한히 늘릴 수 없다."""
        now = datetime.now(timezone.utc)
        rows = (
            self._make_row(
                consumed_at=now,
                attempt_count=settings.otp_max_attempts,
            ),
            self._make_row(
                expires_at=now - timedelta(minutes=1),
                attempt_count=settings.otp_max_attempts,
            ),
            self._make_row(attempt_count=settings.otp_max_attempts + 1),
        )

        for row in rows:
            with self.subTest(row=row):
                key = row.id
                db = FakeDb({(PhoneVerificationRequest, key): row})
                body = PhoneVerifyBody(verification_id=key, otp=self.OTP)

                with self.assertRaises(HTTPException):
                    await verify_phone_otp(body, db)

                self.assertEqual(db.audit_logs, [])
                self.assertEqual(db.outbox_events, [])
                self.assertEqual(db.commits, 0)

    async def test_mismatch_is_logged_with_incremented_attempt_count(self):
        row = self._make_row(attempt_count=2)
        log = await self._verify_failure_log(row, otp="999999")

        self.assertEqual(log.payload["reason"], AuthError.OTP_MISMATCH.value)
        self.assertEqual(
            log.payload["attempt_count"], 3, "불일치 시 시도 횟수가 증가해야 한다"
        )

    async def test_verification_row_is_locked_before_attempt_count_update(self):
        row = self._make_row(attempt_count=2)
        key = row.id
        db = FakeDb({(PhoneVerificationRequest, key): row})
        body = PhoneVerifyBody(verification_id=key, otp="999999")

        with self.assertRaises(HTTPException):
            await verify_phone_otp(body, db)

        self.assertEqual(len(db.get_calls), 1)
        self.assertTrue(db.get_calls[0][2].get("with_for_update"))

    async def test_phone_number_is_masked(self):
        row = self._make_row(attempt_count=5)
        log = await self._verify_failure_log(row)

        self.assertIsNotNone(log.actor_ref)
        self.assertNotIn("1012345678", log.actor_ref)
        self.assertIn("*", log.actor_ref)


if __name__ == "__main__":
    unittest.main()
