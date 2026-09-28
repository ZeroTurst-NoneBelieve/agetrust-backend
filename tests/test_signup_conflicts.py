"""가입 중복 충돌 회귀 테스트 (#49).

전화번호는 users에 UNIQUE가 걸려 있지만 애플리케이션 검사가 없어 제약 위반이
그대로 500으로 올라갔다. 모바일은 500을 "서버 오류가 발생했습니다"로 안내해서,
사용자가 고칠 수 있는 상황(이미 가입된 번호)이 장애로 보였다.

사전 확인과 DB 제약 두 경로 모두 409 + 코드로 나가는지 확인한다.
제약 위반은 commit이 아니라 INSERT가 나가는 flush에서 터지므로 그 지점을 흉내낸다.
"""

import base64
import os
import unittest
import uuid
from types import SimpleNamespace

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from app.api.v1.endpoints.auth import _conflicting_unique, signup  # noqa: E402
from app.models import PhoneVerificationRequest, User  # noqa: E402
from app.schemas.errors import AuthError  # noqa: E402
from app.schemas.user import SignupRequest  # noqa: E402
from tests.fakes import FakeDb, FakeResult  # noqa: E402

PHONE = "+821099887766"


class _AsyncpgUniqueViolation(Exception):
    """asyncpg.exceptions.UniqueViolationError의 최소 대역.

    실측한 형태를 그대로 따른다 — asyncpg 어댑터는 SQLAlchemy 예외의 orig에
    constraint_name을 달지 않고, 원래 예외를 orig.__cause__로 걸어 둔다.
    """

    def __init__(self, constraint_name: str):
        super().__init__(f'duplicate key value violates unique constraint "{constraint_name}"')
        self.constraint_name = constraint_name


def _integrity_error(constraint: str, *, expose_constraint_name: bool = True) -> IntegrityError:
    cause = _AsyncpgUniqueViolation(constraint)
    orig = Exception(f"<class 'asyncpg.exceptions.UniqueViolationError'>: {cause}")
    if expose_constraint_name:
        orig.__cause__ = cause
    return IntegrityError("INSERT INTO users ...", {}, orig)


def _verified_request(verification_id):
    return PhoneVerificationRequest(
        id=verification_id,
        phone_number=PHONE,
        otp_digest="digest",
        verified_at="2026-09-22T00:00:00+00:00",
        consumed_at=None,
    )


def _body(verification_id):
    return SignupRequest(
        verification_id=str(verification_id),
        login_id="signup-conflict-test",
        password="password1234",
        name="테스트 사용자",
    )


class PhoneTakenDb(FakeDb):
    """전화번호 조회에만 "이미 있음"을 돌려준다.

    login_id 조회는 select(User) 엔티티 조회라 FakeDb가 대역을 주입하지만,
    전화번호 조회는 select(User.id) 컬럼 조회라서 걸리지 않는다. 두 사전
    확인을 따로 검증하려면 렌더된 SQL로 갈라야 한다. SELECT 목록이 아니라 WHERE로
    가르는데, select(User)의 컬럼 목록에도 phone_number가 들어 있다.
    """

    async def execute(self, statement, params=None):
        if "WHERE users.phone_number" in self._render(statement):
            return FakeResult(scalar=4242)
        return await super().execute(statement, params)


class FlushConflictDb(FakeDb):
    """flush에서 UNIQUE 제약 위반이 터지는 상황."""

    def __init__(self, *args, constraint: str, **kwargs):
        super().__init__(*args, **kwargs)
        self.constraint = constraint

    async def flush(self):
        raise _integrity_error(self.constraint)


class SignupPreCheckTests(unittest.IsolatedAsyncioTestCase):
    async def test_duplicate_phone_number_returns_409_with_code(self):
        verification_id = uuid.uuid4()
        db = PhoneTakenDb({(PhoneVerificationRequest, verification_id): _verified_request(verification_id)})

        with self.assertRaises(HTTPException) as caught:
            await signup(_body(verification_id), db)

        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(
            caught.exception.detail["code"], AuthError.PHONE_ALREADY_REGISTERED.value
        )
        self.assertEqual(db.added, [], "충돌이면 users 행을 만들지 않는다")

    async def test_duplicate_login_id_still_returns_user_already_exists(self):
        """번호 검사를 끼워 넣어도 기존 아이디 중복 경로가 그대로여야 한다."""
        verification_id = uuid.uuid4()
        db = FakeDb(
            {(PhoneVerificationRequest, verification_id): _verified_request(verification_id)},
            scalar_results={User: SimpleNamespace(id=1, login_id="signup-conflict-test")},
        )

        with self.assertRaises(HTTPException) as caught:
            await signup(_body(verification_id), db)

        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(caught.exception.detail["code"], AuthError.USER_ALREADY_EXISTS.value)


class SignupUniqueViolationTests(unittest.IsolatedAsyncioTestCase):
    """사전 확인을 통과한 뒤 DB 제약에서 만나는 경로 (동시 가입·이중 탭)."""

    async def _signup_expecting_conflict(self, constraint):
        verification_id = uuid.uuid4()
        db = FlushConflictDb(
            {(PhoneVerificationRequest, verification_id): _verified_request(verification_id)},
            constraint=constraint,
        )
        with self.assertRaises(HTTPException) as caught:
            await signup(_body(verification_id), db)
        return caught.exception, db

    async def test_phone_unique_violation_becomes_409_not_500(self):
        error, db = await self._signup_expecting_conflict("users_phone_number_key")

        self.assertEqual(error.status_code, 409)
        self.assertEqual(error.detail["code"], AuthError.PHONE_ALREADY_REGISTERED.value)
        self.assertEqual(db.rollbacks, 1, "실패한 트랜잭션은 되돌린다")
        self.assertEqual(db.commits, 0)

    async def test_login_id_unique_violation_becomes_409(self):
        error, _ = await self._signup_expecting_conflict("users_login_id_key")

        self.assertEqual(error.status_code, 409)
        self.assertEqual(error.detail["code"], AuthError.USER_ALREADY_EXISTS.value)

    async def test_unrelated_integrity_error_is_not_masked_as_409(self):
        """모르는 제약은 409로 덮지 않는다. 조용히 삼키면 원인을 못 찾는다."""
        verification_id = uuid.uuid4()
        db = FlushConflictDb(
            {(PhoneVerificationRequest, verification_id): _verified_request(verification_id)},
            constraint="audit_logs_event_id_key",
        )

        with self.assertRaises(IntegrityError):
            await signup(_body(verification_id), db)


class ConstraintNameResolutionTests(unittest.TestCase):
    """제약 이름이 드라이버마다 다른 자리에 실린다."""

    def test_reads_constraint_name_from_asyncpg_cause(self):
        error = _integrity_error("users_phone_number_key")

        self.assertEqual(_conflicting_unique(error), AuthError.PHONE_ALREADY_REGISTERED)

    def test_falls_back_to_message_when_attribute_is_absent(self):
        error = _integrity_error("users_login_id_key", expose_constraint_name=False)

        self.assertIsNone(getattr(error.orig, "constraint_name", None))
        self.assertEqual(_conflicting_unique(error), AuthError.USER_ALREADY_EXISTS)

    def test_reads_constraint_name_from_psycopg2_diag(self):
        orig = Exception("duplicate key value violates unique constraint")
        orig.diag = SimpleNamespace(constraint_name="users_phone_number_key")

        error = IntegrityError("INSERT INTO users ...", {}, orig)

        self.assertEqual(_conflicting_unique(error), AuthError.PHONE_ALREADY_REGISTERED)

    def test_unknown_constraint_resolves_to_none(self):
        self.assertIsNone(_conflicting_unique(_integrity_error("stores_store_code_key")))


if __name__ == "__main__":
    unittest.main()
