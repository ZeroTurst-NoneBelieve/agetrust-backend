"""실제 PostgreSQL에서 가입 중복 충돌을 확인한다 (#49).

이 버그는 DB의 UNIQUE 제약에서 났으므로 대역으로는 재현되지 않는다.
`E2E_DATABASE_URL`이 있을 때만 켜지며, 관례는 tests/test_status_list_db.py와 같다.

세 가지를 본다.

1. 이미 가입된 번호로 가입하면 409 + PHONE_ALREADY_REGISTERED (이전에는 500)
2. 같은 번호로 동시에 들어온 가입 두 건 중 하나만 성공하고, 나머지도 500이 아니다
3. 탈퇴한 계정의 번호도 제약에 남아 있으므로 같은 409로 막힌다

2번은 두 요청이 **모두 사전 확인을 지난 뒤에** INSERT가 나가도록 `_FlushGate`로
맞춘다. 붙잡아 두지 않으면 앞선 요청이 먼저 커밋해 버려 뒤의 요청은 사전 확인에서
409로 끝나고, 이 테스트가 노리는 DB 제약 위반 경로는 한 번도 실행되지 않는다.

만든 행은 테스트마다 `_remove_owned_rows`로 되돌린다.
"""

import asyncio
import base64
import os
import unittest
import uuid
from datetime import datetime, timezone

E2E_DB_URL = os.environ.get("E2E_DATABASE_URL")

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())


def _login_id():
    return f"dup-{uuid.uuid4().hex[:12]}"


class _FlushGate:
    """가입 요청들을 INSERT 직전에 모아 두었다가 함께 내보낸다.

    사전 확인(SELECT)과 INSERT 사이에는 await 지점이 있다. 그냥 두면 앞선 요청이
    INSERT·커밋까지 끝낸 뒤에야 뒤의 요청이 사전 확인을 하게 되어, 뒤의 요청은
    사전 확인에서 409로 끝난다. 그래도 단언은 그대로 통과하므로 제약 위반 경로가
    실행되지 않은 것을 알아챌 수 없다 — 두 요청을 순차 실행으로 바꿔 실측했다.

    한쪽이 INSERT 앞까지 오지 못하면 무한정 기다리지 않고 이유를 적어 실패한다.
    """

    def __init__(self, parties, timeout=10.0):
        self.parties = parties
        self.arrivals = 0
        self._barrier = asyncio.Barrier(parties)
        self._timeout = timeout

    async def wait(self):
        self.arrivals += 1
        try:
            await asyncio.wait_for(self._barrier.wait(), self._timeout)
        except TimeoutError as exc:
            raise AssertionError(
                f"가입 {self.parties}건 중 {self.arrivals}건만 INSERT 앞에 도달했다. "
                "나머지는 사전 확인에서 끝나 DB 제약 위반 경로가 실행되지 않았다."
            ) from exc


class _GatedSession:
    """첫 flush 앞에서 게이트를 한 번 통과하는 AsyncSession 대리자.

    엔드포인트에 테스트용 훅을 심지 않으려고 세션 쪽에서 붙잡는다. signup의
    명시적 `flush`는 사전 확인 다음·users INSERT 직전이라 노리는 지점과 정확히
    겹친다. 나머지 호출은 그대로 넘긴다.
    """

    def __init__(self, session, gate):
        self._session = session
        self._gate = gate

    def __getattr__(self, name):
        return getattr(self._session, name)

    async def flush(self, *args, **kwargs):
        gate, self._gate = self._gate, None  # 요청당 한 번만 기다린다
        if gate is not None:
            await gate.wait()
        return await self._session.flush(*args, **kwargs)


@unittest.skipUnless(E2E_DB_URL, "실제 PostgreSQL 검증에는 E2E_DATABASE_URL이 필요하다")
class SignupConflictDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import httpx
        from sqlalchemy import func, select
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        from app.config import settings
        from app.database import get_db
        from app.main import app
        from app.models import AuditLog, OutboxEvent

        # 앱 엔진은 임포트 시점의 DATABASE_URL에 묶인다. discover로 돌리면 먼저
        # 임포트된 단위 테스트의 자리표시자가 잡히므로 전용 엔진으로 갈아끼운다.
        self.engine = create_async_engine(E2E_DB_URL, echo=False)
        self.addAsyncCleanup(self.engine.dispose)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

        # 정리 기준점. 이 테스트가 넣은 행만 골라내려고 현재 tip을 잡아 둔다.
        self.created_phones = []
        async with self.session_factory() as db:
            self.audit_tip = await db.scalar(select(func.max(AuditLog.id)))
            self.outbox_tip = await db.scalar(select(func.max(OutboxEvent.id)))
        self.addAsyncCleanup(self._remove_owned_rows)

        # 경합 테스트에서만 건다. 인증 건을 받는 동안에는 None이라 그대로 지나간다.
        self.flush_gate = None

        async def _override_get_db():
            async with self.session_factory() as session:
                gate = self.flush_gate
                yield session if gate is None else _GatedSession(session, gate)

        self.app = app
        app.dependency_overrides[get_db] = _override_get_db
        self.addCleanup(app.dependency_overrides.pop, get_db, None)

        # 가입 흐름이 OTP를 응답으로 받아야 이어진다. settings는 이미 만들어져
        # 있어서 환경변수로는 켜지지 않으므로 직접 켜고 되돌린다.
        self._dev_mode_before = settings.dev_mode
        settings.dev_mode = True
        self.addCleanup(setattr, settings, "dev_mode", self._dev_mode_before)

        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://signup-conflict"
        )
        self.addAsyncCleanup(self.client.aclose)

    async def _remove_owned_rows(self):
        """이 테스트가 넣은 행을 되돌린다.

        users·phone_verification_requests는 번호로 고른다. 번호는 테스트마다 새로
        만들므로 다른 데이터와 겹치지 않는다.

        audit_logs·outbox_events는 기준점보다 뒤만 지운다. 감사 로그는
        `previous_hash`로 이어진 체인이라 중간을 파내면 체인 검증이 LINK_MISMATCH로
        잡는다(`app/api/v1/endpoints/admin.py:104`, 구간 지정 없이 전체를 훑는
        `tests/test_e2e_scenarios.py:375`). 꼬리만 잘라내면 남은 행의 연결은
        그대로다. 테스트는 한 프로세스에서 차례로 도므로 기준점 뒤의 행은 이
        테스트가 넣은 것뿐이다.
        """
        from sqlalchemy import delete

        from app.models import AuditLog, OutboxEvent, PhoneVerificationRequest, User

        async with self.session_factory() as db:
            await db.execute(delete(AuditLog).where(AuditLog.id > (self.audit_tip or 0)))
            await db.execute(delete(OutboxEvent).where(OutboxEvent.id > (self.outbox_tip or 0)))
            if self.created_phones:
                await db.execute(
                    delete(PhoneVerificationRequest).where(
                        PhoneVerificationRequest.phone_number.in_(self.created_phones)
                    )
                )
                await db.execute(delete(User).where(User.phone_number.in_(self.created_phones)))
            await db.commit()

    def _new_phone(self):
        """정리 대상으로 기록하면서 번호를 하나 만든다."""
        phone = f"+8210{uuid.uuid4().int % 10**8:08d}"
        self.created_phones.append(phone)
        return phone

    async def _verified_verification_id(self, phone):
        """phone/request -> phone/verify까지 통과한 인증 건을 만든다."""
        response = await self.client.post("/api/v1/auth/phone/request", json={"phone_number": phone})
        self.assertEqual(response.status_code, 200, response.text)
        verification_id = response.json()["verification_id"]
        otp = response.json()["dev_otp"]

        response = await self.client.post(
            "/api/v1/auth/phone/verify",
            json={"verification_id": verification_id, "otp": otp},
        )
        self.assertEqual(response.status_code, 204, response.text)
        return verification_id

    async def _signup(self, verification_id, login_id):
        return await self.client.post(
            "/api/v1/auth/signup",
            json={
                "verification_id": verification_id,
                "login_id": login_id,
                "password": "signup-conflict-1234",
                "name": "중복 가입 테스트",
            },
        )

    async def _registered_user(self, phone):
        verification_id = await self._verified_verification_id(phone)
        response = await self._signup(verification_id, _login_id())
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["id"]

    async def test_already_registered_phone_returns_409_not_500(self):
        phone = self._new_phone()
        await self._registered_user(phone)

        # 같은 번호로 인증을 새로 받아 다시 가입한다. 이전에는 이 지점에서
        # UniqueViolationError가 500으로 올라갔다.
        second = await self._verified_verification_id(phone)
        response = await self._signup(second, _login_id())

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()["detail"]["code"], "PHONE_ALREADY_REGISTERED")

    async def test_withdrawn_account_phone_is_also_a_conflict(self):
        """탈퇴해도 번호는 UNIQUE에 남는다. 사전 확인이 이 행까지 봐야 500이 안 난다."""
        from sqlalchemy import update

        from app.models import User

        phone = self._new_phone()
        user_id = await self._registered_user(phone)
        async with self.session_factory() as db:
            await db.execute(
                update(User)
                .where(User.id == user_id)
                .values(withdrawn_at=datetime.now(timezone.utc), status="WITHDRAWN")
            )
            await db.commit()

        second = await self._verified_verification_id(phone)
        response = await self._signup(second, _login_id())

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()["detail"]["code"], "PHONE_ALREADY_REGISTERED")

    async def test_concurrent_signups_for_one_phone_leave_a_single_user(self):
        """사전 확인을 둘 다 통과하는 경합에서도 500이 나지 않아야 한다.

        같은 번호로 인증 건 두 개를 받아 동시에 가입을 넣는다. 모바일 가입 버튼
        이중 탭이 만드는 상황이다. 두 요청을 INSERT 직전에 모아 두어, 둘 다 사전
        확인을 지난 뒤 DB 제약에서 만나게 한다 — 그 경로가 실행되지 않으면 게이트가
        기다리다 실패하므로 조용히 통과하지 않는다.
        """
        from sqlalchemy import func, select

        from app.models import User

        phone = self._new_phone()
        first, second = await asyncio.gather(
            self._verified_verification_id(phone), self._verified_verification_id(phone)
        )

        self.flush_gate = _FlushGate(2)
        responses = await asyncio.gather(
            self._signup(first, _login_id()), self._signup(second, _login_id())
        )
        codes = sorted(response.status_code for response in responses)

        self.assertEqual(self.flush_gate.arrivals, 2, "두 요청이 모두 INSERT 앞까지 오지 않았다")
        self.assertEqual(codes, [200, 409], [r.text for r in responses])
        conflicted = next(r for r in responses if r.status_code == 409)
        self.assertEqual(conflicted.json()["detail"]["code"], "PHONE_ALREADY_REGISTERED")

        async with self.session_factory() as db:
            registered = await db.execute(
                select(func.count()).select_from(User).where(User.phone_number == phone)
            )
            self.assertEqual(registered.scalar_one(), 1, "번호당 계정은 하나만 남아야 한다")


if __name__ == "__main__":
    unittest.main()
