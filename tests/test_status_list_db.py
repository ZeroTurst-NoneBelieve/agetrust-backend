"""실제 PostgreSQL에서 상태 목록 배정·폐기 회귀를 검증한다.

E2E_DATABASE_URL로 명시적으로 켠다. 각 테스트는 고유 발급자와 FK 데이터를
만들고 자신이 만든 행만 제거한다. 일반 개발 DB 대신 별도 테스트 DB를 권장한다.
"""

import asyncio
import base64
import os
import unittest
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

E2E_DB_URL = os.environ.get("E2E_DATABASE_URL")

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from sqlalchemy import delete, func, select, text  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402

from app.api.v1.endpoints import vc  # noqa: E402
from app.core.revocation import mark_revoked_bits  # noqa: E402
from app.core.status_list import BITSTRING_SIZE, decode_bitstring, empty_encoded_list, get_bit  # noqa: E402
from app.models import AdultVerification, CredentialStatusList, Device, User, VcCredential  # noqa: E402


@unittest.skipUnless(E2E_DB_URL, "실제 PostgreSQL 검증에는 E2E_DATABASE_URL이 필요하다")
class StatusListDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = create_async_engine(E2E_DB_URL, echo=False)
        self.addAsyncCleanup(self.engine.dispose)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self.user_id = None
        self.device_id = None
        self.verification_id = None
        self.status_list_id = None
        self.addAsyncCleanup(self._remove_owned_rows)

        token = uuid.uuid4().hex
        self.issuer_did = f"did:example:status-list-test-{token}"
        self.holder_did = f"did:example:holder-{token}"
        # 배정 함수가 다른 테스트/개발 데이터의 목록을 선택하지 않게 한다.
        self.issuer_patch = patch.object(vc, "ISSUER_DID", self.issuer_did)
        self.issuer_patch.start()
        self.addCleanup(self.issuer_patch.stop)

        async with self.session_factory() as db:
            user = User(
                login_id=f"status-list-{token}",
                password_hash="not-a-login-credential",
                name="status list regression test",
                phone_number=f"test-{token[:24]}",
                phone_verified_at=datetime.now(timezone.utc),
            )
            db.add(user)
            await db.flush()
            self.user_id = user.id
            device = Device(
                user_id=user.id,
                device_identifier=f"status-list-{token}",
                platform="ANDROID",
                holder_did=self.holder_did,
            )
            db.add(device)
            await db.flush()
            self.device_id = device.id
            verification = AdultVerification(
                user_id=user.id,
                device_id=device.id,
                age_check_passed=True,
                id_face_match_passed=True,
                result_status="SUCCESS",
            )
            db.add(verification)
            await db.flush()
            self.verification_id = verification.id
            status_list = CredentialStatusList(
                issuer_did=self.issuer_did,
                status_purpose="REVOCATION",
                status_list_url=f"https://status-list-test.invalid/status-lists/{token}",
                encoded_list=empty_encoded_list(),
                updated_at=datetime(2000, 1, 1, tzinfo=timezone.utc),
            )
            db.add(status_list)
            await db.flush()
            self.status_list_id = status_list.id
            await db.commit()

    async def _remove_owned_rows(self):
        async with self.session_factory() as db:
            if self.user_id is not None:
                await db.execute(delete(VcCredential).where(VcCredential.user_id == self.user_id))
            if self.status_list_id is not None:
                await db.execute(
                    delete(CredentialStatusList).where(CredentialStatusList.id == self.status_list_id)
                )
            if self.verification_id is not None:
                await db.execute(delete(AdultVerification).where(AdultVerification.id == self.verification_id))
            if self.device_id is not None:
                await db.execute(delete(Device).where(Device.id == self.device_id))
            if self.user_id is not None:
                await db.execute(delete(User).where(User.id == self.user_id))
            await db.commit()

    def _credential(self, index):
        return VcCredential(
            user_id=self.user_id,
            device_id=self.device_id,
            adult_verification_id=self.verification_id,
            credential_id=f"urn:uuid:{uuid.uuid4()}",
            holder_did=self.holder_did,
            issuer_did=self.issuer_did,
            status_list_id=self.status_list_id,
            status_list_index=index,
        )

    async def _insert_credential(self, index):
        async with self.session_factory() as db:
            db.add(self._credential(index))
            await db.commit()

    async def test_occupied_candidate_is_retried_using_real_database(self):
        await self._insert_credential(7)

        async with self.session_factory() as db:
            self.assertTrue(await vc._index_is_taken(db, self.status_list_id, 7))
            self.assertFalse(await vc._index_is_taken(db, self.status_list_id, 8))
            with patch.object(vc.secrets, "randbelow", side_effect=[7, 8]) as pick:
                status_list, index = await vc._allocate_status_list_entry(db)
            self.assertEqual(status_list.id, self.status_list_id)
            self.assertEqual(index, 8)
            self.assertEqual(pick.call_count, 2)
            db.add(self._credential(index))
            await db.commit()

        async with self.session_factory() as db:
            indexes = (await db.scalars(
                select(VcCredential.status_list_index).where(VcCredential.user_id == self.user_id)
            )).all()
        self.assertCountEqual(indexes, [7, 8])

    async def test_retry_exhaustion_still_finds_a_free_position(self):
        await self._insert_credential(5)

        async with self.session_factory() as db:
            # 모든 후보를 이미 사용 중인 자리로 고정한다. 최후의 빈자리 선택은
            # 같은 난수라도 전체 인덱스가 아닌 빈자리 집합을 대상으로 해야 한다.
            with patch.object(vc.secrets, "randbelow", return_value=5) as pick:
                status_list, index = await vc._allocate_status_list_entry(db)
            self.assertEqual(status_list.id, self.status_list_id)
            self.assertNotEqual(index, 5)
            self.assertGreaterEqual(index, 0)
            self.assertLess(index, BITSTRING_SIZE)
            self.assertGreaterEqual(pick.call_count, vc._INDEX_PICK_ATTEMPTS)
            db.add(self._credential(index))
            await db.commit()  # 실제 UNIQUE 제약을 통과해야 한다.

    async def _wait_until_advisory_lock_is_queued(self, backend_pid):
        async with self.session_factory() as db:
            while True:
                waiting = await db.scalar(text(
                    "SELECT EXISTS (SELECT 1 FROM pg_locks "
                    "WHERE pid = :pid AND locktype = 'advisory' AND NOT granted)"
                ), {"pid": backend_pid})
                if waiting:
                    return
                await asyncio.sleep(0.01)

    async def test_concurrent_transactions_do_not_allocate_the_same_position(self):
        first_allocated = asyncio.Event()
        release_first = asyncio.Event()
        second_started = asyncio.Event()
        second_pid = None

        async def first_request():
            async with self.session_factory() as db:
                _, index = await vc._allocate_status_list_entry(db)
                db.add(self._credential(index))
                await db.flush()
                first_allocated.set()
                await release_first.wait()
                await db.commit()
                return index

        async def second_request():
            nonlocal second_pid
            async with self.session_factory() as db:
                second_pid = await db.scalar(select(func.pg_backend_pid()))
                second_started.set()
                _, index = await vc._allocate_status_list_entry(db)
                db.add(self._credential(index))
                await db.commit()
                return index

        tasks = []
        with patch.object(vc.secrets, "randbelow", side_effect=[17, 17, 18]):
            try:
                tasks.append(asyncio.create_task(first_request()))
                await asyncio.wait_for(first_allocated.wait(), timeout=5)
                tasks.append(asyncio.create_task(second_request()))
                await asyncio.wait_for(second_started.wait(), timeout=5)
                # 단순히 "두 요청 성공"만 보는 대신, 첫 INSERT가 커밋되기
                # 전에는 두 번째 트랜잭션이 실제 advisory lock을 기다림을 확인한다.
                await asyncio.wait_for(self._wait_until_advisory_lock_is_queued(second_pid), timeout=5)
                self.assertFalse(tasks[1].done())
                release_first.set()
                indexes = await asyncio.wait_for(asyncio.gather(*tasks), timeout=5)
            finally:
                release_first.set()
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

        self.assertEqual(indexes, [17, 18])
        async with self.session_factory() as db:
            stored = (await db.scalars(
                select(VcCredential.status_list_index).where(VcCredential.user_id == self.user_id)
            )).all()
        self.assertCountEqual(stored, [17, 18])

    async def test_revocation_updates_timestamp_only_when_a_bit_changes(self):
        async with self.session_factory() as db:
            status_list = await db.get(CredentialStatusList, self.status_list_id)
            original_time = status_list.updated_at
            self.assertEqual(await mark_revoked_bits(db, [(self.status_list_id, 23)]), 1)
            await db.commit()
            await db.refresh(status_list)
            changed_time = status_list.updated_at
            self.assertGreater(changed_time, original_time)
            self.assertEqual(status_list.version, 2)
            self.assertTrue(get_bit(decode_bitstring(status_list.encoded_list), 23))

            self.assertEqual(await mark_revoked_bits(db, [(self.status_list_id, 23)]), 0)
            await db.commit()
            await db.refresh(status_list)
            self.assertEqual(status_list.updated_at, changed_time)
            self.assertEqual(status_list.version, 2)
