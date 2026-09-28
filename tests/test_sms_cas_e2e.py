"""SOLAPI 실패 정리의 compare-and-set 조건을 실제 PostgreSQL에서 검증한다.

E2E_DATABASE_URL로 명시적으로 켠다. 테스트마다 고유한 UUID와 전화번호를
사용하고 자신이 만든 phone_verification_requests 행만 제거한다.
"""

import base64
import os
import unittest
import uuid
from datetime import datetime, timedelta, timezone

E2E_DB_URL = os.environ.get("E2E_DATABASE_URL")

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault(
    "ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode()
)

from sqlalchemy import delete, select  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402

from app.api.v1.endpoints.auth import _invalidate_failed_sms_request  # noqa: E402
from app.models import PhoneVerificationRequest  # noqa: E402


@unittest.skipUnless(
    E2E_DB_URL,
    "실제 PostgreSQL 검증에는 E2E_DATABASE_URL이 필요하다",
)
class SmsFailureCleanupCompareAndSetTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = create_async_engine(E2E_DB_URL, echo=False)
        self.addAsyncCleanup(self.engine.dispose)
        self.session_factory = async_sessionmaker(
            self.engine,
            expire_on_commit=False,
        )
        self.owned_ids: list[uuid.UUID] = []
        self.addAsyncCleanup(self._remove_owned_rows)

    async def _remove_owned_rows(self):
        if not self.owned_ids:
            return
        async with self.session_factory() as db:
            await db.execute(
                delete(PhoneVerificationRequest).where(
                    PhoneVerificationRequest.id.in_(self.owned_ids)
                )
            )
            await db.commit()

    async def _insert_request(
        self,
        *,
        digest: str,
        last_sent_at: datetime,
        verified_at: datetime | None = None,
        consumed_at: datetime | None = None,
    ) -> tuple[uuid.UUID, datetime]:
        verification_id = uuid.uuid4()
        self.owned_ids.append(verification_id)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        phone_suffix = verification_id.int % 10**8
        async with self.session_factory() as db:
            db.add(
                PhoneVerificationRequest(
                    id=verification_id,
                    phone_number=f"+8210{phone_suffix:08d}",
                    otp_digest=digest,
                    purpose="SIGN_UP",
                    attempt_count=0,
                    resend_count=0,
                    last_sent_at=last_sent_at,
                    expires_at=expires_at,
                    verified_at=verified_at,
                    consumed_at=consumed_at,
                )
            )
            await db.commit()
        return verification_id, expires_at

    async def _get_request(self, verification_id: uuid.UUID):
        async with self.session_factory() as db:
            return await db.scalar(
                select(PhoneVerificationRequest).where(
                    PhoneVerificationRequest.id == verification_id
                )
            )

    async def test_matching_prepared_values_invalidate_request(self):
        sent_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        digest = f"digest-{uuid.uuid4().hex}"
        verification_id, original_expiry = await self._insert_request(
            digest=digest,
            last_sent_at=sent_at,
        )

        async with self.session_factory() as db:
            await _invalidate_failed_sms_request(
                db,
                verification_id=verification_id,
                prepared_digest=digest,
                prepared_last_sent_at=sent_at,
            )

        row = await self._get_request(verification_id)
        self.assertIsNotNone(row)
        self.assertLess(row.expires_at, original_expiry)
        self.assertLess(row.expires_at, datetime.now(timezone.utc))

    async def test_stale_cleanup_cannot_invalidate_newer_send(self):
        old_sent_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        old_digest = f"old-{uuid.uuid4().hex}"
        verification_id, _ = await self._insert_request(
            digest=old_digest,
            last_sent_at=old_sent_at,
        )

        cleanup_session = self.session_factory()
        newer_session = self.session_factory()
        self.addAsyncCleanup(cleanup_session.close)
        self.addAsyncCleanup(newer_session.close)

        # 실패 응답을 기다리는 오래된 요청이 CAS 인자를 보관한 상황을 만든다.
        stale_row = await cleanup_session.get(
            PhoneVerificationRequest,
            verification_id,
        )
        self.assertEqual(stale_row.otp_digest, old_digest)

        newer_digest = f"new-{uuid.uuid4().hex}"
        newer_sent_at = datetime.now(timezone.utc)
        newer_expiry = newer_sent_at + timedelta(minutes=10)
        newer_row = await newer_session.get(
            PhoneVerificationRequest,
            verification_id,
        )
        newer_row.otp_digest = newer_digest
        newer_row.last_sent_at = newer_sent_at
        newer_row.expires_at = newer_expiry
        await newer_session.commit()

        await _invalidate_failed_sms_request(
            cleanup_session,
            verification_id=verification_id,
            prepared_digest=old_digest,
            prepared_last_sent_at=old_sent_at,
        )

        row = await self._get_request(verification_id)
        self.assertIsNotNone(row)
        self.assertEqual(row.otp_digest, newer_digest)
        self.assertEqual(row.last_sent_at, newer_sent_at)
        self.assertEqual(row.expires_at, newer_expiry)

    async def test_verified_and_consumed_requests_are_not_invalidated(self):
        protected_at = datetime.now(timezone.utc)
        cases = (
            {"verified_at": protected_at, "consumed_at": None},
            {"verified_at": None, "consumed_at": protected_at},
        )

        for case in cases:
            with self.subTest(**case):
                sent_at = datetime.now(timezone.utc) - timedelta(seconds=1)
                digest = f"protected-{uuid.uuid4().hex}"
                verification_id, original_expiry = await self._insert_request(
                    digest=digest,
                    last_sent_at=sent_at,
                    **case,
                )

                async with self.session_factory() as db:
                    await _invalidate_failed_sms_request(
                        db,
                        verification_id=verification_id,
                        prepared_digest=digest,
                        prepared_last_sent_at=sent_at,
                    )

                row = await self._get_request(verification_id)
                self.assertIsNotNone(row)
                self.assertEqual(row.expires_at, original_expiry)
