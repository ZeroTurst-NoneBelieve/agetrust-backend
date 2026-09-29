"""키오스크 결과 기록 계약을 실제 PostgreSQL과 HTTP로 검증한다.

테스트마다 UUID 스키마를 만들어 결과·감사 체인·Outbox를 함께 격리한다.
일반 CI의 agetrust_test DB에서도 E2E_DATABASE_URL만 있으면 실행한다.
"""

import asyncio
import base64
import hashlib
import json
import os
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import httpx
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.schema import CreateSchema, DropSchema
from sqlalchemy.sql.dml import Insert

E2E_DB_URL = os.environ.get("E2E_DATABASE_URL")

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from app.api.v1.endpoints import kiosk as kiosk_results  # noqa: E402
from app.core.audit import GENESIS_HASH, recompute_hash_for  # noqa: E402
from app.core.security import create_access_token  # noqa: E402
from app.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import (  # noqa: E402
    AuditLog,
    Business,
    Kiosk,
    KioskApiKey,
    OutboxEvent,
    Store,
    VerificationLog,
)

PATH = "/api/v1/kiosk/verification-results"


class _InsertGate:
    def __init__(self):
        self.barrier = asyncio.Barrier(2)
        self.arrivals = 0

    async def wait(self):
        self.arrivals += 1
        await asyncio.wait_for(self.barrier.wait(), timeout=10)


class _GatedSession(AsyncSession):
    """실제 DB INSERT 직전까지 두 HTTP 요청이 모두 도달하도록 강제한다."""

    async def execute(self, statement, *args, **kwargs):
        gate = self.info.get("verification_insert_gate")
        if gate is not None and isinstance(statement, Insert) and statement.table.name == "verification_logs":
            await gate.wait()
        return await super().execute(statement, *args, **kwargs)


@unittest.skipUnless(E2E_DB_URL, "실제 PostgreSQL 검증에는 E2E_DATABASE_URL이 필요하다")
class KioskResultDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.schema = "kiosk_result_" + uuid.uuid4().hex
        self.admin_engine = create_async_engine(E2E_DB_URL, echo=False)
        self.addAsyncCleanup(self.admin_engine.dispose)
        async with self.admin_engine.begin() as connection:
            await connection.execute(CreateSchema(self.schema))
        self.addAsyncCleanup(self._drop_schema)
        self.engine = create_async_engine(
            E2E_DB_URL,
            echo=False,
            connect_args={"server_settings": {"search_path": self.schema}},
        )
        self.addAsyncCleanup(self.engine.dispose)
        async with self.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        self.session_factory = async_sessionmaker(
            self.engine, class_=_GatedSession, expire_on_commit=False,
        )
        self.insert_gate = None
        self.keys = ["ak_results_first_" + uuid.uuid4().hex, "ak_results_second_" + uuid.uuid4().hex]
        self.identifiers = ["result-kiosk-one", "result-kiosk-two"]
        self.kiosk_ids = []
        self.key_ids = []
        async with self.session_factory() as db:
            business = Business(business_number="result-test", business_name="Results test")
            db.add(business)
            await db.flush()
            store = Store(
                business_id=business.id, store_code="result-test", store_name="Results test",
                store_type_code="TEST", address="Test fixture",
            )
            db.add(store)
            await db.flush()
            for identifier, raw_key in zip(self.identifiers, self.keys):
                kiosk = Kiosk(store_id=store.id, kiosk_identifier=identifier)
                db.add(kiosk)
                await db.flush()
                key = KioskApiKey(
                    kiosk_id=kiosk.id, key_prefix=raw_key[:8],
                    key_hash=hashlib.sha256(raw_key.encode()).hexdigest(),
                )
                db.add(key)
                await db.flush()
                self.kiosk_ids.append(kiosk.id)
                self.key_ids.append(key.id)
            await db.commit()

        async def override_db():
            async with self.session_factory() as db:
                db.info["verification_insert_gate"] = self.insert_gate
                yield db

        self.old_overrides = app.dependency_overrides.copy()
        app.dependency_overrides[get_db] = override_db
        self.addCleanup(self._restore_overrides)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://results-test")
        self.addAsyncCleanup(self.client.aclose)

    async def _drop_schema(self):
        async with self.admin_engine.begin() as connection:
            await connection.execute(DropSchema(self.schema, cascade=True))

    def _restore_overrides(self):
        app.dependency_overrides.clear()
        app.dependency_overrides.update(self.old_overrides)

    def _body(self, **changes):
        body = {
            "kiosk_identifier": self.identifiers[0],
            "nonce": "nonce-" + uuid.uuid4().hex,
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "result_status": "PASS",
            "is_vc_valid": True,
            "is_face_matched": True,
            "transport_type": "QR_BLE",
        }
        return body | changes

    async def _post(self, body, *, index=0):
        return await self.client.post(PATH, json=body, headers={"Authorization": f"Bearer {self.keys[index]}"})

    async def _counts(self):
        async with self.session_factory() as db:
            return tuple([
                await db.scalar(select(func.count()).select_from(model))
                for model in (VerificationLog, AuditLog, OutboxEvent)
            ])

    def _assert_error(self, response, status, code):
        self.assertEqual(response.status_code, status, response.text)
        self.assertEqual(response.json()["detail"]["code"], code)

    async def test_first_result_persists_whitelisted_audit_and_outbox_atomically(self):
        body = self._body(
            nonce="opaque/non-base64 nonce 한글", is_vp_valid=True, is_liveness_valid=True,
            face_model_version="face-v1", threshold_version="threshold-v2", status_list_age_seconds=321,
        )
        response = await self._post(body)
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(set(response.json()), {"id", "received_at", "is_late"})
        self.assertFalse(response.json()["is_late"])
        self.assertEqual(await self._counts(), (1, 1, 1))
        async with self.session_factory() as db:
            row = (await db.scalars(select(VerificationLog))).one()
            audit = (await db.scalars(select(AuditLog))).one()
            outbox = (await db.scalars(select(OutboxEvent))).one()
            self.assertEqual(row.id, response.json()["id"])
            self.assertEqual(row.kiosk_id, self.kiosk_ids[0])
            self.assertEqual(row.nonce_hash, hashlib.sha256(body["nonce"].encode("utf-8")).hexdigest())
            self.assertEqual(row.status_list_age_seconds, 321)
            self.assertEqual(row.face_model_version, "face-v1")
            self.assertTrue(row.is_vp_valid)
            self.assertTrue(row.is_liveness_valid)
            self.assertEqual(audit.event_type, "VERIFICATION_RESULT_RECORDED")
            self.assertEqual(audit.actor_type, "KIOSK")
            self.assertEqual(audit.source_kiosk_id, row.kiosk_id)
            self.assertEqual(audit.aggregate_type, "VERIFICATION_LOG")
            self.assertEqual(audit.aggregate_id, str(row.id))
            self.assertIn(audit.previous_hash, (None, GENESIS_HASH))
            self.assertEqual(audit.event_hash, recompute_hash_for(audit))
            self.assertEqual(outbox.event_id, audit.event_id)
            self.assertEqual(outbox.aggregate_type, audit.aggregate_type)
            self.assertEqual(outbox.aggregate_id, audit.aggregate_id)
            self.assertEqual(outbox.event_type, audit.event_type)
            self.assertEqual(outbox.payload, audit.payload | {"event_hash": audit.event_hash})
            allowed = {
                "verification_log_id", "id", "kiosk_id", "kiosk_identifier", "nonce_hash",
                "verified_at", "received_at", "is_late", "result_status", "is_vc_valid", "is_vp_valid",
                "is_face_matched", "is_liveness_valid", "transport_type", "failure_code",
                "face_model_version", "threshold_version", "status_list_age_seconds",
            }
            self.assertTrue(set(audit.payload) <= allowed, audit.payload)
            serialized = json.dumps([audit.payload, outbox.payload], ensure_ascii=False)
            self.assertNotIn(body["nonce"], serialized)
            self.assertNotIn(self.keys[0], serialized)
            self.assertFalse({"nonce", "user_id", "holder_did", "embedding", "face_image"} & set(audit.payload))

    async def test_identical_retry_returns_original_response_without_new_events(self):
        body = self._body()
        first = await self._post(body)
        self.assertEqual(first.status_code, 201, first.text)
        retry = await self._post(body)
        self.assertEqual(retry.status_code, 200, retry.text)
        self.assertEqual(retry.json(), first.json())
        self.assertEqual(await self._counts(), (1, 1, 1))

    async def test_retry_normalizes_timestamp_offset_and_optional_defaults(self):
        timestamp = datetime(2026, 9, 22, 2, 0, tzinfo=timezone.utc)
        body = self._body(verified_at=timestamp.isoformat())
        first = await self._post(body)
        self.assertEqual(first.status_code, 201, first.text)
        retry_body = body | {
            "verified_at": timestamp.astimezone(timezone(timedelta(hours=9))).isoformat(),
            "is_vp_valid": False, "is_liveness_valid": None, "failure_code": None,
            "face_model_version": None, "threshold_version": None, "status_list_age_seconds": None,
        }
        retry = await self._post(retry_body)
        self.assertEqual(retry.status_code, 200, retry.text)
        self.assertEqual(retry.json(), first.json())
        self.assertEqual(await self._counts(), (1, 1, 1))

    async def test_same_nonce_with_any_changed_result_field_is_rejected(self):
        body = self._body()
        first = await self._post(body)
        self.assertEqual(first.status_code, 201, first.text)
        changes = {
            "result_status": "FAIL_FACE_MISMATCH", "is_vc_valid": False, "is_vp_valid": True,
            "is_face_matched": False, "is_liveness_valid": True, "failure_code": "FACE_MISMATCH",
            "face_model_version": "new-model", "threshold_version": "new-threshold",
            "status_list_age_seconds": 1,
            "verified_at": (datetime.fromisoformat(body["verified_at"]) + timedelta(seconds=1)).isoformat(),
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                response = await self._post(body | {field: value})
                self._assert_error(response, 400, "KIOSK_RESULT_PAYLOAD_MISMATCH")
        self.assertEqual(await self._counts(), (1, 1, 1))

    async def test_same_nonce_is_independent_between_authenticated_kiosks(self):
        body = self._body()
        first = await self._post(body)
        second = await self._post(body | {"kiosk_identifier": self.identifiers[1]}, index=1)
        self.assertEqual(first.status_code, 201, first.text)
        self.assertEqual(second.status_code, 201, second.text)
        self.assertNotEqual(first.json()["id"], second.json()["id"])
        self.assertEqual(await self._counts(), (2, 2, 2))

    async def test_concurrent_identical_uploads_reach_insert_and_create_one_event(self):
        body = self._body()
        gate = self.insert_gate = _InsertGate()
        responses = await asyncio.wait_for(asyncio.gather(self._post(body), self._post(body)), timeout=20)
        self.assertEqual(gate.arrivals, 2, "두 요청이 실제 INSERT에 도달해야 중복 제약 경로를 검증한다")
        self.assertEqual(sorted(response.status_code for response in responses), [200, 201])
        self.assertEqual(responses[0].json(), responses[1].json())
        self.assertEqual(await self._counts(), (1, 1, 1))

    async def test_authenticated_kiosk_cannot_report_for_another_identifier(self):
        response = await self._post(self._body(kiosk_identifier=self.identifiers[1]))
        self._assert_error(response, 403, "KIOSK_IDENTIFIER_MISMATCH")
        self.assertEqual(await self._counts(), (0, 0, 0))

    async def test_missing_wrong_and_user_jwt_credentials_are_rejected(self):
        for headers in ({}, {"Authorization": "Bearer wrong-key"},
                        {"Authorization": f"Bearer {create_access_token(1, 'USER')}"}):
            with self.subTest(headers_present=bool(headers)):
                response = await self.client.post(PATH, json=self._body(), headers=headers)
                self._assert_error(response, 401, "KIOSK_KEY_INVALID")
        self.assertEqual(await self._counts(), (0, 0, 0))

    async def test_revoked_expired_keys_and_inactive_kiosk_are_rejected(self):
        async with self.session_factory() as db:
            key = await db.get(KioskApiKey, self.key_ids[0])
            key.status = "REVOKED"
            await db.commit()
        self._assert_error(await self._post(self._body()), 401, "KIOSK_KEY_INVALID")
        async with self.session_factory() as db:
            key = await db.get(KioskApiKey, self.key_ids[0])
            key.status = "ACTIVE"
            key.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            await db.commit()
        self._assert_error(await self._post(self._body()), 401, "KIOSK_KEY_INVALID")
        async with self.session_factory() as db:
            key = await db.get(KioskApiKey, self.key_ids[0])
            key.expires_at = None
            kiosk = await db.get(Kiosk, self.kiosk_ids[0])
            kiosk.status = "INACTIVE"
            await db.commit()
        self._assert_error(await self._post(self._body()), 401, "KIOSK_INACTIVE")
        self.assertEqual(await self._counts(), (0, 0, 0))

    async def test_late_threshold_is_strictly_more_than_seven_days_and_future_is_accepted(self):
        now = datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc)

        class FixedDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return now if tz is not None else now.replace(tzinfo=None)

        cases = [
            (now - timedelta(days=7), False),
            (now - timedelta(days=7, microseconds=1), True),
            (now - timedelta(days=7) + timedelta(microseconds=1), False),
            (now + timedelta(days=3), False),
        ]
        with patch.object(kiosk_results, "datetime", FixedDateTime):
            for verified_at, is_late in cases:
                with self.subTest(verified_at=verified_at):
                    response = await self._post(self._body(verified_at=verified_at.isoformat()))
                    self.assertEqual(response.status_code, 201, response.text)
                    self.assertEqual(response.json()["is_late"], is_late)
                    received_at = datetime.fromisoformat(response.json()["received_at"].replace("Z", "+00:00"))
                    self.assertEqual(received_at, now)
        self.assertEqual(await self._counts(), (4, 4, 4))

    async def test_status_list_age_zero_and_postgres_integer_max_are_accepted(self):
        for age in (0, 2_147_483_647):
            with self.subTest(age=age):
                response = await self._post(self._body(status_list_age_seconds=age))
                self.assertEqual(response.status_code, 201, response.text)
        async with self.session_factory() as db:
            ages = (await db.scalars(select(VerificationLog.status_list_age_seconds))).all()
        self.assertCountEqual(ages, [0, 2_147_483_647])

    async def test_malformed_inputs_and_private_extra_fields_do_not_reach_storage(self):
        invalid = [
            {"nonce": ""}, {"nonce": "   "}, {"nonce": "x" * 129}, {"nonce": 123},
            {"kiosk_identifier": ""}, {"kiosk_identifier": "x" * 256},
            {"verified_at": "2026-09-22T12:00:00"}, {"verified_at": "invalid"},
            {"result_status": "SUCCESS"}, {"transport_type": "BLE"},
            {"is_vc_valid": "true"}, {"is_face_matched": 1}, {"is_vp_valid": 1},
            {"is_liveness_valid": "false"}, {"status_list_age_seconds": -1},
            {"status_list_age_seconds": 2_147_483_648}, {"status_list_age_seconds": True},
            {"status_list_age_seconds": 1.5}, {"status_list_age_seconds": "123"},
            {"failure_code": "x" * 101}, {"face_model_version": "x" * 101},
            {"threshold_version": "x" * 101}, {"user_id": "private-user-marker"},
            {"embedding": [0.123, 0.456]}, {"face_image": "private-image-marker"},
        ]
        for fields in invalid:
            with self.subTest(fields=fields):
                response = await self._post(self._body(**fields))
                self._assert_error(response, 400, "INVALID_VERIFICATION_RESULT")
                self.assertNotIn("private-user-marker", response.text)
                self.assertNotIn("private-image-marker", response.text)
        missing = self._body()
        del missing["is_face_matched"]
        self._assert_error(await self._post(missing), 400, "INVALID_VERIFICATION_RESULT")
        broken_json = await self.client.post(
            PATH, content="{broken", headers={"Authorization": f"Bearer {self.keys[0]}",
                                              "Content-Type": "application/json"},
        )
        self._assert_error(broken_json, 400, "INVALID_VERIFICATION_RESULT")
        self.assertEqual(await self._counts(), (0, 0, 0))

    async def test_database_failure_rolls_back_result_audit_and_outbox(self):
        original = kiosk_results.record_audit_event

        async def fail_after_audit_flush(db, **kwargs):
            await original(db, **kwargs)
            await db.flush()
            # 세 종류의 INSERT 뒤 실제 PostgreSQL 오류를 발생시킨다.
            await db.execute(text("SELECT 1 / 0"))

        with patch.object(kiosk_results, "record_audit_event", side_effect=fail_after_audit_flush):
            response = await self._post(self._body())
        self._assert_error(response, 503, "VERIFICATION_RESULT_UNAVAILABLE")
        self.assertNotIn("division by zero", response.text)
        self.assertEqual(await self._counts(), (0, 0, 0))
