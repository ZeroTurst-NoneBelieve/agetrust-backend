"""docs#3 — 성인 인증 E2E 시나리오 통합 테스트 (백엔드 구간).

## 범위

원래 이슈는 Mobile -> Backend -> Admin Web 3단 통합이지만, 작성 시점에
모바일은 `lib/main.dart` 1개, 어드민 웹은 Vite 스캐폴드 상태라 두 구간은
검증할 대상이 없다. 따라서 이 파일은 **백엔드 구간 전체**를 실제 HTTP로
관통하고, 어드민 웹이 소비할 감사 로그가 실제로 조회되는지까지 확인한다.

모바일/어드민 구간은 각 파트 구현 후 이 시나리오에 이어 붙인다.

## 실행

DB가 필요하다. localhost DATABASE_URL이 없으면 전체 스킵된다.
실행 방법은 docs 레포의 E2E 시나리오 문서를 참고한다.
"""

import base64
import os
import time
import unittest
import uuid

# E2E는 실제 DB가 필요하므로 전용 환경변수로 명시적으로 켠다.
# DATABASE_URL을 쓰면, 같은 discover 실행에서 먼저 임포트된 단위 테스트가
# 넣어둔 자리표시자 URL을 진짜 DB로 오인해 연결을 시도하게 된다.
E2E_DB_URL = os.environ.get("E2E_DATABASE_URL")
RUN_E2E = bool(E2E_DB_URL)

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())


def _unique(prefix):
    return f"{prefix}{uuid.uuid4().hex[:10]}"


def _phone():
    return f"+8210{uuid.uuid4().int % 10**8:08d}"


def _holder_material(device_id):
    """모바일이 Secure Storage에서 하는 일을 테스트에서 대신한다."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    signature = base64.b64encode(private_key.sign(str(device_id).encode())).decode()
    return pem, signature


@unittest.skipUnless(RUN_E2E, "E2E는 로컬 DATABASE_URL이 있을 때만 실행한다")
class AdultVerificationE2ETests(unittest.IsolatedAsyncioTestCase):
    """시나리오 1·2와 병목 점검을 순서대로 수행한다."""

    async def asyncSetUp(self):
        import httpx
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        from app.config import settings
        from app.database import get_db
        from app.main import app

        self.app = app

        # 앱의 엔진은 임포트 시점의 DATABASE_URL에 묶인다. discover로 돌리면
        # 먼저 임포트된 단위 테스트의 자리표시자 URL이 잡혀 있으므로,
        # E2E 전용 엔진을 만들어 get_db 의존성을 갈아끼운다.
        #
        # IsolatedAsyncioTestCase가 테스트마다 새 이벤트 루프를 만들기 때문에
        # 엔진도 테스트마다 새로 만든다. 이전 루프에 묶인 커넥션을 재사용하면
        # "another operation is in progress"로 깨진다.
        self.engine = create_async_engine(E2E_DB_URL, echo=False)
        session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self.session_factory = session_factory

        async def _override_get_db():
            async with session_factory() as session:
                yield session

        app.dependency_overrides[get_db] = _override_get_db

        # 시나리오가 OTP를 응답으로 받아야 흐름을 이어갈 수 있다.
        # 환경변수는 settings가 이미 만들어진 뒤라 효과가 없으므로 직접 켠다.
        self._dev_mode_before = settings.dev_mode
        settings.dev_mode = True

        self.timings = {}
        self.transport = httpx.ASGITransport(app=app)
        self.client = httpx.AsyncClient(transport=self.transport, base_url="http://e2e")

    async def asyncTearDown(self):
        from app.config import settings
        from app.database import get_db

        settings.dev_mode = self._dev_mode_before
        self.app.dependency_overrides.pop(get_db, None)
        await self.client.aclose()
        await self.engine.dispose()

    async def _timed(self, label, method, url, **kwargs):
        """각 구간 소요 시간을 기록한다 (세부 작업 3: 병목 구간 점검)."""
        started = time.perf_counter()
        response = await self.client.request(method, url, **kwargs)
        self.timings[label] = (time.perf_counter() - started) * 1000
        return response

    async def _admin_headers(self):
        """감사 로그 조회용 관리자 계정을 확보한다."""
        from datetime import datetime, timezone

        from sqlalchemy import select

        from app.core.security import create_access_token, hash_password
        from app.models import User

        async with self.session_factory() as db:
            found = await db.execute(select(User).where(User.login_id == "e2e-admin"))
            admin = found.scalar_one_or_none()
            if admin is None:
                admin = User(
                    login_id="e2e-admin",
                    password_hash=hash_password("admin-password"),
                    name="e2e admin",
                    phone_number=_phone(),
                    phone_verified_at=datetime.now(timezone.utc),
                    platform_role="ADMIN",
                    status="ACTIVE",
                )
                db.add(admin)
                await db.commit()
                await db.refresh(admin)
            return {"Authorization": f"Bearer {create_access_token(admin.id, 'ADMIN')}"}

    async def _audit_events(self, admin_headers, **params):
        response = await self.client.get(
            "/api/v1/admin/logs", headers=admin_headers, params=params
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    async def _signed_up_user(self):
        """전화 인증 -> 가입 -> 로그인까지 마친 사용자를 만든다."""
        r = await self.client.post("/api/v1/auth/phone/request", json={"phone_number": _phone()})
        self.assertEqual(r.status_code, 200, r.text)
        verification_id = r.json()["verification_id"]
        otp = r.json()["dev_otp"]

        r = await self.client.post(
            "/api/v1/auth/phone/verify", json={"verification_id": verification_id, "otp": otp}
        )
        self.assertEqual(r.status_code, 204, r.text)

        login_id = _unique("e2e")
        r = await self.client.post(
            "/api/v1/auth/signup",
            json={
                "verification_id": verification_id,
                "login_id": login_id,
                "password": "e2e-password-1234",
                "name": "통합테스트",
            },
        )
        self.assertEqual(r.status_code, 200, r.text)
        user_id = r.json()["id"]

        r = await self.client.post(
            "/api/v1/auth/login",
            json={"login_id": login_id, "password": "e2e-password-1234"},
        )
        self.assertEqual(r.status_code, 200, r.text)
        return user_id, login_id, {"Authorization": f"Bearer {r.json()['access_token']}"}

    async def _bound_device(self, auth):
        """기기 등록 + Holder 키 바인딩까지 마친 device_id를 준다."""
        r = await self.client.post(
            "/api/v1/auth/devices",
            headers=auth,
            json={"device_identifier": _unique("dev"), "platform": "ANDROID"},
        )
        self.assertEqual(r.status_code, 200, r.text)
        device_id = r.json()["id"]
        self.assertIsNone(r.json()["holder_did"], "등록 직후엔 holder_did가 없어야 한다")

        pem, signature = _holder_material(device_id)
        r = await self.client.post(
            "/api/v1/auth/devices/bind-holder-key",
            headers=auth,
            json={
                "device_id": device_id,
                "holder_public_key_pem": pem,
                "proof_signature_b64": signature,
            },
        )
        self.assertEqual(r.status_code, 200, r.text)
        return device_id, r.json()["holder_did"]

    # -----------------------------------------------------------------
    # 시나리오 1: 정상 사용자의 인증 -> VC 발급 -> 승인 로그 확인
    # -----------------------------------------------------------------
    async def test_scenario_1_happy_path_issues_vc_and_logs_approval(self):
        admin = await self._admin_headers()

        # 1) 전화 인증
        phone = _phone()
        r = await self._timed(
            "phone/request", "POST", "/api/v1/auth/phone/request",
            json={"phone_number": phone},
        )
        self.assertEqual(r.status_code, 200, r.text)
        verification_id = r.json()["verification_id"]
        otp = r.json()["dev_otp"]
        self.assertIsNotNone(otp, "DEV_MODE=true인데 dev_otp가 없다")

        r = await self._timed(
            "phone/verify", "POST", "/api/v1/auth/phone/verify",
            json={"verification_id": verification_id, "otp": otp},
        )
        self.assertEqual(r.status_code, 204, r.text)

        # 2) 가입
        login_id = _unique("e2euser")
        r = await self._timed(
            "signup", "POST", "/api/v1/auth/signup",
            json={
                "verification_id": verification_id,
                "login_id": login_id,
                "password": "e2e-password-1234",
                "name": "통합테스트",
            },
        )
        self.assertEqual(r.status_code, 200, r.text)
        user_id = r.json()["id"]

        # 3) 로그인
        r = await self._timed(
            "login", "POST", "/api/v1/auth/login",
            json={"login_id": login_id, "password": "e2e-password-1234"},
        )
        self.assertEqual(r.status_code, 200, r.text)
        auth = {"Authorization": f"Bearer {r.json()['access_token']}"}

        # 4) 기기 등록
        r = await self._timed(
            "devices", "POST", "/api/v1/auth/devices", headers=auth,
            json={"device_identifier": _unique("dev"), "platform": "ANDROID"},
        )
        self.assertEqual(r.status_code, 200, r.text)
        device_id = r.json()["id"]

        # 5) Holder 키 바인딩 (모바일 Secure Storage 대역)
        pem, signature = _holder_material(device_id)
        r = await self._timed(
            "bind-holder-key", "POST", "/api/v1/auth/devices/bind-holder-key", headers=auth,
            json={
                "device_id": device_id,
                "holder_public_key_pem": pem,
                "proof_signature_b64": signature,
            },
        )
        self.assertEqual(r.status_code, 200, r.text)
        holder_did = r.json()["holder_did"]
        self.assertTrue(holder_did.startswith("did:key:z"), holder_did)

        # 6) 온디바이스 성인 인증 결과 업로드
        r = await self._timed(
            "adult-verifications", "POST", "/api/v1/adult-verifications", headers=auth,
            json={
                "device_id": device_id,
                "age_check_passed": True,
                "id_face_match_passed": True,
                "liveness_passed": True,
                "age_policy_version": "2026-KR-19",
                "model_version": "MobileFaceNet-v1.0",
                "threshold_version": "th-2026-08",
            },
        )
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["result_status"], "SUCCESS")
        verification_row_id = r.json()["id"]

        # 7) VC 발급
        r = await self._timed(
            "did/issue", "POST", "/api/v1/did/issue", headers=auth,
            json={"adult_verification_id": verification_row_id},
        )
        self.assertEqual(r.status_code, 200, r.text)
        issued = r.json()
        self.assertEqual(issued["holder_did"], holder_did)
        self.assertEqual(issued["credential"].count("."), 2, "JWT 형식이 아니다")

        # 8) 발급자 DID Document가 VC의 issuer와 일치하는가
        r = await self._timed("did/issuer", "GET", "/api/v1/did/issuer")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["id"], issued["issuer_did"])

        # 9) 어드민 웹이 볼 승인 로그가 실제로 조회되는가
        r = await self._timed(
            "admin/logs", "GET", "/api/v1/admin/logs", headers=admin,
            params={"event_type": "VC_ISSUED", "actor_ref": str(user_id)},
        )
        self.assertEqual(r.status_code, 200, r.text)
        page = r.json()
        self.assertEqual(page["total"], 1, "VC 발급 승인 로그가 조회되지 않는다")
        event = page["items"][0]
        self.assertEqual(event["payload"]["credential_id"], issued["credential_id"])
        self.assertEqual(event["payload"]["holder_did"], holder_did)
        # 감사 로그가 유출돼도 그대로 쓸 수 있는 자격증명이 되면 안 된다.
        self.assertNotIn("credential", event["payload"])

        # 10) 인증 여정 전체가 감사 로그로 재구성되는가
        journey = await self._audit_events(admin, actor_ref=str(user_id), limit=50)
        types = {e["event_type"] for e in journey["items"]}
        for expected in (
            "USER_SIGNED_UP",
            "LOGIN_SUCCEEDED",
            "DEVICE_REGISTERED",
            "HOLDER_KEY_BOUND",
            "ADULT_VERIFICATION_RECORDED",
            "VC_ISSUED",
        ):
            self.assertIn(expected, types, f"{expected}가 감사 로그에 없다")

        # 11) 체인 무결성
        r = await self.client.get("/api/v1/admin/logs/chain-verification", headers=admin)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["is_intact"], f"체인 파손: {r.json()['first_break']}")

    # -----------------------------------------------------------------
    # 시나리오 2: 비정상 요청 / 인증 실패의 예외 처리와 실패 로그
    # -----------------------------------------------------------------
    async def test_scenario_2_failures_are_rejected_and_logged(self):
        admin = await self._admin_headers()

        # 2-1) 잘못된 OTP -> 401, 실패 로그 기록
        phone = _phone()
        r = await self.client.post("/api/v1/auth/phone/request", json={"phone_number": phone})
        verification_id = r.json()["verification_id"]
        real_otp = r.json()["dev_otp"]
        wrong_otp = "000000" if real_otp != "000000" else "111111"

        r = await self.client.post(
            "/api/v1/auth/phone/verify",
            json={"verification_id": verification_id, "otp": wrong_otp},
        )
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["detail"]["code"], "OTP_MISMATCH")

        page = await self._audit_events(
            admin, event_type="PHONE_VERIFICATION_FAILED", aggregate_id=verification_id
        )
        self.assertEqual(page["total"], 1, "OTP 실패가 감사 로그에 남지 않았다")
        # 실패 로그에 전화번호 원문이 남으면 안 된다.
        self.assertNotIn(phone.lstrip("+"), page["items"][0]["actor_ref"] or "")

        # 2-2) 없는 계정 / 틀린 비밀번호 -> 401, 실패 로그
        ghost_login_id = _unique("ghost")
        r = await self.client.post(
            "/api/v1/auth/login",
            json={"login_id": ghost_login_id, "password": "wrong-password"},
        )
        self.assertEqual(r.status_code, 401)

        page = await self._audit_events(
            admin, event_type="LOGIN_FAILED", actor_ref=ghost_login_id
        )
        self.assertEqual(page["total"], 1, "로그인 실패가 감사 로그에 남지 않았다")
        self.assertNotIn("wrong-password", str(page["items"][0]["payload"]))

        # 이후 경로를 위해 정상 계정과 기기를 준비한다.
        _user_id, _login_id, auth = await self._signed_up_user()
        device_id, _holder_did = await self._bound_device(auth)

        # 2-3) 연령 미달 -> FAIL_AGE로 기록되고 감사 로그에도 남는다
        r = await self.client.post(
            "/api/v1/adult-verifications", headers=auth,
            json={
                "device_id": device_id,
                "age_check_passed": False,
                "id_face_match_passed": True,
                "liveness_passed": True,
            },
        )
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["result_status"], "FAIL_AGE")
        failed_verification_id = r.json()["id"]

        page = await self._audit_events(
            admin,
            event_type="ADULT_VERIFICATION_RECORDED",
            aggregate_id=str(failed_verification_id),
        )
        self.assertEqual(page["total"], 1, "실패한 성인 인증이 감사 로그에 없다")
        self.assertEqual(page["items"][0]["payload"]["result_status"], "FAIL_AGE")

        # 2-4) 실패한 인증으로 VC 발급 시도 -> 400 (핵심 우회 차단)
        r = await self.client.post(
            "/api/v1/did/issue", headers=auth,
            json={"adult_verification_id": failed_verification_id},
        )
        self.assertEqual(r.status_code, 400, "실패한 인증으로 VC가 발급되면 안 된다")

        # 2-5) 존재하지 않는 인증 id -> 404
        r = await self.client.post(
            "/api/v1/did/issue", headers=auth,
            json={"adult_verification_id": 999_999_999},
        )
        self.assertEqual(r.status_code, 404)

        # 2-6) 남의 인증 id로 발급 시도 -> 404 (소유자 검증)
        _other_id, _other_login, other_auth = await self._signed_up_user()
        other_device_id, _ = await self._bound_device(other_auth)
        r = await self.client.post(
            "/api/v1/adult-verifications", headers=other_auth,
            json={
                "device_id": other_device_id,
                "age_check_passed": True,
                "id_face_match_passed": True,
                "liveness_passed": True,
            },
        )
        others_verification_id = r.json()["id"]
        r = await self.client.post(
            "/api/v1/did/issue", headers=auth,
            json={"adult_verification_id": others_verification_id},
        )
        self.assertEqual(r.status_code, 404, "남의 인증으로 VC가 발급되면 안 된다")

        # 2-7) 토큰 없이 보호된 엔드포인트 -> 401
        r = await self.client.get("/api/v1/auth/me")
        self.assertEqual(r.status_code, 401)

        # 2-8) 일반 사용자가 감사 로그 조회 -> 403
        r = await self.client.get("/api/v1/admin/logs", headers=auth)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()["detail"]["code"], "PERMISSION_DENIED")

        # 2-9) 기기 분실 후 키 재바인딩 -> 기존 VC 폐기 + 재바인딩 로그 (#22)
        r = await self.client.post(
            "/api/v1/adult-verifications", headers=auth,
            json={
                "device_id": device_id,
                "age_check_passed": True,
                "id_face_match_passed": True,
                "liveness_passed": True,
            },
        )
        good_verification_id = r.json()["id"]
        r = await self.client.post(
            "/api/v1/did/issue", headers=auth,
            json={"adult_verification_id": good_verification_id},
        )
        self.assertEqual(r.status_code, 200, r.text)

        new_pem, new_signature = _holder_material(device_id)
        r = await self.client.post(
            "/api/v1/auth/devices/bind-holder-key", headers=auth,
            json={
                "device_id": device_id,
                "holder_public_key_pem": new_pem,
                "proof_signature_b64": new_signature,
            },
        )
        self.assertEqual(r.status_code, 200, r.text)

        page = await self._audit_events(
            admin, event_type="HOLDER_KEY_REBOUND", aggregate_id=str(device_id)
        )
        self.assertEqual(page["total"], 1, "재바인딩이 감사 로그에 없다")
        self.assertGreaterEqual(
            page["items"][0]["payload"]["revoked_vc_count"], 1,
            "재바인딩했는데 폐기된 VC가 0건이다",
        )

        # 2-10) 소유증명 서명이 틀리면 바인딩 거부
        other_pem, _unused = _holder_material(device_id)
        _unused2, mismatched_signature = _holder_material(device_id + 1)
        r = await self.client.post(
            "/api/v1/auth/devices/bind-holder-key", headers=auth,
            json={
                "device_id": device_id,
                "holder_public_key_pem": other_pem,
                "proof_signature_b64": mismatched_signature,
            },
        )
        self.assertEqual(r.status_code, 400, "소유증명 실패가 통과됐다")

        # 실패가 이어져도 체인은 온전해야 한다.
        r = await self.client.get("/api/v1/admin/logs/chain-verification", headers=admin)
        self.assertTrue(r.json()["is_intact"], f"체인 파손: {r.json()['first_break']}")

    # -----------------------------------------------------------------
    # 세부 작업 3: 데이터 통신 병목 구간 점검
    # -----------------------------------------------------------------
    async def test_scenario_3_reports_slowest_stages(self):
        """각 구간 소요 시간을 재서 눈에 띄는 병목을 드러낸다.

        ASGI 인프로세스 호출이라 네트워크 지연은 빠져 있다. 절대값이 아니라
        구간 간 상대 비교용이다.
        """
        await self.test_scenario_1_happy_path_issues_vc_and_logs_approval()

        ranked = sorted(self.timings.items(), key=lambda kv: kv[1], reverse=True)
        print("\n--- 구간별 소요 시간 (ms, 느린 순) ---")
        for label, elapsed in ranked:
            print(f"  {label:22} {elapsed:8.1f}")

        slowest_label, slowest_ms = ranked[0]
        # bcrypt를 쓰는 signup/login이 가장 느린 것이 정상이다. VC 발급이나
        # 감사 로그 기록이 그보다 느리면 서명·체인 쪽을 들여다봐야 한다.
        self.assertIn(
            slowest_label, {"signup", "login"},
            f"예상 밖의 병목: {slowest_label} ({slowest_ms:.1f}ms). "
            "보통은 bcrypt를 쓰는 signup/login이 가장 느리다.",
        )


if __name__ == "__main__":
    unittest.main()
