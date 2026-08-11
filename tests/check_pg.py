"""실제 PostgreSQL(asyncpg)을 대상으로 한 End-to-End 테스트.

가입 -> 로그인 -> 기기등록 -> 성인인증기록 -> VC발급
-> 키오스크 challenge -> 키오스크 verify 까지 실제 DB에 쿼리하며 검증한다.

몇 번을 다시 실행해도 겹치지 않도록, 전화번호/아이디/키오스크 식별자를
매번 랜덤하게 만든다. (UNIQUE 제약 충돌 방지)
"""

import asyncio
import base64
import hashlib
import random
import string

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.core.did_crypto import public_key_pem
from app.database import AsyncSessionLocal, engine
from app.main import app

PASS, FAIL = [], []


def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("  PASS " if cond else "  FAIL ") + name)


def _rand_suffix(n=6):
    return "".join(random.choices(string.digits, k=n))


async def main():
    # 매 실행마다 겹치지 않는 값들. UNIQUE 제약(login_id, phone_number,
    # kiosk_identifier, device_identifier, business_number, store_code)에 걸리지 않게 한다.
    suffix = _rand_suffix()
    phone = f"+8210{_rand_suffix(8)}"
    login_id = f"gayeon{suffix}"
    device_identifier = f"device-{suffix}"
    kiosk_identifier = f"KIOSK-{suffix}"
    business_number = f"{_rand_suffix(3)}-{_rand_suffix(2)}-{_rand_suffix(5)}"
    store_code = f"STORE-{suffix}"

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:

        print("\n[0] 헬스체크")
        r = await c.get("/health")
        check("health 200", r.status_code == 200)

        print("\n[1] 회원가입 (SMS OTP 흐름) - 실제 PostgreSQL")
        r = await c.post("/api/v1/auth/phone/request", json={"phone_number": phone})
        check("otp 요청 200", r.status_code == 200)
        vid = r.json()["verification_id"]
        otp = r.json()["dev_otp"]

        r = await c.post("/api/v1/auth/phone/verify", json={"verification_id": vid, "otp": "000000"})
        check("틀린 otp 401", r.status_code == 401 and r.json()["detail"]["code"] == "OTP_MISMATCH")

        r = await c.post("/api/v1/auth/phone/verify", json={"verification_id": vid, "otp": otp})
        check("올바른 otp 204", r.status_code == 204)

        r = await c.post("/api/v1/auth/signup", json={
            "verification_id": vid, "login_id": login_id, "password": "test1234!", "name": "이가연",
        })
        if r.status_code != 200:
            print("  [디버그] signup 실패 응답:", r.status_code, r.json())
        check("회원가입 200", r.status_code == 200)
        check("id가 정수(BIGSERIAL)", isinstance(r.json().get("id"), int))
        check("phone_number 서버가 채움", r.json().get("phone_number") == phone)

        r = await c.post("/api/v1/auth/signup", json={
            "verification_id": vid, "login_id": f"{login_id}-2", "password": "test1234!", "name": "이가연",
        })
        check("같은 verification_id 재사용 차단", r.status_code == 400)

        print("\n[2] 로그인")
        r = await c.post("/api/v1/auth/login", json={"login_id": login_id, "password": "test1234!"})
        if r.status_code != 200:
            print("  [디버그] login 실패 응답:", r.status_code, r.json())
        check("로그인 200", r.status_code == 200)
        access = r.json()["access_token"]
        auth_header = {"Authorization": f"Bearer {access}"}

        print("\n[3] 기기 등록 + Holder DID 바인딩")
        holder_priv = Ed25519PrivateKey.generate()
        holder_pub_pem = public_key_pem(holder_priv.public_key())

        r = await c.post("/api/v1/auth/devices",
                          json={"device_identifier": device_identifier, "platform": "ANDROID"},
                          headers=auth_header)
        check("기기 등록 200", r.status_code == 200)
        device_id = r.json()["id"]
        check("device id도 정수", isinstance(device_id, int))
        check("아직 holder_did 없음", r.json()["holder_did"] is None)

        bad_sig = base64.b64encode(holder_priv.sign(b"wrong")).decode()
        r = await c.post("/api/v1/auth/devices/bind-holder-key", json={
            "device_id": device_id, "holder_public_key_pem": holder_pub_pem, "proof_signature_b64": bad_sig,
        }, headers=auth_header)
        check("잘못된 소유증명 400", r.status_code == 400)

        good_sig = base64.b64encode(holder_priv.sign(str(device_id).encode())).decode()
        r = await c.post("/api/v1/auth/devices/bind-holder-key", json={
            "device_id": device_id, "holder_public_key_pem": holder_pub_pem, "proof_signature_b64": good_sig,
        }, headers=auth_header)
        check("올바른 소유증명 200", r.status_code == 200)
        holder_did = r.json()["holder_did"]
        check("holder_did 생성됨", holder_did.startswith("did:key:z"))

        print("\n[4] 최초 성인 인증 기록 + VC 발급")
        r = await c.post("/api/v1/adult-verifications", json={
            "device_id": device_id, "age_check_passed": True, "id_face_match_passed": True,
        }, headers=auth_header)
        check("성인인증 기록 200", r.status_code == 200)
        check("SUCCESS", r.json()["result_status"] == "SUCCESS")
        av_id = r.json()["id"]

        r2 = await c.post("/api/v1/adult-verifications", json={
            "device_id": device_id, "age_check_passed": False, "id_face_match_passed": True,
        }, headers=auth_header)
        check("연령미달 FAIL_AGE", r2.json()["result_status"] == "FAIL_AGE")

        r = await c.post("/api/v1/did/issue", json={"adult_verification_id": av_id}, headers=auth_header)
        check("VC 발급 200", r.status_code == 200)
        vc_jwt = r.json()["credential"]

        r = await c.post("/api/v1/did/issue", json={"adult_verification_id": r2.json()["id"]}, headers=auth_header)
        check("실패기록으로 발급시도 400", r.status_code == 400)

        print("\n[5] 키오스크용 business -> store -> kiosk 체인 생성 (실제 FK 제약 확인)")
        async with AsyncSessionLocal() as db:
            from app.models import Business, Store, Kiosk
            biz = Business(business_number=business_number, business_name="테스트 편의점 본사", status="ACTIVE")
            db.add(biz)
            await db.flush()
            store = Store(business_id=biz.id, store_code=store_code, store_name="강남점",
                         store_type_code="CONVENIENCE", address="서울시 강남구", status="ACTIVE")
            db.add(store)
            await db.flush()
            raw_key = "test-kiosk-secret-key"
            kiosk = Kiosk(store_id=store.id, kiosk_identifier=kiosk_identifier,
                         api_key_hash=hashlib.sha256(raw_key.encode()).hexdigest(), status="ACTIVE")
            db.add(kiosk)
            await db.commit()
        check("business->store->kiosk FK 체인 정상 생성", True)
        kiosk_header = {"X-Kiosk-Key": f"{kiosk_identifier}:{raw_key}"}

        r = await c.post("/api/v1/did/challenges", json={"transport_type": "QR"},
                          headers={"X-Kiosk-Key": f"{kiosk_identifier}:wrong-key"})
        check("잘못된 키오스크 키 401", r.status_code == 401)

        print("\n[6] 키오스크 인증 - 성공 케이스")
        r = await c.post("/api/v1/did/challenges", json={"transport_type": "QR"}, headers=kiosk_header)
        check("challenge 생성 200", r.status_code == 200)
        challenge_hash = r.json()["challenge_hash"]

        holder_sig = base64.b64encode(holder_priv.sign(challenge_hash.encode())).decode()
        r = await c.post("/api/v1/did/verify", json={
            "challenge_hash": challenge_hash, "credential": vc_jwt,
            "holder_signature_b64": holder_sig, "face_matched": True,
        }, headers=kiosk_header)
        check("최종 검증 200", r.status_code == 200)
        check("SUCCESS", r.json()["result_status"] == "SUCCESS")

        r = await c.post("/api/v1/did/verify", json={
            "challenge_hash": challenge_hash, "credential": vc_jwt,
            "holder_signature_b64": holder_sig, "face_matched": True,
        }, headers=kiosk_header)
        check("challenge 재사용 차단", r.json()["result_status"] == "FAIL_CHALLENGE")

        print("\n[7] 키오스크 인증 - 실패 케이스들")
        r = await c.post("/api/v1/did/challenges", json={"transport_type": "QR"}, headers=kiosk_header)
        ch2 = r.json()["challenge_hash"]
        sig2 = base64.b64encode(holder_priv.sign(ch2.encode())).decode()
        r = await c.post("/api/v1/did/verify", json={
            "challenge_hash": ch2, "credential": vc_jwt, "holder_signature_b64": sig2, "face_matched": False,
        }, headers=kiosk_header)
        check("얼굴 불일치 FAIL_FACE_MISMATCH", r.json()["result_status"] == "FAIL_FACE_MISMATCH")

        r = await c.post("/api/v1/did/challenges", json={"transport_type": "QR"}, headers=kiosk_header)
        ch3 = r.json()["challenge_hash"]
        fake_priv = Ed25519PrivateKey.generate()
        fake_sig = base64.b64encode(fake_priv.sign(ch3.encode())).decode()
        r = await c.post("/api/v1/did/verify", json={
            "challenge_hash": ch3, "credential": vc_jwt, "holder_signature_b64": fake_sig, "face_matched": True,
        }, headers=kiosk_header)
        check("VP 서명 위조 FAIL_INVALID_VP", r.json()["result_status"] == "FAIL_INVALID_VP")

        # 실패한 challenge를 같은 값으로 재시도했을 때 500이 나면 안 된다.
        # (실패 경로에서 challenge가 PENDING으로 남으면 verification_logs.challenge_id
        #  UNIQUE 제약을 위반해 IntegrityError -> 500이 발생한다)
        r = await c.post("/api/v1/did/verify", json={
            "challenge_hash": ch3, "credential": vc_jwt, "holder_signature_b64": fake_sig, "face_matched": True,
        }, headers=kiosk_header)
        check("실패 후 재시도 500 안 남", r.status_code == 200)
        check("실패 후 재시도 CHALLENGE_ALREADY_USED", r.json()["failure_code"] == "CHALLENGE_ALREADY_USED")

        vc_payload = pyjwt.decode(vc_jwt, options={"verify_signature": False})
        async with AsyncSessionLocal() as db:
            from app.models import VcCredential
            from sqlalchemy import update
            await db.execute(
                update(VcCredential).where(VcCredential.credential_id == vc_payload["jti"])
                .values(status="REVOKED")
            )
            await db.commit()

        r = await c.post("/api/v1/did/challenges", json={"transport_type": "QR"}, headers=kiosk_header)
        ch4 = r.json()["challenge_hash"]
        sig4 = base64.b64encode(holder_priv.sign(ch4.encode())).decode()
        r = await c.post("/api/v1/did/verify", json={
            "challenge_hash": ch4, "credential": vc_jwt, "holder_signature_b64": sig4, "face_matched": True,
        }, headers=kiosk_header)
        check("폐기된 VC FAIL_REVOKED_VC", r.json()["result_status"] == "FAIL_REVOKED_VC")

        print("\n[8] 전화번호 형식 검증")
        r = await c.post("/api/v1/auth/phone/request", json={"phone_number": "01012345678"})
        check("형식 틀린 번호 422", r.status_code == 422)
        r = await c.post("/api/v1/auth/phone/request", json={"phone_number": f"+8210{_rand_suffix(8)}"})
        check("올바른 E.164 200", r.status_code == 200)

    # 실제 테이블 row 수 직접 확인 (진짜 저장됐는지 최종 검증)
    print("\n[9] 실제 DB row 개수 직접 확인")
    async with engine.connect() as conn:
        for table in ["users", "devices", "adult_verifications", "vc_credentials",
                     "verification_challenges", "verification_logs", "kiosks"]:
            result = await conn.execute(text(f"SELECT COUNT(*) FROM {table}"))
            count = result.scalar()
            check(f"{table} 테이블에 실제 row 존재 ({count}건)", count > 0)

    print(f"\n{'='*40}\n총 {len(PASS)+len(FAIL)}개 중 PASS {len(PASS)} / FAIL {len(FAIL)}")
    if FAIL:
        print("실패:", FAIL)


asyncio.run(main())