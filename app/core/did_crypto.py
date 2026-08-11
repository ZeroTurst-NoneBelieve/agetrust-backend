"""DID / VC / VP 관련 암호 유틸.

- VC(성인 인증 증명서) 발급/검증: EduTrust 발급자 키로 서명 (EdDSA)
- VP(사용자 제출) 서명 검증: 사용자(Holder) 공개키로 검증 (개인키는 서버에 없음)
- DID(did:key) 인코딩
"""

import base64
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import base58
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

from app.config import settings
from app.schemas.errors import VerificationResultStatus

_MULTICODEC_ED25519_PUB = b"\xed\x01"


def public_key_to_did_key(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    encoded = base58.b58encode(_MULTICODEC_ED25519_PUB + raw).decode()
    return f"did:key:z{encoded}"


def public_key_pem(public_key: Ed25519PublicKey) -> str:
    return public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()


def load_public_key_pem(pem: str) -> Ed25519PublicKey:
    return load_pem_public_key(pem.encode())


# 개발용 발급자 키. 실제 배포 전 고정 키로 교체 필요 (재시작 시 바뀌면
# 이전에 발급한 VC를 검증할 수 없게 된다).
_issuer_private_key = Ed25519PrivateKey.generate()
_issuer_public_key = _issuer_private_key.public_key()
ISSUER_DID = public_key_to_did_key(_issuer_public_key)


def issue_vc(holder_did: str, expires_days: int | None = None) -> tuple[str, str]:
    credential_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    payload = {
        "iss": ISSUER_DID, "sub": holder_did, "jti": credential_id, "iat": now,
        "credentialType": "AdultCredential",
        "credentialSubject": {"isOver19": True},
    }
    days = expires_days if expires_days is not None else settings.vc_expire_days
    if days:
        payload["exp"] = now + timedelta(days=days)
    token = jwt.encode(payload, _issuer_private_key, algorithm="EdDSA")
    return token, credential_id


class VcError(Exception):
    def __init__(self, code: VerificationResultStatus):
        self.code = code
        super().__init__(code)


def decode_vc(token: str) -> dict:
    try:
        return jwt.decode(token, _issuer_public_key, algorithms=["EdDSA"])
    except jwt.ExpiredSignatureError:
        raise VcError(VerificationResultStatus.FAIL_EXPIRED)
    except jwt.InvalidTokenError:
        raise VcError(VerificationResultStatus.FAIL_INVALID_VC)


def verify_holder_signature(holder_public_key_pem: str, challenge_hash: str,
                             signature_b64: str) -> bool:
    try:
        pub = load_public_key_pem(holder_public_key_pem)
        pub.verify(base64.b64decode(signature_b64), challenge_hash.encode())
        return True
    except Exception:
        return False


def compute_challenge_hash(nonce: str, kiosk_id: int, timestamp: str, expires_at: str) -> str:
    raw = f"{nonce}:{kiosk_id}:{timestamp}:{expires_at}"
    return hashlib.sha256(raw.encode()).hexdigest()