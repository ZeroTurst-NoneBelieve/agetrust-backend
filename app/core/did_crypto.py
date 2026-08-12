"""DID / VC / VP 관련 암호 유틸.

- VC(성인 인증 크레덴셜) 발급/검증: EduTrust 발급자 키로 서명 (EdDSA)
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

# W3C Verifiable Credentials Data Model v1.1
VC_CONTEXT = "https://www.w3.org/2018/credentials/v1"
VC_TYPE = "VerifiableCredential"
ADULT_CREDENTIAL_TYPE = "AdultCredential"

# W3C DID Core / did:key
DID_CONTEXT = "https://www.w3.org/ns/did/v1"
ED25519_2020_CONTEXT = "https://w3id.org/security/suites/ed25519-2020/v1"


def public_key_to_did_key(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    encoded = base58.b58encode(_MULTICODEC_ED25519_PUB + raw).decode()
    return f"did:key:z{encoded}"


def build_did_document(did: str) -> dict:
    """did:key 문자열로부터 W3C DID Document를 생성한다.

    did:key는 DID 문자열 자체에 공개키가 인코딩되어 있는 방식이라,
    별도 저장소 없이 DID만으로 Document를 결정론적으로 유도할 수 있다.
    (https://w3c-ccg.github.io/did-method-key/)
    """
    prefix = "did:key:"
    if not did.startswith(prefix + "z"):
        raise ValueError("unsupported DID method (only did:key is supported)")

    multibase = did[len(prefix):]          # 예: "z6Mk..."
    try:
        decoded = base58.b58decode(multibase[1:])
    except Exception:
        raise ValueError("invalid did:key encoding")

    if (not decoded.startswith(_MULTICODEC_ED25519_PUB)
            or len(decoded) != len(_MULTICODEC_ED25519_PUB) + 32):
        raise ValueError("did:key is not an Ed25519 public key")

    verification_method_id = f"{did}#{multibase}"
    return {
        "@context": [DID_CONTEXT, ED25519_2020_CONTEXT],
        "id": did,
        "verificationMethod": [
            {
                "id": verification_method_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": multibase,
            }
        ],
        "authentication": [verification_method_id],
        "assertionMethod": [verification_method_id],
    }


def public_key_pem(public_key: Ed25519PublicKey) -> str:
    return public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()


def load_public_key_pem(pem: str) -> Ed25519PublicKey:
    return load_pem_public_key(pem.encode())


# 개발용 발급자 키. 실제 배포 시 고정 키로 교체 필요 (재시작 시 키가 바뀌면
# 이전에 발급한 VC를 검증할 수 없게 된다).
_issuer_private_key = Ed25519PrivateKey.generate()
_issuer_public_key = _issuer_private_key.public_key()
ISSUER_DID = public_key_to_did_key(_issuer_public_key)


def issue_vc(holder_did: str, expires_days: int | None = None) -> tuple[str, str]:
    """성인 인증 VC를 W3C VC Data Model의 JWT 인코딩 형식으로 발급한다.

    VC Data Model v1.1의 JWT 표현 규칙에 따라 아래 항목은 JWT 등록 클레임으로
    표현하고 `vc` 객체 안에서는 중복하지 않는다.
      iss -> issuer, sub -> credentialSubject.id, jti -> id,
      nbf -> issuanceDate, exp -> expirationDate

    credentialSubject에는 최소 클레임(isOver19)만 담는다.
    생년월일/이름 등 식별 가능한 개인정보는 포함하지 않는다.
    """
    credential_id = f"urn:uuid:{uuid.uuid4()}"
    now = datetime.now(timezone.utc)

    payload = {
        "iss": ISSUER_DID,
        "sub": holder_did,
        "jti": credential_id,
        "iat": now,
        "nbf": now,
        "vc": {
            "@context": [VC_CONTEXT],
            "type": [VC_TYPE, ADULT_CREDENTIAL_TYPE],
            "credentialSubject": {
                "id": holder_did,
                "isOver19": True,
            },
        },
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
    """VC JWT의 서명/만료를 검증하고 payload를 돌려준다.

    서명 검증에 더해 W3C VC 구조(`vc` 클레임, type 목록)도 함께 확인한다.
    """
    try:
        payload = jwt.decode(token, _issuer_public_key, algorithms=["EdDSA"])
    except jwt.ExpiredSignatureError:
        raise VcError(VerificationResultStatus.FAIL_EXPIRED)
    except jwt.InvalidTokenError:
        raise VcError(VerificationResultStatus.FAIL_INVALID_VC)

    vc = payload.get("vc")
    if not isinstance(vc, dict):
        raise VcError(VerificationResultStatus.FAIL_INVALID_VC)
    if VC_TYPE not in (vc.get("type") or []):
        raise VcError(VerificationResultStatus.FAIL_INVALID_VC)

    return payload


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