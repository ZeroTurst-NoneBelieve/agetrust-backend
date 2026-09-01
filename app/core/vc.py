"""AgeTrust VC 발급 및 did:key DID Document 생성 유틸."""

import base64
import binascii
import uuid
from datetime import datetime, timedelta, timezone

import base58
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.config import settings
from app.core.did_key import public_key_to_did_key
from app.core.status_list import STATUS_LIST_CREDENTIAL_TYPE

_MULTICODEC_ED25519_PUB = b"\xed\x01"

# W3C Verifiable Credentials Data Model v1.1
VC_CONTEXT = "https://www.w3.org/2018/credentials/v1"
VC_TYPE = "VerifiableCredential"
ADULT_CREDENTIAL_TYPE = "AdultCredential"

# W3C Status List 2021
STATUS_LIST_CONTEXT = "https://w3id.org/vc/status-list/2021/v1"

# W3C DID Core / did:key
DID_CONTEXT = "https://www.w3.org/ns/did/v1"
ED25519_2020_CONTEXT = "https://w3id.org/security/suites/ed25519-2020/v1"


def _load_issuer_private_key(encoded_key: str) -> Ed25519PrivateKey:
    """base64로 인코딩된 raw 32바이트 Ed25519 개인키를 불러온다."""
    try:
        raw_key = base64.b64decode(encoded_key, validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise ValueError(
            "ISSUER_PRIVATE_KEY must be valid base64 encoded raw Ed25519 key"
        ) from None

    if len(raw_key) != 32:
        raise ValueError("ISSUER_PRIVATE_KEY must decode to exactly 32 bytes")

    return Ed25519PrivateKey.from_private_bytes(raw_key)


_issuer_private_key = _load_issuer_private_key(settings.issuer_private_key)
ISSUER_DID = public_key_to_did_key(_issuer_private_key.public_key())


def build_did_document(did: str) -> dict:
    """did:key 문자열로부터 W3C DID Document를 결정론적으로 생성한다."""
    prefix = "did:key:"
    if not did.startswith(prefix + "z"):
        raise ValueError("unsupported DID method (only did:key is supported)")

    multibase = did[len(prefix):]
    try:
        decoded = base58.b58decode(multibase[1:])
    except (ValueError, TypeError):
        raise ValueError("invalid did:key encoding") from None

    if (
        not decoded.startswith(_MULTICODEC_ED25519_PUB)
        or len(decoded) != len(_MULTICODEC_ED25519_PUB) + 32
    ):
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


def issue_vc(
    holder_did: str,
    expires_days: int | None = None,
    credential_status: dict | None = None,
) -> tuple[str, str, datetime | None]:
    """최소 성인 여부 클레임만 담은 W3C VC JWT를 발급한다.

    credential_status를 주면 VC 본문에 credentialStatus로 실어 보낸다.
    키오스크는 이 값을 보고 폐기 목록을 조회한다. 상태 목록의 인덱스를
    배정하려면 DB가 필요한데 이 함수는 DB를 알지 못하므로, 호출부가
    배정 결과를 만들어 넘겨주는 구조로 둔다.

    VC JWT에서 credentialStatus는 payload 최상단이 아니라 payload["vc"]
    안에 들어간다. credentialSubject와 같은 자리다.
    """
    credential_id = f"urn:uuid:{uuid.uuid4()}"
    now = datetime.now(timezone.utc).replace(microsecond=0)

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

    # 상태 목록을 쓰지 않고 발급하던 기존 경로를 그대로 두기 위해,
    # 값이 있을 때만 넣는다. 빈 dict를 실어 보내면 키오스크가 조회할
    # 주소가 없는 credentialStatus가 되므로 None과 같이 취급한다.
    if credential_status:
        payload["vc"]["credentialStatus"] = credential_status

    days = expires_days if expires_days is not None else settings.vc_expire_days
    expires_at = now + timedelta(days=days) if days else None
    if expires_at is not None:
        payload["exp"] = expires_at

    token = jwt.encode(payload, _issuer_private_key, algorithm="EdDSA")
    return token, credential_id, expires_at


def issue_status_list_vc(
    status_list_url: str,
    encoded_list: str,
    status_purpose: str,
) -> str:
    """폐기 목록 자체를 담은 StatusList2021Credential JWT를 만든다.

    목록을 서명 없이 내보내면 중간에서 전부 0인 가짜 목록으로 바꿔치기할 수
    있고, 그러면 폐기된 VC가 키오스크를 다시 통과한다. 발급자 키로 서명해야
    키오스크가 목록의 진위를 확인할 수 있다.

    성인 VC와 달리 만료(exp)를 넣지 않는다. 목록은 폐기가 생길 때마다 갱신되는
    최신 상태 그 자체이고, 만료를 두면 갱신이 늦어졌을 때 키오스크가 검증할
    목록을 잃는다.
    """
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = {
        "iss": ISSUER_DID,
        "sub": status_list_url,
        "jti": status_list_url,
        "iat": now,
        "nbf": now,
        "vc": {
            "@context": [VC_CONTEXT, STATUS_LIST_CONTEXT],
            "id": status_list_url,
            "type": [VC_TYPE, STATUS_LIST_CREDENTIAL_TYPE],
            "issuer": ISSUER_DID,
            "credentialSubject": {
                "id": f"{status_list_url}#list",
                "type": "StatusList2021",
                "statusPurpose": status_purpose,
                "encodedList": encoded_list,
            },
        },
    }
    return jwt.encode(payload, _issuer_private_key, algorithm="EdDSA")