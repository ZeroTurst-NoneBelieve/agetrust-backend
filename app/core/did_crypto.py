"""DID(did:key) 키 인코딩 유틸.

기기 등록 시 사용자(Holder) 공개키를 did:key 문자열로 변환하는 데 쓰인다.
VC 발급/검증 로직은 #7 재설계(탈중앙 검증 방향 확정) 후 이 모듈에 다시 추가한다.
"""

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

_MULTICODEC_ED25519_PUB = b"\xed\x01"


def public_key_to_did_key(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    encoded = base58.b58encode(_MULTICODEC_ED25519_PUB + raw).decode()
    return f"did:key:z{encoded}"


def load_public_key_pem(pem: str) -> Ed25519PublicKey:
    return load_pem_public_key(pem.encode())
