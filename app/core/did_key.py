"""DID(did:key) 키 인코딩 유틸 — #7·#8 공통.

기기 등록 시 사용자(Holder) 공개키를 did:key 문자열로 변환하는 데 쓰인다.

이 모듈은 #8(기기 등록·Holder 키 바인딩)이 의존하므로 #7 전용 코드를 넣지 않는다.
VC 발급/서명 로직은 별도 모듈(app/core/vc.py)로 분리해, #7이 되돌려지더라도
#8 기능이 함께 깨지지 않도록 한다. (2026-08-12 dev 기동 불가 사고 재발 방지)
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