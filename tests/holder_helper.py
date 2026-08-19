"""시연/테스트용 Holder 키쌍 생성 및 소유증명 서명 헬퍼.

사용법:
    python tests/holder_helper.py <device_id>

출력:
    1) holder_public_key_pem  -> bind-holder-key 요청의 공개키 필드에 붙여넣기
    2) proof_signature        -> bind-holder-key 요청의 서명 필드에 붙여넣기

주의: 개인키는 화면에 출력하지 않는다. 실행할 때마다 새 키쌍이 생성되므로
      같은 기기에 대해 재실행하면 이전 서명은 무효가 된다.
"""

import base64
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

if len(sys.argv) < 2:
    print("사용법: python tests/holder_helper.py <device_id>")
    sys.exit(1)

device_id = sys.argv[1]

private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
signature = base64.b64encode(private_key.sign(device_id.encode())).decode()

print()
print("=== device_id ===")
print(device_id)
print()
print("=== holder public key (PEM) ===")
print(pem)
print("=== proof signature (base64) ===")
print(signature)
print()
