"""StatusList2021 비트열 인코딩·디코딩 유틸.

W3C Status List 2021 규격에 따라 VC 폐기 상태를 하나의 긴 비트열로 관리한다.
VC 한 건이 비트 하나를 차지하며, 0이면 유효하고 1이면 폐기된 상태다.

키오스크가 "이 VC 유효한가?"를 서버에 개별로 묻지 않고 목록 전체를 받아가는
구조라서, 서버는 누가 어디서 인증을 시도했는지 알 수 없다. 목록이 클수록
숨을 무리가 커지므로 규격은 최소 16KB를 요구한다.

이 모듈은 DB나 HTTP를 모르는 순수 함수만 둔다.
"""

import base64
import gzip

# 규격이 요구하는 최소 크기. 16KB = 131,072비트이므로 목록 하나로
# VC 13만 건을 담을 수 있다.
BITSTRING_SIZE = 131072
BITSTRING_BYTES = BITSTRING_SIZE // 8

# VC 본문 credentialStatus에 들어가는 값들.
# DB의 status_purpose는 'REVOCATION'(대문자) CHECK 제약을 쓰지만,
# VC 본문에는 규격대로 소문자를 넣어야 키오스크가 목적을 대조할 수 있다.
STATUS_LIST_ENTRY_TYPE = "StatusList2021Entry"
STATUS_LIST_CREDENTIAL_TYPE = "StatusList2021Credential"
PURPOSE_REVOCATION = "revocation"
DB_PURPOSE_REVOCATION = "REVOCATION"


def new_bitstring() -> bytearray:
    """모든 비트가 0인(= 전부 유효한) 새 비트열을 만든다."""
    return bytearray(BITSTRING_BYTES)


def encode_bitstring(bitstring: bytes | bytearray) -> str:
    """비트열을 GZIP 압축 후 base64url로 인코딩한다.

    대부분의 비트가 0이라 압축률이 매우 높다. 16KB 빈 목록이 68글자로 줄어든다.
    규격이 base64url에서 패딩('=')을 빼도록 정하고 있다.
    """
    compressed = gzip.compress(bytes(bitstring))
    return base64.urlsafe_b64encode(compressed).decode("ascii").rstrip("=")


def decode_bitstring(encoded: str) -> bytearray:
    """encode_bitstring의 역연산. 저장된 문자열을 비트열로 되돌린다."""
    # 인코딩할 때 뗀 패딩을 다시 붙여야 디코딩이 된다.
    padded = encoded + "=" * (-len(encoded) % 4)
    try:
        raw = gzip.decompress(base64.urlsafe_b64decode(padded))
    except Exception as error:  # noqa: BLE001 - 손상된 저장값을 한 곳에서 걸러낸다
        raise ValueError("encoded_list is not a valid StatusList2021 bitstring") from error
    if len(raw) < BITSTRING_BYTES:
        raise ValueError("encoded_list is shorter than the required 16KB")
    return bytearray(raw)


def _check_index(index: int, bitstring: bytes | bytearray) -> None:
    if index < 0 or index >= len(bitstring) * 8:
        raise ValueError(f"status list index out of range: {index}")


def get_bit(bitstring: bytes | bytearray, index: int) -> bool:
    """index 위치의 비트를 읽는다. True면 폐기된 VC다."""
    _check_index(index, bitstring)
    return bool(bitstring[index // 8] & (0b10000000 >> (index % 8)))


def set_bit(bitstring: bytearray, index: int) -> bool:
    """index 위치의 비트를 1로 만든다. 실제로 값이 바뀌었으면 True를 돌려준다.

    이미 1이면 아무것도 하지 않고 False를 돌려준다. 같은 VC를 두 번 폐기해도
    안전하도록(멱등) 호출부가 이 반환값으로 판단한다.

    규격은 index 0을 첫 바이트의 '가장 왼쪽' 비트로 정한다. 흔히 쓰는
    1 << (index % 8)은 오른쪽부터 세므로 서버와 키오스크가 서로 다른 비트를
    보게 된다. 반드시 0b10000000 >> 로 왼쪽부터 센다.
    """
    _check_index(index, bitstring)
    mask = 0b10000000 >> (index % 8)
    byte_index = index // 8
    if bitstring[byte_index] & mask:
        return False
    bitstring[byte_index] |= mask
    return True


def empty_encoded_list() -> str:
    """새 상태 목록에 넣을 초기 encoded_list 값."""
    return encode_bitstring(new_bitstring())


def build_status_list_url(base_url: str, status_list_id: int) -> str:
    """상태 목록의 공개 조회 URL을 만든다.

    이 값은 발급되는 VC 안에 그대로 박혀 나중에 고칠 수 없다. 따라서 목록을
    만들 때 한 번 계산해 status_list_url 컬럼에 저장하고, 이후에는 설정값으로
    다시 계산하지 말고 저장된 값을 읽어 써야 한다.
    """
    return f"{base_url.rstrip('/')}/api/v1/status/{status_list_id}"


def build_credential_status(status_list_url: str, index: int) -> dict:
    """VC 본문에 넣을 credentialStatus 객체를 만든다.

    statusListIndex가 정수가 아니라 문자열인 것은 규격이 그렇게 정한 것이다.
    """
    return {
        "id": f"{status_list_url}#{index}",
        "type": STATUS_LIST_ENTRY_TYPE,
        "statusPurpose": PURPOSE_REVOCATION,
        "statusListIndex": str(index),
        "statusListCredential": status_list_url,
    }
