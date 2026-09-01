"""VC 폐기를 상태 목록 비트까지 반영하는 처리.

status_list.py가 비트 계산만 하는 순수 모듈인 것과 달리, 이 모듈은 DB
트랜잭션 위에서 동작한다.

#22에서 재바인딩 시 서버 DB의 VC를 REVOKED로 바꾸는 데까지 했지만,
did:key는 자기완결적이라 키오스크가 서버를 조회하지 않는다. 서버에서만
폐기하면 분실 기기의 VC가 만료 전까지 키오스크를 그대로 통과한다.
여기서 상태 목록의 비트까지 켜야 실제 차단이 완성된다(#27).
"""

from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.status_list import (
    decode_bitstring,
    encode_bitstring,
    new_bitstring,
    set_bit,
)
from app.models import CredentialStatusList, VcCredential


async def revoke_active_credentials_for_device(
    db: AsyncSession, device_id: int
) -> tuple[int, int]:
    """기기의 ACTIVE VC를 모두 폐기하고 상태 목록 비트까지 켠다.

    (폐기된 VC 수, 새로 켠 비트 수)를 돌려준다. 두 값은 다를 수 있다.
    상태 목록 도입 전에 발급된 VC는 배정된 인덱스가 없어 비트를 켤 자리가
    없기 때문이다.

    UPDATE에 RETURNING을 붙여 폐기된 행의 배정 정보를 그대로 받는다.
    "먼저 SELECT로 대상을 고른 뒤 UPDATE" 방식이면 그 사이에 다른 요청이
    끼어들어 목록이 어긋날 수 있다.

    이 함수는 커밋하지 않는다. 호출부의 트랜잭션에 얹혀서, 뒤에서 실패하면
    폐기도 비트도 함께 롤백된다.
    """
    revoked = (
        await db.execute(
            update(VcCredential)
            .where(
                VcCredential.device_id == device_id,
                VcCredential.status == "ACTIVE",
            )
            .values(status="REVOKED", revoked_at=datetime.now(timezone.utc))
            .returning(
                VcCredential.status_list_id,
                VcCredential.status_list_index,
            )
        )
    ).all()

    flipped = await mark_revoked_bits(db, revoked)
    return len(revoked), flipped


async def mark_revoked_bits(db: AsyncSession, entries) -> int:
    """(status_list_id, status_list_index) 쌍들의 비트를 켠다.

    encoded_list는 "읽고 → 고치고 → 다시 쓰기" 구조라 잠금 없이 다루면
    나중 쓰기가 앞의 쓰기를 덮어써 폐기가 조용히 사라진다(lost update).
    목록 행을 with_for_update로 잠가 이 구간을 직렬화한다.

    한 목록을 여러 번 열지 않도록 먼저 목록별로 묶고, 목록 id 순서대로
    잠근다. 잠그는 순서가 요청마다 다르면 서로를 기다리다 교착에 빠진다.
    """
    by_list: dict[int, list[int]] = {}
    for status_list_id, status_list_index in entries:
        if status_list_id is None or status_list_index is None:
            # 상태 목록 도입 전에 발급된 VC다. DB 상태는 REVOKED가 되지만
            # 본문에 credentialStatus가 없어 키오스크가 확인할 수단도 없다.
            continue
        by_list.setdefault(status_list_id, []).append(status_list_index)

    flipped = 0
    for status_list_id, indexes in sorted(by_list.items()):
        status_list = await db.scalar(
            select(CredentialStatusList)
            .where(CredentialStatusList.id == status_list_id)
            .with_for_update()
        )
        if status_list is None:
            continue

        bitstring = (
            decode_bitstring(status_list.encoded_list)
            if status_list.encoded_list
            else new_bitstring()
        )

        changed = 0
        for index in indexes:
            if set_bit(bitstring, index):
                changed += 1

        if changed:
            status_list.encoded_list = encode_bitstring(bitstring)
            # 키오스크가 캐시를 갱신할지 판단하는 값이다. 실제로 바뀐 게
            # 없으면 올리지 않아야 헛된 재다운로드를 만들지 않는다.
            status_list.version = (status_list.version or 0) + 1
            flipped += changed

    return flipped
