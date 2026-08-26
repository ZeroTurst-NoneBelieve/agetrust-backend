"""감사 로그(audit_logs) 기록 — 해시 체인 기반 위·변조 탐지.

설계서 15번 audit_logs는 `previous_hash` / `event_hash` 컬럼으로 해시 체인을
구성한다. 각 이벤트의 해시는 **직전 이벤트의 해시를 입력에 포함**하므로,
중간 레코드를 하나라도 수정·삭제하면 그 이후 전체 체인이 깨진다.
DB 쓰기 권한을 가진 사람도 조용히 과거 기록을 고칠 수 없다는 것이 목적이다.

## 트랜잭션 정책

`record_audit_event()`는 **커밋하지 않는다.** 호출자의 트랜잭션에 참여해
비즈니스 변경과 감사 로그가 함께 커밋되거나 함께 롤백되도록 한다
(설계서 14번 outbox_events의 의도와 동일).

인증 **실패**를 기록할 때는 호출자가 `await db.commit()` 후에 예외를
던져야 한다. 그렇지 않으면 실패 이력이 롤백되어 남지 않는다.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog, OutboxEvent

# 체인 append를 직렬화하기 위한 Postgres 트랜잭션 자문 잠금 키.
# 동시 요청이 같은 previous_hash를 읽어 체인이 분기하는 것을 막는다.
# 트랜잭션 종료 시 자동 해제되므로 별도 unlock이 필요 없다.
_CHAIN_LOCK_KEY = 0x4147_4C4F  # "AGLO"

GENESIS_HASH = "0" * 64


def canonical_json(value: Any) -> str:
    """해시 입력용 정규화 JSON.

    키 정렬 + 공백 제거로, 같은 내용이면 항상 같은 바이트열이 나오게 한다.
    (dict 순서가 달라졌다는 이유로 체인이 깨지면 안 된다)
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def compute_event_hash(
    *,
    previous_hash: str | None,
    event_id: uuid.UUID | str,
    event_type: str,
    actor_type: str,
    actor_ref: str | None,
    aggregate_type: str | None,
    aggregate_id: str | None,
    payload: dict,
    created_at: datetime,
) -> str:
    """이벤트 해시를 계산한다.

    `previous_hash`를 입력에 포함하는 것이 체인의 핵심이다.
    체인의 첫 이벤트는 GENESIS_HASH를 직전 해시로 사용한다.
    """
    material = canonical_json(
        {
            "previous_hash": previous_hash or GENESIS_HASH,
            "event_id": str(event_id),
            "event_type": event_type,
            "actor_type": actor_type,
            "actor_ref": actor_ref or "",
            "aggregate_type": aggregate_type or "",
            "aggregate_id": aggregate_id or "",
            "payload": payload,
            "created_at": created_at.isoformat(),
        }
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def recompute_hash_for(row: AuditLog) -> str:
    """저장된 레코드로부터 해시를 다시 계산한다 (검증용)."""
    return compute_event_hash(
        previous_hash=row.previous_hash,
        event_id=row.event_id,
        event_type=row.event_type,
        actor_type=row.actor_type,
        actor_ref=row.actor_ref,
        aggregate_type=row.aggregate_type,
        aggregate_id=row.aggregate_id,
        payload=row.payload,
        created_at=row.created_at,
    )


async def record_audit_event(
    db: AsyncSession,
    *,
    event_type: str,
    actor_type: str,
    payload: dict,
    actor_ref: str | None = None,
    aggregate_type: str | None = None,
    aggregate_id: str | None = None,
    source_kiosk_id: int | None = None,
    emit_outbox: bool = True,
) -> AuditLog:
    """감사 이벤트 1건을 체인에 덧붙인다. 커밋은 호출자 책임이다.

    `emit_outbox=True`면 outbox_events에도 같은 이벤트를 넣어, 별도 Publisher가
    Kafka로 전송할 수 있게 한다(설계서 14번). Kafka 좌표(kafka_topic/partition/
    offset)는 Publisher가 전송 후 채우므로 여기서는 비워 둔다.
    """
    # 체인 append 구간 직렬화. 빈 테이블에 동시 삽입되는 경우까지 포함해
    # 항상 한 번에 하나의 트랜잭션만 tip을 읽고 이어붙이도록 한다.
    await db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _CHAIN_LOCK_KEY})

    tip = await db.execute(select(AuditLog.event_hash).order_by(AuditLog.id.desc()).limit(1))
    previous_hash = tip.scalar_one_or_none()

    event_id = uuid.uuid4()
    # created_at을 파이썬에서 확정한다. server_default(func.now())에 맡기면
    # INSERT 이전에 값을 알 수 없어 해시 입력에 포함할 수 없다.
    created_at = datetime.now(timezone.utc)

    event_hash = compute_event_hash(
        previous_hash=previous_hash,
        event_id=event_id,
        event_type=event_type,
        actor_type=actor_type,
        actor_ref=actor_ref,
        aggregate_type=aggregate_type,
        aggregate_id=aggregate_id,
        payload=payload,
        created_at=created_at,
    )

    row = AuditLog(
        event_id=event_id,
        event_type=event_type,
        actor_type=actor_type,
        actor_ref=actor_ref,
        source_kiosk_id=source_kiosk_id,
        aggregate_type=aggregate_type,
        aggregate_id=aggregate_id,
        payload=payload,
        previous_hash=previous_hash,
        event_hash=event_hash,
        created_at=created_at,
    )
    db.add(row)

    if emit_outbox:
        db.add(
            OutboxEvent(
                event_id=event_id,
                aggregate_type=aggregate_type or "AUDIT_LOG",
                aggregate_id=aggregate_id,
                event_type=event_type,
                payload={**payload, "event_hash": event_hash},
            )
        )

    return row


def mask_phone(phone: str | None) -> str | None:
    """감사 로그에는 전화번호를 원문으로 남기지 않는다.

    누가 시도했는지 추적할 수 있을 만큼만 남기고 나머지는 가린다.
    """
    if not phone:
        return None
    digits = "".join(c for c in phone if c.isdigit())
    if len(digits) <= 4:
        return "*" * len(digits)
    if len(digits) <= 7:
        return f"{'*' * (len(digits) - 4)}{digits[-4:]}"
    return f"{digits[:3]}{'*' * (len(digits) - 7)}{digits[-4:]}"
