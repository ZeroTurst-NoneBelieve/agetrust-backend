"""Outbox → Kafka Publisher (설계서 14 / REQ-INF-002).

`record_audit_event()`가 비즈니스 트랜잭션 안에서 `outbox_events`에 넣어 둔
이벤트를, 여기 백그라운드 루프가 꺼내 Kafka로 발행한다.

## 왜 트랜잭션 안에서 바로 Kafka로 보내지 않나

Postgres 커밋과 Kafka 전송은 하나로 묶을 수 없다(dual-write). 커밋은 됐는데
전송만 실패하면 DB에는 사건이 있는데 이벤트는 없는 불일치가 남고, 되돌릴
방법이 없다. 그래서 일단 DB에만 적어 두고(outbox) 발행은 여기서 따로
재시도한다. 설계서 §5.1.5가 outbox를 도입한 이유가 정확히 이것이다.

## audit_logs와의 관계 — 설계서와 다른 부분

설계서 §5.1.6 / B.7은 `Kafka → Consumer → audit_logs INSERT` 순서로,
audit_logs를 Kafka 하류의 조회용 Projection으로 본다. 이 구현은 그렇게 하지
않는다. audit_logs는 **원장**이기 때문이다:

- 해시 체인(`previous_hash`/`event_hash`)은 "쓰기 권한자도 과거를 조용히
  못 고친다"가 목적인데, 그러려면 사건이 일어난 그 트랜잭션 안에서 기록되어야
  한다. Kafka를 거쳐 나중에 적히면 그 사이 감사 기록이 존재하지 않는 구간이
  생긴다 — 로그인 실패가 쏟아지는 동안 대시보드가 비어 있게 된다.
- 설계서 자신이 "Kafka는 retention으로 오래된 segment가 제거되므로 영구
  불변 원장으로 간주하지 않는다"고 쓴다(§5.1.6). 되살릴 원본이 없는 유일한
  사본은 파생 데이터가 아니라 원본이다.

그래서 여기서는 audit_logs를 만들지 않고, 이미 기록된 원장에 **그 이벤트가
Kafka 어디에 실렸는지**(topic/partition/offset)만 되채운다.

## 전송 보장은 at-least-once다 (exactly-once가 아니다)

Kafka 전송과 `published_at` 커밋은 서로 다른 시스템이라 원자적으로 묶을 수
없다. 전송이 성공한 뒤 커밋 전에 프로세스가 죽으면, 재기동 시 그 이벤트는
여전히 미발행으로 보여 **같은 event_id가 다시 발행된다.**

`enable_idempotence=True`는 한 프로듀서 세션 안의 재시도 중복만 막는다.
프로세스 재기동을 건너뛰는 중복은 막지 못한다.

따라서 **구독자는 `event_id`로 중복을 걸러야 한다.** 메시지에 `event_id`를
넣는 이유가 이것이다. 반대 방향(이벤트 유실)은 일어나지 않는다. 커밋되지
않으면 다음 주기에 다시 집어가기 때문이다.

감사 이벤트에서는 이 선택이 맞다. 유실보다 중복이 낫다.
"""

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError, InterfaceError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.audit import canonical_json
from app.models import AuditLog, OutboxEvent

logger = logging.getLogger(__name__)


class PublishFailed(Exception):
    """전송 실패로 배치를 중단했음을 루프에 알린다.

    프로듀서가 한 번 못 쓰는 상태가 되면(브로커 다운, 연결 종료, 멱등 프로듀서의
    ProducerFenced 등) 같은 인스턴스로 다시 보내도 계속 실패한다. 그래서 실패를
    안에서 삼키지 않고 밖으로 올려, 루프가 프로듀서를 새로 만들도록 한다.

    이 예외가 올라오기 전에 retry_count는 이미 커밋된다.
    """


def build_message(event: OutboxEvent) -> bytes:
    """Kafka로 보낼 이벤트 본문.

    구독자가 DB를 다시 조회하지 않고도 처리할 수 있을 만큼만 담는다.
    민감 원본은 애초에 payload에 들어오지 않는다(설계서 §9).
    """
    return canonical_json(
        {
            "event_id": str(event.event_id),
            "event_type": event.event_type,
            "aggregate_type": event.aggregate_type,
            "aggregate_id": event.aggregate_id,
            "payload": event.payload,
            "created_at": event.created_at.isoformat() if event.created_at else None,
        }
    ).encode("utf-8")


def partition_key(event: OutboxEvent) -> bytes:
    """같은 대상(aggregate)의 이벤트가 순서를 유지하도록 파티션 키를 정한다.

    Kafka는 파티션 안에서만 순서를 보장한다. aggregate_id로 키를 잡으면
    "user 5의 이벤트들"은 항상 같은 파티션에 들어가 순서가 유지된다.
    aggregate_id가 없는 이벤트는 순서를 따질 대상이 없으므로 event_id로 흩는다.
    """
    return (event.aggregate_id or str(event.event_id)).encode("utf-8")


async def _claim_pending(db: AsyncSession, limit: int) -> list[OutboxEvent]:
    """아직 발행되지 않은 이벤트를 잠가서 가져온다.

    `FOR UPDATE SKIP LOCKED`가 핵심이다. 앱을 여러 개 띄워도 각 프로세스가
    서로 다른 행을 집어가므로 같은 이벤트가 두 번 발행되지 않는다.
    """
    result = await db.execute(
        select(OutboxEvent)
        .where(
            OutboxEvent.published_at.is_(None),
            OutboxEvent.retry_count < settings.outbox_max_retry_count,
        )
        .order_by(OutboxEvent.id)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    return list(result.scalars().all())


async def _backfill_kafka_position(db: AsyncSession, event_id, metadata) -> None:
    """원장(audit_logs)에 이 이벤트가 실린 Kafka 좌표를 기록한다.

    outbox 이벤트가 항상 audit_logs 행을 갖는 것은 아니므로(감사와 무관한
    이벤트도 outbox를 탈 수 있다) 매칭되는 행이 없어도 정상이다.

    SAVEPOINT로 감싸는 이유: 좌표는 "이 이벤트가 Kafka 어디에 실렸나"를
    알려주는 부가 정보다. 이걸 못 적었다고 배치 전체 커밋을 되돌리면 이미
    Kafka로 나간 이벤트의 published_at까지 사라져, 다음 주기에 같은 메시지를
    중복 발행하게 된다. 발행 성공이 메타데이터 기록 실패에 끌려가면 안 된다.
    """
    try:
        async with db.begin_nested():
            await db.execute(
                update(AuditLog)
                .where(AuditLog.event_id == event_id)
                .values(
                    kafka_topic=metadata.topic,
                    kafka_partition=metadata.partition,
                    kafka_offset=metadata.offset,
                )
            )
    except IntegrityError:
        # uq_audit_logs_kafka_position 충돌. 같은 좌표를 이미 쓴 레코드가 있다는
        # 뜻이고, 보통 Kafka 토픽이 재생성되어 offset이 0부터 되감긴 경우다
        # (예: 로컬에서 docker compose down 후 재기동). 발행 자체는 성공했으므로
        # 좌표만 비워 둔 채 계속 진행한다.
        logger.warning(
            "Kafka 좌표 기록 실패 — 같은 좌표(%s/%s/%s)를 쓴 감사 레코드가 이미 있다. "
            "Kafka offset이 되감겼을 수 있다. 발행은 성공했으므로 계속 진행한다. (event_id=%s)",
            metadata.topic,
            metadata.partition,
            metadata.offset,
            event_id,
        )
    except (OperationalError, InterfaceError) as error:
        # 커넥션 리셋·statement timeout·데드락 등 (#39). 유니크 충돌과 마찬가지로
        # 좌표 하나 못 적었다고 배치 전체를 되돌리면 이미 Kafka로 나간 이벤트가
        # 중복 발행된다. SAVEPOINT가 이 UPDATE만 되돌리므로 계속 진행한다.
        # 커넥션 자체가 죽은 경우라면 뒤따르는 commit이 실패하고 루프가 재연결한다.
        logger.warning(
            "Kafka 좌표 기록 실패 — DB 오류: %r. 발행은 성공했으므로 계속 진행한다. (event_id=%s)",
            error,
            event_id,
        )


async def count_exhausted(db: AsyncSession) -> int:
    """재시도 한도를 넘겨 더 이상 발행되지 않는 이벤트 수.

    이 이벤트들은 `_claim_pending`의 조회 대상에서 빠지므로, 세지 않으면
    존재 자체가 보이지 않는다.
    """
    return await db.scalar(
        select(func.count())
        .select_from(OutboxEvent)
        .where(
            OutboxEvent.published_at.is_(None),
            OutboxEvent.retry_count >= settings.outbox_max_retry_count,
        )
    )


async def publish_pending_once(db: AsyncSession, producer) -> int:
    """미발행 이벤트를 한 배치 발행하고, 발행한 건수를 돌려준다.

    전송에 실패하면 `retry_count`를 올려 커밋한 뒤 `PublishFailed`를 올린다.
    브로커가 죽어 있으면 나머지도 어차피 실패하므로 배치를 중단하고, 프로듀서를
    새로 만들 기회를 루프에 넘긴다. 실패를 여기서 삼키면 못 쓰게 된 프로듀서로
    영원히 재시도하게 된다.

    ## 실패가 곧바로 돌아오지는 않는다

    aiokafka는 `send_and_wait` 안에서 자체적으로 재연결·재시도를 하다가
    타임아웃에 도달해야 예외를 던진다. 브로커를 끊어도 이 함수는 수십 초
    블로킹된 뒤에야 실패한다.

    그래서 `retry_count`는 폴링 주기가 아니라 aiokafka의 타임아웃 간격으로
    올라간다. `outbox_max_retry_count`를 몇 초 만에 소진하는 일은 없다.
    """
    events = await _claim_pending(db, settings.outbox_publish_batch_size)
    if not events:
        return 0

    published = 0
    failure: Exception | None = None

    for event in events:
        try:
            metadata = await producer.send_and_wait(
                settings.kafka_audit_topic,
                value=build_message(event),
                key=partition_key(event),
            )
        except Exception as error:
            # retry_count는 server_default라 아직 DB를 거치지 않은 행에서는
            # None일 수 있다.
            event.retry_count = (event.retry_count or 0) + 1

            if event.retry_count >= settings.outbox_max_retry_count:
                # 한도를 넘기면 이후 조회 대상에서 빠져 조용히 사라진다.
                # 사라지는 순간만큼은 반드시 눈에 띄어야 한다.
                logger.error(
                    "outbox 이벤트가 재시도 한도(%d)에 도달해 더 이상 발행되지 않는다. "
                    "감사 원장(audit_logs)에는 남아 있지만 Kafka 구독자에게는 전달되지 "
                    "않으므로 수동 조치가 필요하다. (event_id=%s, event_type=%s): %r",
                    settings.outbox_max_retry_count,
                    event.event_id,
                    event.event_type,
                    error,
                )
            else:
                # 브로커 장애는 재시도로 해결되는 정상 경로다. 매 주기 traceback을
                # 남기면 로그가 묻히므로 예외 타입·메시지만 남긴다.
                logger.warning(
                    "outbox 이벤트 발행 실패 (event_id=%s, retry_count=%d): %r",
                    event.event_id,
                    event.retry_count,
                    error,
                )
            failure = error
            break

        event.published_at = datetime.now(timezone.utc)
        await _backfill_kafka_position(db, event.event_id, metadata)
        published += 1

    # 성공한 published_at과 실패한 retry_count를 함께 커밋한다.
    # 여기서 롤백하면 실패 횟수가 남지 않아 같은 이벤트를 영원히 재시도한다.
    # 예외를 올리기 전에 반드시 커밋해야 한다.
    await db.commit()

    if failure is not None:
        raise PublishFailed(
            f"Kafka 전송 실패로 배치를 중단했다 (발행 {published}건): {failure!r}"
        ) from failure

    return published


async def _wait(stop_event: asyncio.Event, seconds: float) -> None:
    """중단 신호가 오면 즉시 깨어나는 sleep."""
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=seconds)
    except asyncio.TimeoutError:
        pass


async def _report_exhausted(session_factory) -> None:
    """포기된 이벤트가 쌓여 있으면 알린다.

    한도를 넘긴 이벤트는 조회 대상에서 빠지므로 가만히 두면 아무도 모른다.
    프로듀서를 새로 연결할 때마다 현황을 남겨 최소한의 가시성을 확보한다.
    """
    try:
        async with session_factory() as db:
            stuck = await count_exhausted(db)
    except Exception:
        # 현황 보고 실패가 발행을 막아서는 안 된다.
        logger.warning("포기된 outbox 이벤트 수를 세지 못했다.", exc_info=True)
        return

    if stuck:
        logger.error(
            "재시도 한도를 넘겨 발행되지 않은 outbox 이벤트가 %d건 있다. "
            "감사 원장에는 남아 있으나 Kafka 구독자에게는 전달되지 않았다.",
            stuck,
        )


def _new_producer():
    """기본 프로듀서 팩토리.

    aiokafka는 여기서만 import한다. Publisher를 끈 채로도(또는 테스트에서)
    앱이 뜰 수 있어야 하기 때문이다.
    """
    from aiokafka import AIOKafkaProducer

    return AIOKafkaProducer(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        # 한 세션 안의 재시도 중복을 브로커 단에서도 막는다.
        # (프로세스 재기동을 건너뛰는 중복은 막지 못한다 — 모듈 docstring 참고)
        acks="all",
        enable_idempotence=True,
    )


async def run_publisher_loop(
    session_factory,
    stop_event: asyncio.Event,
    producer_factory=None,
) -> None:
    """앱이 사는 동안 미발행 이벤트를 계속 Kafka로 흘려보낸다.

    Kafka가 아직 안 떴거나 도중에 죽어도 루프는 살아남는다. 감사 이벤트는
    outbox에 안전하게 쌓여 있으므로 브로커가 돌아오면 밀린 만큼 따라잡는다.

    전송이 실패하면(`PublishFailed`) 프로듀서를 버리고 바깥 루프에서 새로
    만든다. 한 번 못 쓰게 된 프로듀서를 계속 붙들고 있으면 브로커가 돌아와도
    영영 복구되지 않는다.

    `producer_factory`는 테스트에서 프로듀서를 갈아끼우기 위한 것이다.
    """
    make_producer = producer_factory or _new_producer
    interval = settings.outbox_poll_interval_seconds

    while not stop_event.is_set():
        producer = make_producer()
        try:
            await producer.start()
        except Exception as error:
            logger.warning(
                "Kafka(%s) 연결 실패: %r. %.1f초 후 재시도한다.",
                settings.kafka_bootstrap_servers,
                error,
                interval,
            )
            await producer.stop()
            await _wait(stop_event, interval)
            continue

        logger.info("Kafka Publisher 시작 (topic=%s)", settings.kafka_audit_topic)
        await _report_exhausted(session_factory)

        try:
            while not stop_event.is_set():
                async with session_factory() as db:
                    published = await publish_pending_once(db, producer)
                # 밀린 이벤트가 있으면 쉬지 않고 이어서 따라잡는다.
                await _wait(stop_event, 0 if published else interval)
        except asyncio.CancelledError:
            raise
        except PublishFailed as error:
            # 실패 내용은 publish_pending_once에서 이미 남겼다. 여기서는 프로듀서를
            # 버리고 바깥 루프로 나가 새로 만든다. 못 쓰게 된 프로듀서를 계속
            # 붙들고 있으면 브로커가 돌아와도 영영 복구되지 않는다.
            logger.warning("프로듀서를 새로 만들어 재연결한다: %s", error)
            await _wait(stop_event, interval)
        except Exception:
            logger.exception("Publisher 루프가 중단됐다. 재연결한다.")
            await _wait(stop_event, interval)
        finally:
            await producer.stop()

    logger.info("Kafka Publisher 종료")
