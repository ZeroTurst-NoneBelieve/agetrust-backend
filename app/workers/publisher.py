"""Outbox → Kafka Publisher 워커 진입점 (설계서 14 / REQ-INF-002, #39).

    python -m app.workers.publisher

API 프로세스(uvicorn) 안의 백그라운드 태스크가 아니라 **별도 프로세스**로 돈다.
설계서(database-design.md §5.1.5)가 말하는 "별도 Publisher"가 이것이다.

## 왜 API 안에서 돌리지 않나

백그라운드 태스크는 죽어도 프로세스가 살아 있어서 흔적이 남지 않는다.
태스크의 예외는 누군가 await하지 않으면 어디에도 나타나지 않고, API는 계속
200을 돌려준다. #39가 재현한 "감사 이벤트가 영영 안 나가는데 아무도 모르는"
상태다. 별도 프로세스면 루프가 죽는 순간 프로세스가 끝나고, 파이썬이
traceback을 출력하고, 컨테이너의 restart 정책이 다시 띄운다. 죽음이 숨겨질
자리가 없다.

## 그래서 이 파일은 예외를 잡지 않는다

`run_publisher_loop`가 예외로 끝나면 그대로 프로세스가 죽어야 한다.
여기서 잡아서 로그만 남기고 계속 돌면 다시 "죽었는데 살아 있는 척"이 된다.
일시적 문제(브로커 다운, DB 재시작)는 루프 안에서 이미 재시도한다. 여기까지
올라온 예외는 재시도로 풀리지 않는 것이다.

## 종료

docker는 컨테이너를 멈출 때 SIGTERM을 보내고 `stop_grace_period` 뒤에 SIGKILL을
보낸다. SIGTERM을 받으면 `stop_event`를 켜서 루프가 진행 중인 배치의 커밋까지
마치고 나가게 한다. 발행 도중 강제 종료되면 이미 Kafka로 나간 이벤트의
published_at이 남지 않아 다음 기동 때 다시 발행된다(at-least-once라 유실은 없다).
"""

import asyncio
import logging
import signal

from app.config import log_defaulted_settings, settings
from app.core.kafka_publisher import run_publisher_loop
from app.core.logging import configure_logging
from app.database import AsyncSessionLocal, engine

logger = logging.getLogger(__name__)


def _install_stop_handlers(stop_event: asyncio.Event) -> None:
    """SIGTERM·SIGINT가 오면 stop_event를 켠다."""
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            # Windows에는 add_signal_handler가 없다. 로컬 개발용 대체 경로다.
            signal.signal(sig, lambda *_: stop_event.set())


async def main() -> None:
    stop_event = asyncio.Event()
    _install_stop_handlers(stop_event)

    logger.info("Outbox Publisher 워커 시작 (kafka=%s)", settings.kafka_bootstrap_servers)
    try:
        await run_publisher_loop(AsyncSessionLocal, stop_event)
    finally:
        # 예외로 나가든 정상 종료든 커넥션 풀은 닫는다.
        await engine.dispose()
    logger.info("Outbox Publisher 워커 종료")


def run() -> None:
    configure_logging(settings.log_level)
    log_defaulted_settings(settings)
    asyncio.run(main())


if __name__ == "__main__":
    run()
