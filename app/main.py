import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.api import api_router
from app.config import log_defaulted_settings, settings
from app.core.kafka_publisher import run_publisher_loop
from app.core.kiosk_key_cleanup import run_unused_key_cleanup_loop
from app.database import AsyncSessionLocal

logger = logging.getLogger(__name__)
PUBLISHER_SHUTDOWN_TIMEOUT_SECONDS = 10
KEY_CLEANUP_SHUTDOWN_TIMEOUT_SECONDS = 2


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Outbox Publisher와 미사용 키 정리를 앱 수명에 맞춰 실행한다."""
    log_defaulted_settings(settings)
    stop_event = asyncio.Event()
    publisher = None
    key_cleanup = asyncio.create_task(run_unused_key_cleanup_loop(AsyncSessionLocal, stop_event))

    if settings.kafka_publisher_enabled:
        publisher = asyncio.create_task(run_publisher_loop(AsyncSessionLocal, stop_event))
    else:
        logger.info("KAFKA_PUBLISHER_ENABLED=false — Outbox Publisher를 띄우지 않는다.")

    try:
        yield
    finally:
        stop_event.set()
        try:
            if publisher is not None:
                # 발행 중이던 배치가 커밋을 마칠 때까지 먼저 기다린다.
                # 먼저 취소하면 이미 Kafka로 나간 이벤트의 published_at이
                # 남지 않아 다음 기동 때 같은 이벤트를 다시 발행할 수 있다.
                try:
                    await asyncio.wait_for(publisher, timeout=PUBLISHER_SHUTDOWN_TIMEOUT_SECONDS)
                except asyncio.TimeoutError:
                    logger.warning("Publisher 종료가 지연되어 취소한다.")
        finally:
            # Publisher에서 예외가 나도 정리 태스크를 회수한다. 정리는 다음
            # 기동에서 이어갈 수 있으므로 대기 시간을 짧게 둔다. wait_for가
            # 타임아웃 시 취소와 회수까지 수행하므로 별도 cancel은 필요 없다.
            try:
                await asyncio.wait_for(key_cleanup, timeout=KEY_CLEANUP_SHUTDOWN_TIMEOUT_SECONDS)
            except asyncio.TimeoutError:
                logger.warning("미사용 키 정리 종료가 지연되어 취소한다.")


app = FastAPI(
    title="AgeTrust Adult Verification API",
    version="2.0.0",
    description="W3C DID 및 온디바이스 AI 기반 성인 인증 백엔드 API",
    lifespan=lifespan,
)

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Retry-After"],
)


@app.get("/health")
def health_check():
    return {"status": "ok", "message": "AgeTrust Server is running"}
