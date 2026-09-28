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
            await asyncio.wait_for(key_cleanup, timeout=10)
        except asyncio.TimeoutError:
            logger.warning("미사용 키 정리 종료가 지연되어 취소한다.")
            key_cleanup.cancel()
            await asyncio.gather(key_cleanup, return_exceptions=True)
        if publisher is not None:
            # 발행 중이던 배치가 커밋을 마칠 때까지 기다린다. 여기서 그냥
            # cancel하면 이미 Kafka로 나간 이벤트의 published_at이 남지 않아
            # 다음 기동 때 같은 이벤트를 다시 발행하게 된다.
            try:
                await asyncio.wait_for(publisher, timeout=10)
            except asyncio.TimeoutError:
                logger.warning("Publisher 종료가 지연되어 취소한다.")
                publisher.cancel()


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
