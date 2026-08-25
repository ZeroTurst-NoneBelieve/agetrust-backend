import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.api import api_router
from app.config import settings
from app.core.kafka_publisher import run_publisher_loop
from app.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """앱과 수명을 같이하는 Outbox Publisher를 띄운다 (설계서 14 / REQ-INF-002)."""
    stop_event = asyncio.Event()
    publisher = None

    if settings.kafka_publisher_enabled:
        publisher = asyncio.create_task(run_publisher_loop(AsyncSessionLocal, stop_event))
    else:
        logger.info("KAFKA_PUBLISHER_ENABLED=false — Outbox Publisher를 띄우지 않는다.")

    try:
        yield
    finally:
        stop_event.set()
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
)


@app.get("/health")
def health_check():
    return {"status": "ok", "message": "AgeTrust Server is running"}
