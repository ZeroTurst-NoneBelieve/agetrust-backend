import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.api import api_router
from app.config import log_defaulted_settings, settings
from app.core.kiosk_key_cleanup import run_unused_key_cleanup_loop
from app.core.logging import configure_logging
from app.database import AsyncSessionLocal

configure_logging(settings.log_level)
logger = logging.getLogger(__name__)

KEY_CLEANUP_SHUTDOWN_TIMEOUT_SECONDS = 2

# Outbox → Kafka Publisher는 여기서 띄우지 않는다. 별도 프로세스
# (app/workers/publisher.py, compose의 publisher 서비스)로 돈다 (#39).
# API 안의 백그라운드 태스크로 두면 죽어도 프로세스가 살아 있어 아무 흔적이
# 남지 않는다. 별도 프로세스면 죽는 순간 컨테이너가 종료되어 눈에 띈다.


@asynccontextmanager
async def lifespan(app: FastAPI):
    """미사용 키 정리를 앱 수명에 맞춰 실행한다."""
    log_defaulted_settings(settings)
    stop_event = asyncio.Event()
    key_cleanup = asyncio.create_task(run_unused_key_cleanup_loop(AsyncSessionLocal, stop_event))

    try:
        yield
    finally:
        stop_event.set()
        # 정리는 다음 기동에서 이어갈 수 있으므로 대기 시간을 짧게 둔다. wait_for가
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
