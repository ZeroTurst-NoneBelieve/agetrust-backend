import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.api import api_router
from app.config import log_defaulted_settings, settings
from app.core.logging import configure_logging

configure_logging(settings.log_level)
logger = logging.getLogger(__name__)
log_defaulted_settings(settings)

# Outbox → Kafka Publisher는 여기서 띄우지 않는다. 별도 프로세스
# (app/workers/publisher.py, compose의 publisher 서비스)로 돈다 (#39).
# API 안의 백그라운드 태스크로 두면 죽어도 프로세스가 살아 있어 아무 흔적이
# 남지 않는다. 별도 프로세스면 죽는 순간 컨테이너가 종료되어 눈에 띈다.

app = FastAPI(
    title="AgeTrust Adult Verification API",
    version="2.0.0",
    description="W3C DID 및 온디바이스 AI 기반 성인 인증 백엔드 API",
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
