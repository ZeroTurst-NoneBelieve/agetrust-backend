from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="AgeTrust Adult Verification API",
    version="2.0.0",
    description="W3C DID 및 온디바이스 AI 기반 성인 인증 백엔드 API"
)

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