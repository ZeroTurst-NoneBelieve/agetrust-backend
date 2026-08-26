from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.api import api_router  

app = FastAPI(
    title="AgeTrust Adult Verification API",
    version="2.0.0",
    description="W3C DID 및 온디바이스 AI 기반 성인 인증 백엔드 API"
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