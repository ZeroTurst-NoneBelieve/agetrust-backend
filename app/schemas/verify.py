from typing import Literal

from pydantic import BaseModel, Field


class CreateChallengeRequest(BaseModel):
    # DB CHECK 제약(QR/NFC/BLE)과 일치시켜, 잘못된 값이 DB까지 내려가
    # 500이 되는 대신 422로 걸러지게 한다.
    transport_type: Literal["QR", "NFC", "BLE"] = Field(examples=["QR"])


class CreateChallengeResponse(BaseModel):
    nonce: str
    kiosk_id: int
    timestamp: str
    expires_at: str
    challenge_hash: str


class VerifyRequest(BaseModel):
    challenge_hash: str
    credential: str
    holder_signature_b64: str
    face_matched: bool

    # 현장 라이브니스 결과(적용 시). 키오스크가 로컬에서 판정한 결과만 받는다.
    liveness_passed: bool | None = None

    # 현장 얼굴 대조를 수행한 모델/임계치 버전. 사후 감사·장애 분석에 사용한다.
    # (DB 설계서 v2.3 verification_logs 참조)
    face_model_version: str | None = Field(default=None, examples=["MobileFaceNet-v1.0"])
    threshold_version: str | None = Field(default=None, examples=["th-2026-08"])


class VerifyResponse(BaseModel):
    result_status: str
    failure_code: str | None