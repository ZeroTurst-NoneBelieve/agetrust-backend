from pydantic import BaseModel, Field


class CreateChallengeRequest(BaseModel):
    transport_type: str = Field(examples=["QR", "NFC", "BLE"])


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


class VerifyResponse(BaseModel):
    result_status: str
    failure_code: str | None