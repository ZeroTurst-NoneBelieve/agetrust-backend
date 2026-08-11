from datetime import datetime

from pydantic import BaseModel, Field


class AdultVerificationRequest(BaseModel):
    device_id: int # 단말 무결성 증명(Play Integrity / App Attest) 토큰.
    age_check_passed: bool  # MVP에서는 검증하지 않고 받기만 한다. 추후 도입 시
    id_face_match_passed: bool # 필드 추가 없이 검증 로직만 붙이면 되도록 계약을 미리 열어둔다.
    liveness_passed: bool | None = None
    attestation: str | None = None  


class AdultVerificationResponse(BaseModel):
    id: int
    result_status: str
    failure_code: str | None
    verified_at: datetime

    model_config = {"from_attributes": True}


class IssueVcRequest(BaseModel):
    adult_verification_id: int


class IssueVcResponse(BaseModel):
    credential: str
    credential_id: str
    holder_did: str
    issuer_did: str
    expires_at: datetime | None