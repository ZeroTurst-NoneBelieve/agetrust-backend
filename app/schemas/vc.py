from datetime import datetime

from pydantic import BaseModel, Field


class AdultVerificationRequest(BaseModel):
    device_id: int
    age_check_passed: bool
    id_face_match_passed: bool
    liveness_passed: bool | None = None


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