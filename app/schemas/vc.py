from datetime import datetime

from pydantic import BaseModel, Field


class AdultVerificationRequest(BaseModel):
    device_id: int
    age_check_passed: bool
    id_face_match_passed: bool
    liveness_passed: bool | None = None

    # 단말 무결성 증명(Play Integrity / App Attest) 토큰.
    # MVP에서는 검증하지 않고 받기만 한다. 추후 도입 시
    # 필드 추가 없이 검증 로직만 붙이면 되도록 계약을 미리 열어둔다.
    attestation: str | None = None

    # 온디바이스에서 판정이 이루어지므로, 어떤 정책/모델/임계치로
    # 통과시켰는지는 단말만 알 수 있다. 사후 감사를 위해 버전 정보를 함께 받는다.
    # (DB 설계서 v2.3 adult_verifications 참조)
    age_policy_version: str | None = Field(default=None, examples=["2026-KR-19"])
    model_version: str | None = Field(default=None, examples=["MobileFaceNet-v1.0"])
    threshold_version: str | None = Field(default=None, examples=["th-2026-08"])


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