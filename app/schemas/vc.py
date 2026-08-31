from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.errors import (
    AdultVerificationFailureCode,
    AdultVerificationStatus,
)


class AdultVerificationRequest(BaseModel):
    """온디바이스 성인 판정 결과 수신 요청.

    얼굴 대조와 연령 판정은 단말에서 수행하고, 서버는 그 결과만 기록한다.
    얼굴 이미지나 임베딩은 서버로 전송하지 않는다.

    MVP 범위에서는 클라이언트가 보고한 판정 결과를 그대로 신뢰한다.
    attestation은 스키마에만 존재하며 현재 검증하지 않는다.
    """

    device_id: int = Field(
        description="판정을 수행한 기기 ID. 요청자 본인의 ACTIVE 기기여야 한다.",
        examples=[15],
    )
    age_check_passed: bool = Field(
        description="연령 기준(만 19세 이상) 충족 여부.",
        examples=[True],
    )
    id_face_match_passed: bool = Field(
        description="신분증 사진과 현장 얼굴의 대조 통과 여부.",
        examples=[True],
    )
    liveness_passed: bool | None = Field(
        default=None,
        description=(
            "라이브니스(실물 여부) 검사 통과 여부. 미수행 시 null이며, "
            "null은 판정에 반영되지 않는다."
        ),
        examples=[True],
    )
    attestation: str | None = Field(
        default=None,
        description=(
            "Play Integrity / App Attest 토큰. "
            "MVP에서는 저장·검증하지 않으며 추후 도입을 위한 예약 필드다."
        ),
    )
    age_policy_version: str | None = Field(
        default=None,
        description="판정에 적용한 연령 정책 버전.",
        examples=["2026-KR-19"],
    )
    model_version: str | None = Field(
        default=None,
        description="얼굴 대조에 사용한 온디바이스 모델 버전.",
        examples=["MobileFaceNet-v1.0"],
    )
    threshold_version: str | None = Field(
        default=None,
        description="판정에 적용한 임계치 세트 버전.",
        examples=["th-2026-08"],
    )


class AdultVerificationResponse(BaseModel):
    """성인 판정 기록 응답."""

    id: int = Field(
        description="판정 기록 ID. VC 발급 요청의 adult_verification_id로 사용한다.",
        examples=[29],
    )
    result_status: AdultVerificationStatus = Field(
        description=(
            "판정 결과. SUCCESS 또는 실패 지점에 대응하는 FAIL_AGE, "
            "FAIL_FACE_MISMATCH, FAIL_LIVENESS 중 하나다. "
            "실패한 기록으로는 VC를 발급하지 않는다."
        ),
        examples=[
            "SUCCESS",
            "FAIL_AGE",
            "FAIL_FACE_MISMATCH",
            "FAIL_LIVENESS",
        ],
    )
    failure_code: AdultVerificationFailureCode | None = Field(
        description=(
            "실패 사유 코드. AGE_POLICY_FAILED, ID_SELFIE_MISMATCH, "
            "LIVENESS_FAILED 중 하나이며 SUCCESS인 경우 null."
        ),
        examples=[
            "AGE_POLICY_FAILED",
            "ID_SELFIE_MISMATCH",
            "LIVENESS_FAILED",
        ],
    )
    verified_at: datetime = Field(description="판정 결과를 서버가 기록한 시각(UTC).")

    model_config = {"from_attributes": True}


class IssueVcRequest(BaseModel):
    """VC 발급 요청.

    기기 정보는 판정 기록에서 조회하므로 device_id를 따로 보내지 않는다.
    """

    adult_verification_id: int = Field(
        description=(
            "성인 판정 기록 ID. 요청자 본인의 SUCCESS 기록이어야 하며, "
            "해당 기기가 ACTIVE이고 holder_did가 등록되어 있어야 한다."
        ),
        examples=[29],
    )


class IssueVcResponse(BaseModel):
    """VC 발급 응답."""

    credential: str = Field(
        description=(
            "W3C VC Data Model v1.1 형식의 JWT 문자열(EdDSA 서명). "
            "credentialSubject에는 Holder DID(id)와 isOver19가 담기며 "
            "이름·생년월일 등 개인정보는 포함하지 않는다. "
            "서버는 원문을 저장하지 않으므로 클라이언트가 보관해야 한다."
        ),
    )
    credential_id: str = Field(
        description="VC 식별자(JWT의 jti). 폐기·조회 시 이 값으로 식별한다.",
        examples=["urn:uuid:cefe0eef-3416-476a-9b7c-fc1562f0b6f5"],
    )
    holder_did: str = Field(
        description="VC 소유자 DID(JWT의 sub). 기기에 바인딩된 did:key와 동일하다.",
        examples=["did:key:z6MkfDPXFg3QvpCr1iKB8JRs3Ai8dDjmVWLuG3e1P2xLbesk"],
    )
    issuer_did: str = Field(
        description=(
            "발급자 DID(JWT의 iss). 키오스크는 이 DID의 공개키로 서명을 검증한다."
        ),
        examples=["did:key:z6MkeTRiVbRs2LZPqk1WXfGPDain6dv953NmcYi63p3KGZxH"],
    )
    expires_at: datetime | None = Field(
        description="VC 만료 시각(UTC). JWT의 exp와 동일한 값이다.",
    )
