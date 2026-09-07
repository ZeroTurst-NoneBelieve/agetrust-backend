"""에러 코드 사전. EduTrust DB 설계서 7장 CHECK 권장값을 그대로 상수화."""

from enum import StrEnum

from pydantic import BaseModel, Field


class AuthError(StrEnum):
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    TOKEN_MISSING = "TOKEN_MISSING"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    TOKEN_INVALID = "TOKEN_INVALID"
    TOKEN_WRONG_TYPE = "TOKEN_WRONG_TYPE"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    USER_NOT_FOUND = "USER_NOT_FOUND"
    USER_ALREADY_EXISTS = "USER_ALREADY_EXISTS"
    OTP_NOT_FOUND = "OTP_NOT_FOUND"
    OTP_EXPIRED = "OTP_EXPIRED"
    OTP_MISMATCH = "OTP_MISMATCH"
    OTP_MAX_ATTEMPTS = "OTP_MAX_ATTEMPTS"
    OTP_ALREADY_CONSUMED = "OTP_ALREADY_CONSUMED"
    PHONE_NOT_VERIFIED = "PHONE_NOT_VERIFIED"
    KIOSK_KEY_INVALID = "KIOSK_KEY_INVALID"
    KIOSK_INACTIVE = "KIOSK_INACTIVE"


class AuthErrorDetail(BaseModel):
    """인증·인가 오류 상세."""

    code: AuthError = Field(description="클라이언트가 분기할 수 있는 오류 코드.")


class AuthErrorResponse(BaseModel):
    """FastAPI HTTPException의 인증·인가 오류 응답."""

    detail: AuthErrorDetail


class AdultVerificationStatus(StrEnum):
    SUCCESS = "SUCCESS"
    FAIL_AGE = "FAIL_AGE"
    FAIL_FACE_MISMATCH = "FAIL_FACE_MISMATCH"
    FAIL_LIVENESS = "FAIL_LIVENESS"
    ERROR = "ERROR"


class AdultVerificationFailureCode(StrEnum):
    AGE_POLICY_FAILED = "AGE_POLICY_FAILED"
    ID_SELFIE_MISMATCH = "ID_SELFIE_MISMATCH"
    LIVENESS_FAILED = "LIVENESS_FAILED"


class VerificationResultStatus(StrEnum):
    """verification_logs.result_status. 키오스크 결과 기록 API(ADR-0011)의 계약값.

    정상 판정이 위 AdultVerificationStatus와 달리 SUCCESS가 아니라 PASS다.
    둘은 다른 테이블이고 값을 정한 주체가 다르다. adult_verifications는 서버가
    신분증-셀카 대조를 판정해 남기는 기록이라 설계서의 SUCCESS를 그대로 쓴다.
    verification_logs는 키오스크가 자기 판정을 보고하는 기록이고, 그 판정은
    BLE status_notify 0x20 PASS로 폰에 먼저 나간다(transport-protocol §5.7).
    같은 판정을 API 경계에서만 SUCCESS로 바꿔 부르면 키오스크 화면과 서버
    기록의 용어가 갈라지므로, ADR-0011의 요청 본문 예시대로 PASS로 맞춘다.
    """

    PASS = "PASS"
    FAIL_EXPIRED = "FAIL_EXPIRED"
    FAIL_FACE_MISMATCH = "FAIL_FACE_MISMATCH"
    FAIL_INVALID_VC = "FAIL_INVALID_VC"
    FAIL_INVALID_VP = "FAIL_INVALID_VP"
    FAIL_REVOKED_VC = "FAIL_REVOKED_VC"
    FAIL_CHALLENGE = "FAIL_CHALLENGE"
    INTERNAL_ERROR = "INTERNAL_ERROR"
