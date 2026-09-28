from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class PhoneRequestBody(BaseModel):
    """전화번호 인증 요청."""

    phone_number: str = Field(
        pattern=r"^\+8210\d{8}$",
        examples=["+821012345678"],
        description="대한민국 휴대전화의 E.164 형식(+8210XXXXXXXX).",
    )


class PhoneRequestResponse(BaseModel):
    """전화번호 인증 접수 응답."""

    verification_id: str = Field(
        description=(
            "발급마다 새로 생성되는 인증 요청 식별자(UUID). 재발급 성공 시 "
            "이전 미검증 요청은 만료된다. 최신 ID를 verify·signup에 전달한다."
        ),
        examples=["9d65e6a3-3f06-4ce2-9928-7359667a9577"],
    )
    expires_at: datetime = Field(
        description="인증번호 만료 시각(UTC). 이후에는 재요청이 필요하다."
    )
    dev_otp: str | None = Field(
        default=None,
        description=(
            "개발 편의용 인증번호. DEV_MODE=true 일 때만 채워지며 "
            "그 외에는 항상 null이다. 운영 환경에서는 노출되지 않는다."
        ),
    )


class PhoneVerifyBody(BaseModel):
    """인증번호 검증 요청."""

    verification_id: UUID = Field(
        description="phone/request 응답에서 받은 인증 요청 식별자.",
        examples=["9d65e6a3-3f06-4ce2-9928-7359667a9577"],
    )
    otp: str = Field(
        max_length=64,
        description=(
            "SMS로 수신한 6자리 인증번호. 길이·문자가 틀린 입력도 검증 경로에서 "
            "401 OTP_MISMATCH로 처리한다(요청 문자열 상한 64자)."
        ),
        examples=["792330"],
    )


class SignupRequest(BaseModel):
    """회원가입 요청.

    전화번호 인증(phone/verify)을 마친 verification_id가 필요하며,
    해당 인증 건은 가입 시 소모되어 재사용할 수 없다.
    """

    verification_id: UUID = Field(
        description="phone/verify를 통과한 인증 요청 식별자.",
        examples=["9d65e6a3-3f06-4ce2-9928-7359667a9577"],
    )
    login_id: str = Field(
        min_length=1,
        max_length=100,
        examples=["gayeon123"],
        description="로그인 아이디.",
    )
    password: str = Field(min_length=8, description="비밀번호. 최소 8자.")
    name: str = Field(examples=["이가연"], description="사용자 이름.")


class UserResponse(BaseModel):
    """사용자 정보 응답."""

    id: int = Field(description="사용자 ID.")
    login_id: str = Field(description="로그인 아이디.")
    name: str = Field(description="사용자 이름.")
    phone_number: str = Field(description="인증된 전화번호(E.164).")
    platform_role: str = Field(
        description="플랫폼 권한. 가맹점 권한(business_role)과는 별개다.",
        examples=["USER", "ADMIN"],
    )

    model_config = {"from_attributes": True}


class LoginRequest(BaseModel):
    """로그인 요청."""

    login_id: str = Field(
        min_length=1,
        max_length=100,
        examples=["gayeon123"],
        description="로그인 아이디.",
    )
    password: str = Field(description="비밀번호.")


class TokenResponse(BaseModel):
    """토큰 발급 응답."""

    access_token: str = Field(
        description=(
            "API 호출용 액세스 토큰(JWT). "
            "Authorization: Bearer <token> 헤더로 전달한다."
        )
    )
    refresh_token: str = Field(
        description=(
            "액세스 토큰 재발급용 토큰(JWT). "
            "MVP에서는 블랙리스트를 두지 않으므로 만료 전까지 유효하다."
        )
    )
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    """토큰 재발급 요청."""

    refresh_token: str = Field(description="로그인 시 발급받은 리프레시 토큰.")
