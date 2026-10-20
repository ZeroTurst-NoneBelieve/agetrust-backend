"""관리자용 KIOSK 계정 요청·응답 (#66).

임시 비밀번호는 생성·초기화 응답(KioskAccountCredentialResponse)에서만 한 번
노출한다. 조회 응답 모델에는 넣지 않는다.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class CreateKioskAccountRequest(BaseModel):
    """KIOSK 계정 생성 요청. 전화번호는 받지 않는다."""

    login_id: str = Field(
        min_length=1, max_length=100, examples=["gangnam-kiosk"], description="키오스크 로그인 아이디."
    )
    name: str = Field(
        min_length=1, max_length=100, examples=["강남점 키오스크"], description="계정 표시 이름(매장명 등)."
    )
    business_number: str = Field(
        min_length=1,
        max_length=50,
        examples=["123-45-67890"],
        description="사업자등록번호. 이미 등록된 사업자면 새로 만들지 않고 그 사업자에 연결한다.",
    )
    business_name: str = Field(
        min_length=1,
        max_length=200,
        examples=["에이지트러스트 편의점"],
        description="상호. 사업자를 새로 만들 때만 저장한다.",
    )
    contact_number: str | None = Field(
        default=None, max_length=30, description="사업자 연락처. 사업자를 새로 만들 때만 저장한다."
    )


class KioskAccountBusiness(BaseModel):
    """계정이 OWNER로 연결된 사업자."""

    model_config = ConfigDict(from_attributes=True)

    business_id: int = Field(validation_alias="id")
    business_number: str
    business_name: str
    status: str


class KioskAccountResponse(BaseModel):
    """KIOSK 계정 정보. 비밀번호·임시 비밀번호는 들어 있지 않다."""

    id: int
    login_id: str
    name: str
    status: str = Field(examples=["ACTIVE", "SUSPENDED"])
    must_change_password: bool = Field(description="true면 아직 임시 비밀번호를 바꾸지 않은 상태다.")
    temp_password_expires_at: datetime | None = Field(description="임시 비밀번호 사용 기한. 바꾼 뒤에는 null.")
    created_at: datetime
    business: KioskAccountBusiness | None


class KioskAccountCredentialResponse(BaseModel):
    """임시 비밀번호를 담는 유일한 응답. 생성·비밀번호 초기화 때만 내려간다."""

    account: KioskAccountResponse
    temporary_password: str = Field(
        description=(
            "임시 비밀번호. 이 응답에서만 제공되므로 매장에 안전하게 전달한다. "
            "첫 로그인 후 POST /api/v1/auth/password로 바꿔야 다른 API를 쓸 수 있다."
        )
    )
