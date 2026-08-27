from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class PhoneRequestBody(BaseModel):
    phone_number: str = Field(
        pattern=r"^\+[1-9]\d{6,14}$",
        examples=["+821012345678"],
        description="E.164 형식",
    )


class PhoneRequestResponse(BaseModel):
    verification_id: str
    expires_at: datetime
    dev_otp: str | None = None


class PhoneVerifyBody(BaseModel):
    verification_id: UUID
    otp: str


class SignupRequest(BaseModel):
    verification_id: UUID
    login_id: str = Field(min_length=1, max_length=100, examples=["gayeon123"])
    password: str = Field(min_length=8)
    name: str = Field(examples=["이가연"])


class UserResponse(BaseModel):
    id: int
    login_id: str
    name: str
    phone_number: str
    platform_role: str

    model_config = {"from_attributes": True}


class LoginRequest(BaseModel):
    login_id: str = Field(min_length=1, max_length=100)
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str
