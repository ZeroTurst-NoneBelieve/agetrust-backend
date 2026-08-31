from pydantic import BaseModel, Field


class RegisterDeviceRequest(BaseModel):
    """기기 등록 요청."""

    device_identifier: str = Field(
        description="클라이언트가 생성한 기기 고유 식별자. 앱 재설치 시에도 유지되는 값을 권장한다.",
        examples=["a1b2c3d4-e5f6-7890-abcd-ef1234567890"],
    )
    platform: str = Field(
        description="기기 플랫폼.",
        examples=["ANDROID", "IOS"],
    )


class DeviceResponse(BaseModel):
    """기기 정보 응답."""

    id: int = Field(description="서버가 부여한 기기 ID. 이후 요청의 device_id로 사용한다.")
    device_identifier: str = Field(description="클라이언트가 등록한 기기 고유 식별자.")
    platform: str = Field(description="기기 플랫폼.", examples=["ANDROID", "IOS"])
    holder_did: str | None = Field(
        description=(
            "Holder 공개키에서 파생된 did:key. "
            "bind-holder-key 호출 전에는 null이며, VC 발급에는 이 값이 반드시 필요하다."
        ),
        examples=["did:key:z6MkfDPXFg3QvpCr1iKB8JRs3Ai8dDjmVWLuG3e1P2xLbesk"],
    )
    status: str = Field(
        description="기기 상태. ACTIVE가 아니면 VC를 발급하지 않는다.",
        examples=["ACTIVE", "LOST", "REVOKED"],
    )

    model_config = {"from_attributes": True}


class BindHolderKeyRequest(BaseModel):
    """Holder 공개키 바인딩 요청.

    기기가 개인키를 실제로 보유하고 있음을 증명해야 등록된다.
    서버는 전달받은 공개키로 서명을 검증한 뒤 did:key를 파생해 저장한다.
    """

    device_id: int = Field(
        description="기기 등록 응답에서 받은 기기 ID.",
        examples=[15],
    )
    holder_public_key_pem: str = Field(
        description=(
            "Ed25519 공개키(PEM, SubjectPublicKeyInfo). "
            "JSON 문자열이므로 줄바꿈은 \\n 으로 이스케이프해서 보낸다."
        ),
        examples=[
            "-----BEGIN PUBLIC KEY-----\n"
            "MCowBQYDK2VwAyEAC04Cgm7XU4bvCk68Tog+jekF3o4rSIxEcymBjAYm99M=\n"
            "-----END PUBLIC KEY-----\n"
        ],
    )
    proof_signature_b64: str = Field(
        description=(
            "소유 증명 서명(base64). "
            "device_id를 10진 문자열로 바꾼 바이트열을 Holder 개인키로 서명한 값이다. "
            '예: device_id가 15이면 "15"의 UTF-8 바이트에 서명한다.'
        ),
        examples=["/3TgMBtI+kBLTNUlKerfINw95i//b0zU0DD1i58JuY/J..."],
    )
