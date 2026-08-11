from pydantic import BaseModel, Field


class RegisterDeviceRequest(BaseModel):
    device_identifier: str
    platform: str = Field(examples=["ANDROID", "IOS"])


class DeviceResponse(BaseModel):
    id: int
    device_identifier: str
    platform: str
    holder_did: str | None
    status: str

    model_config = {"from_attributes": True}


class BindHolderKeyRequest(BaseModel):
    device_id: int
    holder_public_key_pem: str
    proof_signature_b64: str