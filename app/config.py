from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str
    secret_key: str

    # Issuer(발급자) Ed25519 개인키 — base64(raw 32바이트).
    # 서버 재시작마다 키가 바뀌면 이전에 발급한 VC를 검증할 수 없고,
    # 체인에 등록한 공개키와도 어긋나므로 반드시 고정 값을 쓴다.
    issuer_private_key: str

    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    otp_length: int = 6
    otp_expire_minutes: int = 5
    otp_max_attempts: int = 5
    vc_expire_days: int = 365
    challenge_expire_seconds: int = 120
    dev_mode: bool = True

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()