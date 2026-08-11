from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str
    secret_key: str

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
