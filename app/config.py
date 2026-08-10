from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # 기본값을 두지 않는다: 값이 없으면 엉뚱한/안전하지 않은 값으로 조용히 뜨는 대신 시작 자체를 실패시킨다.
    database_url: str
    # JWT Access/Refresh Token 서명·검증용 비밀키. 로그인 API 구현 시 python-jose에서 사용 예정 (아직 미사용).
    secret_key: str

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
