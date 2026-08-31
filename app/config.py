from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str
    secret_key: str

    # Issuer(발급자) Ed25519 개인키 — base64(raw 32바이트).
    # 서버 재시작마다 키가 바뀌면 이전에 발급한 VC를 검증할 수 없고,
    # 체인에 등록한 공개키와도 어긋나므로 반드시 고정 값을 쓴다.
    issuer_private_key: str

    # Kafka — outbox_events를 바깥으로 발행하는 통로 (설계서 14 / REQ-INF-002).
    # 시크릿이 아니라 배포 환경마다 달라지는 주소·이름이므로 기본값을 둔다.
    kafka_bootstrap_servers: str = "kafka:29092"
    kafka_audit_topic: str = "agetrust.audit-events"
    # 미발행 이벤트를 얼마나 자주 훑을지. 감사 이벤트는 초당 수천 건이 아니라
    # 짧은 폴링으로 충분하고, 지연보다 브로커 부하가 적은 쪽이 낫다.
    outbox_poll_interval_seconds: float = 2.0
    outbox_publish_batch_size: int = 100
    # 이 횟수를 넘기면 해당 이벤트는 건너뛴다. 깨진 이벤트 하나가 뒤의 정상
    # 이벤트를 영원히 막지 않도록 하기 위한 것이다.
    # 한도에 도달하면 ERROR 로그가 남는다. 감사 원장(audit_logs)에는 그대로
    # 남아 있고 Kafka 구독자에게만 전달되지 않는다.
    outbox_max_retry_count: int = 10
    # 로컬에서 Kafka 없이 API만 띄우고 싶을 때 끈다.
    kafka_publisher_enabled: bool = True

    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    otp_length: int = 6
    otp_expire_minutes: int = 5
    otp_max_attempts: int = 5
    vc_expire_days: int = 365
    challenge_expire_seconds: int = 120

    # 개발 편의 기능(OTP 응답 노출, 콘솔 출력) 스위치.
    # 기본값을 False로 두어, 명시적으로 켜지 않는 한 인증번호가
    # 응답이나 로그로 새어 나가지 않도록 한다.
    # 로컬 개발 시에만 .env에 DEV_MODE=true 를 넣어 사용한다.
    dev_mode: bool = False

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()