# agetrust-backend
FastAPI 백엔드 &amp; Docker 인프라

# 파일 구조
```
agetrust-backend/
├── app/
│   ├── __init__.py
│   ├── main.py                  # FastAPI 엔트리포인트 (기본 헬스체크 구현)
│   ├── config.py                # Pydantic Settings 환경변수 설정
│   ├── database.py              # PostgreSQL DB 연결 설정
│   ├── api/
│   │   ├── __init__.py
│   │   ├── deps.py              # JWT / 권한 검증 미들웨어
│   │   └── v1/
│   │       ├── __init__.py
│   │       ├── api.py           # v1 라우터 통합
│   │       └── endpoints/       # auth.py, vc.py, verify.py, stores.py (빈 파일 또는 .gitkeep)
│   ├── core/                    # security.py, did_crypto.py
│   ├── models/                  # user.py, store.py, challenge.py, log.py
│   ├── schemas/                 # user.py, vc.py, verify.py, store.py
│   └── services/                # kafka_producer.py, kafka_consumer.py
├── .env                          # 로컬 환경변수 파일 (git에 커밋되지 않음, 아래 "환경변수" 참고)
├── .gitignore                   # Python 및 Docker용 gitignore
├── .dockerignore                # Docker 빌드 컨텍스트 제외 목록
├── Dockerfile                   # FastAPI 백엔드 단독 도커파일
├── docker-compose.yml           # FastAPI + PostgreSQL + Kafka 인프라 일원화
├── alembic.ini, alembic/        # DB 마이그레이션 설정 및 버전 파일
└── requirements.txt             # 파이썬 의존성 패키지 목록
```

# 환경변수

`.env` 파일은 git에 올라가지 않으므로, 저장소를 새로 clone했다면 프로젝트 루트에 직접 만들어야 한다. 아래 값을 그대로 채우면 `docker-compose.yml`의 기본값과 동일하게 로컬에서 바로 동작한다.

```
POSTGRES_USER=agetrust_user
POSTGRES_PASSWORD=agetrust_password
POSTGRES_DB=agetrust_db

DATABASE_URL=postgresql+asyncpg://agetrust_user:agetrust_password@postgres:5432/agetrust_db

SECRET_KEY=change-me-in-real-env
```

`.env` 파일이 없어도 `docker-compose.yml`에 동일한 기본값이 설정되어 있어 로컬 개발은 가능하다. 다만 비밀번호를 다르게 쓰거나 `SECRET_KEY`처럼 실제 보안이 필요한 값을 관리하려면 `.env`를 직접 만들어 오버라이드해야 한다.
