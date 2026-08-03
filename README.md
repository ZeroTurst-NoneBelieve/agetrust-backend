# agetrust-backend
FastAPI 백엔드 &amp; Docker 인프라

# 파일 구조
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
├── .env.example                 # 샘플 환경변수 파일 (.env는 .gitignore에 등록)
├── .gitignore                   # Python 및 Docker용 gitignore
├── Dockerfile                   # FastAPI 백엔드 단독 도커파일
├── docker-compose.yml           # FastAPI + PostgreSQL + Kafka 인프라 일원화
└── requirements.txt             # 파이썬 의존성 패키지 목록