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
├── .github/workflows/ci.yml     # CI (Lint · 테스트 자동 실행)
├── pyproject.toml               # ruff 린트 규칙 설정
├── requirements.txt             # 파이썬 의존성 패키지 목록
└── requirements-dev.txt         # 개발 전용 의존성 (ruff)
```

# 개발 환경

## 사전 요구사항

- **Python 3.11** — Dockerfile(`python:3.11-slim`) 및 CI와 같은 버전입니다. `pyproject.toml`의 `target-version`도 `py311`입니다.
- **Docker / Docker Compose** — PostgreSQL·Kafka를 띄우는 데 씁니다.

## 1. 가상환경과 의존성

```bash
python -m venv .venv

# macOS / Linux
source .venv/bin/activate
# Windows PowerShell
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt -r requirements-dev.txt
```

`requirements-dev.txt`에는 린터 같은 개발 도구만 들어 있습니다. Dockerfile은 `requirements.txt`만 설치하므로 운영 이미지에는 포함되지 않습니다.

## 2. 환경변수

`.env.example`을 복사해 `.env`를 만들고 값을 채웁니다. 아래 항목은 **기본값이 없어, 비어 있으면 앱이 뜨지 않습니다.**

| 변수 | 설명 |
|---|---|
| `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | docker compose가 PostgreSQL 컨테이너 초기화와 `DATABASE_URL` 조립에 씁니다 |
| `DATABASE_URL` | 호스트에서 직접 실행할 때 쓰는 접속 문자열. 예: `postgresql+asyncpg://<user>:<pw>@localhost:5432/<db>` |
| `SECRET_KEY` | JWT 서명 키. 32바이트 이상 |
| `ISSUER_PRIVATE_KEY` | 발급자 Ed25519 개인키(base64 raw 32바이트). **팀에서 공유하는 값**을 써야 합니다 — `.env.example` 주석 참고 |

나머지(Kafka 주소, 토픽, OTP·토큰 만료 시간 등)는 `app/config.py`에 기본값이 있어 그대로 두어도 됩니다.

`.env`는 커밋되지 않습니다. Public 레포이므로 실제 키를 다른 파일에 옮겨 적지 마세요.

## 3. 인프라와 마이그레이션

```bash
docker compose up -d postgres     # DB만 띄우기 (Kafka까지 필요하면 인자 없이 up)
alembic upgrade head              # 최신 리비전까지 스키마 적용
```

이미 적용된 리비전 파일은 수정하지 않는 것이 이 저장소의 규칙입니다. 스키마를 바꿔야 하면 새 리비전을 만드세요.

## 4. 서버 실행

```bash
uvicorn app.main:app --reload
```

- Swagger UI: http://localhost:8000/docs
- 전체 스택을 컨테이너로 띄우려면 `docker compose up`

## 5. 린트

규칙은 `pyproject.toml`의 `[tool.ruff]`에 있고, CI가 도는 명령과 같습니다.

```bash
ruff check .              # 검사
ruff check . --fix        # 자동 수정 가능한 것만 고침
ruff check . --diff       # 고치기 전 변경 내용 미리보기
ruff check . --statistics # 규칙별 위반 건수 집계
```

ruff 버전은 `requirements-dev.txt`와 워크플로 양쪽에 고정돼 있습니다. **한쪽만 올리면 로컬과 CI 결과가 갈리므로 반드시 같이 올리세요.**

한 줄만 예외로 두려면 규칙 코드를 명시합니다 — `# noqa: F401`. 코드 없는 `# noqa`는 그 줄의 모든 규칙을 끄므로 쓰지 않습니다. 파일 단위 예외는 `pyproject.toml`의 `per-file-ignores`에 추가합니다.

**VS Code 연동** — 확장 `charliermarsh.ruff`를 설치하고 `"ruff.importStrategy": "fromEnvironment"`로 둡니다. 이 설정이 없으면 확장에 번들된 다른 버전이 쓰여 에디터와 CI 결과가 어긋납니다.

## 6. 테스트

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

E2E 3건(`tests/test_e2e_scenarios.py`)과 상태 목록 PostgreSQL 회귀 테스트 4건
(`tests/test_status_list_db.py`)은 `E2E_DATABASE_URL`이 있을 때만 실행되고, 없으면 스킵됩니다. 켜려면:

```bash
# macOS / Linux
E2E_DATABASE_URL=postgresql+asyncpg://<user>:<pw>@localhost:5432/<db> \
  python -m unittest discover -s tests -p "test_*.py" -v
```

```powershell
# Windows PowerShell
$env:E2E_DATABASE_URL = "postgresql+asyncpg://<user>:<pw>@localhost:5432/<db>"
python -m unittest discover -s tests -p "test_*.py" -v
```

E2E는 테이블에 실제로 쓰기를 하므로 운영 DB를 가리키지 마세요.

상태 목록은 `X-Kiosk-Key: <kiosk_identifier>:<raw_key>`로 등록된 ACTIVE 키오스크만
조회할 수 있습니다. 기존 `/api/v1/status/{id}` 경로에도 같은 인증이 필요합니다.
URL 호환성, 캐시 동작, 인증 헤더·키 배포 관련 팀 확인 사항은
[#27 리뷰 반영 범위](docs/status-list-review.md)를 참고하세요.
키오스크 K-6 담당자와 연동할 때는
[폐기 목록 연동 안내](docs/status-list-kiosk-handoff.md)를 참고하세요.

## 7. CI

`dev`/`main` 대상 PR과 두 브랜치로의 push에서 `.github/workflows/ci.yml`이 돕니다.

| 잡 | 내용 |
|---|---|
| **Lint (ruff)** | `ruff check .` |
| **Test (unittest + E2E)** | `postgres:15-alpine` → `alembic upgrade head` → `unittest discover` |

로컬에서 5·6번을 통과하면 CI도 같은 결과가 나옵니다.
