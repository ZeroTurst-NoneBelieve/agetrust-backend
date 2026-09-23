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
| `ISSUER_PRIVATE_KEY` | 발급자 Ed25519 개인키(base64 raw 32바이트). **팀에서 공유하는 값**을 써야 합니다 — `.env.example` 주석 참고. 보관·회전 정책은 ADR-0015(`agetrust-docs`) |

나머지(Kafka 주소, 토픽, OTP·토큰 만료 시간 등)는 `app/config.py`에 기본값이 있어 그대로 두어도 됩니다.

`.env`에 적은 값은 docker compose가 `env_file`로 컨테이너에 전부 넘깁니다. 설정을 추가할 때 `docker-compose.yml`을 같이 고칠 필요가 없습니다. 예외는 `DATABASE_URL`로, 컨테이너 안에서는 compose가 `POSTGRES_*`로 다시 조립합니다. 앱은 기동 시 기본값으로 떨어진 설정을 WARNING 로그로 남기므로, 값을 적었는데 반영이 안 되면 그 로그부터 보세요.

`.env`는 커밋되지 않습니다. Public 레포이므로 실제 키를 다른 파일에 옮겨 적지 마세요.

`ISSUER_PRIVATE_KEY`를 바꾸면 발급자 DID(`ISSUER_DID`)도 함께 바뀝니다. 값은 프로세스가 뜰 때
한 번만 읽으므로 교체에는 재기동이 필요하고, 무중단 회전은 되지 않습니다. 절차는 ADR-0015를 따릅니다.

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

## 7. 키오스크 등록과 API Key 현장 주입

관리자 API를 쓰려면 먼저 승인된 관리자 계정이 필요합니다. 공개 회원가입은 `USER`만 생성하므로
관리자 권한은 셀프서비스로 부여하지 않습니다. 팀에서 권한 부여를 승인한 뒤, DB 접근 권한이
있는 운영자가 **이미 가입하고 휴대전화 확인을 마친 ACTIVE 계정**의 내부 `id`를 확인하여
해당 계정만 `ADMIN`으로 승격합니다. 승인 내역과 작업자를 팀 운영 기록에 남기고, 공용 계정은
만들지 마세요. 예를 들어 `<approved_user_id>`를 승인된 계정의 숫자 ID로 바꾼 뒤 DB 콘솔에서
다음을 실행할 수 있습니다.

```sql
UPDATE users
SET platform_role = 'ADMIN', updated_at = now()
WHERE id = <approved_user_id>
  AND status = 'ACTIVE'
  AND phone_verified_at IS NOT NULL
RETURNING id, platform_role;
```

`RETURNING`이 1건인지 확인하고, 그 계정으로 다시 로그인해 관리자 JWT를 받습니다. 이 JWT는
관리자 API 호출에만 사용하고 키오스크에 설치하지 않습니다.

1. `POST /api/v1/admin/kiosks`에 `{"store_id": <store_id>}`를 보내 등록합니다. 응답에는
   `kiosk_identifier`와 **한 번만 표시되는** `key.api_key`가 함께 들어 있습니다.
2. 승인된 설치 담당자가 두 값을 현장 키오스크의 보안 설정에 주입합니다. 관제 웹 QR 화면이
   준비되기 전 개발 시연에서는 응답 화면에서 직접 입력합니다. 응답·QR·평문 키를 파일,
   채팅, 로그, 화면 캡처에 보관하지 마세요. 화면을 벗어나면 원문은 다시 조회할 수 없습니다.
   새 키는 발급 후 24시간 안에 한 번 인증해야 합니다. 그때까지 쓰지 않은 키는 자동
   폐기되고 인증 요청도 거부되므로, 설치가 늦어졌다면 새 키를 발급하세요.
3. 키오스크는 상태 목록 조회에 `Authorization: Bearer <api_key>`를 보냅니다. 기존
   `/api/v1/status/{id}` 별칭에도 같은 인증이 필요합니다. 사용자 로그인 JWT,
   `식별자:키`, 이전 `X-Kiosk-Key` 헤더는 사용하지 않습니다.
4. 회전할 때는 `POST /api/v1/admin/kiosks/{kiosk_identifier}/keys`에 `{}`를 보내 새 키를 발급하고
   먼저 키오스크에 주입합니다. 두 키가 함께 유효한 동안 전환한 뒤,
   `GET /api/v1/admin/kiosks/{kiosk_identifier}/keys`의 `last_used_at`으로 구 키 사용 중단을
   확인합니다. 필요하면 `PATCH /api/v1/admin/kiosks/{kiosk_identifier}/keys/{key_id}`에
   `{"expires_at": "<ISO 8601 미래 시각>"}`을 보내 구 키의 만료 시각을 정하고,
   `POST /api/v1/admin/kiosks/{kiosk_identifier}/keys/{key_id}/revoke`로 최종 폐기합니다.

마이그레이션 전의 유일한 정상 키 해시는 `legacy__` 표식으로 보존되지만 원문은 복구할 수
없습니다. 동일한 해시가 여러 키오스크에 있던 경우는 기존에도 인증이 거부됐으므로 옮기지
않습니다. 이런 키오스크에는 관리자 API로 새 키를 발급해 주입해야 합니다. 키오스크 K-6
담당자와 연동할 때는 `agetrust-docs`(팀 전용)의
[StatusList 폐기 목록 조회 API](https://github.com/ZeroTurst-NoneBelieve/agetrust-docs/blob/main/api-specs/status-list-api.md)를
참고하세요. 문서 정본은 그쪽입니다.

## 8. 키오스크 검증 결과 업로드 (#42)

현장 판정이 끝나면 키오스크가 `POST /api/v1/kiosk/verification-results`로 결과를 전송합니다.
헤더는 `Authorization: Bearer <api_key>`이며, 등록할 때 받은 키오스크 API Key를 사용합니다.
본문의 `kiosk_identifier`는 그 키로 인증된 키오스크와 일치해야 합니다.

```json
{
  "kiosk_identifier": "<등록 응답의 kiosk_identifier>",
  "nonce": "AAECAwQFBgcICQoLDA0ODw",
  "verified_at": "2026-09-22T15:00:00+09:00",
  "result_status": "PASS",
  "is_vc_valid": true,
  "is_vp_valid": true,
  "is_face_matched": true,
  "failure_code": null,
  "transport_type": "QR_BLE",
  "face_model_version": "mobilefacenet-v1",
  "threshold_version": "t-0.62",
  "status_list_age_seconds": 120
}
```

위 nonce는 문서용 값입니다. 실제 판정에서는 키오스크가 해당 세션에 생성한 nonce를 사용하고,
같은 결과를 재전송할 때는 nonce와 본문을 그대로 유지합니다. 서버는 nonce 문자열의 UTF-8
SHA-256만 저장하며, `(kiosk_id, nonce_hash)` UNIQUE로 동시에 도착한 중복도 한 번만 기록합니다.
결과·감사 이벤트(`VERIFICATION_RESULT_RECORDED`)·Outbox는 같은 트랜잭션에서 저장됩니다.

| 응답 | 의미 / 키오스크 동작 |
|---|---|
| `201` | 신규 저장 성공, 큐에서 제거 |
| `200` | 이미 저장된 동일 결과, 큐에서 제거. 새 결과·감사·Outbox는 만들지 않음 |
| `400 INVALID_VERIFICATION_RESULT` | 잘못된 본문, 큐에서 제거하고 오류 확인 |
| `400 KIOSK_RESULT_PAYLOAD_MISMATCH` | 같은 키오스크·nonce에 다른 본문. 기존 결과는 보존하고 오류 확인 |
| `401` | 키 누락·무효·폐기 또는 비활성 키오스크. 큐 보존 후 재시도 중단 |
| `403 KIOSK_IDENTIFIER_MISMATCH` | 인증 주체와 본문 식별자가 다름. 큐 보존 후 설정 확인 |
| `503 VERIFICATION_RESULT_UNAVAILABLE` | 저장 일시 실패, 동일 본문으로 재시도 |

성공 본문은 `{"id": 123, "received_at": "2026-09-22T06:00:01Z", "is_late": false}` 형태입니다.
재전송에는 최초 저장한 영수증을 그대로 반환합니다. 같은 nonce의 **내용이 달라진 경우 400**과
이 영수증 필드는 기존 문서에 없던 #42 구현 계약이므로 K-7 연동 시 함께 확인합니다.
429·5xx는 30초부터 최대 1시간까지 지수 백오프로 재시도합니다. 정상 중복에 409는 반환하지 않습니다.

`verified_at`은 시간대가 있는 ISO 8601 문자열이며, `received_at`은 서버가 요청을 받은 시각입니다.
7일을 **초과**해 늦게 도착한 결과도 저장하고 `is_late=true`로 표시합니다. 시계가 잘못 설정된
키오스크의 미래 시각도 원문 시점대로 저장하고 서버 수신 시각과 비교할 수 있게 합니다.

`nonce`는 비어 있지 않은 문자열(최대 128자)로 받습니다. 생성 품질·현장 replay 방지는
키오스크 책임이며, 업로드 API의 UNIQUE는 기록 중복만 방지합니다. `failure_code` 허용 목록은
전송 계약에서 아직 미정이므로 최대 100자의 선택적 문자열로 받습니다. `result_status`는
기존 DB의 `PASS`, `FAIL_EXPIRED`, `FAIL_FACE_MISMATCH`, `FAIL_INVALID_VC`, `FAIL_INVALID_VP`,
`FAIL_REVOKED_VC`, `FAIL_CHALLENGE`, `INTERNAL_ERROR`를 사용하며 `PROTO_ERROR`는 받지 않습니다.

기존 요청 예제와의 호환을 위해 `is_vp_valid` 생략 시 DB 기본값과 같은 `false`,
`is_liveness_valid` 생략 시 `null`입니다. 실제 수행한 검증 결과는 키오스크가 명시해서 보냅니다.
`status_list_age_seconds`는 `null` 또는 0~2147483647의 정수입니다. 모델·임계값 버전은
선택적 문자열(최대 100자)입니다. `user_id`, VP/VC 원문, 얼굴 임베딩 등 정의되지 않은 필드는
400으로 거절하며, 검증 오류 응답에 입력값을 다시 싣지 않습니다.

`tests/test_kiosk_results_db.py`는 전용 `E2E_DATABASE_URL`이 있을 때 실제 PostgreSQL로
인증·동시 재전송·본문 불일치·감사/Outbox 원자성을 검증합니다. 각 테스트가 만든 별도 스키마를
끝에 제거하므로 테스트 DB 계정에 `CREATE SCHEMA` 권한이 필요합니다.

## 9. CI

`dev`/`main` 대상 PR과 두 브랜치로의 push에서 `.github/workflows/ci.yml`이 돕니다.

| 잡 | 내용 |
|---|---|
| **Lint (ruff)** | `ruff check .` |
| **Test (unittest + E2E)** | `postgres:15-alpine` → `alembic upgrade head` → `unittest discover` |

로컬에서 5·6번을 통과하면 CI도 같은 결과가 나옵니다.
