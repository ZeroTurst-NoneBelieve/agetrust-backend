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

`DEV_MODE=false`로 실제 OTP 문자를 보낼 때는 다음 SOLAPI 설정도 필요합니다.

| 변수 | 설명 |
|---|---|
| `SOLAPI_API_KEY` | SOLAPI 콘솔에서 발급한 API Key |
| `SOLAPI_API_SECRET` | API Key와 함께 발급된 Secret. 저장소나 채팅에 공유하지 않습니다 |
| `SOLAPI_SENDER` | SOLAPI에서 등록을 마친 발신번호. 하이픈 없이 숫자만 입력합니다 |
| `OTP_RESEND_COOLDOWN_SECONDS` | 동일 번호 재전송 대기시간. 기본값은 프로젝트 정책에 따른 30초입니다 |
| `OTP_MAX_RESENDS` | 하나의 유효한 인증 요청에서 허용할 재발송 횟수. 기본값 5회입니다 |
| `OTP_REQUEST_LIMIT_PER_CLIENT` / `OTP_REQUEST_LIMIT_WINDOW_SECONDS` | 접속 IP별 실제 발송 한도와 시간 창. 기본값은 10분에 10건입니다 |
| `OTP_REQUEST_LIMIT_PER_RECIPIENT` / `OTP_REQUEST_RECIPIENT_WINDOW_SECONDS` | 수신번호별 장기 발송 한도와 시간 창. 기본값은 1시간에 6건입니다 |
| `OTP_REQUEST_GLOBAL_LIMIT` / `OTP_REQUEST_GLOBAL_WINDOW_SECONDS` | 서버 프로세스 전체의 실제 발송 한도와 시간 창. 기본값은 1시간에 100건입니다 |

나머지(Kafka 주소, 토픽, OTP·토큰 만료 시간 등)는 `app/config.py`에 기본값이 있어 그대로 두어도 됩니다.

`.env`에 적은 값은 docker compose가 `env_file`로 컨테이너에 전부 넘깁니다. 설정을 추가할 때 `docker-compose.yml`을 같이 고칠 필요가 없습니다. 예외는 `DATABASE_URL`로, 컨테이너 안에서는 compose가 `POSTGRES_*`로 다시 조립합니다. 앱은 기동 시 기본값으로 떨어진 설정을 WARNING 로그로 남기므로, 값을 적었는데 반영이 안 되면 그 로그부터 보세요.

`.env`는 커밋되지 않습니다. Public 레포이므로 실제 키를 다른 파일에 옮겨 적지 마세요.

`ISSUER_PRIVATE_KEY`를 바꾸면 발급자 DID(`ISSUER_DID`)도 함께 바뀝니다. 값은 프로세스가 뜰 때
한 번만 읽으므로 교체에는 재기동이 필요하고, 무중단 회전은 되지 않습니다. 절차는 ADR-0015를 따릅니다.

### 실제 OTP 문자 발송

SOLAPI 콘솔에서 API Key를 만든 뒤 `.env`에 위 세 값을 채우고
`DEV_MODE=false`로 설정합니다. 서버를 다시 기동한 다음 대한민국 휴대전화
번호를 E.164 형식으로 요청합니다.

```bash
curl -X POST http://localhost:8000/api/v1/auth/phone/request \
  -H "Content-Type: application/json" \
  -d '{"phone_number":"+821012345678"}'
```

서버는 `+8210XXXXXXXX`를 SOLAPI의 국내 형식인 `010XXXXXXXX`로 변환해
등록된 발신번호로 SMS를 접수합니다. 실제 발송 모드의 응답에서 `dev_otp`는
항상 `null`이며, 수신한 인증번호를 `/api/v1/auth/phone/verify`에 전달합니다.
이 API의 성공은 SOLAPI가 발송 요청을 접수했다는 뜻이며 단말의 최종 수신
결과는 SOLAPI 메시지 상태에서 별도로 확인합니다.

동일 번호로 30초 안에 다시 요청하면 `429 OTP_RESEND_TOO_SOON`과
`Retry-After` 헤더를 반환합니다. 승인된 재전송은 **새로운 `verification_id`**와
OTP를 발급하고 이전 미검증 요청을 만료시킵니다. 앱은 성공 응답을 받았을 때
새 ID를 저장하고 이후 검증·가입에 사용해야 합니다. 기존 실패·재발송 횟수는
새 요청으로 이어받아 초기화하지 않습니다. 실패 시도를 모두 쓴 뒤 발송을 요청하면
`429 OTP_LOCKED_UNTIL_EXPIRY`와 해당 인증 요청의 만료까지 남은 시간을 나타내는
`Retry-After` 헤더를 반환합니다. 재발송 한도에 도달한 요청은 만료될 때까지
`429 OTP_RESEND_LIMIT_REACHED`로 거절합니다.

검증 API(`/api/v1/auth/phone/verify`)는 실패 시도를 모두 쓴 요청에
`401 OTP_MAX_ATTEMPTS`를 반환합니다. 생성되는 OTP는 기존과 같이 6자리 숫자이며,
유효한 인증 요청에 64자 이하의 잘못된 OTP 문자열을 보내면 `401 OTP_MISMATCH`로
처리하고 실패 횟수에 포함합니다. 64자를 넘기거나 문자열이 아닌 본문은 스키마 검증에서
거절합니다.

`429`로 재전송이 거절됐을 때는 기존 인증 입력 상태를 유지합니다. 타임아웃이나
`502`로 응답이 불명확하면 서버에서 새 요청이 만들어졌을 수 있으므로, 대기 후
재요청해 성공 응답의 ID와 새 SMS를 함께 사용합니다.

실제 문자 발송에는 접속 IP별·수신번호별·서버 전체 발송량 제한도 적용하며, 초과 시
`429 OTP_REQUEST_RATE_LIMITED`와 `Retry-After`를 반환합니다. 현재 배포 방식인
단일 FastAPI 프로세스에 맞춰 메모리에서 집계하므로, 프로세스나 서버를 여러
개로 늘릴 때는 API 게이트웨이 또는 Redis 같은 공유 저장소로 같은 제한을
옮겨야 합니다. DB 저장 실패나 SOLAPI의 확정 미접수는 수신번호·전체 발송량
예약에서 빼지만, 반복 호출을 막기 위한 접속 IP 요청 한도에는 포함합니다.
타임아웃처럼 접수 결과를 알 수 없는 요청은 중복 발송과 비용 초과를 막기 위해
시간 창이 끝날 때까지 예약을 유지합니다. SOLAPI 설정이 없으면
`503 SMS_SERVICE_UNAVAILABLE`, SOLAPI가 접수하지 못하면
`502 SMS_DELIVERY_FAILED`를 반환합니다.

접속 IP는 `request.client.host`를 사용하며 현재 배포는 직접 접속을 전제로 합니다.
리버스 프록시를 추가할 때는 신뢰할 프록시의 전달 헤더와 원래 클라이언트 IP가
올바르게 반영되도록 서버를 설정해야 합니다. 클라이언트가 임의로 보낸
`X-Forwarded-For`를 신뢰해서는 안 됩니다.

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

다음 통합 테스트는 `E2E_DATABASE_URL`이 있을 때만 실행되고, 없으면 스킵됩니다.

| 검증 범위 | 테스트 파일 |
|---|---|
| 백엔드 성인 인증 E2E | `tests/test_e2e_scenarios.py` |
| 상태 목록 PostgreSQL 회귀 | `tests/test_status_list_db.py` |
| SMS 실패 시 인증 요청 정리 | `tests/test_sms_cas_e2e.py` |
| 실제 SOLAPI SDK와 로컬 모의 SMS 서버 연동 | `tests/test_sms_http_e2e.py` |
| OTP 재발송·실패 횟수·가입 검증 격리 | `tests/test_otp_isolation_e2e.py` |
| 키오스크 관리자 키 발급·회전·폐기 | `tests/test_kiosk_admin_db.py` |
| 키오스크 미사용 키 정리 | `tests/test_kiosk_key_cleanup_db.py` |
| 키오스크 키 정리·관리자 폐기 간 잠금 경합 | `tests/test_kiosk_key_concurrency_db.py` |
| 기존·탈퇴 계정 및 동시 가입의 전화번호 충돌 | `tests/test_signup_conflicts_db.py` |

SMS HTTP 테스트는 실제 문자를 발송하지 않습니다. SMS HTTP와 OTP 격리 테스트는
테스트별 스키마를 만들므로 테스트 계정에 `CREATE SCHEMA` 권한이 필요합니다. 켜려면:

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

## 8. CI

`dev`/`main` 대상 PR과 두 브랜치로의 push에서 `.github/workflows/ci.yml`이 돕니다.

| 잡 | 내용 |
|---|---|
| **Lint (ruff)** | `ruff check .` |
| **Test (unittest + E2E)** | `postgres:15-alpine` → `alembic upgrade head` → `unittest discover` |

로컬에서 5·6번을 통과하면 CI도 같은 결과가 나옵니다.
