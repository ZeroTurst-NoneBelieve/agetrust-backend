"""키오스크의 최종 판정 결과를 수집한다 (#42, ADR-0011/0016)."""

import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.deps import get_current_kiosk
from app.api.errors import api_error
from app.core.audit import record_audit_event
from app.database import get_db
from app.models import Kiosk, VerificationLog
from app.schemas.audit import AuditActorType, AuditAggregateType, AuditEventType
from app.schemas.errors import AuthErrorResponse, KioskResultError, KioskResultErrorResponse
from app.schemas.kiosk import KioskVerificationResultRequest, KioskVerificationResultResponse


def _error(code: KioskResultError, status_code: int):
    return api_error(code, status_code, headers={"Cache-Control": "no-store"})


class _KioskResultRoute(APIRoute):
    """입력·저장 실패 응답을 이 경로의 계약으로 맞춘다."""

    def get_route_handler(self):
        handler = super().get_route_handler()

        async def handle(request: Request) -> Response:
            request.state.kiosk_received_at = datetime.now(timezone.utc)
            try:
                return await handler(request)
            except RequestValidationError:
                # 검증 오류의 input에는 nonce나 잘못 보낸 생체정보가 있을 수
                # 있으므로 요청 본문·필드 값을 응답 또는 로그에 재출력하지 않는다.
                raise _error(KioskResultError.INVALID_VERIFICATION_RESULT, 400) from None
            except StarletteHTTPException as error:
                # JSON 인코딩 해독 실패는 RequestValidationError가 아니라
                # 일반 400이다. 본문 파싱 오류도 동일한 코드와 no-store로 반환한다.
                # 이미 코드가 지정된 본문 불일치 오류와 401/403 등은 유지한다.
                if error.status_code == 400 and isinstance(error.detail, str):
                    raise _error(KioskResultError.INVALID_VERIFICATION_RESULT, 400) from None
                raise
            except (SQLAlchemyError, OSError):
                # 인증 의존성의 DB 조회·커밋 실패도 재시도 가능한 응답으로
                # 통일한다. asyncpg 연결 시간 초과는 OSError의 하위 타입이다.
                # 세션 정리는 get_db의 컨텍스트 관리자가 수행한다.
                raise _error(KioskResultError.VERIFICATION_RESULT_UNAVAILABLE, 503) from None

        return handle


router = APIRouter(prefix="/api/v1/kiosk", tags=["kiosk"], route_class=_KioskResultRoute)


@router.post(
    "/verification-results",
    status_code=status.HTTP_201_CREATED,
    response_model=KioskVerificationResultResponse,
    summary="키오스크 검증 결과 기록",
    responses={
        200: {"model": KioskVerificationResultResponse, "description": "동일한 결과의 재전송. 기존 영수증 반환"},
        400: {
            "model": KioskResultErrorResponse,
            "description": (
                "형식 오류(INVALID_VERIFICATION_RESULT) 또는 "
                "같은 nonce의 본문 변경(KIOSK_RESULT_PAYLOAD_MISMATCH)"
            ),
        },
        401: {"model": AuthErrorResponse, "description": "키오스크 API Key가 없거나 무효, 또는 비활성 키오스크"},
        403: {"model": KioskResultErrorResponse, "description": "인증된 키오스크와 본문 식별자 불일치"},
        503: {"model": KioskResultErrorResponse, "description": "결과 저장 일시 실패. 같은 본문으로 재시도"},
        # FastAPI의 자동 422 문서 대신, 이 경로의 400 검증 계약을 적용한다.
        "4XX": {"model": KioskResultErrorResponse, "description": "본문 검증 실패는 위 400 응답을 사용"},
    },
)
async def record_verification_result(
    body: KioskVerificationResultRequest,
    request: Request,
    response: Response,
    kiosk: Kiosk = Depends(get_current_kiosk),
    db: AsyncSession = Depends(get_db),
):
    """현장 판정을 다시 수행하지 않고 인증된 키오스크가 보고한 결과를 저장한다."""
    if body.kiosk_identifier != kiosk.kiosk_identifier:
        raise _error(KioskResultError.KIOSK_IDENTIFIER_MISMATCH, 403)

    received_at = request.state.kiosk_received_at
    values = body.model_dump(exclude={"kiosk_identifier", "nonce"})
    values["verified_at"] = body.verified_at.astimezone(timezone.utc)
    nonce_hash = hashlib.sha256(body.nonce.encode("utf-8")).hexdigest()
    try:
        # 사전 SELECT만으로는 동시 요청 두 건이 모두 통과한다. 이름이 지정된
        # DB UNIQUE만 처리하므로 다른 제약 위반을 성공으로 숨기지 않는다.
        statement = (
            insert(VerificationLog)
            .values(
                **values,
                kiosk_id=kiosk.id,
                nonce_hash=nonce_hash,
                received_at=received_at,
                is_late=received_at - values["verified_at"] > timedelta(days=7),
            )
            .on_conflict_do_nothing(constraint="uq_verification_logs_kiosk_nonce")
            .returning(VerificationLog)
        )
        row = (await db.execute(statement)).scalar_one_or_none()
        if row is None:
            # ON CONFLICT는 선행 INSERT의 커밋을 기다린다. 다음 READ COMMITTED
            # 문장은 그 행을 볼 수 있고, 시각/기본값을 정규화한 본문을 대조한다.
            row = await db.scalar(select(VerificationLog).where(
                VerificationLog.kiosk_id == kiosk.id,
                VerificationLog.nonce_hash == nonce_hash,
            ))
            if row is None:
                raise _error(KioskResultError.VERIFICATION_RESULT_UNAVAILABLE, 503)
            if any(getattr(row, field) != value for field, value in values.items()):
                raise _error(KioskResultError.KIOSK_RESULT_PAYLOAD_MISMATCH, 400)
            receipt = KioskVerificationResultResponse.model_validate(row)
            await db.rollback()
            response.status_code = status.HTTP_200_OK
        else:
            await record_audit_event(
                db,
                event_type=AuditEventType.VERIFICATION_RESULT_RECORDED.value,
                actor_type=AuditActorType.KIOSK.value,
                source_kiosk_id=kiosk.id,
                aggregate_type=AuditAggregateType.VERIFICATION_LOG.value,
                aggregate_id=str(row.id),
                # 명시적인 허용 목록. nonce/VP/얼굴 정보는 감사·Outbox에도 넣지 않는다.
                payload={
                    "verification_log_id": row.id,
                    "kiosk_id": kiosk.id,
                    "result_status": row.result_status,
                    "verified_at": row.verified_at.isoformat(),
                    "received_at": row.received_at.isoformat(),
                    "is_late": row.is_late,
                },
            )
            receipt = KioskVerificationResultResponse.model_validate(row)
            await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise _error(KioskResultError.VERIFICATION_RESULT_UNAVAILABLE, 503) from None

    response.headers["Cache-Control"] = "no-store"
    return receipt
