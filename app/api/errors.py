"""API 오류 응답 생성기.

모든 오류 응답 본문은 한 형태로 나간다.

    {"detail": {"code": "DEVICE_NOT_FOUND"}}

클라이언트는 detail.code 하나만 보고 분기한다. 산문 메시지로 분기하게 두면
문구를 다듬거나 번역하는 순간 클라이언트가 조용히 깨진다(#38).
"""

from enum import StrEnum

from fastapi import HTTPException

from app.schemas.errors import AuthErrorResponse


def api_error(
    code: StrEnum,
    status_code: int,
    message: str | None = None,
    headers: dict[str, str] | None = None,
) -> HTTPException:
    """오류 코드를 담은 HTTPException을 만든다.

    message는 코드로 표현할 수 없는 진단 정보에만 채운다(예: DID 파싱 실패 사유).
    분기 근거는 어디까지나 code이며, message는 사람이 읽는 용도다.

    headers는 오류 응답에도 캐시 지시가 필요한 경우에 쓴다. 폐기 목록 조회의
    404·503이 그렇다 — no-store를 빠뜨리면 중간 캐시가 "목록 없음"을 들고
    있다가 폐기가 반영된 뒤에도 그대로 돌려줄 수 있다.
    """
    detail: dict[str, str] = {"code": code.value}
    if message is not None:
        detail["message"] = message
    return HTTPException(status_code=status_code, detail=detail, headers=headers)


# 문지기(deps.py)가 던지는 401·403은 엔드포인트 코드에 나타나지 않아 FastAPI가
# 문서화하지 못한다. 그래서 보호된 엔드포인트마다 손으로 얹는다.
# 딕셔너리 하나를 공유하므로 문구가 엔드포인트별로 갈라지지 않는다.
AUTHENTICATED_RESPONSES = {
    401: {
        "model": AuthErrorResponse,
        "description": (
            "액세스 토큰이 없거나(TOKEN_MISSING) 만료(TOKEN_EXPIRED) · "
            "위조(TOKEN_INVALID) · 종류가 다르거나(TOKEN_WRONG_TYPE) "
            "토큰의 사용자가 없음(USER_NOT_FOUND)"
        ),
    },
}

ADMIN_RESPONSES = {
    **AUTHENTICATED_RESPONSES,
    403: {
        "model": AuthErrorResponse,
        "description": "platform_role이 ADMIN이 아님 (PERMISSION_DENIED)",
    },
}
