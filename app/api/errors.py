"""API 오류 응답 생성기.

모든 오류 응답 본문은 한 형태로 나간다.

    {"detail": {"code": "DEVICE_NOT_FOUND"}}

클라이언트는 detail.code 하나만 보고 분기한다. 산문 메시지로 분기하게 두면
문구를 다듬거나 번역하는 순간 클라이언트가 조용히 깨진다(#38).
"""

from enum import StrEnum

from fastapi import HTTPException


def api_error(code: StrEnum, status_code: int, message: str | None = None) -> HTTPException:
    """오류 코드를 담은 HTTPException을 만든다.

    message는 코드로 표현할 수 없는 진단 정보에만 채운다(예: DID 파싱 실패 사유).
    분기 근거는 어디까지나 code이며, message는 사람이 읽는 용도다.
    """
    detail: dict[str, str] = {"code": code.value}
    if message is not None:
        detail["message"] = message
    return HTTPException(status_code=status_code, detail=detail)
