"""프로세스 전역 로깅 설정 (#39).

uvicorn은 자기 로거(`uvicorn.*`)에만 핸들러를 달고 루트 로거는 건드리지 않는다.
그래서 `app.*` 로거의 INFO는 어디에도 찍히지 않았고, WARNING 이상만 파이썬의
최후 핸들러(lastResort)로 stderr에 흘렀다. API와 Publisher 워커가 같은 설정을 쓴다.
"""

import logging

from sqlalchemy.exc import SQLAlchemyError

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def _contains_database_error(error: BaseException) -> bool:
    pending = [error]
    seen = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, SQLAlchemyError) or type(current).__module__.startswith("asyncpg."):
            return True
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions)
    return False


class DatabaseErrorFilter(logging.Filter):
    """DB 예외 원문·드라이버 DETAIL·체인 traceback을 출력하지 않는다.

    hide_parameters는 드라이버가 오류 문자열에 포함한 값까지 숨기지 않는다.
    작업 문구는 유지하고 DB 예외는 타입만 남긴다.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        def safe_argument(value):
            if isinstance(value, BaseException) and _contains_database_error(value):
                return type(value).__name__
            return value

        if isinstance(record.args, dict):
            record.args = {key: safe_argument(value) for key, value in record.args.items()}
        elif record.args:
            record.args = tuple(safe_argument(value) for value in record.args)
        if isinstance(record.msg, BaseException):
            record.msg = safe_argument(record.msg)
        if record.exc_info and record.exc_info[1] and _contains_database_error(record.exc_info[1]):
            error_type = type(record.exc_info[1]).__name__
            record.msg = f"{record.getMessage()} (database exception: {error_type})"
            record.args = ()
            record.exc_info = None
            record.exc_text = None
        return True


def configure_logging(level: str) -> None:
    """루트 로거에 핸들러와 레벨을 설정한다.

    `basicConfig`는 루트에 이미 핸들러가 있으면 아무것도 하지 않으므로,
    테스트 러너나 임베딩 환경이 먼저 설정한 로깅을 덮어쓰지 않는다.
    """
    logging.basicConfig(level=level.upper(), format=LOG_FORMAT)
    # Uvicorn의 별도 핸들러에도 적용한다. 루트 로거 필터만으로는 자식 로거의
    # 전파 로그를 거를 수 없으므로 출력 핸들러에 장착한다.
    handlers = set(logging.getLogger().handlers)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        handlers.update(logging.getLogger(name).handlers)
    for handler in handlers:
        if not any(isinstance(item, DatabaseErrorFilter) for item in handler.filters):
            handler.addFilter(DatabaseErrorFilter())
