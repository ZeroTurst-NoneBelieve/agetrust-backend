"""프로세스 전역 로깅 설정 (#39).

uvicorn은 자기 로거(`uvicorn.*`)에만 핸들러를 달고 루트 로거는 건드리지 않는다.
그래서 `app.*` 로거의 INFO는 어디에도 찍히지 않았고, WARNING 이상만 파이썬의
최후 핸들러(lastResort)로 stderr에 흘렀다. API와 Publisher 워커가 같은 설정을 쓴다.
"""

import logging

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def configure_logging(level: str) -> None:
    """루트 로거에 핸들러와 레벨을 설정한다.

    `basicConfig`는 루트에 이미 핸들러가 있으면 아무것도 하지 않으므로,
    테스트 러너나 임베딩 환경이 먼저 설정한 로깅을 덮어쓰지 않는다.
    """
    logging.basicConfig(level=level.upper(), format=LOG_FORMAT)
