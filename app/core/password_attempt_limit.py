"""계정별 비밀번호 시도 횟수를 프로세스 메모리에서 센다 (#68).

로그인(/auth/login)과 비밀번호 변경(/auth/password)이 같은 계정 키(login_id)를
함께 쓴다. 그래서 한쪽 경로를 막아도 다른 경로로 대입을 이어갈 수 없다.

비밀번호를 검사하기 전에 시도 한 번을 먼저 센다(acquire). 확인과 기록을 나누면
동시에 보낸 요청들이 모두 확인을 통과해 한도를 넘길 수 있기 때문이다.
비밀번호가 맞으면 clear로 그 계정의 기록을 지우고, 틀리면 센 그대로 둔다.

IP별 제한은 두지 않는다. 리버스 프록시 뒤에서는 모든 요청의 접속 IP가 같게 보일 수
있어, IP 기준으로 막으면 정상 사용자 전체가 함께 막힐 수 있다.

상태는 OTP 발송 제한(otp_rate_limit)과 같이 하나의 Python 프로세스 안에서만
공유된다. 서버를 다시 띄우면 초기화된다.
"""

from __future__ import annotations

import asyncio
import math
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PasswordAttempt:
    """acquire 결과. allowed가 False면 retry_after초 뒤에 다시 시도할 수 있다."""

    allowed: bool
    retry_after: int = 0
    # 이번 시도로 창 안의 시도가 한도에 이르렀다. 이번 시도도 틀리면 계정이 막히기 시작한다.
    reached_limit: bool = False
    reservation: object | None = None


class PasswordAttemptLimiter:
    """이동 시간 창 안의 시도가 limit번에 이르면 창이 지날 때까지 막는다."""

    def __init__(
        self,
        *,
        limit: int,
        window_seconds: float,
        max_accounts: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if limit <= 0 or window_seconds <= 0 or max_accounts <= 0:
            raise ValueError("limit, window_seconds, max_accounts must be positive")
        self._limit = limit
        self._window_seconds = window_seconds
        self._max_accounts = max_accounts
        self._clock = clock
        self._lock = asyncio.Lock()
        # 계정 키 → 시도 시각들. dict는 삽입 순서를 지키므로 맨 앞이 가장 오래 쉰 계정이다.
        self._attempts: dict[str, deque[tuple[float, object]]] = {}

    async def acquire(self, account_key: str) -> PasswordAttempt:
        """한도 안이면 시도 한 번을 세고 허용한다. 한도에 걸렸으면 세지 않고 거부한다."""
        async with self._lock:
            now = self._clock()
            events = self._fresh_events(account_key, now)
            if events is not None and len(events) >= self._limit:
                # 창 안의 시도 중 limit번째로 최근 것이 창을 벗어나야 다시 한 번 시도할 수 있다.
                unlock_at = events[-self._limit][0] + self._window_seconds
                return PasswordAttempt(allowed=False, retry_after=max(1, math.ceil(unlock_at - now)))

            if events is None:
                self._make_room(now)
                if len(self._attempts) >= self._max_accounts:
                    # Preserve active budgets; unknown account churn must not
                    # erase another account's lock. Retry when a slot expires.
                    unlock_at = min(
                        timestamps[-1][0] + self._window_seconds
                        for timestamps in self._attempts.values()
                    )
                    return PasswordAttempt(
                        allowed=False,
                        retry_after=max(1, math.ceil(unlock_at - now)),
                    )
                events = deque()
            else:
                # 최근에 시도한 계정을 맨 뒤로 보내 오래 쉰 계정부터 밀려나게 한다.
                del self._attempts[account_key]
            reservation = object()
            events.append((now, reservation))
            self._attempts[account_key] = events
            return PasswordAttempt(allowed=True, reached_limit=len(events) == self._limit, reservation=reservation)

    async def cancel(self, account_key: str, attempt: PasswordAttempt) -> None:
        """Return only this request's reservation if verification never completed."""
        async with self._lock:
            events = self._attempts.get(account_key)
            if events is None or attempt.reservation is None:
                return
            remaining = deque(event for event in events if event[1] is not attempt.reservation)
            if remaining:
                self._attempts[account_key] = remaining
            else:
                self._attempts.pop(account_key, None)

    async def clear(self, account_key: str) -> None:
        """비밀번호가 맞았을 때 그 계정의 시도 기록을 지운다."""
        async with self._lock:
            self._attempts.pop(account_key, None)

    async def reset(self) -> None:
        async with self._lock:
            self._attempts.clear()

    def _fresh_events(self, account_key: str, now: float) -> deque[tuple[float, object]] | None:
        events = self._attempts.get(account_key)
        if events is None:
            return None
        threshold = now - self._window_seconds
        while events and events[0][0] <= threshold:
            events.popleft()
        if not events:
            del self._attempts[account_key]
            return None
        return events

    def _make_room(self, now: float) -> None:
        """새 계정을 넣기 전에 만료된 기록만 치운다. 유효한 시도 기록은 보존한다.

        없는 아이디를 대량으로 넣어 메모리를 채우는 요청을 막기 위한 상한이다.
        """
        if len(self._attempts) < self._max_accounts:
            return
        for key in list(self._attempts):
            self._fresh_events(key, now)
