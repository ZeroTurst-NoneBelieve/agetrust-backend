"""실제 OTP 문자 발송량을 프로세스별로 예약한다."""

from __future__ import annotations

import asyncio
import math
import time
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeAlias


@dataclass(frozen=True, slots=True)
class OtpSmsReservationToken:
    """예약 한 건을 확정하거나 해제할 때 사용하는 불투명한 식별자."""

    value: uuid.UUID


@dataclass(frozen=True, slots=True)
class OtpSmsReservationGranted:
    token: OtpSmsReservationToken


@dataclass(frozen=True, slots=True)
class OtpSmsReservationDenied:
    retry_after_seconds: int


OtpSmsReservationResult: TypeAlias = OtpSmsReservationGranted | OtpSmsReservationDenied


@dataclass(frozen=True, slots=True)
class _Reservation:
    client_id: str
    recipient_id: str
    timestamp: float


@dataclass(frozen=True, slots=True)
class _Event:
    token_value: uuid.UUID
    timestamp: float


class OtpSmsRateLimiter:
    """접속자별·수신번호별·전체 발송량을 이동 시간 창으로 함께 제한한다.

    상태는 하나의 Python 프로세스 안에서만 공유된다. 실제 문자 발송 직전에
    발송량을 예약하고, DB 커밋 실패나 제공업체의 확정 미접수 시 반환된 토큰으로
    예약을 해제한다. 제공업체가 접수를 확정하면 예약도 확정하여 발송량 집계는
    유지하고 해제를 위한 토큰 관리 정보만 버린다. 접수 결과가 불명확하면
    확정·해제하지 않고 예약을 유지하여 중복 발송과 한도 초과를 막는다.
    """

    def __init__(
        self,
        *,
        per_client_limit: int,
        per_client_window_seconds: float,
        per_recipient_limit: int,
        per_recipient_window_seconds: float,
        global_limit: int,
        global_window_seconds: float,
        max_clients: int = 10_000,
        max_recipients: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
        token_factory: Callable[[], uuid.UUID] = uuid.uuid4,
    ) -> None:
        self._require_positive("per_client_limit", per_client_limit)
        self._require_positive("per_client_window_seconds", per_client_window_seconds)
        self._require_positive("per_recipient_limit", per_recipient_limit)
        self._require_positive("per_recipient_window_seconds", per_recipient_window_seconds)
        self._require_positive("global_limit", global_limit)
        self._require_positive("global_window_seconds", global_window_seconds)
        self._require_positive("max_clients", max_clients)
        self._require_positive("max_recipients", max_recipients)

        self._per_client_limit = per_client_limit
        self._per_client_window_seconds = per_client_window_seconds
        self._per_recipient_limit = per_recipient_limit
        self._per_recipient_window_seconds = per_recipient_window_seconds
        self._global_limit = global_limit
        self._global_window_seconds = global_window_seconds
        self._max_clients = max_clients
        self._max_recipients = max_recipients
        self._clock = clock
        self._token_factory = token_factory

        self._lock = asyncio.Lock()
        self._global_events: deque[_Event] = deque()
        self._client_events: dict[str, deque[_Event]] = {}
        self._recipient_events: dict[str, deque[_Event]] = {}
        self._reservations: dict[uuid.UUID, _Reservation] = {}
        self._active_token_expiries: dict[uuid.UUID, float] = {}

    async def reserve(self, client_id: str, recipient_id: str) -> OtpSmsReservationResult:
        """세 한도를 원자적으로 함께 예약하거나 재시도 대기시간을 반환한다."""

        normalized_client_id = self._normalize_id("client_id", client_id)
        normalized_recipient_id = self._normalize_id("recipient_id", recipient_id)

        async with self._lock:
            now = self._clock()
            self._cleanup(now)

            client_events = self._client_events.get(normalized_client_id)
            recipient_events = self._recipient_events.get(normalized_recipient_id)
            retry_after = max(
                self._quota_retry_after(
                    client_events,
                    self._per_client_limit,
                    self._per_client_window_seconds,
                    now,
                ),
                self._quota_retry_after(
                    recipient_events,
                    self._per_recipient_limit,
                    self._per_recipient_window_seconds,
                    now,
                ),
                self._quota_retry_after(
                    self._global_events,
                    self._global_limit,
                    self._global_window_seconds,
                    now,
                ),
            )

            if client_events is None and len(self._client_events) >= self._max_clients:
                retry_after = max(
                    retry_after,
                    self._capacity_retry_after(self._client_events, self._per_client_window_seconds, now),
                )
            if recipient_events is None and len(self._recipient_events) >= self._max_recipients:
                retry_after = max(
                    retry_after,
                    self._capacity_retry_after(
                        self._recipient_events,
                        self._per_recipient_window_seconds,
                        now,
                    ),
                )

            if retry_after > 0:
                return OtpSmsReservationDenied(retry_after_seconds=max(1, math.ceil(retry_after)))

            token = OtpSmsReservationToken(self._new_unique_token_value())
            event = _Event(token_value=token.value, timestamp=now)
            if client_events is None:
                client_events = deque()
                self._client_events[normalized_client_id] = client_events
            if recipient_events is None:
                recipient_events = deque()
                self._recipient_events[normalized_recipient_id] = recipient_events

            client_events.append(event)
            recipient_events.append(event)
            self._global_events.append(event)
            self._reservations[token.value] = _Reservation(
                client_id=normalized_client_id,
                recipient_id=normalized_recipient_id,
                timestamp=now,
            )
            self._active_token_expiries[token.value] = now + max(
                self._per_client_window_seconds,
                self._per_recipient_window_seconds,
                self._global_window_seconds,
            )
            return OtpSmsReservationGranted(token=token)

    async def release(
        self,
        token: OtpSmsReservationToken,
        *,
        retain_client_attempt: bool = False,
    ) -> bool:
        """예약 한 건을 취소하며, 선택에 따라 접속자의 시도 횟수는 유지한다."""

        self._require_token(token)
        async with self._lock:
            self._cleanup(self._clock())
            reservation = self._reservations.pop(token.value, None)
            if reservation is None:
                return False

            self._remove_event(self._global_events, token.value)
            self._remove_from_bucket(self._recipient_events, reservation.recipient_id, token.value)
            if retain_client_attempt:
                client_events = self._client_events.get(reservation.client_id)
                client_event_remains = client_events is not None and any(
                    event.token_value == token.value for event in client_events
                )
                if client_event_remains:
                    self._active_token_expiries[token.value] = (
                        reservation.timestamp + self._per_client_window_seconds
                    )
                else:
                    self._active_token_expiries.pop(token.value, None)
            else:
                self._active_token_expiries.pop(token.value, None)
                self._remove_from_bucket(
                    self._client_events,
                    reservation.client_id,
                    token.value,
                )
            return True

    async def confirm(self, token: OtpSmsReservationToken) -> bool:
        """접수 확정 후 발송량 집계는 유지하고 예약 해제용 관리 정보만 버린다."""

        self._require_token(token)
        async with self._lock:
            self._cleanup(self._clock())
            return self._reservations.pop(token.value, None) is not None

    async def reset(self) -> None:
        """모든 발송량 집계와 예약 상태를 초기화한다."""

        async with self._lock:
            self._global_events.clear()
            self._client_events.clear()
            self._recipient_events.clear()
            self._reservations.clear()
            self._active_token_expiries.clear()

    def _cleanup(self, now: float) -> None:
        self._discard_expired_events(self._global_events, now, self._global_window_seconds)
        self._discard_expired_buckets(
            self._client_events,
            now,
            self._per_client_window_seconds,
        )
        self._discard_expired_buckets(
            self._recipient_events,
            now,
            self._per_recipient_window_seconds,
        )
        expired_tokens = [
            token_value
            for token_value, expires_at in self._active_token_expiries.items()
            if expires_at <= now
        ]
        for token_value in expired_tokens:
            del self._active_token_expiries[token_value]
            self._reservations.pop(token_value, None)

    @staticmethod
    def _discard_expired_buckets(
        buckets: dict[str, deque[_Event]],
        now: float,
        window_seconds: float,
    ) -> None:
        for identity, events in list(buckets.items()):
            OtpSmsRateLimiter._discard_expired_events(events, now, window_seconds)
            if not events:
                del buckets[identity]

    @staticmethod
    def _discard_expired_events(events: deque[_Event], now: float, window_seconds: float) -> None:
        threshold = now - window_seconds
        while events and events[0].timestamp <= threshold:
            events.popleft()

    @staticmethod
    def _quota_retry_after(
        events: deque[_Event] | None,
        limit: int,
        window_seconds: float,
        now: float,
    ) -> float:
        if events is None or len(events) < limit:
            return 0.0
        return events[0].timestamp + window_seconds - now

    @staticmethod
    def _capacity_retry_after(
        buckets: dict[str, deque[_Event]],
        window_seconds: float,
        now: float,
    ) -> float:
        return min(events[-1].timestamp + window_seconds for events in buckets.values()) - now

    def _new_unique_token_value(self) -> uuid.UUID:
        token_value = self._token_factory()
        while token_value in self._active_token_expiries:
            token_value = self._token_factory()
        return token_value

    @staticmethod
    def _remove_event(events: deque[_Event], token_value: uuid.UUID) -> None:
        for index, event in enumerate(events):
            if event.token_value == token_value:
                del events[index]
                return

    @staticmethod
    def _remove_from_bucket(
        buckets: dict[str, deque[_Event]],
        identity: str,
        token_value: uuid.UUID,
    ) -> None:
        events = buckets.get(identity)
        if events is None:
            return
        OtpSmsRateLimiter._remove_event(events, token_value)
        if not events:
            del buckets[identity]

    @staticmethod
    def _normalize_id(name: str, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()

    @staticmethod
    def _require_token(token: OtpSmsReservationToken) -> None:
        if not isinstance(token, OtpSmsReservationToken):
            raise TypeError("token must be an OtpSmsReservationToken")

    @staticmethod
    def _require_positive(name: str, value: int | float) -> None:
        if value <= 0:
            raise ValueError(f"{name} must be positive")
