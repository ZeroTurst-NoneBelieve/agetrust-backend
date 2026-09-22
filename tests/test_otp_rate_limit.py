"""Unit tests for live OTP SMS quota reservations."""

import asyncio
import unittest

from app.core.otp_rate_limit import (
    OtpSmsRateLimiter,
    OtpSmsReservationDenied,
    OtpSmsReservationGranted,
)


class MutableClock:
    def __init__(self, now: float = 0.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_limiter(clock: MutableClock, **overrides) -> OtpSmsRateLimiter:
    options = {
        "per_client_limit": 2,
        "per_client_window_seconds": 10,
        "per_recipient_limit": 2,
        "per_recipient_window_seconds": 20,
        "global_limit": 10,
        "global_window_seconds": 60,
        "clock": clock,
    }
    options.update(overrides)
    return OtpSmsRateLimiter(**options)


def granted(result) -> OtpSmsReservationGranted:
    if not isinstance(result, OtpSmsReservationGranted):
        raise AssertionError(f"expected grant, got {result!r}")
    return result


class OtpSmsRateLimiterTests(unittest.IsolatedAsyncioTestCase):
    async def test_client_quota_is_atomic_under_concurrency(self):
        limiter = make_limiter(MutableClock(), per_client_limit=1)

        results = await asyncio.gather(
            limiter.reserve("client-a", "phone-a"),
            limiter.reserve("client-a", "phone-b"),
        )

        self.assertEqual(sum(isinstance(result, OtpSmsReservationGranted) for result in results), 1)
        denial = next(result for result in results if isinstance(result, OtpSmsReservationDenied))
        self.assertEqual(denial.retry_after_seconds, 10)

    async def test_recipient_quota_applies_across_different_clients(self):
        clock = MutableClock()
        limiter = make_limiter(clock, per_recipient_limit=1)

        granted(await limiter.reserve("client-a", "same-phone"))
        result = await limiter.reserve("client-b", "same-phone")

        self.assertEqual(result, OtpSmsReservationDenied(retry_after_seconds=20))

    async def test_global_quota_applies_across_clients_and_recipients(self):
        clock = MutableClock()
        limiter = make_limiter(clock, global_limit=2)

        granted(await limiter.reserve("client-a", "phone-a"))
        clock.advance(0.1)
        granted(await limiter.reserve("client-b", "phone-b"))

        result = await limiter.reserve("client-c", "phone-c")
        self.assertEqual(result, OtpSmsReservationDenied(retry_after_seconds=60))

    async def test_release_restores_client_recipient_and_global_quotas(self):
        limiter = make_limiter(
            MutableClock(),
            per_client_limit=1,
            per_recipient_limit=1,
            global_limit=1,
        )
        first = granted(await limiter.reserve("client-a", "phone-a"))

        self.assertTrue(await limiter.release(first.token))
        granted(await limiter.reserve("client-a", "phone-a"))

    async def test_release_can_retain_only_the_client_attempt_quota(self):
        limiter = make_limiter(
            MutableClock(),
            per_client_limit=1,
            per_recipient_limit=1,
            global_limit=1,
        )
        first = granted(await limiter.reserve("client-a", "phone-a"))

        self.assertTrue(
            await limiter.release(first.token, retain_client_attempt=True)
        )
        self.assertEqual(
            await limiter.reserve("client-a", "phone-b"),
            OtpSmsReservationDenied(retry_after_seconds=10),
        )
        granted(await limiter.reserve("client-b", "phone-a"))

    async def test_release_removes_only_the_exact_concurrent_reservation(self):
        limiter = make_limiter(
            MutableClock(),
            per_client_limit=2,
            per_client_window_seconds=10,
            per_recipient_limit=2,
            per_recipient_window_seconds=10,
            global_limit=2,
            global_window_seconds=10,
        )
        first, second = await asyncio.gather(
            limiter.reserve("client-a", "phone-a"),
            limiter.reserve("client-a", "phone-a"),
        )
        first = granted(first)
        second = granted(second)

        release_results = await asyncio.gather(
            limiter.release(first.token),
            limiter.release(first.token),
        )
        self.assertCountEqual(release_results, [True, False])

        third = granted(await limiter.reserve("client-a", "phone-a"))
        self.assertEqual(
            await limiter.reserve("client-a", "phone-a"),
            OtpSmsReservationDenied(retry_after_seconds=10),
        )
        self.assertTrue(await limiter.release(second.token))
        self.assertTrue(await limiter.release(third.token))

    async def test_confirmation_keeps_quota_and_disables_release(self):
        limiter = make_limiter(MutableClock(), per_client_limit=1)
        reservation = granted(await limiter.reserve("client-a", "phone-a"))

        self.assertTrue(await limiter.confirm(reservation.token))
        self.assertFalse(await limiter.release(reservation.token))
        self.assertEqual(
            await limiter.reserve("client-a", "phone-b"),
            OtpSmsReservationDenied(retry_after_seconds=10),
        )

    async def test_expiry_clears_each_window_independently(self):
        clock = MutableClock()
        limiter = make_limiter(
            clock,
            per_client_limit=1,
            per_client_window_seconds=5,
            per_recipient_limit=1,
            per_recipient_window_seconds=7,
            global_limit=1,
            global_window_seconds=9,
        )
        granted(await limiter.reserve("client-a", "phone-a"))

        clock.advance(5)
        self.assertEqual(
            await limiter.reserve("client-a", "phone-b"),
            OtpSmsReservationDenied(retry_after_seconds=4),
        )
        clock.advance(2)
        self.assertEqual(
            await limiter.reserve("client-b", "phone-a"),
            OtpSmsReservationDenied(retry_after_seconds=2),
        )
        clock.advance(2)
        granted(await limiter.reserve("client-a", "phone-a"))

    async def test_active_identity_state_is_bounded_without_eviction(self):
        clock = MutableClock()
        limiter = make_limiter(clock, max_clients=1, max_recipients=1)
        granted(await limiter.reserve("client-a", "phone-a"))

        self.assertEqual(
            await limiter.reserve("client-b", "phone-b"),
            OtpSmsReservationDenied(retry_after_seconds=20),
        )
        clock.advance(20)
        # The longer global quota has room; identity state is now reusable.
        granted(await limiter.reserve("client-b", "phone-b"))


if __name__ == "__main__":
    unittest.main()
