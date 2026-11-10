"""계정별 비밀번호 시도 제한기 단위 테스트 (#68)."""

import asyncio
import unittest

from app.core.password_attempt_limit import PasswordAttemptLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class PasswordAttemptLimiterTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.limiter = PasswordAttemptLimiter(limit=3, window_seconds=60, clock=self.clock)

    async def test_blocks_after_limit_until_window_passes(self):
        results = [await self.limiter.acquire("kiosk-a") for _ in range(3)]
        self.assertTrue(all(result.allowed for result in results))
        self.assertEqual([result.reached_limit for result in results], [False, False, True])

        self.clock.now += 10
        denied = await self.limiter.acquire("kiosk-a")
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.retry_after, 50)

        # 막혀 있는 동안의 시도는 세지 않아 기한이 늘어나지 않는다.
        self.clock.now += 49
        self.assertFalse((await self.limiter.acquire("kiosk-a")).allowed)
        self.clock.now += 1
        self.assertTrue((await self.limiter.acquire("kiosk-a")).allowed)

    async def test_sliding_window_frees_one_attempt_at_a_time(self):
        await self.limiter.acquire("kiosk-a")
        self.clock.now += 20
        await self.limiter.acquire("kiosk-a")
        await self.limiter.acquire("kiosk-a")

        self.clock.now += 40  # 첫 시도만 창을 벗어난다.
        self.assertTrue((await self.limiter.acquire("kiosk-a")).allowed)
        denied = await self.limiter.acquire("kiosk-a")
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.retry_after, 20)

    async def test_clear_forgets_attempts_and_accounts_are_separate(self):
        for _ in range(3):
            await self.limiter.acquire("kiosk-a")
        self.assertTrue((await self.limiter.acquire("kiosk-b")).allowed)
        self.assertFalse((await self.limiter.acquire("kiosk-a")).allowed)

        await self.limiter.clear("kiosk-a")
        self.assertTrue((await self.limiter.acquire("kiosk-a")).allowed)

    async def test_concurrent_attempts_cannot_exceed_limit(self):
        results = await asyncio.gather(*(self.limiter.acquire("kiosk-a") for _ in range(20)))
        self.assertEqual(sum(result.allowed for result in results), 3)

    async def test_capacity_preserves_locks_and_rejects_new_accounts(self):
        limiter = PasswordAttemptLimiter(limit=2, window_seconds=60, max_accounts=2, clock=self.clock)
        await limiter.acquire("locked")
        await limiter.acquire("locked")
        self.clock.now += 10
        await limiter.acquire("existing")
        for index in range(20):
            denied = await limiter.acquire(f"new-{index}")
            self.assertFalse(denied.allowed)
            self.assertEqual(denied.retry_after, 50)
        self.assertFalse((await limiter.acquire("locked")).allowed)
        self.assertTrue((await limiter.acquire("existing")).allowed)
        self.assertEqual(len(limiter._attempts), 2)

        self.clock.now += 50
        self.assertTrue((await limiter.acquire("new")).allowed)
        self.assertFalse((await limiter.acquire("existing")).allowed)
        self.assertEqual(len(limiter._attempts), 2)

    async def test_capacity_retry_waits_for_whole_record_to_expire(self):
        limiter = PasswordAttemptLimiter(limit=3, window_seconds=60, max_accounts=1, clock=self.clock)
        await limiter.acquire("existing")
        self.clock.now += 20
        await limiter.acquire("existing")
        self.clock.now += 40
        denied = await limiter.acquire("new")
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.retry_after, 20)
        self.clock.now += 20
        self.assertTrue((await limiter.acquire("new")).allowed)

    async def test_cancel_preserves_other_attempts_at_same_timestamp(self):
        first = await self.limiter.acquire("account")
        await self.limiter.acquire("account")
        await self.limiter.acquire("account")
        await self.limiter.cancel("account", first)
        await self.limiter.cancel("account", first)
        self.assertTrue((await self.limiter.acquire("account")).allowed)
        self.assertFalse((await self.limiter.acquire("account")).allowed)

    async def test_stale_cancel_does_not_remove_new_reservations(self):
        old = await self.limiter.acquire("account")
        await self.limiter.clear("account")
        for _ in range(3):
            await self.limiter.acquire("account")
        await self.limiter.cancel("account", old)
        self.assertFalse((await self.limiter.acquire("account")).allowed)

    def test_rejects_non_positive_settings(self):
        with self.assertRaises(ValueError):
            PasswordAttemptLimiter(limit=0, window_seconds=60)
        with self.assertRaises(ValueError):
            PasswordAttemptLimiter(limit=3, window_seconds=0)


if __name__ == "__main__":
    unittest.main()
