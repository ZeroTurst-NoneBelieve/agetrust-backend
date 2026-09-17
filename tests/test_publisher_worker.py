"""#39 — Publisher 워커 진입점.

DB와 Kafka 없이 돈다. 루프 함수를 대역으로 바꿔 끼우고, 진입점이 지켜야 할
세 가지를 확인한다: 정지 신호를 루프에 전달하는지, 예외를 삼키지 않는지,
어떻게 끝나든 커넥션 풀을 닫는지.
"""

import asyncio
import base64
import os
import signal
import unittest
from unittest import mock

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from app.workers import publisher as worker  # noqa: E402


class PublisherWorkerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # AsyncEngine은 속성 패치가 안 되므로 모듈이 참조하는 engine 자체를 바꿔 끼운다.
        fake_engine = mock.Mock()
        fake_engine.dispose = mock.AsyncMock()
        self.dispose = fake_engine.dispose
        self._engine_patch = mock.patch.object(worker, "engine", fake_engine)
        self._engine_patch.start()

    async def asyncTearDown(self):
        self._engine_patch.stop()

    async def test_loop_gets_session_factory_and_stop_event(self):
        seen = {}

        async def fake_loop(session_factory, stop_event):
            seen["session_factory"] = session_factory
            seen["stop_event"] = stop_event

        with mock.patch.object(worker, "run_publisher_loop", fake_loop):
            await worker.main()

        self.assertIs(seen["session_factory"], worker.AsyncSessionLocal)
        self.assertIsInstance(seen["stop_event"], asyncio.Event)
        self.dispose.assert_awaited_once()

    async def test_exception_is_not_swallowed(self):
        """여기서 잡아 버리면 다시 '죽었는데 살아 있는 척'이 된다."""

        async def crashing_loop(session_factory, stop_event):
            raise RuntimeError("No module named 'aiokafka'")

        with mock.patch.object(worker, "run_publisher_loop", crashing_loop):
            with self.assertRaises(RuntimeError):
                await worker.main()

        self.dispose.assert_awaited_once()

    async def test_sigterm_stops_the_loop(self):
        """docker stop이 보내는 SIGTERM에 진행 중인 배치를 마치고 나가야 한다."""

        async def loop_until_stopped(session_factory, stop_event):
            await stop_event.wait()

        with mock.patch.object(worker, "run_publisher_loop", loop_until_stopped):
            task = asyncio.create_task(worker.main())
            await asyncio.sleep(0.05)  # 시그널 핸들러가 설치될 시간
            self.assertFalse(task.done(), "정지 신호 전에 끝났다")

            signal.raise_signal(signal.SIGTERM)
            await asyncio.wait_for(task, timeout=2)

        self.dispose.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
