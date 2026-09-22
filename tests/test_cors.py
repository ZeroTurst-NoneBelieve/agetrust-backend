"""브라우저 클라이언트가 인증 재시도 시간을 읽을 수 있는지 검증한다."""

import base64
import os
import unittest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

import httpx  # noqa: E402

from app.main import app  # noqa: E402


class CorsHeaderTests(unittest.IsolatedAsyncioTestCase):
    async def test_browser_can_read_retry_after_header(self):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as client:
            response = await client.get(
                "/health",
                headers={"Origin": "https://mobile.example"},
            )

        exposed = {
            header.strip().lower()
            for header in response.headers["access-control-expose-headers"].split(",")
        }
        self.assertIn("retry-after", exposed)


if __name__ == "__main__":
    unittest.main()
