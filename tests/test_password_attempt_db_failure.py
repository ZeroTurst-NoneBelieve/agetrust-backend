"""Infrastructure failures before password verification must not lock an account."""
import asyncio
import base64
import os
import unittest
from unittest.mock import AsyncMock, patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from sqlalchemy.exc import SQLAlchemyError  # noqa: E402
from app.api.v1.endpoints import auth  # noqa: E402
from app.core.password_attempt_limit import PasswordAttemptLimiter  # noqa: E402
from app.schemas.user import LoginRequest  # noqa: E402


class PasswordAttemptDatabaseFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_database_errors_and_cancellation_release_only_own_reservation(self):
        limiter = PasswordAttemptLimiter(limit=3, window_seconds=900)
        await limiter.acquire("review-user")  # An earlier real failure must survive.
        body = LoginRequest(login_id="review-user", password="valid-password-123")
        with patch.object(auth, "password_attempt_limiter", limiter):
            for error in [SQLAlchemyError("unavailable")] * 4 + [asyncio.CancelledError()]:
                db = AsyncMock()
                db.execute.side_effect = error
                with patch.object(auth, "verify_password_or_dummy") as verify:
                    with self.assertRaises(type(error)):
                        await auth.login(body, db)
                    verify.assert_not_called()
            self.assertTrue((await limiter.acquire("review-user")).allowed)
            self.assertTrue((await limiter.acquire("review-user")).allowed)
            self.assertFalse((await limiter.acquire("review-user")).allowed)
