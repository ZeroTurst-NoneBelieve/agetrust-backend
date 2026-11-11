"""DB errors must not print SQL parameters or provider error details."""

import base64
import io
import logging
import os
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes")
os.environ.setdefault("ISSUER_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())

from sqlalchemy.exc import StatementError  # noqa: E402
from app.core.logging import DatabaseErrorFilter, configure_logging  # noqa: E402
from app.database import engine  # noqa: E402
from app.api.v1.endpoints.auth import _invalidate_failed_sms_request  # noqa: E402


def database_error():
    return StatementError(
        "driver DETAIL phone=FAKE-PHONE", "UPDATE example SET otp=$1",
        {"otp": "FAKE-OTP", "password_hash": "FAKE-HASH", "api_key": "FAKE-KEY"},
        ValueError("driver FAKE-DETAIL"),
    )


def raise_database_error():
    raise database_error()  # FAKE-SOURCE-MUST-NOT-BE-LOGGED


class DatabaseLogPrivacyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.stream = io.StringIO()
        self.handler = logging.StreamHandler(self.stream)
        self.handler.addFilter(DatabaseErrorFilter())
        logging.getLogger().addHandler(self.handler)
        self.addCleanup(logging.getLogger().removeHandler, self.handler)

    def assert_private(self):
        output = self.stream.getvalue()
        self.assertNotIn("FAKE-", output)
        self.assertIn("StatementError", output)

    def test_engine_hides_parameters(self):
        self.assertTrue(engine.sync_engine.hide_parameters)

    async def test_sms_cleanup_failure_log_does_not_include_parameters(self):
        db = AsyncMock()
        db.execute.side_effect = database_error()
        await _invalidate_failed_sms_request(
            db, verification_id=uuid4(), prepared_digest="FAKE-OTP",
            prepared_last_sent_at=datetime.now(timezone.utc),
        )
        db.rollback.assert_awaited_once()
        self.assert_private()
        self.assertIn("in _invalidate_failed_sms_request", self.stream.getvalue())

    def test_exception_arguments_and_traceback_are_redacted(self):
        log = logging.getLogger("app.review")
        error = database_error()
        log.warning("DB update failed: %r", error)
        log.warning("DB update failed: %(error)s", {"error": error})
        try:
            raise error
        except StatementError:
            log.exception("DB update failed")
        self.assert_private()

    def test_exact_location_survives_without_source_or_locals(self):
        secret_local = "FAKE-LOCAL"
        expected_line = raise_database_error.__code__.co_firstlineno + 1
        try:
            raise_database_error()
        except StatementError:
            logging.getLogger("app.review").exception("DB update failed")
        output = self.stream.getvalue()
        self.assertNotIn(secret_local, output)
        self.assert_private()
        self.assertIn(
            f"File {__file__!r}, line {expected_line}, in raise_database_error", output,
        )

    def test_multiple_handlers_replace_cached_traceback_consistently(self):
        try:
            raise_database_error()
        except StatementError:
            record = logging.LogRecord("app.review", logging.ERROR, __file__, 1, "DB failed", (), sys.exc_info())
        formatter = logging.Formatter("%(message)s")
        formatter.format(record)  # Simulate a previous formatter's cached exception text.
        self.assertIn("FAKE-", record.exc_text)
        privacy_filter = DatabaseErrorFilter()
        privacy_filter.filter(record)
        first = formatter.format(record)
        privacy_filter.filter(record)
        self.assertEqual(first, formatter.format(record))
        self.assertNotIn("FAKE-", first)
        self.assertIn("in raise_database_error", first)

    def test_uvicorn_handler_redacts_wrapped_database_error(self):
        log = logging.getLogger("uvicorn.error")
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        log.addHandler(handler)
        self.addCleanup(log.removeHandler, handler)
        configure_logging("INFO")
        configure_logging("INFO")
        self.assertEqual(sum(isinstance(f, DatabaseErrorFilter) for f in handler.filters), 1)
        try:
            try:
                raise_database_error()
            except StatementError as error:
                raise RuntimeError("FAKE-WRAPPER") from error
        except RuntimeError:
            log.exception("Exception in ASGI application")
        self.assertNotIn("FAKE-", stream.getvalue())
        self.assertIn("RuntimeError", stream.getvalue())
        self.assertIn("in raise_database_error", stream.getvalue())

    def test_non_database_exception_keeps_diagnostics(self):
        try:
            raise ValueError("ordinary failure")
        except ValueError:
            logging.getLogger("app.review").exception("worker failed")
        self.assertIn("ValueError: ordinary failure", self.stream.getvalue())

    def test_exception_group_redacts_nested_database_error(self):
        try:
            try:
                raise_database_error()
            except StatementError as error:
                group = ExceptionGroup("FAKE-GROUP", [error])
            raise group
        except ExceptionGroup:
            logging.getLogger("app.review").exception("worker failed")
        self.assertNotIn("FAKE-", self.stream.getvalue())
        self.assertIn("ExceptionGroup", self.stream.getvalue())
        self.assertIn("in raise_database_error", self.stream.getvalue())
