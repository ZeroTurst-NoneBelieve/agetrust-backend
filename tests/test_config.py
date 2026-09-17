"""설정 로드 시 기본값으로 떨어진 항목이 눈에 보이는지 확인한다 (#37)."""

import logging
import os
import unittest
from unittest import mock

from app.config import Settings, log_defaulted_settings

REQUIRED = {
    "DATABASE_URL": "postgresql+asyncpg://u:p@localhost:5432/x",
    "SECRET_KEY": "test-secret-key-at-least-32-bytes",
    "ISSUER_PRIVATE_KEY": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
}


def _settings_with_env(extra: dict[str, str]) -> Settings:
    # 로컬 .env 파일의 영향을 받지 않도록 env_file을 끈다.
    with mock.patch.dict(os.environ, {**REQUIRED, **extra}, clear=True):
        return Settings(_env_file=None)


class DefaultedFieldsTest(unittest.TestCase):
    def test_env_provided_fields_are_not_reported(self):
        s = _settings_with_env({"DEV_MODE": "true", "KAFKA_AUDIT_TOPIC": "t"})

        missing = s.defaulted_fields()

        self.assertNotIn("DEV_MODE", missing)
        self.assertNotIn("KAFKA_AUDIT_TOPIC", missing)
        for name in REQUIRED:
            self.assertNotIn(name, missing)

    def test_fields_falling_back_to_default_are_reported(self):
        s = _settings_with_env({})

        missing = s.defaulted_fields()

        self.assertIn("DEV_MODE", missing)
        self.assertIn("PUBLIC_BASE_URL", missing)
        self.assertIn("KAFKA_PUBLISHER_ENABLED", missing)

    def test_warning_lists_defaulted_fields_in_one_line(self):
        s = _settings_with_env({"DEV_MODE": "true"})

        with self.assertLogs("app.config", level="WARNING") as cm:
            log_defaulted_settings(s)

        self.assertEqual(len(cm.records), 1)
        message = cm.records[0].getMessage()
        self.assertIn("PUBLIC_BASE_URL", message)
        self.assertNotIn("DEV_MODE", message)

    def test_no_warning_when_everything_is_provided(self):
        every = {name.upper(): "1" for name in Settings.model_fields}
        every.update(REQUIRED)
        every["DEV_MODE"] = "false"
        every["KAFKA_PUBLISHER_ENABLED"] = "false"
        s = _settings_with_env(every)

        logger = logging.getLogger("app.config")
        with mock.patch.object(logger, "warning") as warning:
            log_defaulted_settings(s)

        warning.assert_not_called()


if __name__ == "__main__":
    unittest.main()
