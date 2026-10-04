import unittest
from unittest.mock import MagicMock, patch

try:
    from fastapi import HTTPException
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from api import settings as settings_api
    from database import Base
    from models import User, UserSetting

    DEPS_AVAILABLE = True
except ModuleNotFoundError:
    DEPS_AVAILABLE = False


@unittest.skipUnless(DEPS_AVAILABLE, "Backend dependencies are not installed")
class GenericSettingValidationTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.user = User(username="ash", hashed_password="x", role="trainer", is_active=True)
        self.db.add(self.user)
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_unknown_keys_are_rejected_on_both_endpoints(self):
        with self.assertRaises(HTTPException) as raised:
            settings_api.update_settings({"anything_goes": "x"}, db=self.db, current_user=self.user)
        self.assertEqual(raised.exception.status_code, 400)
        with self.assertRaises(HTTPException) as raised:
            settings_api.set_setting("anything_goes", {"value": "x"}, db=self.db, current_user=self.user)
        self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(self.db.query(UserSetting).count(), 0)

    def test_oversized_values_are_rejected(self):
        huge = "x" * (settings_api.MAX_SETTING_VALUE_LENGTH + 1)
        with self.assertRaises(HTTPException) as raised:
            settings_api.update_settings({"hidden_set_ids": huge}, db=self.db, current_user=self.user)
        self.assertEqual(raised.exception.status_code, 413)

    def test_known_per_user_keys_still_save(self):
        result = settings_api.update_settings({"currency": "USD"}, db=self.db, current_user=self.user)
        self.assertEqual(result["currency"], "USD")
        saved = settings_api.set_setting("price_alert_threshold", {"value": "15"}, db=self.db, current_user=self.user)
        self.assertEqual(saved["value"], "15")


@unittest.skipUnless(DEPS_AVAILABLE, "Backend dependencies are not installed")
class ExchangeRateCacheTests(unittest.TestCase):
    def setUp(self):
        settings_api._exchange_rate_cache.clear()

    def tearDown(self):
        settings_api._exchange_rate_cache.clear()

    def test_successful_rates_are_cached_but_fallbacks_are_not(self):
        response = MagicMock()
        response.json.return_value = {"rate": 1.1}
        with patch.object(settings_api, "parse_frankfurter_v2_rate", return_value=1.1), \
             patch.object(settings_api.httpx, "get", return_value=response) as get:
            first = settings_api.get_exchange_rate("EUR", "USD", _current_user=None)
            second = settings_api.get_exchange_rate("EUR", "USD", _current_user=None)
        self.assertEqual((first["rate"], second["rate"]), (1.1, 1.1))
        self.assertEqual(get.call_count, 1)

        with patch.object(settings_api.httpx, "get", side_effect=OSError("down")) as get:
            settings_api.get_exchange_rate("USD", "EUR", _current_user=None)
            settings_api.get_exchange_rate("USD", "EUR", _current_user=None)
        self.assertEqual(get.call_count, 2)


if __name__ == "__main__":
    unittest.main()
