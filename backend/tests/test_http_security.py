import unittest
from unittest.mock import patch

try:
    from fastapi.testclient import TestClient

    import main
    from services.rate_limit import ApiRateLimiter

    DEPS_AVAILABLE = True
except ModuleNotFoundError:
    DEPS_AVAILABLE = False


@unittest.skipUnless(DEPS_AVAILABLE, "FastAPI dependencies are not installed")
class CsrfHeaderTests(unittest.TestCase):
    def setUp(self):
        main.limiter.reset()
        # No context manager: the lifespan (database bootstrap) is not needed here.
        self.client = TestClient(main.app)

    def test_unsafe_request_without_credentials_or_header_is_rejected(self):
        for method in ("post", "put", "delete"):
            response = getattr(self.client, method)("/api/does-not-exist")
            self.assertEqual(response.status_code, 403, method)
            self.assertIn("X-Requested-With", response.json()["detail"])

    def test_cross_site_multipart_restore_is_rejected_before_auth(self):
        response = self.client.post(
            "/api/backup/restore",
            files={"file": ("backup.sql", b"\\! id\n", "application/sql")},
        )
        self.assertEqual(response.status_code, 403)

    def test_custom_header_passes_the_guard(self):
        response = self.client.post(
            "/api/does-not-exist",
            headers={"X-Requested-With": "pokecollector"},
        )
        self.assertEqual(response.status_code, 404)

    def test_bearer_token_clients_do_not_need_the_header(self):
        response = self.client.post(
            "/api/does-not-exist",
            headers={"Authorization": "Bearer anything"},
        )
        self.assertEqual(response.status_code, 404)

    def test_ambient_basic_auth_does_not_bypass_the_guard(self):
        response = self.client.post(
            "/api/does-not-exist",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        self.assertEqual(response.status_code, 403)

    def test_safe_methods_and_login_are_not_guarded(self):
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        # Missing form fields -> validation error, not the CSRF guard.
        self.assertEqual(self.client.post("/api/auth/login").status_code, 422)


@unittest.skipUnless(DEPS_AVAILABLE, "FastAPI dependencies are not installed")
class CorsSettingsTests(unittest.TestCase):
    def test_unset_means_same_origin_only(self):
        self.assertIsNone(main.cors_settings(None))
        self.assertIsNone(main.cors_settings(" , "))

    def test_wildcard_never_allows_credentials(self):
        settings = main.cors_settings("*")
        self.assertEqual(settings["allow_origins"], ["*"])
        self.assertFalse(settings["allow_credentials"])

    def test_explicit_origins_may_use_credentials(self):
        settings = main.cors_settings("https://a.example, https://b.example")
        self.assertEqual(settings["allow_origins"], ["https://a.example", "https://b.example"])
        self.assertTrue(settings["allow_credentials"])
        self.assertIn("X-Requested-With", settings["allow_headers"])

    def test_default_app_does_not_reflect_foreign_origins(self):
        client = TestClient(main.app)
        response = client.get(
            "/api/health",
            headers={"Origin": "https://evil.example", "Cookie": "proxy_session=1"},
        )
        self.assertNotIn("access-control-allow-origin", response.headers)


@unittest.skipUnless(DEPS_AVAILABLE, "FastAPI dependencies are not installed")
class RateLimitTests(unittest.TestCase):
    def setUp(self):
        main.limiter.reset()
        self.client = TestClient(main.app)

    def tearDown(self):
        main.limiter.reset()

    def test_default_budget_is_generous_enough_for_a_page_view(self):
        limit = main.DEFAULT_RATE_LIMIT.split("/", 1)[0]
        self.assertGreaterEqual(int(limit), 300)

    def test_every_api_path_is_limited(self):
        # Path-based on purpose: newer FastAPI wraps included routers, which made
        # route-discovery limiters (slowapi) silently skip every router route.
        limiter = ApiRateLimiter(default_limit="3/minute", login_limit="2/minute")
        with patch.object(main, "limiter", limiter):
            codes = [
                self.client.get("/api/collection/x/y/z/does-not-exist").status_code
                for _ in range(4)
            ]
        self.assertNotEqual(codes[2], 429)
        self.assertEqual(codes[3], 429)

    def test_image_and_health_routes_are_exempt(self):
        limiter = ApiRateLimiter(default_limit="1/minute", login_limit="1/minute")
        with patch.object(main, "limiter", limiter):
            for _ in range(3):
                self.assertEqual(self.client.get("/api/health").status_code, 200)
                self.assertNotEqual(
                    self.client.get("/api/images/card/x/bogus").status_code, 429
                )

    def test_login_budget_is_per_client(self):
        limiter = ApiRateLimiter(default_limit="100/minute", login_limit="2/minute")
        with patch.object(main, "limiter", limiter):
            codes = [self.client.post("/api/auth/login").status_code for _ in range(3)]
            self.assertEqual(codes, [422, 422, 429])
            other = TestClient(main.app, client=("203.0.113.9", 50000))
            self.assertEqual(other.post("/api/auth/login").status_code, 422)


if __name__ == "__main__":
    unittest.main()
