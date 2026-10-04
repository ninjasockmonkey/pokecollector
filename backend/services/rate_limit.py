"""Per-client request throttling for the HTTP API.

The limiter keys on ``request.client.host``. Behind the bundled nginx that is
the real client address only because uvicorn rewrites it from
``X-Forwarded-For`` for peers listed in ``FORWARDED_ALLOW_IPS``; see
docker-compose.yml and docs/DEPLOYMENT.md.

State is in-process memory: budgets are per worker and reset on restart. Run a
single uvicorn worker, or replace the storage with a shared backend (for example
``limits.storage.RedisStorage``) before scaling out.
"""

from __future__ import annotations

import os

from limits import parse
from limits.storage import MemoryStorage
from limits.strategies import MovingWindowRateLimiter
from starlette.requests import Request
from starlette.responses import JSONResponse

DEFAULT_RATE_LIMIT = os.environ.get("RATE_LIMIT_DEFAULT", "").strip() or "600/minute"
LOGIN_RATE_LIMIT = os.environ.get("RATE_LIMIT_LOGIN", "").strip() or "5/minute"
LOGIN_PATH = "/api/auth/login"

# Image routes are fetched by <img> tags (dozens per gallery view) and cached by
# the browser; counting them against the API budget only produces broken art.
EXEMPT_PREFIXES = ("/api/images/", "/api/pokedex/images/", "/api/health")


def client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


class ApiRateLimiter:
    def __init__(self, default_limit: str = DEFAULT_RATE_LIMIT, login_limit: str = LOGIN_RATE_LIMIT):
        self.default_limit = parse(default_limit)
        self.login_limit = parse(login_limit)
        self._storage = MemoryStorage()
        self._strategy = MovingWindowRateLimiter(self._storage)

    def reset(self) -> None:
        self._storage.reset()

    def check(self, request: Request) -> JSONResponse | None:
        """Record the request and return a 429 response when a budget is spent."""
        path = request.url.path
        if not path.startswith("/api/") or path.startswith(EXEMPT_PREFIXES):
            return None
        key = client_key(request)
        if path == LOGIN_PATH and request.method == "POST":
            if not self._strategy.hit(self.login_limit, "login", key):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many login attempts. Try again in 1 minute."},
                    headers={"Retry-After": "60"},
                )
        if not self._strategy.hit(self.default_limit, "api", key):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again shortly."},
                headers={"Retry-After": "60"},
            )
        return None
