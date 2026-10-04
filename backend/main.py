from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import os
import time
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

from services.rate_limit import DEFAULT_RATE_LIMIT, ApiRateLimiter

# Per-client budgets: a generous default for every API route (images exempt) and
# a strict one for login attempts. See services/rate_limit.py.
limiter = ApiRateLimiter()

# Unsafe methods that carry no Authorization header rely on ambient credentials:
# single-user mode (no login at all) or cookies set by an authenticating reverse
# proxy. A cross-site page can send such requests without a CORS preflight when
# they use a "simple" content type (form, multipart, text/plain), which would let
# any website the user visits drive the API, including database restore. Requiring
# a custom header forces a preflight, which the browser only passes for allowed
# origins. Bearer-token clients are unaffected. Only *Bearer* tokens count as
# explicit credentials: browsers attach HTTP Basic credentials (for example from
# a reverse proxy) to cross-site requests automatically.
CSRF_HEADER = "x-requested-with"
CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
CSRF_EXEMPT_PATHS = {"/api/auth/login"}


def cors_settings(raw: str | None) -> dict | None:
    """Translate CORS_ORIGINS into CORSMiddleware options, or None for same-origin only.

    The bundled nginx serves the SPA and the API from one origin, so no CORS
    headers are needed by default. Explicit origins may send credentials; a
    wildcard never may, because Starlette would then reflect any Origin.
    """
    origins = [origin.strip() for origin in (raw or "").split(",") if origin.strip()]
    if not origins:
        return None
    allow_all = "*" in origins
    return {
        "allow_origins": ["*"] if allow_all else origins,
        "allow_credentials": not allow_all,
        "allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Authorization", "Content-Type", "X-Requested-With"],
    }


def read_app_version() -> str:
    """Read the release version from the repository VERSION file."""
    env_version = os.environ.get("APP_VERSION")
    if env_version:
        return env_version

    for candidate in (
        Path(__file__).resolve().parent.parent / "VERSION",
        Path(__file__).resolve().parent / "VERSION",
        Path("/app/VERSION"),
    ):
        try:
            version = candidate.read_text(encoding="utf-8").strip()
            if version:
                return version
        except OSError:
            continue
    return "0.0.0"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Pokemon TCG Collection API...")
    from api.auth import env_user_mode
    _forced_mode = env_user_mode(warn_invalid=True)
    if _forced_mode == "single":
        logger.warning(
            "USER_MODE=single: single-user mode is forced and the login screen is disabled "
            "regardless of the stored setting. This is a local recovery hatch - unset it once "
            "you have regained access, and do not leave it set on a public install."
        )
    elif _forced_mode == "multi":
        logger.info("USER_MODE=multi: multi-user mode is forced; the in-app toggle is disabled.")
    current_version = read_app_version()
    from database import DATABASE_URL, SessionLocal, engine, init_db
    from services.auth import bootstrap_admin
    from services.pre_upgrade_backup import maybe_create_pre_upgrade_backup, record_successful_app_version
    maybe_create_pre_upgrade_backup(engine, DATABASE_URL, current_version)
    init_db()
    logger.info("Database initialized")

    db = SessionLocal()
    try:
        bootstrap_admin(db)
        from services.public_profile import migrate_public_profile_handles
        public_handle_migration = migrate_public_profile_handles(db)
        if public_handle_migration["migrated"] or public_handle_migration["disabled"]:
            logger.info(
                "Public trainer-name URL migration updated %s profiles and disabled %s invalid/conflicting profiles",
                public_handle_migration["migrated"],
                public_handle_migration["disabled"],
            )
        from models import Setting
        from services.debug_logging import configure_debug_logging
        debug_setting = db.query(Setting).filter(Setting.key == "debug_mode").first()
        configure_debug_logging(debug_setting is not None and debug_setting.value == "true")
        record_successful_app_version(engine, current_version)
    finally:
        db.close()

    from services.scheduler import start_scheduler
    start_scheduler()

    yield

    # Shutdown
    from services.scheduler import stop_scheduler
    stop_scheduler()
    logger.info("Shutdown complete")


app = FastAPI(
    title="Pokemon TCG Collection API",
    version=read_app_version(),
    description="Complete Pokemon TCG collection management system",
    lifespan=lifespan,
)


@app.middleware("http")
async def require_csrf_header(request: Request, call_next):
    if (
        request.method not in CSRF_SAFE_METHODS
        and request.url.path.startswith("/api/")
        and request.url.path not in CSRF_EXEMPT_PATHS
        and not request.headers.get("authorization", "").lower().startswith("bearer ")
        and CSRF_HEADER not in request.headers
    ):
        return JSONResponse(
            status_code=403,
            content={"detail": "Missing X-Requested-With header"},
        )
    return await call_next(request)


@app.middleware("http")
async def prevent_failed_public_response_caching(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/public") and response.status_code >= 400:
        response.headers["Cache-Control"] = "no-store"
    return response


_cors = cors_settings(os.environ.get("CORS_ORIGINS"))
if _cors is not None:
    app.add_middleware(CORSMiddleware, **_cors)



@app.middleware("http")
async def debug_request_logging(request: Request, call_next):
    from services.debug_logging import is_debug_logging_enabled

    if not is_debug_logging_enabled():
        return await call_next(request)

    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.url.path)
        raise

    duration_ms = (time.perf_counter() - started) * 1000
    logger.debug(
        "Request: %s %s -> %s %.1fms",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response

# Include routers
from api import auth, cards, collection, sets, wishlist, binders, decks, dashboard, analytics, sync, products, trades, export, backup, settings, images, social, pokedex, public, profile, scan_jobs, community
from api.github import router as github_router
from api.recognize import router as recognize_router

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])

@app.middleware("http")
async def rate_limit(request: Request, call_next):
    limited = limiter.check(request)
    if limited is not None:
        return limited
    return await call_next(request)


app.include_router(cards.router, prefix="/api/cards", tags=["cards"])
app.include_router(recognize_router, prefix="/api/cards", tags=["recognize"])
app.include_router(scan_jobs.router, prefix="/api/cards", tags=["scan-jobs"])
app.include_router(collection.router, prefix="/api/collection", tags=["collection"])
app.include_router(sets.router, prefix="/api/sets", tags=["sets"])
app.include_router(wishlist.router, prefix="/api/wishlist", tags=["wishlist"])
app.include_router(binders.router, prefix="/api/binders", tags=["binders"])
app.include_router(decks.router, prefix="/api/decks", tags=["decks"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(analytics.router, prefix="/api/analytics", tags=["analytics"])
app.include_router(sync.router, prefix="/api/sync", tags=["sync"])
app.include_router(products.router, prefix="/api/products", tags=["products"])
app.include_router(trades.router, prefix="/api/trades", tags=["trades"])
app.include_router(export.router, prefix="/api/export", tags=["export"])
app.include_router(backup.router, prefix="/api/backup", tags=["backup"])
app.include_router(settings.router, prefix="/api/settings", tags=["settings"])
app.include_router(images.router, prefix="/api/images", tags=["images"])
app.include_router(social.router, prefix="/api/social", tags=["social"])
app.include_router(pokedex.router, prefix="/api/pokedex", tags=["pokedex"])
app.include_router(public.router, prefix="/api/public", tags=["public"])
app.include_router(profile.router, prefix="/api/profile", tags=["profile"])
app.include_router(github_router, prefix="/api/github", tags=["github"])
app.include_router(community.router, prefix="/api/community", tags=["community"])


@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "pokemon-tcg-collection"}
