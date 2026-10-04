import fcntl
import hashlib
import hmac
import logging
import os
import secrets
import tempfile
from datetime import datetime, timedelta

import bcrypt
import jwt
from jwt import InvalidTokenError as JWTError
from sqlalchemy.orm import Session

from models import User, UserSetting

logger = logging.getLogger(__name__)


def _default_secret_file() -> str:
    return os.getenv(
        "JWT_SECRET_FILE",
        os.path.join(os.getenv("DATA_DIR", "/app/data"), "auth", "jwt_secret.key"),
    )


def resolve_jwt_secret() -> str:
    """Resolve the JWT signing key.

    An explicitly configured JWT_SECRET_KEY wins. It is rejected when blank, because
    docker-compose passes it through as `${JWT_SECRET_KEY:-}` (present but empty) and
    `os.getenv(key, fallback)` only uses the fallback when the variable is *absent*, not
    when it is empty. That made the effective HMAC key the empty string on stock Compose
    installs, so anyone could forge a valid admin token. When no key is configured, a
    strong one is generated and persisted to a file so it survives restarts; if the file
    cannot be written, an ephemeral key is used (unforgeable, but sessions reset on
    restart) rather than falling back to a predictable value.
    """
    configured = os.getenv("JWT_SECRET_KEY")
    if configured and configured.strip():
        return configured

    if configured is not None and not configured.strip():
        logger.warning(
            "JWT_SECRET_KEY is set but empty; ignoring it. Set a non-empty value, or "
            "leave it unset to use a generated, persisted key."
        )

    secret_file = _default_secret_file()
    secret_dir = os.path.dirname(secret_file) or "."
    tmp_path = None
    try:
        os.makedirs(secret_dir, mode=0o700, exist_ok=True)

        # Multiple workers can start at the same time. Serialize the read/create path so
        # every worker uses the same key instead of racing through a shared fixed temp file.
        lock_path = f"{secret_file}.lock"
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)

            if os.path.exists(secret_file):
                with open(secret_file, "r", encoding="utf-8") as fh:
                    existing = fh.read().strip()
                if existing:
                    return existing

            new_secret = secrets.token_urlsafe(48)
            tmp_fd, tmp_path = tempfile.mkstemp(prefix=".jwt_secret.", dir=secret_dir)
            try:
                os.fchmod(tmp_fd, 0o600)
                with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
                    tmp_fd = None
                    fh.write(new_secret)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp_path, secret_file)
                tmp_path = None
            finally:
                if tmp_fd is not None:
                    os.close(tmp_fd)
                if tmp_path is not None:
                    try:
                        os.unlink(tmp_path)
                    except FileNotFoundError:
                        pass

            logger.info("Generated and persisted a JWT signing key at %s", secret_file)
            return new_secret
        finally:
            os.close(lock_fd)
    except OSError as exc:
        logger.warning(
            "Could not persist a JWT signing key (%s); using an ephemeral one. Set "
            "JWT_SECRET_KEY to a fixed value so sessions survive restarts.",
            exc,
        )
        return secrets.token_urlsafe(48)


SECRET_KEY = resolve_jwt_secret()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days


def secret_fingerprint(namespace: str, material: str) -> str:
    """Create a stable, non-reversible identifier using the resolved server secret."""
    scoped = f"{namespace}\0{material}".encode()
    return hmac.new(SECRET_KEY.encode(), scoped, hashlib.sha256).hexdigest()


MIN_PASSWORD_LENGTH = 8
# bcrypt only uses the first 72 bytes and bcrypt>=5 raises for longer input.
MAX_PASSWORD_BYTES = 72


class PasswordPolicyError(ValueError):
    """A new password does not meet the minimum requirements."""


def validate_new_password(password: str | None) -> str:
    if password is None or len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise PasswordPolicyError(f"Password must be at most {MAX_PASSWORD_BYTES} bytes")
    return password


def hash_password(password: str) -> str:
    encoded = password.encode("utf-8")
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise PasswordPolicyError(f"Password must be at most {MAX_PASSWORD_BYTES} bytes")
    return bcrypt.hashpw(encoded, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    encoded = (plain_password or "").encode("utf-8")
    if len(encoded) > MAX_PASSWORD_BYTES:
        # Never stored (hash_password refuses it), so it cannot match; bcrypt>=5
        # would raise instead of returning False.
        return False
    try:
        return bcrypt.checkpw(encoded, hashed_password.encode("utf-8"))
    except ValueError:
        return False


# Spend the same bcrypt work for unknown usernames so response timing does not
# reveal which accounts exist.
_DUMMY_PASSWORD_HASH = bcrypt.hashpw(b"pokecollector-timing-equalizer", bcrypt.gensalt()).decode("utf-8")


def burn_password_check(plain_password: str) -> None:
    verify_password(plain_password, _DUMMY_PASSWORD_HASH)


def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def bootstrap_admin(db: Session):
    """Create admin user on first run if no users exist."""
    if db.query(User).count() > 0:
        return

    username = os.getenv("ADMIN_USERNAME", "admin")
    password = os.getenv("ADMIN_PASSWORD") or secrets.token_urlsafe(20)
    log_credentials = os.getenv("ADMIN_BOOTSTRAP_LOG", "true").lower() != "false"

    admin = User(
        username=username,
        hashed_password=hash_password(password),
        role="admin",
        is_active=True,
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)

    # init_db() runs before the first administrator exists, so its legacy settings
    # migration cannot import GEMINI_API_KEY on a brand-new installation. Seed the
    # key when the administrator is actually created; later startups keep the
    # stored user setting unchanged.
    gemini_api_key = (os.getenv("GEMINI_API_KEY") or "").strip()
    if gemini_api_key:
        db.add(
            UserSetting(
                user_id=admin.id,
                key="gemini_api_key",
                value=gemini_api_key,
            )
        )
        db.commit()

    from sqlalchemy import text

    for table in ["collection", "wishlist", "binders", "product_purchases", "portfolio_snapshots"]:
        db.execute(text(f"UPDATE {table} SET user_id = :uid WHERE user_id IS NULL"), {"uid": admin.id})
    db.commit()

    if log_credentials:
        logger.info("Initial admin user created — username: %s", username)
        logger.info("Initial admin password: %s", password)  # nosec — intentional, user can set ADMIN_PASSWORD env var instead
    else:
        logger.info("Initial admin user created (credentials suppressed)")
