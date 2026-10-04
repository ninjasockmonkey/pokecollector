import logging
import os
import threading
import time
from collections import deque
from typing import Literal

from fastapi import APIRouter, Body, Depends, HTTPException, Request

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt import InvalidTokenError as JWTError
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database import get_db, get_setting, save_setting
from models import User
from services.auth import (
    PasswordPolicyError,
    burn_password_check,
    create_access_token,
    decode_token,
    hash_password,
    validate_new_password,
    verify_password,
)

router = APIRouter()
logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


UserRole = Literal["admin", "trainer"]


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: UserRole = "trainer"
    avatar_id: int | None = None
    must_change_password: bool = False


class UpdateUserRequest(BaseModel):
    username: str | None = None
    password: str | None = None
    role: UserRole | None = None
    is_active: bool | None = None
    avatar_id: int | None = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class ForceChangePasswordRequest(BaseModel):
    new_password: str


def require_valid_password(password: str | None) -> str:
    try:
        return validate_new_password(password)
    except PasswordPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


def issue_access_token(user: User) -> str:
    return create_access_token({
        "sub": str(user.id),
        "role": user.role,
        "tv": int(user.token_version or 0),
    })


def revoke_sessions(user: User) -> None:
    """Invalidate every access token issued to this user so far."""
    user.token_version = int(user.token_version or 0) + 1


# Repeated failures against one account are throttled regardless of client IP,
# so rotating addresses (or sharing one behind a proxy) cannot be used to
# brute-force a single password. In-process, like the per-IP limiter.
LOGIN_FAILURES_PER_ACCOUNT = 10
LOGIN_FAILURE_WINDOW_SECONDS = 15 * 60
_login_failures: dict[str, deque] = {}
_login_failures_lock = threading.Lock()


def _account_key(username: str | None) -> str:
    return (username or "").strip().casefold()


def _recent_failures(key: str, now: float) -> deque:
    failures = _login_failures.setdefault(key, deque())
    while failures and now - failures[0] > LOGIN_FAILURE_WINDOW_SECONDS:
        failures.popleft()
    return failures


def _account_locked(username: str) -> bool:
    now = time.monotonic()
    with _login_failures_lock:
        return len(_recent_failures(_account_key(username), now)) >= LOGIN_FAILURES_PER_ACCOUNT


def _record_login_failure(username: str) -> None:
    now = time.monotonic()
    with _login_failures_lock:
        _recent_failures(_account_key(username), now).append(now)
        if len(_login_failures) > 10_000:
            for stale in [k for k, v in _login_failures.items() if not v or now - v[-1] > LOGIN_FAILURE_WINDOW_SECONDS]:
                _login_failures.pop(stale, None)


def _clear_login_failures(username: str) -> None:
    with _login_failures_lock:
        _login_failures.pop(_account_key(username), None)


# While a password change is pending, only what the forced-change screen needs
# is served: the account itself, the password endpoints, and reading settings
# (language/theme for the screen).
_PENDING_PASSWORD_CHANGE_ALLOWED = {
    ("GET", "/api/auth/me"),
    ("GET", "/api/auth/mode"),
    ("PUT", "/api/auth/me/force-password"),
    ("PUT", "/api/auth/me/password"),
    ("GET", "/api/settings/"),
    ("GET", "/api/settings/exchange-rate"),
}


def _enforce_password_change(user: User, request: Request | None) -> None:
    if request is None or not user.must_change_password:
        return
    if (request.method, request.url.path) in _PENDING_PASSWORD_CHANGE_ALLOWED:
        return
    raise HTTPException(status_code=403, detail="Password change required")


def validate_avatar_id(avatar_id: int | None):
    if avatar_id is not None and (avatar_id < 1 or avatar_id > 151):
        raise HTTPException(status_code=400, detail="avatar_id must be 1-151")


def field_was_set(model: BaseModel, field_name: str) -> bool:
    if hasattr(model, "model_fields_set"):
        return field_name in model.model_fields_set
    return field_name in model.__fields_set__


def active_admin_count(db: Session) -> int:
    return db.query(User).filter(User.role == "admin", User.is_active == True).count()


def ensure_keeps_active_admin(db: Session, user: User, data: UpdateUserRequest):
    next_role = data.role if data.role is not None else user.role
    next_is_active = data.is_active if data.is_active is not None else user.is_active
    removes_active_admin = user.role == "admin" and user.is_active and (
        next_role != "admin" or not next_is_active
    )
    if removes_active_admin and active_admin_count(db) <= 1:
        raise HTTPException(status_code=400, detail="At least one active admin account is required")


def _sync_public_handle_for_username(db: Session, user: User, username: str) -> None:
    from services import public_profile as pp

    if not user.is_profile_public:
        user.public_handle = None
        return
    try:
        pp.assign_public_handle(db, user, trainer_name=username)
    except pp.HandleConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    except pp.HandleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


def env_user_mode(*, warn_invalid: bool = False) -> str | None:
    """USER_MODE pins the mode from the environment, overriding the stored setting:
    'single' forces single-user (login screen off), 'multi' forces multi-user (login on).
    Unset, blank, or unrecognised means no override. It is the recovery hatch for an admin
    locked out of multi-user mode: set USER_MODE=single, restart, regain local access, reset
    the password, then remove it. Forcing single-user disables the login screen, so that
    direction is a local/LAN recovery tool, not something to leave set on a public install."""
    raw = os.getenv("USER_MODE", "").strip().lower().replace("-", "_")
    if raw in {"single", "single_user"}:
        return "single"
    if raw in {"multi", "multi_user"}:
        return "multi"
    if raw and warn_invalid:
        logger.warning("USER_MODE=%r is not 'single' or 'multi'; ignoring it.", os.getenv("USER_MODE"))
    return None


def mode_is_env_locked() -> bool:
    """True when USER_MODE pins the mode, so the in-app toggle cannot change it."""
    return env_user_mode() is not None


def multi_user_enabled(db: Session) -> bool:
    """True when the login screen is enforced. The USER_MODE env override wins; otherwise the
    stored setting, falling back to 'more than one user exists' when it has never been set."""
    override = env_user_mode()
    if override is not None:
        return override == "multi"
    multi = get_setting("multi_user_mode")
    if multi is None:
        multi = "true" if db.query(User).count() > 1 else "false"
    return str(multi).lower() == "true"


def get_current_user(
    request: Request = None,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    if not token:
        if not multi_user_enabled(db):
            admin = db.query(User).filter(User.role == "admin", User.is_active == True).first()
            if admin:
                return admin
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.id == int(user_id), User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    # Tokens issued before token versioning carry no "tv" claim and count as 0.
    if int(payload.get("tv", 0)) != int(user.token_version or 0):
        raise HTTPException(status_code=401, detail="Session expired")
    _enforce_password_change(user, request)
    return user


def get_optional_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Returns user if authenticated, None otherwise. For backward compat during transition."""
    if not token:
        return None
    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        if user_id is None:
            return None
    except JWTError:
        return None
    user = db.query(User).filter(User.id == int(user_id), User.is_active == True).first()
    if user is None or int(payload.get("tv", 0)) != int(user.token_version or 0):
        return None
    return user


@router.post("/login", response_model=TokenResponse)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    if _account_locked(form_data.username):
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts for this account. Try again later.",
        )
    user = db.query(User).filter(User.username == form_data.username, User.is_active == True).first()
    if not user:
        burn_password_check(form_data.password)
    if not user or not verify_password(form_data.password, user.hashed_password):
        _record_login_failure(form_data.username)
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    _clear_login_failures(form_data.username)
    token = issue_access_token(user)
    return TokenResponse(
        access_token=token,
        user={
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "avatar_id": user.avatar_id,
            "must_change_password": user.must_change_password,
        },
    )


@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role,
        "avatar_id": current_user.avatar_id,
        "must_change_password": current_user.must_change_password,
    }


@router.get("/mode")
def get_auth_mode(db: Session = Depends(get_db)):
    # `locked` tells the UI to disable the toggle: the mode is pinned by USER_MODE.
    return {"multi_user": multi_user_enabled(db), "locked": mode_is_env_locked()}


@router.put("/mode")
def set_auth_mode(
    enabled: bool = Body(..., embed=True),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    if mode_is_env_locked():
        raise HTTPException(
            status_code=409,
            detail="User mode is pinned by the USER_MODE environment variable and cannot be changed here",
        )
    save_setting("multi_user_mode", str(enabled).lower())
    return {"multi_user": enabled}


@router.get("/users")
def list_users(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    users = db.query(User).order_by(User.id.asc()).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "role": u.role,
            "is_active": u.is_active,
            "avatar_id": u.avatar_id,
            "created_at": str(u.created_at),
        }
        for u in users
    ]


@router.post("/users")
def create_user(
    data: CreateUserRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    validate_avatar_id(data.avatar_id)
    require_valid_password(data.password)
    existing = db.query(User).filter(User.username == data.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    user = User(
        username=data.username,
        hashed_password=hash_password(data.password),
        role=data.role,
        is_active=True,
        avatar_id=data.avatar_id,
        must_change_password=data.must_change_password,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "username": user.username, "role": user.role, "is_active": user.is_active, "avatar_id": user.avatar_id}


@router.put("/users/{user_id}")
def update_user(
    user_id: int,
    data: UpdateUserRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    if field_was_set(data, "avatar_id"):
        validate_avatar_id(data.avatar_id)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    ensure_keeps_active_admin(db, user, data)
    if data.username is not None:
        _sync_public_handle_for_username(db, user, data.username)
        user.username = data.username
    if data.password is not None:
        user.hashed_password = hash_password(require_valid_password(data.password))
        revoke_sessions(user)
    if data.role is not None:
        if data.role != user.role:
            revoke_sessions(user)
        user.role = data.role
    if data.is_active is not None:
        if not data.is_active and user.is_active:
            revoke_sessions(user)
        user.is_active = data.is_active
    if field_was_set(data, "avatar_id"):
        user.avatar_id = data.avatar_id
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Trainer name or public URL is already taken") from None
    return {"id": user.id, "username": user.username, "role": user.role, "is_active": user.is_active, "avatar_id": user.avatar_id}


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Delete all user-owned data first (foreign key constraints)
    from models import (
        Binder,
        BinderCard,
        Card,
        CollectionCardPhoto,
        CollectionItem,
        CustomCardMatch,
        ImageCache,
        PortfolioSnapshot,
        PriceHistory,
        ProductCard,
        ProductLedgerEntry,
        ProductPurchase,
        Trade,
        TradeItem,
        UserSetting,
        WishlistItem,
    )
    owned_custom_card_ids = [
        card_id for (card_id,) in db.query(Card.id).filter(
            Card.is_custom == True,
            Card.custom_owner_id == user_id,
        ).all()
    ]
    db.query(BinderCard).filter(
        BinderCard.binder_id.in_(db.query(Binder.id).filter(Binder.user_id == user_id))
    ).delete(synchronize_session=False)
    db.query(Binder).filter(Binder.user_id == user_id).delete()
    db.query(ProductLedgerEntry).filter(ProductLedgerEntry.user_id == user_id).delete()
    db.query(ProductCard).filter(ProductCard.user_id == user_id).delete()
    db.query(CollectionCardPhoto).filter(CollectionCardPhoto.user_id == user_id).delete()
    db.query(CollectionItem).filter(CollectionItem.user_id == user_id).delete()
    db.query(WishlistItem).filter(WishlistItem.user_id == user_id).delete()
    db.query(ProductPurchase).filter(ProductPurchase.user_id == user_id).delete()
    db.query(TradeItem).filter(TradeItem.user_id == user_id).delete(
        synchronize_session=False
    )
    db.query(Trade).filter(Trade.user_id == user_id).delete(
        synchronize_session=False
    )
    db.query(PortfolioSnapshot).filter(PortfolioSnapshot.user_id == user_id).delete()
    db.query(UserSetting).filter(UserSetting.user_id == user_id).delete()
    if owned_custom_card_ids:
        db.query(CustomCardMatch).filter(
            CustomCardMatch.custom_card_id.in_(owned_custom_card_ids)
        ).delete(synchronize_session=False)
        db.query(PriceHistory).filter(
            PriceHistory.card_id.in_(owned_custom_card_ids)
        ).delete(synchronize_session=False)
        db.query(TradeItem).filter(
            TradeItem.card_id.in_(owned_custom_card_ids)
        ).update({"card_id": None}, synchronize_session=False)
        for card_id in owned_custom_card_ids:
            db.query(ImageCache).filter(
                ImageCache.image_key.like(f"card:{card_id}:%")
            ).delete(synchronize_session=False)
        db.query(Card).filter(Card.id.in_(owned_custom_card_ids)).delete(
            synchronize_session=False
        )
    traces_revoked = False
    try:
        from services.scan_trace import revoke_user_traces

        revoke_user_traces(user_id)
        traces_revoked = True
    except OSError as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="User scanner diagnostics could not be deleted.",
        ) from exc
    db.delete(user)
    try:
        db.commit()
    except Exception:
        db.rollback()
        if traces_revoked:
            try:
                from services.scan_trace import clear_user_trace_revocation

                clear_user_trace_revocation(user_id)
            except OSError:
                logger.exception(
                    "Failed to clear scanner diagnostics revocation after user deletion rollback"
                )
        raise
    return {"message": "User deleted"}


@router.put("/me/password")
def change_password(
    data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(data.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    current_user.hashed_password = hash_password(require_valid_password(data.new_password))
    current_user.must_change_password = False
    revoke_sessions(current_user)
    db.commit()
    # Other sessions are signed out; hand this one a fresh token.
    return {"message": "Password changed", "access_token": issue_access_token(current_user)}


@router.put("/me/force-password")
def force_change_password(
    data: ForceChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not current_user.must_change_password:
        raise HTTPException(status_code=400, detail="Password change is not required")
    current_user.hashed_password = hash_password(require_valid_password(data.new_password))
    current_user.must_change_password = False
    revoke_sessions(current_user)
    db.commit()
    return {"message": "Password changed", "access_token": issue_access_token(current_user)}


@router.put("/me/avatar")
def change_avatar(data: dict, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    avatar_id = data.get("avatar_id")
    validate_avatar_id(avatar_id)
    current_user.avatar_id = avatar_id
    db.commit()
    return {"id": current_user.id, "username": current_user.username, "role": current_user.role, "avatar_id": current_user.avatar_id}


@router.put("/me/username")
def change_username(data: dict, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    new_username = (data.get("username") or "").strip()
    if not new_username or len(new_username) < 2:
        raise HTTPException(status_code=400, detail="Username must be at least 2 characters")
    if len(new_username) > 32:
        raise HTTPException(status_code=400, detail="Username must be at most 32 characters")
    existing = db.query(User).filter(User.username == new_username, User.id != current_user.id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Username already taken")
    _sync_public_handle_for_username(db, current_user, new_username)
    current_user.username = new_username
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Trainer name or public URL is already taken") from None
    return {"id": current_user.id, "username": current_user.username, "role": current_user.role, "avatar_id": current_user.avatar_id}
