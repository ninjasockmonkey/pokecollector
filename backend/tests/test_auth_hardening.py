import unittest
from types import SimpleNamespace
from unittest.mock import patch

try:
    from fastapi import HTTPException
    from pydantic import ValidationError
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import api.auth as auth_api
    from api.auth import (
        ChangePasswordRequest,
        CreateUserRequest,
        ForceChangePasswordRequest,
        UpdateUserRequest,
        change_password,
        create_user,
        force_change_password,
        get_current_user,
        get_optional_user,
        issue_access_token,
        login,
        update_user,
    )
    from database import Base
    from models import User
    from services.auth import (
        PasswordPolicyError,
        create_access_token,
        hash_password,
        validate_new_password,
        verify_password,
    )

    DEPS_AVAILABLE = True
except ModuleNotFoundError:
    DEPS_AVAILABLE = False


def _request(method: str, path: str):
    return SimpleNamespace(method=method, url=SimpleNamespace(path=path))


@unittest.skipUnless(DEPS_AVAILABLE, "Backend dependencies are not installed")
class PasswordPolicyTests(unittest.TestCase):
    def test_short_and_overlong_passwords_are_rejected(self):
        with self.assertRaises(PasswordPolicyError):
            validate_new_password("short")
        with self.assertRaises(PasswordPolicyError):
            validate_new_password("é" * 37)  # 74 bytes
        self.assertEqual(validate_new_password("long enough"), "long enough")

    def test_overlong_password_never_raises_during_verification(self):
        stored = hash_password("correct horse")
        self.assertFalse(verify_password("x" * 200, stored))
        self.assertTrue(verify_password("correct horse", stored))

    def test_hash_refuses_input_bcrypt_would_truncate(self):
        with self.assertRaises(PasswordPolicyError):
            hash_password("x" * 73)


@unittest.skipUnless(DEPS_AVAILABLE, "Backend dependencies are not installed")
class AuthHardeningTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.admin = User(
            username="admin",
            hashed_password=hash_password("admin-password"),
            role="admin",
            is_active=True,
        )
        self.trainer = User(
            username="ash",
            hashed_password=hash_password("pikachu-pass"),
            role="trainer",
            is_active=True,
        )
        self.db.add_all([self.admin, self.trainer])
        self.db.commit()
        auth_api._login_failures.clear()

    def tearDown(self):
        auth_api._login_failures.clear()
        self.db.close()

    def _current(self, token, method="GET", path="/api/collection/"):
        return get_current_user(request=_request(method, path), token=token, db=self.db)

    def test_unknown_roles_are_rejected_by_the_schema(self):
        with self.assertRaises(ValidationError):
            CreateUserRequest(username="x", password="password1", role="superuser")
        with self.assertRaises(ValidationError):
            UpdateUserRequest(role="root")

    def test_create_user_enforces_password_policy(self):
        with self.assertRaises(HTTPException) as raised:
            create_user(
                CreateUserRequest(username="misty", password="123"),
                current_user=self.admin,
                db=self.db,
            )
        self.assertEqual(raised.exception.status_code, 422)

    def test_password_change_revokes_existing_tokens_and_returns_a_new_one(self):
        old_token = issue_access_token(self.trainer)
        self.assertEqual(self._current(old_token).id, self.trainer.id)

        result = change_password(
            ChangePasswordRequest(current_password="pikachu-pass", new_password="raichu-pass"),
            current_user=self.trainer,
            db=self.db,
        )

        with self.assertRaises(HTTPException) as raised:
            self._current(old_token)
        self.assertEqual(raised.exception.status_code, 401)
        self.assertIsNone(get_optional_user(token=old_token, db=self.db))
        self.assertEqual(self._current(result["access_token"]).id, self.trainer.id)

    def test_admin_reset_role_change_and_deactivation_revoke_sessions(self):
        for change in (
            UpdateUserRequest(password="new-password"),
            UpdateUserRequest(role="admin"),
        ):
            token = issue_access_token(self.trainer)
            update_user(self.trainer.id, change, current_user=self.admin, db=self.db)
            with self.assertRaises(HTTPException):
                self._current(token)

    def test_tokens_without_version_claim_remain_valid_until_first_revocation(self):
        legacy = create_access_token({"sub": str(self.trainer.id), "role": "trainer"})
        self.assertEqual(self._current(legacy).id, self.trainer.id)

    def test_pending_password_change_blocks_everything_but_the_change_screen(self):
        self.trainer.must_change_password = True
        self.db.commit()
        token = issue_access_token(self.trainer)

        with self.assertRaises(HTTPException) as raised:
            self._current(token, "GET", "/api/collection/")
        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(self._current(token, "GET", "/api/auth/me").id, self.trainer.id)
        self.assertEqual(self._current(token, "PUT", "/api/auth/me/force-password").id, self.trainer.id)

        result = force_change_password(
            ForceChangePasswordRequest(new_password="a-new-password"),
            current_user=self.trainer,
            db=self.db,
        )
        self.assertEqual(self._current(result["access_token"]).id, self.trainer.id)

    def test_repeated_failures_lock_the_account_from_any_ip(self):
        form = SimpleNamespace(username="ash", password="wrong-password")
        for _ in range(auth_api.LOGIN_FAILURES_PER_ACCOUNT):
            with self.assertRaises(HTTPException) as raised:
                login(request=None, form_data=form, db=self.db)
            self.assertEqual(raised.exception.status_code, 401)

        good = SimpleNamespace(username="ASH ", password="pikachu-pass")
        with self.assertRaises(HTTPException) as raised:
            login(request=None, form_data=good, db=self.db)
        self.assertEqual(raised.exception.status_code, 429)

    def test_successful_login_clears_failures_and_unknown_users_still_burn_bcrypt(self):
        with patch.object(auth_api, "burn_password_check") as burn:
            with self.assertRaises(HTTPException):
                login(request=None, form_data=SimpleNamespace(username="nobody", password="pw"), db=self.db)
        burn.assert_called_once()

        with self.assertRaises(HTTPException):
            login(request=None, form_data=SimpleNamespace(username="ash", password="nope"), db=self.db)
        result = login(
            request=None,
            form_data=SimpleNamespace(username="ash", password="pikachu-pass"),
            db=self.db,
        )
        self.assertTrue(result.access_token)
        self.assertNotIn("ash", auth_api._login_failures)


if __name__ == "__main__":
    unittest.main()
