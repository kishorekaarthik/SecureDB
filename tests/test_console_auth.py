import uuid
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

import pyotp
import pytest
from sqlalchemy import Engine, select, text

from securedb.audit.log import Actor, list_entries
from securedb.console import auth
from securedb.crypto.local import LocalKeyProvider
from securedb.crypto.rotation import reencrypt, rotate_dek
from securedb.crypto.tenant_keys import KeyRing
from securedb.db.models import ConsoleSession, ConsoleUser
from securedb.db.session import Database
from securedb.errors import Conflict
from securedb.tenants.service import create_tenant
from tests.helpers import set_tenant

TEST = Actor.system("test")
PASSWORD = "correct horse battery staple"


@dataclass
class World:
    db: Database
    keyring: KeyRing
    tenant: uuid.UUID
    user_id: uuid.UUID
    secret: str

    def code(self, offset: int = 0) -> str:
        import time

        return pyotp.TOTP(self.secret).at(int(time.time()) + offset * 30)


def _create(db: Database, keyring: KeyRing, tenant: uuid.UUID, email: str, role: str = "owner"):  # type: ignore[no-untyped-def]
    with db.tenant_session(tenant) as session:
        user_id, uri = auth.create_console_user(
            session, keyring, tenant, email, PASSWORD, role, actor=TEST
        )
    return user_id, parse_qs(urlparse(uri).query)["secret"][0]


@pytest.fixture
def world(db: Database, key_provider: LocalKeyProvider) -> World:
    keyring = KeyRing(key_provider)
    tenant = create_tenant(db, keyring, "acme", actor=TEST)
    user_id, secret = _create(db, keyring, tenant, "Admin@Example.com")
    return World(db, keyring, tenant, user_id, secret)


def _login(w: World, password: str = PASSWORD) -> auth.ConsoleUserInfo | None:
    return auth.check_password(w.db, "acme", "admin@example.com", password)


def _user(w: World) -> ConsoleUser:
    with w.db.tenant_session(w.tenant) as session:
        user = session.get(ConsoleUser, w.user_id)
        assert user is not None
        return user


# --- Users ---------------------------------------------------------------------


def test_user_is_stored_with_hashed_password_and_encrypted_totp_secret(world: World) -> None:
    user = _user(world)
    assert user.email == "admin@example.com"
    assert user.password_hash.startswith("$argon2id$")
    assert PASSWORD not in user.password_hash
    assert world.secret.encode() not in user.totp_secret_enc


@pytest.mark.parametrize(
    ("email", "password", "role", "match"),
    [
        ("not-an-email", PASSWORD, "owner", "e-mail"),
        ("a@b.co", "short", "owner", "at least 12"),
        ("a@b.co", PASSWORD, "root", "Role"),
    ],
)
def test_invalid_users_are_rejected(
    world: World, email: str, password: str, role: str, match: str
) -> None:
    with world.db.tenant_session(world.tenant) as session, pytest.raises(ValueError, match=match):
        auth.create_console_user(
            session, world.keyring, world.tenant, email, password, role, actor=TEST
        )


def test_duplicate_email_conflicts(world: World) -> None:
    with pytest.raises(Conflict):
        _create(world.db, world.keyring, world.tenant, "admin@example.com")


# --- Password step -------------------------------------------------------------


def test_correct_password_returns_the_user(world: World) -> None:
    info = _login(world)
    assert info is not None
    assert (info.id, info.tenant_id, info.role, info.is_owner) == (
        world.user_id, world.tenant, "owner", True,
    )  # fmt: skip


@pytest.mark.parametrize(
    ("tenant", "email", "password"),
    [
        ("acme", "admin@example.com", "wrong password here"),
        ("acme", "nobody@example.com", PASSWORD),
        ("no-such-tenant", "admin@example.com", PASSWORD),
    ],
)
def test_every_failure_looks_the_same(world: World, tenant: str, email: str, password: str) -> None:
    assert auth.check_password(world.db, tenant, email, password) is None


def test_five_failures_lock_the_account_even_for_the_right_password(world: World) -> None:
    for _ in range(5):
        assert _login(world, "wrong password here") is None
    assert _user(world).locked_until is not None
    assert _login(world) is None  # locked
    with world.db.tenant_session(world.tenant) as session:
        session.execute(text("UPDATE console_users SET locked_until = now() - interval '1 second'"))
    assert _login(world) is not None  # lock expired


def test_users_of_other_tenants_cannot_log_in_here(
    world: World, key_provider: LocalKeyProvider
) -> None:
    other = create_tenant(world.db, world.keyring, "globex", actor=TEST)
    _create(world.db, world.keyring, other, "boss@globex.com")
    assert auth.check_password(world.db, "acme", "boss@globex.com", PASSWORD) is None
    assert auth.check_password(world.db, "globex", "boss@globex.com", PASSWORD) is not None


# --- TOTP step -----------------------------------------------------------------


def test_valid_totp_code_is_accepted_once(world: World) -> None:
    info = _login(world)
    assert info is not None
    code = world.code()
    assert auth.check_totp(world.db, world.keyring, info, code) is True
    assert auth.check_totp(world.db, world.keyring, info, code) is False  # replay


@pytest.mark.parametrize("code", ["000000", "12345", "abcdef", "", "1234567"])
def test_bad_totp_codes_are_rejected(world: World, code: str) -> None:
    info = _login(world)
    assert info is not None
    if code == world.code():  # astronomically unlikely, but keep the test honest
        pytest.skip("random collision")
    assert auth.check_totp(world.db, world.keyring, info, code) is False


def test_totp_failures_count_towards_the_lockout(world: World) -> None:
    info = _login(world)
    assert info is not None
    for _ in range(5):
        auth.check_totp(world.db, world.keyring, info, "000000")
    assert auth.check_totp(world.db, world.keyring, info, world.code()) is False  # locked
    assert _login(world) is None


def test_logins_are_audited_without_personal_data(world: World) -> None:
    _login(world, "wrong password here")
    info = _login(world)
    assert info is not None
    auth.check_totp(world.db, world.keyring, info, world.code())
    with world.db.tenant_session(world.tenant) as session:
        entries = [
            e for e in list_entries(session, world.tenant, limit=200) if "console" in e.action
        ]
    assert [(e.action, e.outcome) for e in entries] == [
        ("console_user.create", {"user_id": str(world.user_id), "role": "owner"}),
        ("console.login_failed", {"reason": "password", "locked": False}),
        ("console.login", {}),
    ]
    assert all(e.actor_id in (str(world.user_id), "test") for e in entries)
    assert "admin@example.com" not in str([e.outcome for e in entries])


def test_totp_secret_survives_key_rotation(world: World) -> None:
    with world.db.tenant_session(world.tenant) as session:
        rotate_dek(session, world.keyring, world.tenant, actor=TEST)
    result = reencrypt(world.db, world.keyring, world.tenant, actor=TEST)
    assert result.retired_versions == [1]
    assert _user(world).totp_key_version == 2
    info = _login(world)
    assert info is not None
    assert auth.check_totp(world.db, world.keyring, info, world.code()) is True


# --- Sessions ------------------------------------------------------------------


def test_session_round_trip_stores_only_a_hash(world: World, owner_engine: Engine) -> None:
    info = _login(world)
    assert info is not None
    raw = auth.start_session(world.db, info, verified=True)
    loaded = auth.load_session(world.db, raw)
    assert loaded is not None and loaded.user == info and loaded.verified is True
    assert len(loaded.csrf_token) >= 32
    with owner_engine.begin() as conn:
        set_tenant(conn, world.tenant)
        stored = conn.execute(text("SELECT id_hash FROM console_sessions")).scalar_one()
    assert raw.encode() not in bytes(stored) and len(bytes(stored)) == 32


def test_unknown_session_is_rejected(world: World) -> None:
    assert auth.load_session(world.db, "not-a-session") is None


@pytest.mark.parametrize(
    "expire",
    [
        "UPDATE console_sessions SET last_seen_at = now() - interval '31 minutes'",
        "UPDATE console_sessions SET expires_at = now() - interval '1 second'",
    ],
)
def test_idle_and_absolute_expiry(world: World, owner_engine: Engine, expire: str) -> None:
    info = _login(world)
    assert info is not None
    raw = auth.start_session(world.db, info, verified=True)
    with owner_engine.begin() as conn:
        set_tenant(conn, world.tenant)
        conn.execute(text(expire))
    assert auth.load_session(world.db, raw) is None
    with world.db.tenant_session(world.tenant) as session:
        assert session.scalars(select(ConsoleSession)).all() == []  # removed


def test_logout_ends_the_session(world: World) -> None:
    info = _login(world)
    assert info is not None
    raw = auth.start_session(world.db, info, verified=True)
    loaded = auth.load_session(world.db, raw)
    assert loaded is not None
    auth.end_session(world.db, loaded)
    assert auth.load_session(world.db, raw) is None


def test_sessions_are_invisible_without_the_cookie_hash(world: World, app_engine: Engine) -> None:
    info = _login(world)
    assert info is not None
    auth.start_session(world.db, info, verified=True)
    with app_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM console_sessions")).scalar_one() == 0
        assert conn.execute(text("SELECT count(*) FROM console_users")).scalar_one() == 0
