"""Console users, password + TOTP login, lockout and server-side sessions.

* Passwords are hashed with argon2id. Unknown tenants/users still run a hash, so timing
  does not reveal which accounts exist; every failure looks the same to the caller.
* Five failures (password or TOTP) lock the account for 15 minutes. Anyone who knows
  a tenant and e-mail can therefore keep that account locked; operators recover it
  with `securedb unlock-user`. Login attempts are also rate limited per client.
* TOTP secrets are encrypted with the tenant DEK; a code cannot be reused.
* Sessions: the cookie holds a random 256-bit value, the database only its SHA-256.
  8 hours absolute lifetime, 30 minutes idle timeout.
"""

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error, InvalidHashError
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from securedb.audit.log import Actor, append
from securedb.crypto.tenant_keys import KeyRing
from securedb.crypto.values import EncryptedValue, ValueCipher
from securedb.db.models import ConsoleSession, ConsoleUser, Tenant
from securedb.db.session import Database
from securedb.errors import Conflict, NotFound

MIN_PASSWORD_LENGTH = 12
MAX_FAILED_LOGINS = 5
LOCKOUT = timedelta(minutes=15)
SESSION_LIFETIME = timedelta(hours=8)
SESSION_IDLE_TIMEOUT = timedelta(minutes=30)
PENDING_LIFETIME = timedelta(minutes=5)  # between the password and TOTP steps
TOTP_ISSUER = "SecureDB Vault"
TOTP_FIELD = "console_totp"

_hasher = PasswordHasher()
_DUMMY_HASH = _hasher.hash("not a real password")


@dataclass(frozen=True)
class ConsoleUserInfo:
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    role: str

    @property
    def is_owner(self) -> bool:
        return self.role == "owner"

    @property
    def actor(self) -> Actor:
        return Actor.console_user(self.id)


@dataclass(frozen=True)
class SessionInfo:
    id_hash: bytes
    user: ConsoleUserInfo
    csrf_token: str
    verified: bool


def _info(user: ConsoleUser) -> ConsoleUserInfo:
    return ConsoleUserInfo(user.id, user.tenant_id, user.email, user.role)


def _totp_aad_token(user_id: uuid.UUID) -> str:
    return f"console_user:{user_id}"


def _now(session: Session) -> datetime:
    now: datetime = session.execute(select(func.now())).scalar_one()
    return now


# --- Users ---------------------------------------------------------------------


def create_console_user(
    session: Session,
    keyring: KeyRing,
    tenant_id: uuid.UUID,
    email: str,
    password: str,
    role: str,
    *,
    actor: Actor,
) -> tuple[uuid.UUID, str]:
    """Create a user. Returns (user_id, otpauth URI). The URI holds the TOTP secret and
    is only available here. Call in the tenant's session."""
    email = email.strip().lower()
    if "@" not in email or len(email) > 254:
        raise ValueError("Enter a valid e-mail address.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if role not in ("owner", "viewer"):
        raise ValueError("Role must be 'owner' or 'viewer'.")
    user_id = uuid.uuid4()
    secret = pyotp.random_base32()
    encrypted = ValueCipher(keyring).encrypt(
        session, tenant_id, _totp_aad_token(user_id), TOTP_FIELD, secret
    )
    session.add(
        ConsoleUser(
            id=user_id,
            tenant_id=tenant_id,
            email=email,
            password_hash=_hasher.hash(password),
            totp_secret_enc=encrypted.ciphertext,
            totp_nonce=encrypted.nonce,
            totp_key_version=encrypted.key_version,
            role=role,
        )
    )
    try:
        session.flush()
    except IntegrityError:
        raise Conflict("A console user with this e-mail already exists.") from None
    append(
        session,
        tenant_id,
        actor,
        "console_user.create",
        outcome={"user_id": str(user_id), "role": role},
    )
    uri: str = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=TOTP_ISSUER)
    return user_id, uri


def _fail(session: Session, user: ConsoleUser, reason: str) -> None:
    user.failed_logins += 1
    locked = user.failed_logins >= MAX_FAILED_LOGINS
    if locked:
        user.failed_logins = 0
        user.locked_until = _now(session) + LOCKOUT
    append(
        session,
        user.tenant_id,
        Actor.console_user(user.id),
        "console.login_failed",
        outcome={"reason": reason, "locked": locked},
    )


def _is_locked(session: Session, user: ConsoleUser) -> bool:
    return user.locked_until is not None and user.locked_until > _now(session)


def _password_ok(stored_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash, password)
    except (Argon2Error, InvalidHashError):
        return False


def check_password(
    db: Database, tenant_name: str, email: str, password: str
) -> ConsoleUserInfo | None:
    """First login step. None for every kind of failure (the caller cannot tell why).

    The (slow, memory-hungry) password hash runs with no database connection held, so a
    flood of login attempts cannot exhaust the connection pool.
    """
    with db.session() as session:
        tenant_id = session.scalar(select(Tenant.id).where(Tenant.name == tenant_name.strip()))
    stored: tuple[uuid.UUID, str] | None = None
    if tenant_id is not None:
        with db.tenant_session(tenant_id) as session:
            row = session.execute(
                select(ConsoleUser.id, ConsoleUser.password_hash).where(
                    ConsoleUser.email == email.strip().lower()
                )
            ).one_or_none()
            stored = (row.id, row.password_hash) if row else None
    correct = _password_ok(stored[1] if stored else _DUMMY_HASH, password)
    if tenant_id is None or stored is None:
        return None
    with db.tenant_session(tenant_id) as session:
        user = session.scalar(
            select(ConsoleUser).where(ConsoleUser.id == stored[0]).with_for_update()
        )
        if user is None or _is_locked(session, user):
            return None  # the lock itself was audited when it started
        if not correct:
            _fail(session, user, "password")
            return None
        return _info(user)


def unlock_console_user(
    session: Session, tenant_id: uuid.UUID, email: str, *, actor: Actor
) -> None:
    """Operator recovery for a locked-out user. Call in the tenant's session."""
    user = session.scalar(
        select(ConsoleUser).where(ConsoleUser.email == email.strip().lower()).with_for_update()
    )
    if user is None:
        raise NotFound("Console user not found.")
    user.failed_logins = 0
    user.locked_until = None
    append(session, tenant_id, actor, "console_user.unlock", outcome={"user_id": str(user.id)})


def _matching_step(secret: str, code: str, now: datetime) -> int | None:
    totp = pyotp.TOTP(secret)
    current = int(now.timestamp()) // totp.interval
    for step in (current - 1, current, current + 1):
        if hmac.compare_digest(totp.at(step * totp.interval), code):
            return step
    return None


def check_totp(db: Database, keyring: KeyRing, user: ConsoleUserInfo, code: str) -> bool:
    """Second login step. A code is accepted once; failures count towards the lockout."""
    code = code.strip().replace(" ", "")
    with db.tenant_session(user.tenant_id) as session:
        row = session.scalar(select(ConsoleUser).where(ConsoleUser.id == user.id).with_for_update())
        if row is None or _is_locked(session, row):
            return False
        secret = ValueCipher(keyring).decrypt(
            session,
            row.tenant_id,
            _totp_aad_token(row.id),
            TOTP_FIELD,
            EncryptedValue(row.totp_secret_enc, row.totp_nonce, row.totp_key_version),
        )
        step = (
            _matching_step(secret, code, _now(session))
            if len(code) == 6 and code.isascii() and code.isdigit()
            else None
        )
        if step is None or step <= (row.last_totp_step or 0):
            _fail(session, row, "totp")
            return False
        row.last_totp_step = step
        row.failed_logins = 0
        append(session, row.tenant_id, Actor.console_user(row.id), "console.login")
        return True


# --- Sessions ------------------------------------------------------------------


def _hash(raw: str) -> bytes:
    return hashlib.sha256(raw.encode("utf-8")).digest()


def start_session(db: Database, user: ConsoleUserInfo, *, verified: bool) -> str:
    """Create a session and return the cookie value (never stored)."""
    raw = secrets.token_urlsafe(32)
    lifetime = SESSION_LIFETIME if verified else PENDING_LIFETIME
    with db.tenant_session(user.tenant_id) as session:
        session.add(
            ConsoleSession(
                id_hash=_hash(raw),
                tenant_id=user.tenant_id,
                user_id=user.id,
                csrf_token=secrets.token_urlsafe(32),
                verified=verified,
                expires_at=_now(session) + lifetime,
            )
        )
    return raw


def load_session(db: Database, raw: str) -> SessionInfo | None:
    """Resolve a cookie value. Expired or unknown sessions give None (and are removed)."""
    id_hash = _hash(raw)
    with db.session() as session:
        # The session_lookup RLS policy exposes only the row with exactly this hash.
        session.execute(
            text("SELECT set_config('app.session_hash', :hash, true)"), {"hash": id_hash.hex()}
        )
        tenant_id = session.scalar(
            select(ConsoleSession.tenant_id).where(ConsoleSession.id_hash == id_hash)
        )
    if tenant_id is None:
        return None
    with db.tenant_session(tenant_id) as session:
        row = session.get(ConsoleSession, id_hash)
        if row is None:
            return None
        now = _now(session)
        if row.expires_at <= now or row.last_seen_at + SESSION_IDLE_TIMEOUT <= now:
            session.delete(row)
            return None
        user = session.get(ConsoleUser, row.user_id)
        if user is None:
            return None
        row.last_seen_at = now
        return SessionInfo(id_hash, _info(user), row.csrf_token, row.verified)


def end_session(db: Database, info: SessionInfo) -> None:
    with db.tenant_session(info.user.tenant_id) as session:
        session.execute(delete(ConsoleSession).where(ConsoleSession.id_hash == info.id_hash))
