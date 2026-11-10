"""API keys: issue, authenticate, revoke.

Format: ``sdb_live_<prefix>_<secret>`` (12 + 32 base62 characters). The prefix finds the
row; only a SHA-256 hash of the secret is stored. Secrets are ~190 random bits, so a fast
hash is sufficient and keeps per-request authentication cheap (no argon2 DoS vector).
"""

import hashlib
import hmac
import re
import secrets
import string
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum

from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session

from securedb.db.models import ApiKey
from securedb.db.session import Database
from securedb.errors import NotFound, Unauthorized

PREFIX_LENGTH = 12
SECRET_LENGTH = 32
_ALPHABET = string.ascii_letters + string.digits
_KEY = re.compile(rf"sdb_live_([A-Za-z0-9]{{{PREFIX_LENGTH}}})_([A-Za-z0-9]{{{SECRET_LENGTH}}})")
_UNAUTHORIZED = "Invalid or missing API key."
_DUMMY_HASH = hashlib.sha256(b"no such key").digest()


class Scope(StrEnum):
    tokenize = "tokenize"
    detokenize = "detokenize"
    subjects_erase = "subjects:erase"
    subjects_export = "subjects:export"
    audit_read = "audit:read"


@dataclass(frozen=True)
class IssuedKey:
    id: uuid.UUID
    prefix: str
    plaintext: str = field(repr=False)


@dataclass(frozen=True)
class AuthenticatedKey:
    id: uuid.UUID
    tenant_id: uuid.UUID
    scopes: frozenset[str]

    def allows(self, scope: Scope) -> bool:
        return scope.value in self.scopes


def _random(length: int) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def _hash(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("ascii")).digest()


def issue_api_key(
    session: Session, tenant_id: uuid.UUID, name: str, scopes: Iterable[Scope]
) -> IssuedKey:
    """Create a key. Call in the tenant's session; the plaintext is returned only here."""
    prefix, secret = _random(PREFIX_LENGTH), _random(SECRET_LENGTH)
    key = ApiKey(
        tenant_id=tenant_id,
        prefix=prefix,
        secret_hash=_hash(secret),
        name=name,
        scopes=sorted({scope.value for scope in scopes}),
    )
    session.add(key)
    session.flush()
    return IssuedKey(id=key.id, prefix=prefix, plaintext=f"sdb_live_{prefix}_{secret}")


def authenticate(db: Database, authorization: str | None) -> AuthenticatedKey:
    """Resolve an ``Authorization: Bearer`` header. Every failure looks the same."""
    scheme, _, credential = (authorization or "").partition(" ")
    match = _KEY.fullmatch(credential.strip()) if scheme.lower() == "bearer" else None
    if match is None:
        raise Unauthorized(_UNAUTHORIZED)
    prefix, secret = match.groups()

    with db.session() as session:
        # The auth-lookup RLS policy exposes only the row with exactly this prefix.
        session.execute(
            text("SELECT set_config('app.api_key_prefix', :prefix, true)"), {"prefix": prefix}
        )
        row = session.execute(
            select(
                ApiKey.id, ApiKey.tenant_id, ApiKey.secret_hash, ApiKey.scopes, ApiKey.revoked_at
            ).where(ApiKey.prefix == prefix)
        ).one_or_none()

    expected = row.secret_hash if row is not None else _DUMMY_HASH
    if not hmac.compare_digest(expected, _hash(secret)) or row is None or row.revoked_at:
        raise Unauthorized(_UNAUTHORIZED)

    with db.tenant_session(row.tenant_id) as session:
        session.execute(update(ApiKey).where(ApiKey.id == row.id).values(last_used_at=func.now()))
    return AuthenticatedKey(id=row.id, tenant_id=row.tenant_id, scopes=frozenset(row.scopes))


def revoke_api_key(session: Session, key_id: uuid.UUID) -> None:
    """Revoke a key. Call in the owning tenant's session (others get NotFound)."""
    result = session.execute(
        update(ApiKey)
        .where(ApiKey.id == key_id, ApiKey.revoked_at.is_(None))
        .values(revoked_at=func.now())
    )
    if result.rowcount == 0:  # type: ignore[attr-defined]
        raise NotFound("API key not found.")
