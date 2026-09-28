"""Per-tenant data keys (DEKs) and lookup keys, wrapped by the master key."""

import secrets
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from securedb.crypto import aead
from securedb.crypto.provider import KeyProvider
from securedb.db.models import Tenant, TenantKey
from securedb.errors import NotFound


@dataclass(frozen=True)
class DataKey:
    version: int
    key: bytes = field(repr=False)


def _dek_context(tenant_id: uuid.UUID, version: int) -> dict[str, str]:
    return {"purpose": "dek", "tenant_id": str(tenant_id), "version": str(version)}


def _lookup_context(tenant_id: uuid.UUID) -> dict[str, str]:
    return {"purpose": "lookup", "tenant_id": str(tenant_id)}


def _require_tenant_context(session: Session, tenant_id: uuid.UUID) -> None:
    """Refuse to hand out a tenant's keys outside that tenant's database context.

    Row-level security only guards database reads; this check also covers cache hits
    and the lookup key (stored on `tenants`, which has no RLS).
    """
    current = session.scalar(text("SELECT current_setting('app.tenant_id', true)"))
    if current != str(tenant_id):
        raise NotFound("Tenant key not found.")


class KeyRing:
    """Creates, unwraps and caches tenant keys.

    Every call must use Database.tenant_session(tenant_id) for the same tenant;
    any other context (none, or another tenant's) yields NotFound, cached or not.
    """

    def __init__(self, provider: KeyProvider) -> None:
        self._provider = provider
        self._deks: dict[tuple[uuid.UUID, int], bytes] = {}
        self._lookup_keys: dict[uuid.UUID, bytes] = {}

    def create_tenant_keys(self, session: Session, tenant_id: uuid.UUID) -> None:
        _require_tenant_context(session, tenant_id)
        tenant = session.get(Tenant, tenant_id)
        if tenant is None:
            raise NotFound("Tenant not found.")
        if tenant.wrapped_lookup_key is not None:
            raise ValueError("Tenant already has keys.")
        dek = secrets.token_bytes(aead.KEY_SIZE)
        lookup_key = secrets.token_bytes(aead.KEY_SIZE)
        session.add(
            TenantKey(
                tenant_id=tenant_id,
                version=1,
                wrapped_dek=self._provider.wrap(dek, _dek_context(tenant_id, 1)),
                provider=self._provider.name,
                provider_key_id=self._provider.key_id,
                status="active",
            )
        )
        tenant.wrapped_lookup_key = self._provider.wrap(lookup_key, _lookup_context(tenant_id))
        session.flush()

    def active_dek(self, session: Session, tenant_id: uuid.UUID) -> DataKey:
        _require_tenant_context(session, tenant_id)
        version = session.scalar(
            select(TenantKey.version).where(
                TenantKey.tenant_id == tenant_id, TenantKey.status == "active"
            )
        )
        if version is None:
            raise NotFound("No active data key for this tenant.")
        return DataKey(version=version, key=self.dek(session, tenant_id, version))

    def dek(self, session: Session, tenant_id: uuid.UUID, version: int) -> bytes:
        _require_tenant_context(session, tenant_id)
        cached = self._deks.get((tenant_id, version))
        if cached is not None:
            return cached
        row = session.get(TenantKey, (tenant_id, version))
        if row is None:
            raise NotFound("Data key not found.")
        key = self._provider.unwrap(row.wrapped_dek, _dek_context(tenant_id, version))
        self._deks[(tenant_id, version)] = key
        return key

    def lookup_key(self, session: Session, tenant_id: uuid.UUID) -> bytes:
        _require_tenant_context(session, tenant_id)
        cached = self._lookup_keys.get(tenant_id)
        if cached is not None:
            return cached
        wrapped = session.scalar(select(Tenant.wrapped_lookup_key).where(Tenant.id == tenant_id))
        if wrapped is None:
            raise NotFound("Tenant has no lookup key.")
        key = self._provider.unwrap(wrapped, _lookup_context(tenant_id))
        self._lookup_keys[tenant_id] = key
        return key
