"""Per-tenant data keys (DEKs) and lookup keys, wrapped by the master key."""

import secrets
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
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


class KeyRing:
    """Creates, unwraps and caches tenant keys.

    Pass a tenant-scoped session (Database.tenant_session): row-level security
    hides every other tenant's key rows, so a wrong context yields NotFound.
    """

    def __init__(self, provider: KeyProvider) -> None:
        self._provider = provider
        self._deks: dict[tuple[uuid.UUID, int], bytes] = {}
        self._lookup_keys: dict[uuid.UUID, bytes] = {}

    def create_tenant_keys(self, session: Session, tenant_id: uuid.UUID) -> None:
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
        version = session.scalar(
            select(TenantKey.version).where(
                TenantKey.tenant_id == tenant_id, TenantKey.status == "active"
            )
        )
        if version is None:
            raise NotFound("No active data key for this tenant.")
        return DataKey(version=version, key=self.dek(session, tenant_id, version))

    def dek(self, session: Session, tenant_id: uuid.UUID, version: int) -> bytes:
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
        cached = self._lookup_keys.get(tenant_id)
        if cached is not None:
            return cached
        wrapped = session.scalar(select(Tenant.wrapped_lookup_key).where(Tenant.id == tenant_id))
        if wrapped is None:
            raise NotFound("Tenant has no lookup key.")
        key = self._provider.unwrap(wrapped, _lookup_context(tenant_id))
        self._lookup_keys[tenant_id] = key
        return key
