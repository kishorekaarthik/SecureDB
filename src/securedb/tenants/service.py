"""Tenant lifecycle."""

import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from securedb.audit.log import Actor, append
from securedb.crypto.tenant_keys import KeyRing
from securedb.db.models import Tenant
from securedb.db.session import Database
from securedb.errors import Conflict, NotFound


def create_tenant(
    db: Database, keyring: KeyRing, name: str, actor: Actor | None = None
) -> uuid.UUID:
    """Create a tenant and its keys in one transaction (all or nothing)."""
    name = name.strip()
    if not name:
        raise ValueError("Tenant name must not be blank.")
    tenant_id = uuid.uuid4()
    try:
        with db.tenant_session(tenant_id) as session:
            session.add(Tenant(id=tenant_id, name=name))
            session.flush()
            keyring.create_tenant_keys(session, tenant_id)
            append(
                session,
                tenant_id,
                actor or Actor.system("cli"),
                "tenant.create",
                outcome={"name": name},
            )
    except IntegrityError:
        raise Conflict("A tenant with this name already exists.") from None
    return tenant_id


def find_tenant_id(db: Database, name: str) -> uuid.UUID:
    with db.session() as session:
        tenant_id = session.scalar(select(Tenant.id).where(Tenant.name == name.strip()))
    if tenant_id is None:
        raise NotFound("Tenant not found.")
    return tenant_id
