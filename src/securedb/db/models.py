"""ORM models. Every schema change also needs an Alembic migration."""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, LargeBinary, Text, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=text("gen_random_uuid()")
    )
    name: Mapped[str] = mapped_column(Text, unique=True)
    wrapped_lookup_key: Mapped[bytes | None] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class TenantKey(Base):
    """A tenant's data-encryption key (DEK), wrapped by the master key. Versioned."""

    __tablename__ = "tenant_keys"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'retiring', 'retired')", name="ck_tenant_keys_status"
        ),
        Index(
            "uq_tenant_keys_one_active",
            "tenant_id",
            unique=True,
            postgresql_where=text("status = 'active'"),
        ),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), primary_key=True)
    version: Mapped[int] = mapped_column(primary_key=True, autoincrement=False)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary)
    provider: Mapped[str] = mapped_column(Text)
    provider_key_id: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
