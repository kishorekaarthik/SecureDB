"""ORM models. Every schema change also needs an Alembic migration."""

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY
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


class ApiKey(Base):
    """An API key. Only a SHA-256 hash of the secret part is stored."""

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=text("gen_random_uuid()")
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    prefix: Mapped[str] = mapped_column(Text, unique=True)
    secret_hash: Mapped[bytes] = mapped_column(LargeBinary)
    name: Mapped[str] = mapped_column(Text)
    scopes: Mapped[list[str]] = mapped_column(ARRAY(Text))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Policy(Base):
    """What one API key may do with one field type. No row means deny."""

    __tablename__ = "policies"
    __table_args__ = (
        UniqueConstraint("api_key_id", "field_type", "action", name="uq_policies_key_type_action"),
        CheckConstraint("action IN ('tokenize', 'detokenize')", name="ck_policies_action"),
        CheckConstraint("effect IN ('allow', 'mask')", name="ck_policies_effect"),
        CheckConstraint(
            "action = 'detokenize' OR effect = 'allow'", name="ck_policies_tokenize_allow"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=text("gen_random_uuid()")
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    api_key_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("api_keys.id"))
    field_type: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text)
    effect: Mapped[str] = mapped_column(Text)


class Token(Base):
    """A tokenized value: ciphertext plus the keyed lookup hash used for deduplication."""

    __tablename__ = "tokens"
    __table_args__ = (UniqueConstraint("tenant_id", "type", "lookup_hmac", name="uq_tokens_dedup"),)

    token: Mapped[str] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    type: Mapped[str] = mapped_column(Text)
    lookup_hmac: Mapped[bytes] = mapped_column(LargeBinary)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    key_version: Mapped[int] = mapped_column()
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class TokenSubject(Base):
    """Links a token to a data subject. One value (a shared phone number, a joint account)
    can belong to several subjects; erasure removes a token only with its last subject."""

    __tablename__ = "token_subjects"
    __table_args__ = (Index("ix_token_subjects_subject", "tenant_id", "subject_id"),)

    token: Mapped[str] = mapped_column(
        ForeignKey("tokens.token", ondelete="CASCADE"), primary_key=True
    )
    subject_id: Mapped[str] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
