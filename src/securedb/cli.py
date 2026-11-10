"""Operator command-line interface (`securedb ...`)."""

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
import uvicorn
from sqlalchemy import select

from securedb import __version__
from securedb.audit.log import Actor, verify
from securedb.config import get_settings
from securedb.crypto.master_key import (
    MasterKeyError,
    init_file_master_key,
    init_keychain_master_key,
    load_key_provider,
)
from securedb.crypto.provider import KeyProvider
from securedb.crypto.tenant_keys import KeyRing
from securedb.db.models import ApiKey
from securedb.db.session import Database
from securedb.errors import DomainError, KeyProviderLocked, NotFound
from securedb.policy.engine import Action, Effect, set_policy
from securedb.tenants.api_keys import Scope, issue_api_key, revoke_api_key
from securedb.tenants.service import create_tenant, find_tenant_id
from securedb.vault.fields import FieldType

app = typer.Typer(no_args_is_help=True, help="SecureDB Vault operator CLI.")

TenantOption = Annotated[str, typer.Option("--tenant", help="Tenant name.")]


def _open() -> tuple[Database, KeyProvider]:
    settings = get_settings()
    return Database(settings.database_url), load_key_provider(settings)


@contextmanager
def _operator_errors() -> Iterator[None]:
    """Print domain errors as one clean line and exit 1, instead of a traceback."""
    try:
        yield
    except (DomainError, ValueError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from None


def _with_database(action: Callable[[Database, KeyProvider], None]) -> None:
    db, provider = _open()
    try:
        with _operator_errors():
            action(db, provider)
    finally:
        db.dispose()


def _key_id(db: Database, tenant_id: uuid.UUID, prefix: str) -> uuid.UUID:
    with db.tenant_session(tenant_id) as session:
        key_id = session.scalar(select(ApiKey.id).where(ApiKey.prefix == prefix))
    if key_id is None:
        raise NotFound("API key not found.")
    return key_id


@app.command("create-tenant")
def create_tenant_command(name: Annotated[str, typer.Argument(help="Tenant name.")]) -> None:
    """Create a tenant and its encryption keys."""

    def run(db: Database, provider: KeyProvider) -> None:
        if not provider.is_unlocked():
            raise KeyProviderLocked(getattr(provider, "reason", "The vault is locked."))
        tenant_id = create_tenant(db, KeyRing(provider), name, actor=Actor.system("cli"))
        typer.echo(f"Created tenant {name} ({tenant_id}).")

    _with_database(run)


@app.command("create-api-key")
def create_api_key_command(
    tenant: TenantOption,
    name: Annotated[str, typer.Option(help="What this key is for, e.g. billing-service.")],
    scope: Annotated[list[Scope], typer.Option(help="Repeat for several scopes.")],
) -> None:
    """Issue an API key. The key is shown once; store it securely."""

    def run(db: Database, _provider: KeyProvider) -> None:
        tenant_id = find_tenant_id(db, tenant)
        with db.tenant_session(tenant_id) as session:
            issued = issue_api_key(session, tenant_id, name, scope, actor=Actor.system("cli"))
        typer.echo(f"API key (shown once): {issued.plaintext}")
        typer.echo(f"Prefix: {issued.prefix}")

    _with_database(run)


@app.command("revoke-api-key")
def revoke_api_key_command(
    tenant: TenantOption, prefix: Annotated[str, typer.Argument(help="The key's prefix.")]
) -> None:
    """Revoke an API key immediately."""

    def run(db: Database, _provider: KeyProvider) -> None:
        tenant_id = find_tenant_id(db, tenant)
        key_id = _key_id(db, tenant_id, prefix)
        with db.tenant_session(tenant_id) as session:
            revoke_api_key(session, key_id, actor=Actor.system("cli"))
        typer.echo(f"Revoked API key {prefix}.")

    _with_database(run)


@app.command("set-policy")
def set_policy_command(
    tenant: TenantOption,
    key: Annotated[str, typer.Option("--key", help="The API key's prefix.")],
    field_type: Annotated[FieldType, typer.Option("--type", help="Field type.")],
    action: Annotated[Action, typer.Option(help="tokenize or detokenize.")],
    effect: Annotated[Effect, typer.Option(help="allow, mask or deny (removes the policy).")],
) -> None:
    """Grant, change or remove what an API key may do with a field type."""

    def run(db: Database, _provider: KeyProvider) -> None:
        tenant_id = find_tenant_id(db, tenant)
        key_id = _key_id(db, tenant_id, key)
        with db.tenant_session(tenant_id) as session:
            set_policy(
                session, tenant_id, key_id, field_type, action, effect, actor=Actor.system("cli")
            )
        typer.echo(f"Policy set: {key} {action.value} {field_type.value} -> {effect.value}.")

    _with_database(run)


@app.command()
def version() -> None:
    """Print the installed version."""
    typer.echo(__version__)


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Interface to bind.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port to listen on.")] = 8000,
    reload: Annotated[bool, typer.Option(help="Auto-reload on code changes (dev).")] = False,
) -> None:
    """Run the API server."""
    uvicorn.run(
        "securedb.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
        log_config=None,
    )


class MasterKeyStore(StrEnum):
    keychain = "keychain"
    file = "file"


@app.command()
def init(
    store: Annotated[
        MasterKeyStore, typer.Option(help="Where to keep the master key.")
    ] = MasterKeyStore.keychain,
    key_file: Annotated[
        Path, typer.Option(help="Master key file (only with --store file).")
    ] = Path("securedb-master.key"),
) -> None:
    """Create the master key. Run once per installation."""
    try:
        if store is MasterKeyStore.keychain:
            key_id = init_keychain_master_key()
            typer.echo(f"Created master key {key_id} in the OS keychain.")
            return
        passphrase: str = typer.prompt(
            "Master key passphrase", hide_input=True, confirmation_prompt=True
        )
        key_id = init_file_master_key(key_file, passphrase)
        typer.echo(
            f"Created master key {key_id} in {key_file}. Set SECUREDB_MASTER_KEY_STORE=file "
            "and SECUREDB_MASTER_KEY_PASSPHRASE to unlock it at startup."
        )
    except MasterKeyError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from None


@app.command("verify-audit")
def verify_audit_command(
    tenant: TenantOption,
    anchor_seq: Annotated[
        int | None, typer.Option(min=1, help="Seq of a head you recorded earlier.")
    ] = None,
    anchor_hash: Annotated[
        str | None, typer.Option(help="The head_hash you recorded for --anchor-seq.")
    ] = None,
) -> None:
    """Recompute a tenant's audit hash chain. Exits 2 if it is broken.

    An anchor (seq + hash recorded outside the database) also detects truncation of the
    newest entries and a full rewrite by someone with the table-owner role.
    """
    if (anchor_seq is None) != (anchor_hash is None):
        typer.echo("Error: --anchor-seq and --anchor-hash must be given together.", err=True)
        raise typer.Exit(code=1)

    def run(db: Database, _provider: KeyProvider) -> None:
        tenant_id = find_tenant_id(db, tenant)
        with db.tenant_session(tenant_id) as session:
            result = verify(session, tenant_id, anchor_seq=anchor_seq, anchor_hash=anchor_hash)
        if result.ok:
            typer.echo(f"OK: {result.entries} entries, head {result.head_hash}")
            return
        typer.echo(
            f"BROKEN at seq {result.first_broken_seq} "
            f"(first {result.entries} entries intact, head {result.head_hash})",
            err=True,
        )
        raise typer.Exit(code=2)

    _with_database(run)
