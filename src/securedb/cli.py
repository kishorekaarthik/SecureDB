"""Operator command-line interface (`securedb ...`)."""

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
import uvicorn

from securedb import __version__
from securedb.crypto.master_key import (
    MasterKeyError,
    init_file_master_key,
    init_keychain_master_key,
)

app = typer.Typer(no_args_is_help=True, help="SecureDB Vault operator CLI.")


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
