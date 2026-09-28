"""Operator command-line interface (`securedb ...`)."""

from typing import Annotated

import typer
import uvicorn

from securedb import __version__

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
