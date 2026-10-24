# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock dashboard

Starts the Airlock read-only dashboard server.
"""

from __future__ import annotations

from pathlib import Path

import typer

from airlock.config import load_config


def dashboard(
    host: str = "127.0.0.1",
    port: int = 7842,
) -> None:
    """Start the read-only dashboard server."""
    # Check both dependencies before importing anything
    missing = []
    try:
        import fastapi  # noqa: F401
    except ImportError:
        missing.append("fastapi")
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        missing.append("uvicorn")

    if missing:
        typer.echo(typer.style(
            f"✗ Dashboard requires: {', '.join(missing)}\n"
            "  Install with: pip install -e \".[dashboard]\"\n"
            "  Or:           pip install " + " ".join(missing),
            fg=typer.colors.RED,
        ))
        raise typer.Exit(1)

    import uvicorn
    config = load_config()
    root: Path = config["_project_root"]

    from airlock.dashboard.server import create_app
    app = create_app(root)

    typer.echo("")
    typer.echo(
        typer.style("Airlock", fg=typer.colors.CYAN, bold=True)
        + "  —  Dashboard"
    )
    typer.echo(f"  Project   {root.name}")
    typer.echo(f"  URL       " + typer.style(f"http://{host}:{port}", fg=typer.colors.CYAN))
    typer.echo(f"  Mode      read-only observability")
    typer.echo(f"  Data      {root}")
    typer.echo("")
    typer.echo("  Press Ctrl+C to stop.")
    typer.echo("")

    uvicorn.run(app, host=host, port=port, log_level="warning")
