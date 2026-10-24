# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""airlock audit verify [--reanchor]"""

from __future__ import annotations

from pathlib import Path

import typer

from airlock.config import load_config
from airlock.core import audit, signing


def audit_verify(reanchor: bool) -> None:
    config = load_config()
    root: Path = config["_project_root"]
    required = signing.signatures_required(config)
    status = audit.reanchor(root) if reanchor else audit.verify_chain(root, require_signatures=required)
    if reanchor and status.ok:
        status = audit.verify_chain(root, require_signatures=required)

    typer.echo("")
    typer.echo(typer.style("Airlock", fg=typer.colors.CYAN, bold=True) + "  —  Audit Log")
    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))
    typer.echo(f"  Chained entries   {status.entries}")
    typer.echo(f"  Signed entries    {status.signed_entries}")
    if status.legacy_entries:
        typer.echo(f"  Legacy entries    {status.legacy_entries}  (pre-v0.4, unchained — not verifiable)")
    typer.echo(f"  Head              seq {status.head_seq}  {status.head_hash[:23]}")
    typer.echo(f"  Anchored          {'yes' if status.anchored else 'no'}")
    typer.echo(f"  Signatures        {'required' if required else 'not required'}")
    typer.echo("")
    if status.ok:
        typer.echo(typer.style("✓ Audit chain intact", fg=typer.colors.GREEN, bold=True))
        typer.echo("")
        return
    typer.echo(typer.style("✗ Audit chain problems:", fg=typer.colors.RED, bold=True))
    for problem in status.problems:
        typer.echo(f"    • {problem}")
    typer.echo("")
    raise typer.Exit(1)
