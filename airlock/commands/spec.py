# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock spec list
airlock spec new
airlock spec lock
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from airlock.config import load_config
from airlock.core.spec_store import (
    SpecLockError,
    create_spec,
    lock_spec,
)


# ── Status styling ────────────────────────────────────────────────────────────

STATUS_STYLES: dict[str, tuple[str, str]] = {
    "DRAFT":  ("●", typer.colors.YELLOW),
    "LOCKED": ("●", typer.colors.GREEN),
}


def _style_status(status: str) -> str:
    dot, colour = STATUS_STYLES.get(status, ("●", typer.colors.BRIGHT_BLACK))
    return typer.style(f"{dot} {status}", fg=colour)


# ── spec list ─────────────────────────────────────────────────────────────────

def spec_list() -> None:
    """List all specs and their status."""
    config = load_config()
    root: Path = config["_project_root"]
    specs_dir = root / "specs"

    spec_dirs = sorted(
        [d for d in specs_dir.iterdir() if d.is_dir() and not d.name.startswith(".")],
        key=lambda d: d.name,
    )

    typer.echo("")
    typer.echo(
        typer.style("Airlock", fg=typer.colors.CYAN, bold=True)
        + "  —  Specs"
    )
    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))

    if not spec_dirs:
        typer.echo(
            f"  {typer.style('No specs yet.', fg=typer.colors.BRIGHT_BLACK)}"
            "  Run 'python -m airlock spec new' to create one."
        )
        typer.echo("")
        return

    for spec_dir in spec_dirs:
        meta_path = spec_dir / "spec_meta.json"
        if not meta_path.exists():
            typer.echo(
                f"  {spec_dir.name:<20} "
                + typer.style("missing spec_meta.json", fg=typer.colors.RED)
            )
            continue

        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            typer.echo(
                f"  {spec_dir.name:<20} "
                + typer.style("malformed spec_meta.json", fg=typer.colors.RED)
            )
            continue

        spec_id = meta.get("id", spec_dir.name)
        status = meta.get("status", "UNKNOWN")
        description = meta.get("description", "—")
        version = meta.get("version", "1")
        locked_at = meta.get("locked_at", "")
        spec_hash = meta.get("spec_hash", "")

        typer.echo(
            f"  {typer.style(spec_id, bold=True):<20} "
            + _style_status(status)
        )
        typer.echo(f"  {'':20} v{version}  {description}")
        if locked_at:
            typer.echo(
                f"  {'':20} locked {typer.style(locked_at[:10], fg=typer.colors.BRIGHT_BLACK)}"
            )
        if spec_hash:
            short_hash = spec_hash[7:19] if spec_hash.startswith("sha256:") else spec_hash[:12]
            typer.echo(
                f"  {'':20} hash   {typer.style(short_hash + '...', fg=typer.colors.BRIGHT_BLACK)}"
            )
        typer.echo("")

    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))
    typer.echo(f"  {len(spec_dirs)} spec(s) found")
    typer.echo("")


# ── spec new ──────────────────────────────────────────────────────────────────

def spec_new(description: str) -> None:
    """Create a new DRAFT spec."""
    config = load_config()
    root: Path = config["_project_root"]
    specs_dir = root / "specs"

    spec_id, spec_dir = create_spec(specs_dir, description)

    typer.echo("")
    typer.echo(
        typer.style("✓ Spec created: ", fg=typer.colors.GREEN, bold=True)
        + typer.style(spec_id, bold=True)
    )
    typer.echo(f"  Status       {_style_status('DRAFT')}")
    typer.echo(f"  Description  {description}")
    typer.echo(f"  Location     {spec_dir.relative_to(root)}")
    typer.echo("")
    typer.echo(
        f"  {typer.style('Next:', bold=True)} Edit "
        + typer.style(f"specs/{spec_id}/spec.md", fg=typer.colors.CYAN)
        + ", then run:"
    )
    typer.echo(
        f"    python -m airlock spec lock {spec_id}"
    )
    typer.echo("")


# ── spec lock ─────────────────────────────────────────────────────────────────

def spec_lock(spec_id: str) -> None:
    """Lock a DRAFT spec. Hashes and seals spec.md."""
    config = load_config()
    root: Path = config["_project_root"]
    specs_dir = root / "specs"

    try:
        spec_hash = lock_spec(specs_dir, spec_id)
    except SpecLockError as exc:
        typer.echo(typer.style(f"✗ {exc}", fg=typer.colors.RED))
        raise typer.Exit(1)

    short_hash = spec_hash[7:19] if spec_hash.startswith("sha256:") else spec_hash[:12]

    typer.echo("")
    typer.echo(
        typer.style("✓ Spec locked: ", fg=typer.colors.GREEN, bold=True)
        + typer.style(spec_id, bold=True)
    )
    typer.echo(f"  Status  {_style_status('LOCKED')}")
    typer.echo(
        f"  Hash    {typer.style(short_hash + '...', fg=typer.colors.BRIGHT_BLACK)}"
        f"  ({spec_hash})"
    )
    typer.echo("")
    typer.echo(
        f"  {typer.style('Note:', bold=True)} The spec is now sealed. "
        "Any modification will invalidate downstream candidates."
    )
    typer.echo("")
