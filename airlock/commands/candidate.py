# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock candidate register   Register a new quarantined candidate
airlock candidate list       List all candidates and their status
airlock candidate hash       Compute and record the source hash for a candidate
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from airlock.config import load_config
from airlock.core.candidate_store import (
    CandidateError,
    compute_source_hash,
    list_candidates,
    read_manifest,
    register_candidate,
)


STATUS_COLOURS: dict[str, str] = {
    "quarantined": typer.colors.YELLOW,
    "verified":    typer.colors.CYAN,
    "certified":   typer.colors.BLUE,
    "admitted":    typer.colors.GREEN,
    "rejected":    typer.colors.RED,
}


def _style_status(status: str) -> str:
    colour = STATUS_COLOURS.get(status, typer.colors.WHITE)
    return typer.style(f"● {status}", fg=colour)


# ── candidate register ────────────────────────────────────────────────────────

def candidate_register(
    spec_id: str,
    description: str = "",
    language: str = "python",
    generated_by: str = "manual",
) -> None:
    """Register a new quarantined candidate linked to a spec."""
    config = load_config()
    root: Path = config["_project_root"]
    candidates_dir = root / "candidates"

    # Verify the spec exists and is locked
    spec_dir = root / "specs" / spec_id
    if not spec_dir.exists():
        typer.echo(typer.style(f"✗ Spec not found: {spec_id}", fg=typer.colors.RED))
        raise typer.Exit(1)

    meta_path = spec_dir / "spec_meta.json"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if meta.get("status") != "LOCKED":
                typer.echo(
                    typer.style("✗ ", fg=typer.colors.RED)
                    + f"Spec {spec_id} is not locked. "
                    "Lock the spec before registering a candidate."
                )
                raise typer.Exit(1)
        except json.JSONDecodeError:
            pass

    candidate_id, candidate_dir = register_candidate(
        candidates_dir,
        spec_id=spec_id,
        language=language,
        generated_by=generated_by,
        description=description,
    )

    typer.echo("")
    typer.echo(
        typer.style("✓ Candidate registered: ", fg=typer.colors.GREEN, bold=True)
        + typer.style(candidate_id, bold=True)
    )
    typer.echo(f"  Status      {_style_status('quarantined')}")
    typer.echo(f"  Spec        {spec_id}")
    typer.echo(f"  Language    {language}")
    typer.echo(f"  Location    {candidate_dir.relative_to(root)}")
    typer.echo("")
    typer.echo(f"  {typer.style('Next:', bold=True)} Place source files in:")
    typer.echo(f"    {typer.style(f'candidates/{candidate_id}/src/', fg=typer.colors.CYAN)}")
    typer.echo(f"    {typer.style(f'candidates/{candidate_id}/tests/', fg=typer.colors.CYAN)}")
    typer.echo(f"  Then run: python -m airlock candidate hash {candidate_id}")
    typer.echo("")


# ── candidate list ────────────────────────────────────────────────────────────

def candidate_list() -> None:
    """List all candidates and their pipeline status."""
    config = load_config()
    root: Path = config["_project_root"]
    candidates_dir = root / "candidates"

    candidates = list_candidates(candidates_dir)

    typer.echo("")
    typer.echo(
        typer.style("Airlock", fg=typer.colors.CYAN, bold=True)
        + "  —  Candidates"
    )
    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))

    if not candidates:
        typer.echo(
            f"  {typer.style('No candidates yet.', fg=typer.colors.BRIGHT_BLACK)}"
            "  Run 'python -m airlock candidate register <spec_id>' to create one."
        )
        typer.echo("")
        return

    for c in candidates:
        candidate_id = c.get("candidate_id", "unknown")
        status = c.get("status", "unknown")
        spec_id = c.get("spec_id", "—")
        description = c.get("description", "")

        typer.echo(
            f"  {typer.style(candidate_id, bold=True):<24} "
            + _style_status(status)
        )
        typer.echo(f"  {'':24} spec: {spec_id}")
        if description:
            typer.echo(f"  {'':24} {description}")
        typer.echo("")

    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))
    typer.echo(f"  {len(candidates)} candidate(s) found")
    typer.echo("")


# ── candidate hash ────────────────────────────────────────────────────────────

def candidate_hash(candidate_id: str) -> None:
    """Compute and record the source hash for a candidate's src/ tree."""
    config = load_config()
    root: Path = config["_project_root"]
    candidate_dir = root / "candidates" / candidate_id

    if not candidate_dir.exists():
        typer.echo(typer.style(f"✗ Candidate not found: {candidate_id}", fg=typer.colors.RED))
        raise typer.Exit(1)

    try:
        source_hash = compute_source_hash(candidate_dir)
    except CandidateError as exc:
        typer.echo(typer.style(f"✗ {exc}", fg=typer.colors.RED))
        raise typer.Exit(1)

    short_hash = source_hash[7:19] if source_hash.startswith("sha256:") else source_hash[:12]

    typer.echo("")
    typer.echo(
        typer.style("✓ Source hashed: ", fg=typer.colors.GREEN, bold=True)
        + typer.style(candidate_id, bold=True)
    )
    typer.echo(
        f"  Hash    {typer.style(short_hash + '...', fg=typer.colors.BRIGHT_BLACK)}"
        f"  ({source_hash})"
    )
    typer.echo(f"  Recorded in candidates/{candidate_id}/manifest.json")
    typer.echo("")
