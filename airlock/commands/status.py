# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock status

Prints a summary of the current Airlock project:
specs, candidates, and admitted artefacts.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from airlock.config import load_config


# ── Helpers ───────────────────────────────────────────────────────────────────

def _count_specs(specs_dir: Path) -> tuple[int, int]:
    """Returns (total, locked) spec counts."""
    total = locked = 0
    for meta in specs_dir.glob("*/spec_meta.json"):
        total += 1
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
            if data.get("status") == "LOCKED":
                locked += 1
        except (json.JSONDecodeError, OSError):
            pass
    return total, locked


def _summarise_candidates(candidates_dir: Path) -> dict[str, int]:
    """Returns counts by status."""
    counts: dict[str, int] = {}
    for status_file in candidates_dir.glob("*/status.json"):
        try:
            data = json.loads(status_file.read_text(encoding="utf-8"))
            status = data.get("status", "unknown")
            counts[status] = counts.get(status, 0) + 1
        except (json.JSONDecodeError, OSError):
            counts["unknown"] = counts.get("unknown", 0) + 1
    return counts


def _count_admitted(trusted_src: Path) -> int:
    """Count admitted artefacts by certificate presence."""
    evidence_dir = trusted_src.parent.parent / "evidence"
    return sum(1 for f in evidence_dir.glob("*/admission_certificate.json"))


def _risk_colour(risk_class: str) -> str:
    colours = {
        "low": typer.colors.GREEN,
        "medium": typer.colors.YELLOW,
        "high": typer.colors.RED,
        "critical": typer.colors.MAGENTA,
    }
    return colours.get(risk_class, typer.colors.WHITE)


# ── Command ───────────────────────────────────────────────────────────────────

def status() -> None:
    """Show project overview: specs, candidates, and admitted artefacts."""
    config = load_config()
    root: Path = config["_project_root"]
    project = config.get("project", {})
    local_first = config.get("local_first", {})

    risk_class = project.get("risk_class", "unknown")
    risk_colour = _risk_colour(risk_class)

    # ── Header ────────────────────────────────────────────────────────────────
    typer.echo("")
    typer.echo(
        typer.style("Airlock", fg=typer.colors.CYAN, bold=True)
        + f"  {typer.style('◆', fg=typer.colors.CYAN)}  "
        + typer.style(project.get("name", "unknown"), bold=True)
    )
    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))

    # ── Project info ──────────────────────────────────────────────────────────
    typer.echo(f"  Language    {project.get('language', 'unknown')}")
    typer.echo(
        f"  Risk class  "
        + typer.style(risk_class, fg=risk_colour, bold=True)
    )

    network_ok = not local_first.get("allow_network", False)
    remote_llm_ok = not local_first.get("allow_remote_llm", False)
    typer.echo(
        f"  Network     "
        + (typer.style("blocked", fg=typer.colors.GREEN) if network_ok
           else typer.style("ALLOWED", fg=typer.colors.RED))
    )
    typer.echo(
        f"  Remote LLM  "
        + (typer.style("blocked", fg=typer.colors.GREEN) if remote_llm_ok
           else typer.style("ALLOWED", fg=typer.colors.RED))
    )

    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))

    # ── Specs ─────────────────────────────────────────────────────────────────
    specs_dir = root / "specs"
    total_specs, locked_specs = _count_specs(specs_dir)
    typer.echo(
        f"  Specs       {total_specs} total  "
        + typer.style(f"{locked_specs} locked", fg=typer.colors.GREEN if locked_specs else typer.colors.BRIGHT_BLACK)
    )

    # ── Candidates ────────────────────────────────────────────────────────────
    candidates_dir = root / "candidates"
    candidate_counts = _summarise_candidates(candidates_dir)
    total_candidates = sum(candidate_counts.values())

    status_colours = {
        "quarantined": typer.colors.YELLOW,
        "verified": typer.colors.CYAN,
        "certified": typer.colors.BLUE,
        "admitted": typer.colors.GREEN,
        "rejected": typer.colors.RED,
        "unknown": typer.colors.BRIGHT_BLACK,
    }

    if total_candidates == 0:
        typer.echo(f"  Candidates  none")
    else:
        parts = []
        for s, count in sorted(candidate_counts.items()):
            colour = status_colours.get(s, typer.colors.WHITE)
            parts.append(typer.style(f"{count} {s}", fg=colour))
        typer.echo(f"  Candidates  {total_candidates} total  " + "  ".join(parts))

    # ── Admitted artefacts ────────────────────────────────────────────────────
    admitted = _count_admitted(root / "trusted" / "src")
    typer.echo(
        f"  Admitted    "
        + (typer.style(str(admitted), fg=typer.colors.GREEN, bold=True) if admitted
           else typer.style("0", fg=typer.colors.BRIGHT_BLACK))
        + " artefacts in trusted tree"
    )

    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))
    typer.echo(f"  Root        {root}")
    typer.echo("")
