# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock report <candidate_id>

Prints the full evidence summary for a candidate — whatever evidence
currently exists at this pipeline stage.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from airlock.config import load_config


# ── Evidence documents and display order ──────────────────────────────────────

EVIDENCE_DOCS: list[tuple[str, str]] = [
    ("generation_manifest.json",   "Generation manifest"),
    ("static_verification.json",   "Verifier report"),
    ("test_report.json",           "Test report"),
    ("coverage_report.json",       "Coverage report"),
    ("mutation_report.json",       "Mutation report"),
    ("contract_test_report.json",  "Contract test report"),
    ("gate_decision.json",         "Gate decision"),
    ("admission_certificate.json", "Admission certificate"),
]

VERDICT_COLOURS: dict[str, str] = {
    "PASS":       typer.colors.GREEN,
    "FAIL":       typer.colors.RED,
    "ALLOW":      typer.colors.GREEN,
    "DENY":       typer.colors.RED,
    "QUARANTINE": typer.colors.YELLOW,
    "ESCALATE_TO_OPERATOR": typer.colors.MAGENTA,
    "CERTIFIED":     typer.colors.GREEN,
    "NOT_CERTIFIED": typer.colors.RED,
}

STATUS_COLOURS: dict[str, str] = {
    "quarantined": typer.colors.YELLOW,
    "verified":    typer.colors.CYAN,
    "certified":   typer.colors.BLUE,
    "admitted":    typer.colors.GREEN,
    "rejected":    typer.colors.RED,
}


def _style_verdict(value: str) -> str:
    colour = VERDICT_COLOURS.get(value.upper(), typer.colors.WHITE)
    return typer.style(value, fg=colour, bold=True)


def _present(label: str, value: str, indent: int = 4) -> None:
    typer.echo(f"{'':>{indent}}{label:<28}{value}")


# ── Command ───────────────────────────────────────────────────────────────────

def report(candidate_id: str) -> None:
    """Print the full evidence summary for a candidate."""
    config = load_config()
    root: Path = config["_project_root"]

    candidate_dir = root / "candidates" / candidate_id
    evidence_dir = root / "evidence" / candidate_id

    typer.echo("")
    typer.echo(
        typer.style("Airlock", fg=typer.colors.CYAN, bold=True)
        + "  —  Evidence Report"
    )
    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))

    # ── Candidate existence ───────────────────────────────────────────────────
    if not candidate_dir.exists():
        typer.echo(
            f"  {typer.style('✗ Candidate not found:', fg=typer.colors.RED)} {candidate_id}"
        )
        typer.echo("")
        raise typer.Exit(1)

    typer.echo(f"  Candidate   {typer.style(candidate_id, bold=True)}")

    # ── Candidate status ──────────────────────────────────────────────────────
    status_path = candidate_dir / "status.json"
    if status_path.exists():
        try:
            status_data = json.loads(status_path.read_text(encoding="utf-8"))
            status = status_data.get("status", "unknown")
            colour = STATUS_COLOURS.get(status, typer.colors.WHITE)
            typer.echo(f"  Status      {typer.style(status, fg=colour, bold=True)}")
        except json.JSONDecodeError:
            typer.echo(f"  Status      {typer.style('malformed status.json', fg=typer.colors.RED)}")
    else:
        typer.echo(f"  Status      {typer.style('unknown', fg=typer.colors.BRIGHT_BLACK)}")

    # ── Manifest ──────────────────────────────────────────────────────────────
    manifest_path = candidate_dir / "manifest.json"
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            spec_id = manifest.get("spec_id", "—")
            language = manifest.get("language", "—")
            typer.echo(f"  Spec        {spec_id}")
            typer.echo(f"  Language    {language}")
        except json.JSONDecodeError:
            typer.echo(f"  Manifest    {typer.style('malformed', fg=typer.colors.RED)}")
    else:
        typer.echo(f"  Manifest    {typer.style('not found', fg=typer.colors.BRIGHT_BLACK)}")

    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))
    typer.echo("  Evidence")
    typer.echo("")

    # ── Evidence documents ────────────────────────────────────────────────────
    if not evidence_dir.exists():
        typer.echo(
            f"    {typer.style('No evidence yet.', fg=typer.colors.BRIGHT_BLACK)}"
            "  Run the pipeline to generate evidence."
        )
    else:
        any_found = False
        for filename, label in EVIDENCE_DOCS:
            doc_path = evidence_dir / filename
            if not doc_path.exists():
                typer.echo(
                    f"    {typer.style('○', fg=typer.colors.BRIGHT_BLACK)}  "
                    f"{label:<28}"
                    + typer.style("not yet produced", fg=typer.colors.BRIGHT_BLACK)
                )
                continue

            any_found = True
            try:
                data = json.loads(doc_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                typer.echo(
                    f"    {typer.style('✗', fg=typer.colors.RED)}  "
                    f"{label:<28}"
                    + typer.style("malformed JSON", fg=typer.colors.RED)
                )
                continue

            # Pull the most meaningful top-level field for display
            verdict = (
                data.get("verdict")
                or data.get("decision")
                or data.get("certification")
                or data.get("level")
            )
            verdict_str = _style_verdict(str(verdict)) if verdict else typer.style("present", fg=typer.colors.GREEN)

            typer.echo(
                f"    {typer.style('●', fg=typer.colors.GREEN)}  "
                f"{label:<28}{verdict_str}"
            )

        if not any_found:
            typer.echo(
                f"    {typer.style('No evidence documents found.', fg=typer.colors.BRIGHT_BLACK)}"
            )

    typer.echo("")
    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))

    # ── Admission certificate summary ─────────────────────────────────────────
    cert_path = (evidence_dir / "admission_certificate.json") if evidence_dir.exists() else None
    if cert_path and cert_path.exists():
        try:
            cert = json.loads(cert_path.read_text(encoding="utf-8"))
            cert_id = cert.get("certificate_id", "—")
            level = cert.get("level", "—")
            admitted_at = cert.get("admitted_at", "—")[:10]
            typer.echo(
                f"  {typer.style('✓ ADMITTED', fg=typer.colors.GREEN, bold=True)}"
            )
            typer.echo(f"  Certificate  {cert_id}")
            typer.echo(f"  Level        {typer.style(level, fg=typer.colors.GREEN)}")
            typer.echo(f"  Admitted     {admitted_at}")
        except json.JSONDecodeError:
            pass
    else:
        typer.echo(
            f"  {typer.style('Not admitted', fg=typer.colors.BRIGHT_BLACK)}  "
            "No admission certificate found."
        )

    typer.echo("")
