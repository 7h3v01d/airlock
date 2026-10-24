# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock verify <candidate_id>

Runs the static verifier against a candidate.
Produces evidence/candidate_XXXX/static_verification.json.
"""

from __future__ import annotations

from pathlib import Path

import typer

from airlock.config import load_config
from airlock.core.verifier.runner import run_verification
from airlock.core.candidate_store import get_status, transition_status, CandidateError


def verify(candidate_id: str) -> None:
    """Run the static verifier against a quarantined candidate."""
    config = load_config()
    root: Path = config["_project_root"]
    candidate_dir = root / "candidates" / candidate_id

    # ── Guards ────────────────────────────────────────────────────────────────
    if not candidate_dir.exists():
        typer.echo(typer.style(f"✗ Candidate not found: {candidate_id}", fg=typer.colors.RED))
        raise typer.Exit(1)

    try:
        status = get_status(candidate_dir)
    except CandidateError as exc:
        typer.echo(typer.style(f"✗ {exc}", fg=typer.colors.RED))
        raise typer.Exit(1)

    if status == "admitted":
        typer.echo(typer.style("✗ Candidate is already admitted.", fg=typer.colors.RED))
        raise typer.Exit(1)

    if status == "rejected":
        typer.echo(typer.style(
            "✗ Candidate is rejected. Fix the issues and register a new candidate.",
            fg=typer.colors.RED,
        ))
        raise typer.Exit(1)

    # ── Run verifier ──────────────────────────────────────────────────────────
    typer.echo("")
    typer.echo(
        typer.style("Airlock", fg=typer.colors.CYAN, bold=True)
        + "  —  Verifier"
    )
    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))
    typer.echo(f"  Candidate   {typer.style(candidate_id, bold=True)}")
    typer.echo(f"  Running verifier...")
    typer.echo("")

    report = run_verification(candidate_dir, root, config)

    # ── Display results ───────────────────────────────────────────────────────
    _print_results(report)

    # ── Update candidate status ───────────────────────────────────────────────
    if report.verdict == "PASS":
        try:
            if status == "quarantined":
                transition_status(candidate_dir, "verified")
        except CandidateError:
            pass  # already verified or beyond — that's fine
        typer.echo(
            typer.style("✓ Verdict: PASS", fg=typer.colors.GREEN, bold=True)
            + f"  — candidate advanced to "
            + typer.style("verified", fg=typer.colors.CYAN)
        )
    else:
        try:
            transition_status(candidate_dir, "rejected")
        except CandidateError:
            pass
        typer.echo(
            typer.style("✗ Verdict: FAIL", fg=typer.colors.RED, bold=True)
            + f"  — candidate moved to "
            + typer.style("rejected", fg=typer.colors.RED)
        )

    evidence_path = root / "evidence" / candidate_id / "static_verification.json"
    typer.echo(f"\n  Evidence → {evidence_path.relative_to(root)}")
    typer.echo("")

    if report.verdict == "FAIL":
        raise typer.Exit(1)


def _print_results(report) -> None:
    """Print a formatted summary of verifier results."""
    # Group failures for display
    failures = [r for r in report.results if not r["passed"]]
    blocking = [r for r in failures if r["blocking"]]
    non_blocking = [r for r in failures if not r["blocking"]]

    typer.echo(
        f"  Rules evaluated  {report.rules_evaluated}\n"
        f"  Passed           {typer.style(str(report.rules_passed), fg=typer.colors.GREEN)}\n"
        f"  Failed           {typer.style(str(report.rules_failed), fg=typer.colors.RED if report.rules_failed else typer.colors.GREEN)}\n"
        f"  Blocking         {typer.style(str(report.blocking_failures), fg=typer.colors.RED if report.blocking_failures else typer.colors.GREEN)}"
    )
    typer.echo("")

    if blocking:
        typer.echo(typer.style("  Blocking failures:", fg=typer.colors.RED, bold=True))
        for r in blocking:
            loc = f" [{r['file']}:{r['line']}]" if r["file"] else ""
            typer.echo(
                f"    {typer.style('✗', fg=typer.colors.RED)} "
                f"{typer.style(r['rule_id'], bold=True)}{loc}"
            )
            if r["detail"]:
                typer.echo(f"      {r['detail']}")
        typer.echo("")

    if non_blocking:
        typer.echo(typer.style("  Warnings:", fg=typer.colors.YELLOW, bold=True))
        for r in non_blocking:
            loc = f" [{r['file']}:{r['line']}]" if r["file"] else ""
            typer.echo(
                f"    {typer.style('⚠', fg=typer.colors.YELLOW)} "
                f"{r['rule_id']}{loc}"
            )
            if r["detail"]:
                typer.echo(f"      {r['detail']}")
        typer.echo("")
