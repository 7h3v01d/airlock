# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock certify <candidate_id>

Runs the test certifier against a verified candidate.
Produces evidence/candidate_XXXX/test_report.json
and evidence/candidate_XXXX/coverage_report.json.
"""

from __future__ import annotations

from pathlib import Path

import typer

from airlock.config import load_config
from airlock.commands._signing import prepare_signer
from airlock.core.certifier.runner import run_certification
from airlock.core.candidate_store import get_status, transition_status, CandidateError


def certify(candidate_id: str) -> None:
    """Run the test certifier against a verified candidate."""
    config = load_config()
    root: Path = config["_project_root"]
    candidate_dir = root / "candidates" / candidate_id

    # ── Guards ────────────────────────────────────────────────────────────────
    if not candidate_dir.exists():
        typer.echo(typer.style(f"✗ Candidate not found: {candidate_id}", fg=typer.colors.RED))
        raise typer.Exit(1)

    try:
        current_status = get_status(candidate_dir)
    except CandidateError as exc:
        typer.echo(typer.style(f"✗ {exc}", fg=typer.colors.RED))
        raise typer.Exit(1)

    if current_status == "quarantined":
        typer.echo(typer.style(
            "✗ Candidate is quarantined — run 'airlock verify' first.",
            fg=typer.colors.RED,
        ))
        raise typer.Exit(1)

    if current_status == "rejected":
        typer.echo(typer.style(
            "✗ Candidate is rejected. Register a new candidate.",
            fg=typer.colors.RED,
        ))
        raise typer.Exit(1)

    if current_status == "admitted":
        typer.echo(typer.style("✗ Candidate is already admitted.", fg=typer.colors.RED))
        raise typer.Exit(1)

    # ── Run certifier ─────────────────────────────────────────────────────────
    typer.echo("")
    typer.echo(
        typer.style("Airlock", fg=typer.colors.CYAN, bold=True)
        + "  —  Test Certifier"
    )
    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))
    typer.echo(f"  Candidate   {typer.style(candidate_id, bold=True)}")
    typer.echo(f"  Running test suite...")
    typer.echo("")

    prepare_signer(config)
    test_report, cov_report = run_certification(candidate_dir, root, config)

    # ── Display results ───────────────────────────────────────────────────────
    _print_results(test_report, cov_report)

    # ── Update candidate status ───────────────────────────────────────────────
    if test_report.certification == "CERTIFIED":
        try:
            if current_status == "verified":
                transition_status(candidate_dir, "certified")
        except CandidateError:
            pass
        typer.echo(
            typer.style("✓ Certification: CERTIFIED", fg=typer.colors.GREEN, bold=True)
            + f"  — candidate advanced to "
            + typer.style("certified", fg=typer.colors.BLUE)
        )
    else:
        typer.echo(
            typer.style("✗ Certification: NOT_CERTIFIED", fg=typer.colors.RED, bold=True)
        )

    evidence_dir = root / "evidence" / candidate_id
    typer.echo(f"\n  Evidence → {evidence_dir.relative_to(root)}/")
    typer.echo("")

    if test_report.certification != "CERTIFIED":
        raise typer.Exit(1)


def _print_results(test_report, cov_report) -> None:
    # Test results
    total = test_report.total_tests
    passed = test_report.passed
    failed = test_report.failed
    errors = test_report.errors
    skipped = test_report.skipped

    if test_report.timed_out:
        typer.echo(
            typer.style(
                f"  ✗ TIMEOUT after {test_report.timeout_seconds}s — candidate killed",
                fg=typer.colors.RED, bold=True,
            )
        )
    else:
        pass_colour = typer.colors.GREEN if failed == 0 and errors == 0 else typer.colors.RED
        typer.echo(
            f"  Tests        "
            + typer.style(f"{passed}/{total} passed", fg=pass_colour, bold=True)
            + (f"  {failed} failed" if failed else "")
            + (f"  {errors} errors" if errors else "")
            + (f"  {skipped} skipped" if skipped else "")
        )

    # Coverage
    line_pct = f"{cov_report.line_coverage * 100:.1f}%"
    branch_pct = f"{cov_report.branch_coverage * 100:.1f}%"
    cov_colour = typer.colors.GREEN if cov_report.line_coverage >= 0.7 else typer.colors.YELLOW
    typer.echo(
        f"  Line cover   {typer.style(line_pct, fg=cov_colour)}"
        f"   Branch cover  {branch_pct}"
    )
    typer.echo("")

    # Failures
    if test_report.failure_details:
        typer.echo(typer.style("  Failures:", fg=typer.colors.RED, bold=True))
        for detail in test_report.failure_details:
            typer.echo(
                f"    {typer.style('✗', fg=typer.colors.RED)} "
                f"{detail.get('nodeid', 'unknown')}"
            )
            msg = detail.get("message", "")
            if msg:
                # Show last few lines of failure message
                lines = [l for l in msg.splitlines() if l.strip()][-3:]
                for line in lines:
                    typer.echo(f"      {line}")
        typer.echo("")
