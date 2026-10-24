# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock gate <candidate_id>
airlock admit <candidate_id>
"""

from __future__ import annotations

from pathlib import Path

import typer

from airlock.config import load_config
from airlock.commands._signing import prepare_signer
from airlock.core.governance.gate import (
    ALLOW, DENY, QUARANTINE, ESCALATE,
    run_gate, run_admission, run_override, AdmissionError, OverrideError,
)
from airlock.core.candidate_store import get_status, transition_status, CandidateError


# ── airlock gate ───────────────────────────────────────────────────────────────────

def gate(candidate_id: str, override: bool = False, operator: str = "", reason: str = "") -> None:
    """Run the governance gate against a certified candidate."""
    config = load_config()
    root: Path = config["_project_root"]
    candidate_dir = root / "candidates" / candidate_id

    if not candidate_dir.exists():
        typer.echo(typer.style(f"✗ Candidate not found: {candidate_id}", fg=typer.colors.RED))
        raise typer.Exit(1)

    try:
        current_status = get_status(candidate_dir)
    except CandidateError as exc:
        typer.echo(typer.style(f"✗ {exc}", fg=typer.colors.RED))
        raise typer.Exit(1)

    if current_status in ("quarantined", "rejected"):
        typer.echo(typer.style(
            f"✗ Candidate is {current_status}. "
            "Complete verify and certify before running the gate.",
            fg=typer.colors.RED,
        ))
        raise typer.Exit(1)

    if current_status == "admitted":
        typer.echo(typer.style("✗ Candidate is already admitted.", fg=typer.colors.RED))
        raise typer.Exit(1)

    typer.echo("")
    typer.echo(
        typer.style("Airlock", fg=typer.colors.CYAN, bold=True)
        + "  —  Governance Gate"
    )
    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))
    typer.echo(f"  Candidate   {typer.style(candidate_id, bold=True)}")
    typer.echo(f"  Evaluating evidence...")
    typer.echo("")

    prepare_signer(config)
    if override:
        try:
            decision = run_override(candidate_dir, root, config, operator, reason)
        except OverrideError as exc:
            typer.echo(typer.style(f"✗ {exc}", fg=typer.colors.RED))
            raise typer.Exit(1)
    else:
        decision = run_gate(candidate_dir, root, config)

    _print_evidence_checks(decision)
    _print_decision(decision)

    evidence_path = root / "evidence" / candidate_id / "gate_decision.json"
    typer.echo(f"\n  Evidence → {evidence_path.relative_to(root)}")
    typer.echo("")

    if decision.decision == ALLOW:
        typer.echo(
            f"  {typer.style('Run:', bold=True)} "
            + typer.style(f"airlock admit {candidate_id}", fg=typer.colors.CYAN)
            + " to complete admission."
        )
        typer.echo("")
    elif decision.decision in (DENY, QUARANTINE):
        raise typer.Exit(1)
    elif decision.decision == ESCALATE:
        typer.echo(
            typer.style("  Operator action required.", fg=typer.colors.YELLOW, bold=True)
            + " Review the evidence, then if appropriate run:\n  "
            + typer.style(
                f"airlock gate {candidate_id} --override --operator <name> --reason \"...\"",
                fg=typer.colors.CYAN,
            )
        )
        typer.echo("")
        raise typer.Exit(2)


def _print_evidence_checks(decision) -> None:
    typer.echo("  Evidence checks:")
    for check in decision.evidence_checks:
        doc = check["document"]
        present = check["present"]
        hash_valid = check["hash_valid"]
        verdict = check.get("verdict", "")

        if not present:
            icon = typer.style("○", fg=typer.colors.BRIGHT_BLACK)
            status_str = typer.style("missing", fg=typer.colors.RED)
        elif not hash_valid:
            icon = typer.style("!", fg=typer.colors.YELLOW)
            status_str = typer.style("hash missing", fg=typer.colors.YELLOW)
        elif verdict and verdict not in ("PASS", "CERTIFIED"):
            icon = typer.style("✗", fg=typer.colors.RED)
            status_str = typer.style(verdict, fg=typer.colors.RED)
        else:
            icon = typer.style("✓", fg=typer.colors.GREEN)
            status_str = typer.style(verdict or "present", fg=typer.colors.GREEN)

        typer.echo(f"    {icon}  {doc:<35} {status_str}")
    typer.echo("")


def _print_decision(decision) -> None:
    d = decision.decision
    if d == ALLOW:
        colour = typer.colors.GREEN
        icon = "✓"
    elif d == DENY:
        colour = typer.colors.RED
        icon = "✗"
    elif d == QUARANTINE:
        colour = typer.colors.YELLOW
        icon = "⚠"
    else:  # ESCALATE
        colour = typer.colors.MAGENTA
        icon = "↑"

    typer.echo(
        f"  {typer.style(f'{icon} Gate decision: {d}', fg=colour, bold=True)}"
    )
    if getattr(decision, "operator_override", False):
        typer.echo(
            f"  Operator override of {decision.overridden_decision} by "
            f"{typer.style(decision.operator_id, bold=True)}: {decision.override_reason}"
        )

    if decision.reasons:
        typer.echo("")
        typer.echo("  Reasons:")
        for reason in decision.reasons:
            typer.echo(f"    • {reason}")

    if decision.required_actions:
        typer.echo("")
        typer.echo("  Required actions:")
        for action in decision.required_actions:
            typer.echo(f"    → {action}")


# ── airlock admit ──────────────────────────────────────────────────────────────────

def admit(candidate_id: str) -> None:
    """Admit a gate-approved candidate into the trusted tree."""
    config = load_config()
    root: Path = config["_project_root"]
    candidate_dir = root / "candidates" / candidate_id

    if not candidate_dir.exists():
        typer.echo(typer.style(f"✗ Candidate not found: {candidate_id}", fg=typer.colors.RED))
        raise typer.Exit(1)

    typer.echo("")
    typer.echo(
        typer.style("Airlock", fg=typer.colors.CYAN, bold=True)
        + "  —  Admission"
    )
    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))
    typer.echo(f"  Candidate   {typer.style(candidate_id, bold=True)}")
    typer.echo("")

    try:
        prepare_signer(config)
        certificate = run_admission(candidate_dir, root, policy=config)
    except AdmissionError as exc:
        typer.echo(typer.style(f"✗ {exc}", fg=typer.colors.RED))
        raise typer.Exit(1)

    # Advance candidate status
    try:
        transition_status(candidate_dir, "admitted")
    except CandidateError:
        pass

    cert_id = certificate["certificate_id"]
    level = certificate["level"]
    admitted_at = certificate["admitted_at"][:10]
    trusted_path = root / "trusted" / "src" / candidate_id

    typer.echo(
        typer.style("✓ Candidate admitted to trusted tree.", fg=typer.colors.GREEN, bold=True)
    )
    typer.echo("")
    typer.echo(f"  Certificate   {typer.style(cert_id, bold=True)}")
    typer.echo(f"  Level         {typer.style(level, fg=typer.colors.GREEN)}")
    typer.echo(f"  Admitted      {admitted_at}")
    typer.echo(f"  Trusted path  {trusted_path.relative_to(root)}")
    typer.echo("")
    typer.echo(
        f"  {typer.style('Note:', bold=True)} Source is now in the trusted tree. "
        "Evidence is archived in evidence/"
        + candidate_id + "/"
    )
    typer.echo("")
