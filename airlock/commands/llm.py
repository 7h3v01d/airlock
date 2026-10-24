# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock spec draft <intent>           Draft a spec using the local LLM
airlock generate <spec_id> <module>   Generate a candidate from a locked spec
airlock explain <candidate_id>        Explain pipeline failures for a candidate
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from airlock.config import load_config
from airlock.llm.ollama_provider import OllamaProvider, OllamaConnectionError, provider_from_config
from airlock.llm.generator import draft_spec, generate_candidate, explain_failures, GenerationError
from airlock.core.spec_store import create_spec


# ── airlock spec draft ─────────────────────────────────────────────────────────────

def spec_draft(intent: str) -> None:
    """Use the local LLM to draft a spec from a one-line intent."""
    config = load_config()
    root: Path = config["_project_root"]

    provider = _get_provider(config)

    typer.echo("")
    typer.echo(
        typer.style("Airlock", fg=typer.colors.CYAN, bold=True)
        + "  —  Spec Drafter  "
        + typer.style("[LLM Draft]", fg=typer.colors.YELLOW)
    )
    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))
    typer.echo(f"  Model   {typer.style(provider.profile.model, bold=True)}")
    typer.echo(f"  Intent  {intent}")
    typer.echo("")
    typer.echo(f"  Drafting spec... ", nl=False)

    try:
        draft_content = draft_spec(intent, provider, root, config)
    except OllamaConnectionError as exc:
        typer.echo(typer.style(f"\n✗ {exc}", fg=typer.colors.RED))
        raise typer.Exit(1)

    # Create spec and write draft content
    specs_dir = root / "specs"
    spec_id, spec_dir = create_spec(specs_dir, intent)
    spec_md = spec_dir / "spec.md"

    # Prepend header then LLM content
    header = f"# {spec_id}\n\n> {intent}\n\n"
    spec_md.write_text(header + draft_content, encoding="utf-8")

    typer.echo(typer.style("done", fg=typer.colors.GREEN))
    typer.echo("")
    typer.echo(
        typer.style("✓ Draft created: ", fg=typer.colors.GREEN, bold=True)
        + typer.style(spec_id, bold=True)
    )
    typer.echo(f"  Location  specs/{spec_id}/spec.md")
    typer.echo("")
    typer.echo(
        typer.style("  ⚠ LLM DRAFT — operator review required before locking.", fg=typer.colors.YELLOW)
    )
    typer.echo(f"  Review the spec, edit as needed, then:")
    typer.echo(f"    airlock spec lock {spec_id}")
    typer.echo("")


# ── airlock generate ───────────────────────────────────────────────────────────────

def generate(spec_id: str, module_name: str) -> None:
    """Generate a candidate from a locked spec using the local LLM."""
    config = load_config()
    root: Path = config["_project_root"]

    provider = _get_provider(config)

    typer.echo("")
    typer.echo(
        typer.style("Airlock", fg=typer.colors.CYAN, bold=True)
        + "  —  Candidate Generator  "
        + typer.style("[LLM Draft]", fg=typer.colors.YELLOW)
    )
    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))
    typer.echo(f"  Model   {typer.style(provider.profile.model, bold=True)}")
    typer.echo(f"  Spec    {spec_id}")
    typer.echo(f"  Module  {module_name}")
    typer.echo("")
    typer.echo(f"  Generating candidate... ", nl=False)

    try:
        candidate_id, candidate_dir = generate_candidate(
            spec_id, module_name, provider, root, config
        )
    except GenerationError as exc:
        typer.echo(typer.style(f"\n✗ {exc}", fg=typer.colors.RED))
        raise typer.Exit(1)
    except OllamaConnectionError as exc:
        typer.echo(typer.style(f"\n✗ {exc}", fg=typer.colors.RED))
        raise typer.Exit(1)

    # Show what was generated
    src_files = list((candidate_dir / "src").rglob("*.py"))
    test_files = list((candidate_dir / "tests").rglob("*.py"))

    typer.echo(typer.style("done", fg=typer.colors.GREEN))
    typer.echo("")
    typer.echo(
        typer.style("✓ Candidate generated: ", fg=typer.colors.GREEN, bold=True)
        + typer.style(candidate_id, bold=True)
    )
    typer.echo(f"  Status      ● quarantined")
    typer.echo(f"  Source      {len(src_files)} file(s) in candidates/{candidate_id}/src/")
    typer.echo(f"  Tests       {len(test_files)} file(s) in candidates/{candidate_id}/tests/")
    typer.echo("")
    typer.echo(
        typer.style("  ⚠ LLM OUTPUT — quarantined. Run the pipeline:", fg=typer.colors.YELLOW)
    )
    typer.echo(f"    airlock candidate hash {candidate_id}")
    typer.echo(f"    airlock verify {candidate_id}")
    typer.echo(f"    airlock certify {candidate_id}")
    typer.echo(f"    airlock gate {candidate_id}")
    typer.echo("")


# ── airlock explain ────────────────────────────────────────────────────────────────

def explain(candidate_id: str) -> None:
    """Use the local LLM to explain pipeline failures for a candidate."""
    config = load_config()
    root: Path = config["_project_root"]
    candidate_dir = root / "candidates" / candidate_id
    evidence_dir = root / "evidence" / candidate_id

    if not candidate_dir.exists():
        typer.echo(typer.style(f"✗ Candidate not found: {candidate_id}", fg=typer.colors.RED))
        raise typer.Exit(1)

    # Collect failures from evidence
    failures: list[dict] = []
    failure_type = "unknown"

    ver_path = evidence_dir / "static_verification.json"
    test_path = evidence_dir / "test_report.json"

    if ver_path.exists():
        ver_data = json.loads(ver_path.read_text(encoding="utf-8"))
        if ver_data.get("verdict") == "FAIL":
            failure_type = "verifier"
            failures = [
                r for r in ver_data.get("results", [])
                if not r.get("passed") and r.get("blocking")
            ]

    if not failures and test_path.exists():
        test_data = json.loads(test_path.read_text(encoding="utf-8"))
        if test_data.get("certification") == "NOT_CERTIFIED":
            failure_type = "test"
            failures = test_data.get("failure_details", [])

    if not failures:
        typer.echo(
            typer.style("✗ No failures found to explain.", fg=typer.colors.YELLOW)
            + " Run airlock verify or airlock certify first."
        )
        raise typer.Exit(1)

    provider = _get_provider(config)

    typer.echo("")
    typer.echo(
        typer.style("Airlock", fg=typer.colors.CYAN, bold=True)
        + "  —  Failure Explainer  "
        + typer.style("[LLM Advisory]", fg=typer.colors.YELLOW)
    )
    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))
    typer.echo(f"  Model      {typer.style(provider.profile.model, bold=True)}")
    typer.echo(f"  Candidate  {candidate_id}")
    typer.echo(f"  Failures   {len(failures)} {failure_type} failure(s)")
    typer.echo("")
    typer.echo(f"  Analysing... ", nl=False)

    try:
        explanation = explain_failures(
            candidate_id, failure_type, failures, provider, root
        )
    except OllamaConnectionError as exc:
        typer.echo(typer.style(f"\n✗ {exc}", fg=typer.colors.RED))
        raise typer.Exit(1)

    typer.echo(typer.style("done", fg=typer.colors.GREEN))
    typer.echo("")
    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))
    typer.echo(explanation)
    typer.echo(typer.style("─" * 52, fg=typer.colors.BRIGHT_BLACK))
    typer.echo("")
    typer.echo(
        typer.style("  ⚠ LLM advisory only.", fg=typer.colors.YELLOW)
        + " Pipeline rules cannot be overridden."
    )
    typer.echo("")


# ── Provider helper ───────────────────────────────────────────────────────────

def _get_provider(config: dict) -> OllamaProvider:
    """Build and validate the Ollama provider from config."""
    local_first = config.get("local_first", {})
    if local_first.get("allow_remote_llm") is False:
        # Remote LLM blocked — Ollama is local, so this is fine
        pass

    provider = provider_from_config(config)

    if not provider.is_available():
        typer.echo(
            typer.style("✗ Ollama is not available.", fg=typer.colors.RED)
        )
        typer.echo(
            f"  Model '{provider.model}' not found at {provider.base_url}"
        )
        typer.echo("  Is Ollama running? Try: ollama serve")
        typer.echo(f"  Is the model pulled? Try: ollama pull {provider.model}")
        raise typer.Exit(1)

    return provider
