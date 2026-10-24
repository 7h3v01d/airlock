# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock init <project_name>

Initialises a new Airlock project in a subdirectory of the
current working directory.
"""

from __future__ import annotations

from pathlib import Path

import typer

import os

from airlock.config import CONFIG_FILENAME
from airlock.core import signing
from airlock.core.audit import project_id as audit_project_id

# ── Directory layout created by init ─────────────────────────────────────────

DIRECTORIES = [
    "specs",
    "candidates",
    "evidence",
    "trusted/src",
    "logs",
]

GITKEEP_DIRS = [
    "specs",
    "candidates",
    "evidence",
    "trusted/src",
    "logs",
]

# ── Embedded config template ──────────────────────────────────────────────────

_CONFIG_TEMPLATE = """\
# Airlock project policy. Every key below is enforced; this file's hash is
# recorded in each gate decision as policy_version.

project:
  name: "{project_name}"
  language: python
  risk_class: medium          # low | medium | high | critical

local_first:
  allow_network: false        # spec/LLM commands refuse to run when false
  allow_remote_llm: false     # true permits a non-loopback Ollama base_url
  allow_telemetry: false      # Airlock sends no telemetry; recorded for audit

llm:
  provider: ollama
  model: deepseek-coder-v2:16b
  base_url: http://localhost:11434

verification:
  require_tests: true         # MISSING_TESTS becomes blocking
  require_type_hints: true    # MISSING_TYPE_HINTS becomes blocking
  require_docstrings: false   # MISSING_DOCSTRINGS becomes blocking when true
  allowed_imports: []         # stdlib modules granted beyond the safe allowlist

integrity:
  # Evidence, gate decisions, certificates and audit entries are signed with
  # the operator key. The operator floor in the Airlock home can require this
  # even when a project says false; a project can never lower it.
  require_signatures: true

certification:
  test_timeout_seconds: 120
  minimum_line_coverage: 0.70
  minimum_branch_coverage: 0.70

governance:
  # Non-blocking findings in these categories escalate to an operator
  # (airlock gate <id> --override --operator NAME --reason TEXT).
  require_human_approval_for:
    - credential_access       # ENV_ACCESS
    - filesystem_mutation     # FS_SHUTIL_MUTATION
"""


# ── Command ───────────────────────────────────────────────────────────────────

def init(project_name: str) -> None:
    """Initialise a new Airlock project."""
    project_root = Path.cwd() / project_name

    if project_root.exists():
        typer.echo(
            typer.style("✗ Directory already exists: ", fg=typer.colors.RED)
            + str(project_root)
        )
        raise typer.Exit(1)

    typer.echo(f"\nInitialising Airlock project: {typer.style(project_name, fg=typer.colors.CYAN, bold=True)}")

    # Create directories
    for relative in DIRECTORIES:
        path = project_root / relative
        path.mkdir(parents=True, exist_ok=True)
        typer.echo(f"  {typer.style('created', fg=typer.colors.GREEN)}  {relative}/")

    # .gitkeep files so empty dirs are tracked
    for relative in GITKEEP_DIRS:
        (project_root / relative / ".gitkeep").touch()

    # airlock.yaml from embedded template
    _write_config(project_root, project_name)

    # audit log placeholder
    audit_log = project_root / "logs" / "audit.jsonl"
    audit_log.touch()
    typer.echo(f"  {typer.style('created', fg=typer.colors.GREEN)}  logs/audit.jsonl")
    audit_project_id(project_root)

    # Operator signing key (outside the project), created once per machine
    if not signing.private_key_path().exists():
        passphrase = os.environ.get(signing.PASSPHRASE_ENV) or None
        key_id = signing.generate_key(passphrase)
        typer.echo(
            f"  {typer.style('created', fg=typer.colors.GREEN)}  operator key {key_id} "
            f"in {signing.airlock_home()}"
            + ("" if passphrase else "  (unencrypted — consider: airlock keys init --passphrase --force)")
        )

    # .gitignore
    _write_gitignore(project_root)

    typer.echo(
        f"\n{typer.style('✓ Project ready.', fg=typer.colors.GREEN, bold=True)} "
        f"cd into {typer.style(project_name, fg=typer.colors.CYAN)} to get started.\n"
    )


def _write_config(project_root: Path, project_name: str) -> None:
    config_text = _CONFIG_TEMPLATE.replace('"{project_name}"', f'"{project_name}"')
    config_path = project_root / CONFIG_FILENAME
    config_path.write_text(config_text, encoding="utf-8")
    typer.echo(f"  {typer.style('created', fg=typer.colors.GREEN)}  {CONFIG_FILENAME}")


def _write_gitignore(project_root: Path) -> None:
    content = (
        "# Airlock\n"
        "__pycache__/\n"
        "*.py[cod]\n"
        ".pytest_cache/\n"
        ".coverage\n"
        "htmlcov/\n"
        ".mutmut-cache\n"
        "\n"
        "# Candidate sandbox artefacts (not source-controlled by default)\n"
        "candidates/*/src/__pycache__/\n"
        "candidates/*/.coverage\n"
    )
    gitignore = project_root / ".gitignore"
    gitignore.write_text(content, encoding="utf-8")
    typer.echo(f"  {typer.style('created', fg=typer.colors.GREEN)}  .gitignore")
