# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
Airlock project configuration loader.
Reads and validates airlock.yaml from the project root.

Projects created before the Airlock rename used ``cleanroom.yaml``; that
filename is still read as a fallback so existing projects keep working.
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer
import yaml


# ── Constants ────────────────────────────────────────────────────────────────

CONFIG_FILENAME = "airlock.yaml"
LEGACY_CONFIG_FILENAME = "cleanroom.yaml"
VALID_RISK_CLASSES = {"low", "medium", "high", "critical"}
VALID_LANGUAGES = {"python"}
VALID_LLM_PROVIDERS = {"ollama"}


# ── Loader ───────────────────────────────────────────────────────────────────

def config_path_for(root: Path) -> Path | None:
    """Return the project config file in root (airlock.yaml, else legacy cleanroom.yaml)."""
    for name in (CONFIG_FILENAME, LEGACY_CONFIG_FILENAME):
        candidate = root / name
        if candidate.exists():
            return candidate
    return None


def find_project_root(start: Path | None = None) -> Path | None:
    """Walk up from start (default: cwd) looking for a project config file."""
    current = (start or Path.cwd()).resolve()
    for directory in [current, *current.parents]:
        if config_path_for(directory) is not None:
            return directory
    return None


def load_config(project_root: Path | None = None) -> dict:
    """
    Load and lightly validate airlock.yaml.
    Exits with a clean error if the file is missing or malformed.
    """
    root = project_root or find_project_root()
    if root is None:
        typer.echo(
            typer.style("✗ No airlock.yaml found.", fg=typer.colors.RED)
            + " Run 'python -m airlock init <project_name>' first."
        )
        raise typer.Exit(1)

    config_path = config_path_for(root) or (root / CONFIG_FILENAME)
    try:
        with config_path.open("r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        typer.echo(typer.style(f"✗ {config_path.name} is malformed: {exc}", fg=typer.colors.RED))
        raise typer.Exit(1)

    _validate(config, config_path)
    config["_project_root"] = root
    return config


def _validate(config: dict, path: Path) -> None:
    """Basic schema validation — exits on error."""
    errors: list[str] = []

    project = config.get("project", {})
    if not project.get("name"):
        errors.append("project.name is required")

    language = project.get("language", "")
    if language not in VALID_LANGUAGES:
        errors.append(f"project.language must be one of {VALID_LANGUAGES}; got '{language}'")

    risk_class = project.get("risk_class", "")
    if risk_class not in VALID_RISK_CLASSES:
        errors.append(f"project.risk_class must be one of {VALID_RISK_CLASSES}; got '{risk_class}'")

    local_first = config.get("local_first", {}) or {}
    if local_first.get("allow_telemetry"):
        errors.append("local_first.allow_telemetry must be false (Airlock has no telemetry)")

    llm = config.get("llm", {}) or {}
    provider = llm.get("provider", "ollama")
    if provider not in VALID_LLM_PROVIDERS:
        errors.append(f"llm.provider must be one of {VALID_LLM_PROVIDERS}; got '{provider}'")

    if errors:
        typer.echo(typer.style(f"✗ {path} has errors:", fg=typer.colors.RED))
        for err in errors:
            typer.echo(f"  • {err}")
        raise typer.Exit(1)
