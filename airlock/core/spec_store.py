# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock.core.spec_store

Manages the spec lifecycle:
  DRAFT → LOCKED

Each spec lives at:
  <project_root>/specs/<spec_id>/
    spec.md           Human-readable specification (authored by operator)
    spec_meta.json    Metadata: id, version, status, description, hash, timestamps
    spec_hash.txt     Plain hash of spec.md (written on lock)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from airlock.core.hashing import hash_file


# ── ID generation ─────────────────────────────────────────────────────────────

def _next_spec_id(specs_dir: Path) -> str:
    """Return the next available spec_XXXX id."""
    existing = [
        d.name for d in specs_dir.iterdir()
        if d.is_dir() and d.name.startswith("spec_") and not d.name.startswith(".")
    ]
    numbers = []
    for name in existing:
        try:
            numbers.append(int(name.split("_")[1]))
        except (IndexError, ValueError):
            pass
    next_n = max(numbers, default=0) + 1
    return f"spec_{next_n:04d}"


# ── Create ────────────────────────────────────────────────────────────────────

def create_spec(
    specs_dir: Path,
    description: str,
) -> tuple[str, Path]:
    """
    Create a new DRAFT spec directory.

    Returns (spec_id, spec_dir).
    The operator must author spec.md before locking.
    """
    spec_id = _next_spec_id(specs_dir)
    spec_dir = specs_dir / spec_id
    spec_dir.mkdir(parents=True)

    # Placeholder spec.md — operator fills this in
    spec_md = spec_dir / "spec.md"
    spec_md.write_text(
        f"# {spec_id}\n\n"
        f"> {description}\n\n"
        "## Functional requirements\n\n"
        "<!-- Describe what the system must do -->\n\n"
        "## Non-functional requirements\n\n"
        "<!-- Performance, security, offline constraints -->\n\n"
        "## Forbidden behaviours\n\n"
        "<!-- What the system must never do -->\n\n"
        "## Acceptance criteria\n\n"
        "<!-- Testable conditions that define done -->\n",
        encoding="utf-8",
    )

    meta = {
        "id": spec_id,
        "version": "1",
        "status": "DRAFT",
        "description": description,
        "created_at": _now_iso(),
        "locked_at": None,
        "spec_hash": None,
    }
    _write_meta(spec_dir, meta)

    return spec_id, spec_dir


# ── Lock ──────────────────────────────────────────────────────────────────────

class SpecLockError(Exception):
    pass


def lock_spec(specs_dir: Path, spec_id: str) -> str:
    """
    Lock a DRAFT spec. Returns the spec hash.

    Raises SpecLockError if spec does not exist, is already locked,
    or spec.md has not been modified from the placeholder.
    """
    spec_dir = specs_dir / spec_id
    if not spec_dir.exists():
        raise SpecLockError(f"Spec not found: {spec_id}")

    meta = _read_meta(spec_dir)

    if meta.get("status") == "LOCKED":
        raise SpecLockError(f"{spec_id} is already locked.")

    spec_md = spec_dir / "spec.md"
    if not spec_md.exists():
        raise SpecLockError(f"{spec_id}/spec.md does not exist. Author it before locking.")

    content = spec_md.read_text(encoding="utf-8")
    if "<!-- Describe what the system must do -->" in content:
        raise SpecLockError(
            f"{spec_id}/spec.md still contains placeholder text. "
            "Complete the spec before locking."
        )

    spec_hash = hash_file(spec_md)

    # Write hash file
    (spec_dir / "spec_hash.txt").write_text(spec_hash, encoding="utf-8")

    # Update meta
    meta["status"] = "LOCKED"
    meta["locked_at"] = _now_iso()
    meta["spec_hash"] = spec_hash
    _write_meta(spec_dir, meta)

    return spec_hash


# ── Read ──────────────────────────────────────────────────────────────────────

def read_spec_meta(specs_dir: Path, spec_id: str) -> dict:
    """Read and return spec_meta.json for a given spec_id."""
    spec_dir = specs_dir / spec_id
    return _read_meta(spec_dir)


def list_specs(specs_dir: Path) -> list[dict]:
    """Return a list of all spec metadata dicts, sorted by id."""
    results = []
    for spec_dir in sorted(specs_dir.iterdir()):
        if not spec_dir.is_dir() or spec_dir.name.startswith("."):
            continue
        meta_path = spec_dir / "spec_meta.json"
        if meta_path.exists():
            try:
                results.append(json.loads(meta_path.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                pass
    return results


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_meta(spec_dir: Path, meta: dict) -> None:
    (spec_dir / "spec_meta.json").write_text(
        json.dumps(meta, indent=2), encoding="utf-8"
    )


def _read_meta(spec_dir: Path) -> dict:
    meta_path = spec_dir / "spec_meta.json"
    if not meta_path.exists():
        raise SpecLockError(f"spec_meta.json not found in {spec_dir}")
    return json.loads(meta_path.read_text(encoding="utf-8"))
