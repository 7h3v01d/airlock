# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock.core.candidate_store

Manages candidate quarantine:
  quarantined → verified → certified → admitted
                    └──── rejected (from any stage)

Each candidate lives at:
  <project_root>/candidates/<candidate_id>/
    src/              Generated source files (operator-placed)
    tests/            Generated test files (operator-placed)
    manifest.json     Spec link, language, dependencies, file hashes
    status.json       Current pipeline status
    generated_by.json Model/origin metadata (optional for manual candidates)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from airlock.core.hashing import hash_directory_tree


# ── Valid status transitions ───────────────────────────────────────────────────

VALID_TRANSITIONS: dict[str, set[str]] = {
    "quarantined": {"verified", "rejected"},
    "verified":    {"certified", "rejected"},
    "certified":   {"admitted", "rejected"},
    "admitted":    set(),   # terminal
    "rejected":    set(),   # terminal
}

TERMINAL_STATUSES = {"admitted", "rejected"}


# ── ID generation ─────────────────────────────────────────────────────────────

def _next_candidate_id(candidates_dir: Path) -> str:
    existing = [
        d.name for d in candidates_dir.iterdir()
        if d.is_dir() and d.name.startswith("candidate_") and not d.name.startswith(".")
    ]
    numbers = []
    for name in existing:
        try:
            numbers.append(int(name.split("_")[1]))
        except (IndexError, ValueError):
            pass
    next_n = max(numbers, default=0) + 1
    return f"candidate_{next_n:04d}"


# ── Register ──────────────────────────────────────────────────────────────────

class CandidateError(Exception):
    pass


def register_candidate(
    candidates_dir: Path,
    spec_id: str,
    language: str = "python",
    generated_by: str = "manual",
    description: str = "",
) -> tuple[str, Path]:
    """
    Register a new quarantined candidate.

    Creates the directory structure and writes manifest + status.
    The operator then places source files in src/ and tests/.

    Returns (candidate_id, candidate_dir).
    """
    candidate_id = _next_candidate_id(candidates_dir)
    candidate_dir = candidates_dir / candidate_id

    for subdir in ("src", "tests"):
        (candidate_dir / subdir).mkdir(parents=True)

    manifest = {
        "candidate_id": candidate_id,
        "spec_id": spec_id,
        "language": language,
        "description": description,
        "generated_by": generated_by,
        "created_at": _now_iso(),
        "source_hash": None,   # computed on first verify
        "dependencies": [],
    }
    _write_json(candidate_dir / "manifest.json", manifest)

    generated_by_doc = {
        "model": generated_by,
        "created_at": _now_iso(),
        "note": "manual" if generated_by == "manual" else "",
    }
    _write_json(candidate_dir / "generated_by.json", generated_by_doc)

    _write_status(candidate_dir, "quarantined")

    return candidate_id, candidate_dir


# ── Status management ─────────────────────────────────────────────────────────

def get_status(candidate_dir: Path) -> str:
    status_path = candidate_dir / "status.json"
    if not status_path.exists():
        raise CandidateError(f"status.json not found in {candidate_dir}")
    data = json.loads(status_path.read_text(encoding="utf-8"))
    return data["status"]


def transition_status(candidate_dir: Path, new_status: str) -> None:
    """
    Transition a candidate to a new status.
    Raises CandidateError if the transition is invalid.
    """
    current = get_status(candidate_dir)
    allowed = VALID_TRANSITIONS.get(current, set())
    if new_status not in allowed:
        raise CandidateError(
            f"Invalid transition: {current} → {new_status}. "
            f"Allowed from {current}: {allowed or 'none (terminal)'}"
        )
    _write_status(candidate_dir, new_status)


# ── Source hashing ────────────────────────────────────────────────────────────

def compute_source_hash(candidate_dir: Path) -> str:
    """
    Hash the src/ tree and record it in manifest.json.

    The recorded hash is frozen once a candidate leaves quarantine: all
    downstream evidence is bound to it, so re-recording it after
    verification would let modified source inherit evidence produced for
    different code. To change the source of a verified candidate, register
    a new candidate.
    """
    src_dir = candidate_dir / "src"
    if not src_dir.exists():
        raise CandidateError(f"src/ directory not found in {candidate_dir}")

    manifest_path = candidate_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    status_path = candidate_dir / "status.json"
    if manifest.get("source_hash") and status_path.exists():
        status = get_status(candidate_dir)
        if status != "quarantined":
            raise CandidateError(
                f"Source hash is frozen: candidate is {status!r}. "
                "Evidence is bound to the recorded hash. "
                "Register a new candidate to change the source."
            )

    source_hash = hash_directory_tree(src_dir)
    manifest["source_hash"] = source_hash
    manifest["source_hashed_at"] = _now_iso()
    _write_json(manifest_path, manifest)

    return source_hash


# ── Read ──────────────────────────────────────────────────────────────────────

def read_manifest(candidate_dir: Path) -> dict:
    manifest_path = candidate_dir / "manifest.json"
    if not manifest_path.exists():
        raise CandidateError(f"manifest.json not found in {candidate_dir}")
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def list_candidates(candidates_dir: Path) -> list[dict]:
    """Return a list of (manifest, status) dicts for all candidates."""
    results = []
    for cand_dir in sorted(candidates_dir.iterdir()):
        if not cand_dir.is_dir() or cand_dir.name.startswith("."):
            continue
        manifest_path = cand_dir / "manifest.json"
        status_path = cand_dir / "status.json"
        if manifest_path.exists() and status_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                status_data = json.loads(status_path.read_text(encoding="utf-8"))
                results.append({**manifest, **status_data})
            except json.JSONDecodeError:
                pass
    return results


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _write_status(candidate_dir: Path, status: str) -> None:
    _write_json(
        candidate_dir / "status.json",
        {"status": status, "updated_at": _now_iso()},
    )
