# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock.core.hashing

Canonical hashing for all cleanroom artefacts.
SHA-256, hex digest, always UTF-8 for text content.

Evidence integrity model (v0.2):
  - Each evidence document is written WITHOUT an evidence_hash field
  - A detached sidecar file (<name>.sha256) is written alongside it
  - The sidecar contains the SHA-256 of the evidence file's raw bytes
  - Verification recomputes the hash and compares against the sidecar
  - A tampered evidence file will not match its sidecar

This is a detached-hash model. The hash is never inside the file it
covers — so the file cannot lie about its own integrity.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


# ── Core hash functions ───────────────────────────────────────────────────────

def hash_file(path: Path) -> str:
    """SHA-256 hash of a file's raw bytes."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def hash_text(text: str) -> str:
    """SHA-256 hash of a UTF-8 string."""
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def hash_dict(data: dict) -> str:
    """SHA-256 hash of a JSON-serialised dict (sorted keys, no whitespace)."""
    serialised = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hash_text(serialised)


TREE_HASH_DOMAIN = b"airlock-tree-v2\0"


def _tree_files(root: Path, glob: str = "**/*") -> list[Path]:
    """Files covered by a tree hash, sorted by forward-slash relative path."""
    files = [
        path for path in root.glob(glob)
        # Exclude sidecar files, Python cache, and coverage artefacts
        if (path.is_file()
            and path.suffix != ".sha256"
            and "__pycache__" not in path.parts
            and not path.name.startswith(".coverage"))
    ]
    return sorted(files, key=lambda p: p.relative_to(root).as_posix())


def hash_directory_tree(root: Path, glob: str = "**/*") -> str:
    """
    SHA-256 hash of all files under root, sorted by relative path.
    Stable across platforms: uses forward-slash relative paths.
    Excludes .sha256 sidecar files, __pycache__ and coverage artefacts.

    Framing (v2): a domain tag, then for each file the length-prefixed
    relative path followed by the length-prefixed content. Without the
    length prefixes, file "a" containing "bX" and file "ab" containing "X"
    produced the same hash (the v0.2 format).
    """
    h = hashlib.sha256(TREE_HASH_DOMAIN)
    for path in _tree_files(root, glob):
        rel = path.relative_to(root).as_posix().encode("utf-8")
        h.update(len(rel).to_bytes(8, "big"))
        h.update(rel)
        h.update(path.stat().st_size.to_bytes(8, "big"))
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def tree_files(root: Path) -> list[Path]:
    """Public view of exactly the files a tree hash covers."""
    return _tree_files(root)


def find_unhashed_files(root: Path) -> list[str]:
    """
    Relative paths of files under root that a tree hash does NOT cover
    (__pycache__ contents, .sha256 files, coverage data).

    These must never be present in a candidate's src/: they would be
    importable (a forged .pyc runs instead of its verified source) yet
    invisible to both the hash and the verifier.
    """
    if not root.exists():
        return []
    covered = set(_tree_files(root))
    return sorted(
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file() and p not in covered
    )


def find_symlinks(root: Path) -> list[str]:
    """Relative paths of any symlinks under root (files or directories)."""
    if not root.exists():
        return []
    return sorted(
        p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_symlink()
    )


# ── Detached sidecar model ────────────────────────────────────────────────────

def write_sidecar(evidence_path: Path) -> str:
    """
    Compute the SHA-256 of an evidence file and write a detached sidecar.

    The sidecar is written to <evidence_path>.sha256 and contains only
    the hex digest (no prefix), for easy shell verification:
        sha256sum --check file.json.sha256

    Returns the full "sha256:<hex>" string.
    """
    digest = hash_file(evidence_path)
    hex_only = digest.removeprefix("sha256:")
    sidecar_path = evidence_path.with_suffix(evidence_path.suffix + ".sha256")
    sidecar_path.write_text(
        f"{hex_only}  {evidence_path.name}\n",
        encoding="utf-8",
    )
    return digest


def verify_sidecar(evidence_path: Path) -> tuple[bool, str]:
    """
    Verify an evidence file against its detached sidecar.

    Returns (ok, message):
      (True,  "ok")                          — file matches sidecar
      (False, "sidecar missing")             — no .sha256 file found
      (False, "hash mismatch: ...")          — file has been modified
      (False, "sidecar malformed")           — sidecar cannot be parsed
    """
    sidecar_path = evidence_path.with_suffix(evidence_path.suffix + ".sha256")

    if not sidecar_path.exists():
        return False, "sidecar missing"

    try:
        sidecar_content = sidecar_path.read_text(encoding="utf-8").strip()
        # Format: "<hex>  <filename>"
        stored_hex = sidecar_content.split()[0]
    except (OSError, IndexError):
        return False, "sidecar malformed"

    current_digest = hash_file(evidence_path)
    current_hex = current_digest.removeprefix("sha256:")

    if current_hex != stored_hex:
        return False, f"hash mismatch: expected {stored_hex[:16]}... got {current_hex[:16]}..."

    return True, "ok"


def seal_evidence(path: Path, data: dict, signer: "object | None" = None) -> str:
    """
    Write an evidence document and create its detached sidecar.

    The data dict must NOT contain an 'evidence_hash' field — the hash
    is stored only in the sidecar, never inside the document itself.

    Returns the "sha256:<hex>" digest.
    """
    if "evidence_hash" in data:
        raise ValueError(
            "evidence_hash must not be embedded in evidence documents. "
            "Use the detached sidecar model: seal_evidence() writes the "
            "hash to <filename>.sha256, not inside the JSON."
        )

    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    digest = write_sidecar(path)
    if signer is not None:
        from airlock.core.signing import sign_file
        sign_file(path, signer)
    else:
        # Never leave a stale signature describing earlier content.
        stale = path.with_suffix(path.suffix + ".sig")
        if stale.exists():
            stale.unlink()
    return digest
