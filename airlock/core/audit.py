# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock.core.audit

Append-only, hash-chained audit log (logs/audit.jsonl).

Each entry carries:
    seq          1, 2, 3, ... with no gaps
    prev_hash    entry_hash of the previous entry ("genesis" for the first)
    entry_hash   SHA-256 of the canonical JSON of the entry without
                 entry_hash and sig
    sig          optional Ed25519 signature over entry_hash (operator key)

Editing, inserting, reordering or deleting an entry breaks the chain.
Cutting entries off the *end* leaves a valid shorter chain, so the head of
the chain is also anchored in the operator's Airlock home
(anchors/<project_id>.json); a log shorter than its anchor, or whose entry
at the anchored position differs, is reported as tampered.

Entries written before v0.4 have no chain fields. They are tolerated only as
a prefix of the log and are reported as legacy (unverifiable).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from airlock.core import signing

GENESIS = "genesis"
_CHAIN_FIELDS = ("seq", "prev_hash", "entry_hash", "sig")


def audit_path(project_root: Path) -> Path:
    return project_root / "logs" / "audit.jsonl"


def project_id(project_root: Path) -> str:
    """Stable random id for this project, created on first use."""
    path = project_root / "logs" / "project_id"
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    path.parent.mkdir(parents=True, exist_ok=True)
    value = uuid.uuid4().hex
    path.write_text(value + "\n", encoding="utf-8")
    return value


def _anchor_path(project_root: Path) -> Path:
    return signing.airlock_home() / "anchors" / f"{project_id(project_root)}.json"


def _canonical(entry: dict) -> bytes:
    body = {k: v for k, v in entry.items() if k not in ("entry_hash", "sig")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_entry_hash(entry: dict) -> str:
    return "sha256:" + hashlib.sha256(_canonical(entry)).hexdigest()


def _read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _last_chained(path: Path) -> dict | None:
    for line in reversed(_read_lines(path)):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return None
        if "entry_hash" in entry:
            return entry
        return None   # a legacy line after chained ones is itself tampering
    return None


def append_entry(project_root: Path, entry: dict, signer: signing.Signer | None = None) -> dict:
    """Append a chained (and, with a signer, signed) entry. Returns the entry written."""
    path = audit_path(project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {k: v for k, v in entry.items() if k not in _CHAIN_FIELDS}
    last = _last_chained(path)
    data["seq"] = (int(last["seq"]) + 1) if last else 1
    data["prev_hash"] = last["entry_hash"] if last else GENESIS
    data["entry_hash"] = compute_entry_hash(data)
    if signer is not None:
        data["sig"] = signing.sign_audit_hash(data["entry_hash"], signer)
    anchor_ok = _anchor_consistent(project_root)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(data, ensure_ascii=False) + "\n")
    # Never move the anchor onto a chain that contradicts it: after a
    # truncation or rewrite the old anchor must stay as evidence, otherwise
    # the next logged event would silently bless the shortened history.
    if anchor_ok:
        _write_anchor(project_root, data["seq"], data["entry_hash"])
    return data


def _anchor_consistent(project_root: Path) -> bool:
    """True if there is no anchor yet, or the current chain still contains it."""
    anchor_file = _anchor_path(project_root)
    if not anchor_file.exists():
        return True
    try:
        anchor = json.loads(anchor_file.read_text(encoding="utf-8"))
        a_seq, a_hash = int(anchor["seq"]), anchor["entry_hash"]
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return False
    chained = []
    for line in _read_lines(audit_path(project_root)):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return False
        if "entry_hash" in entry:
            chained.append(entry)
    return a_seq <= len(chained) and chained[a_seq - 1].get("entry_hash") == a_hash


def _write_anchor(project_root: Path, seq: int, entry_hash: str) -> None:
    anchor = _anchor_path(project_root)
    try:
        anchor.parent.mkdir(parents=True, exist_ok=True)
        anchor.write_text(
            json.dumps({"seq": seq, "entry_hash": entry_hash,
                        "project_root": str(project_root.resolve())}, indent=2),
            encoding="utf-8",
        )
    except OSError:
        pass   # verification reports a missing/stale anchor


def reanchor(project_root: Path) -> "AuditStatus":
    """Operator action: accept the current head as the anchor (e.g. after moving machines)."""
    status = verify_chain(project_root, require_signatures=False, check_anchor=False)
    if status.problems:
        return status
    if status.head_seq:
        _write_anchor(project_root, status.head_seq, status.head_hash)
    return verify_chain(project_root, require_signatures=False)


@dataclass
class AuditStatus:
    entries: int = 0
    legacy_entries: int = 0
    signed_entries: int = 0
    head_seq: int = 0
    head_hash: str = ""
    anchored: bool = False
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def verify_chain(
    project_root: Path,
    require_signatures: bool = False,
    check_anchor: bool = True,
) -> AuditStatus:
    status = AuditStatus()
    entries: list[dict] = []
    seen_chained = False
    for n, line in enumerate(_read_lines(audit_path(project_root)), start=1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            status.problems.append(f"line {n}: not valid JSON")
            continue
        if "entry_hash" not in entry:
            if seen_chained:
                status.problems.append(f"line {n}: unchained entry after the chain started")
            else:
                status.legacy_entries += 1
            continue
        seen_chained = True
        entries.append(entry)

    prev = GENESIS
    for i, entry in enumerate(entries, start=1):
        label = f"entry seq={entry.get('seq')}"
        if entry.get("seq") != i:
            status.problems.append(f"{label}: expected seq {i} (entry missing, inserted or reordered)")
        if entry.get("prev_hash") != prev:
            status.problems.append(f"{label}: prev_hash does not match the previous entry")
        if compute_entry_hash(entry) != entry.get("entry_hash"):
            status.problems.append(f"{label}: content does not match its entry_hash (edited)")
        sig = entry.get("sig")
        if sig:
            ok, msg = signing.verify_audit_hash(entry.get("entry_hash", ""), sig)
            if ok:
                status.signed_entries += 1
            else:
                status.problems.append(f"{label}: {msg}")
        elif require_signatures:
            status.problems.append(f"{label}: unsigned, but signatures are required")
        prev = entry.get("entry_hash", "")

    status.entries = len(entries)
    if entries:
        status.head_seq = int(entries[-1].get("seq") or 0)
        status.head_hash = entries[-1].get("entry_hash", "")

    if check_anchor:
        anchor_file = _anchor_path(project_root)
        if anchor_file.exists():
            try:
                anchor = json.loads(anchor_file.read_text(encoding="utf-8"))
                a_seq, a_hash = int(anchor["seq"]), anchor["entry_hash"]
            except (OSError, ValueError, KeyError, json.JSONDecodeError):
                status.problems.append("audit anchor is unreadable")
            else:
                status.anchored = True
                if a_seq > len(entries):
                    status.problems.append(
                        f"log ends at seq {len(entries)} but was anchored at seq {a_seq} (truncated)"
                    )
                elif entries[a_seq - 1].get("entry_hash") != a_hash:
                    status.problems.append(f"entry seq={a_seq} differs from the anchored head (rewritten)")
        elif entries and require_signatures:
            status.problems.append(
                "no anchor for this project in the operator's Airlock home "
                "(review the log, then run: airlock audit verify --reanchor)"
            )
    return status
