# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock.dashboard.reader

Reads all cleanroom project data for the dashboard.
All reads are non-destructive — no writes, no transitions.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from airlock.core.hashing import verify_sidecar


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class SpecSummary:
    spec_id: str
    status: str
    description: str
    spec_hash: str
    created_at: str
    locked_at: str


@dataclass
class EvidenceItem:
    document: str
    present: bool
    sidecar_ok: bool
    sidecar_msg: str
    verdict: str
    path: str


@dataclass
class CandidateSummary:
    candidate_id: str
    spec_id: str
    status: str
    language: str
    generated_by: str
    source_hash: str
    registered_at: str
    evidence: list[EvidenceItem] = field(default_factory=list)
    certificate_id: str = ""
    level: str = ""
    admitted_at: str = ""
    operator_override: bool = False
    override_operator: str = ""
    override_reason: str = ""


@dataclass
class AuditEntry:
    event: str
    timestamp: str
    candidate_id: str
    spec_id: str
    decision: str
    gate_id: str
    certificate_id: str
    operator_id: str
    reasons: list[str] = field(default_factory=list)
    overridden_decision: str = ""
    reason: str = ""


@dataclass
class ProjectOverview:
    project_name: str
    risk_class: str
    total_specs: int
    locked_specs: int
    total_candidates: int
    by_status: dict[str, int]
    admitted_count: int
    last_activity: str


# ── Reader ────────────────────────────────────────────────────────────────────

class ProjectReader:
    """Reads all cleanroom project data. All operations are read-only."""

    def __init__(self, project_root: Path) -> None:
        self.root = project_root

    def overview(self) -> ProjectOverview:
        """Return high-level project summary."""
        config = self._load_yaml()
        project_name = config.get("project", {}).get("name", self.root.name)
        risk_class = config.get("project", {}).get("risk_class", "medium")

        specs = self._list_specs()
        candidates = self._list_candidates_raw()

        by_status: dict[str, int] = {}
        for c in candidates:
            s = c.get("status", "unknown")
            by_status[s] = by_status.get(s, 0) + 1

        last_activity = self._last_audit_timestamp()

        return ProjectOverview(
            project_name=project_name,
            risk_class=risk_class,
            total_specs=len(specs),
            locked_specs=sum(1 for s in specs if s.status == "LOCKED"),
            total_candidates=len(candidates),
            by_status=by_status,
            admitted_count=by_status.get("admitted", 0),
            last_activity=last_activity,
        )

    def specs(self) -> list[SpecSummary]:
        return self._list_specs()

    def candidates(self) -> list[CandidateSummary]:
        results = []
        candidates_dir = self.root / "candidates"
        if not candidates_dir.exists():
            return results

        for cdir in sorted(candidates_dir.iterdir()):
            if not cdir.is_dir() or cdir.name.startswith("."):
                continue
            summary = self._read_candidate(cdir)
            if summary:
                results.append(summary)
        return results

    def candidate_detail(self, candidate_id: str) -> CandidateSummary | None:
        base = (self.root / "candidates").resolve()
        cdir = (base / candidate_id).resolve()
        # Path traversal guard: resolved path must be inside candidates/
        if base not in cdir.parents:
            return None
        if not cdir.exists():
            return None
        return self._read_candidate(cdir)

    def audit_log(self) -> list[AuditEntry]:
        log_path = self.root / "logs" / "audit.jsonl"
        if not log_path.exists():
            return []
        entries = []
        for line in log_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                entries.append(AuditEntry(
                    event=data.get("event", ""),
                    timestamp=data.get("timestamp", ""),
                    candidate_id=data.get("candidate_id", ""),
                    spec_id=data.get("spec_id", ""),
                    decision=data.get("decision", ""),
                    gate_id=data.get("gate_id", ""),
                    certificate_id=data.get("certificate_id", ""),
                    operator_id=data.get("operator_id", ""),
                    reasons=data.get("reasons", []),
                    overridden_decision=data.get("overridden_decision", ""),
                    reason=data.get("reason", ""),
                ))
            except (json.JSONDecodeError, KeyError):
                continue
        return list(reversed(entries))  # most recent first

    def llm_calls(self) -> list[dict]:
        log_path = self.root / "logs" / "llm_calls.jsonl"
        if not log_path.exists():
            return []
        entries = []
        for line in log_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return list(reversed(entries))

    # ── Private ───────────────────────────────────────────────────────────────

    def _list_specs(self) -> list[SpecSummary]:
        specs_dir = self.root / "specs"
        results = []
        if not specs_dir.exists():
            return results
        for sdir in sorted(specs_dir.iterdir()):
            if not sdir.is_dir() or sdir.name.startswith("."):
                continue
            meta = self._load_json(sdir / "spec_meta.json")
            if not meta:
                continue
            results.append(SpecSummary(
                spec_id=sdir.name,
                status=meta.get("status", "UNKNOWN"),
                description=meta.get("description", ""),
                spec_hash=meta.get("spec_hash", ""),
                created_at=meta.get("created_at", ""),
                locked_at=meta.get("locked_at", ""),
            ))
        return results

    def _list_candidates_raw(self) -> list[dict]:
        candidates_dir = self.root / "candidates"
        results = []
        if not candidates_dir.exists():
            return results
        for cdir in sorted(candidates_dir.iterdir()):
            if not cdir.is_dir() or cdir.name.startswith("."):
                continue
            manifest = self._load_json(cdir / "manifest.json")
            status_data = self._load_json(cdir / "status.json")
            if manifest:
                manifest["status"] = status_data.get("status", "unknown") if status_data else "unknown"
                results.append(manifest)
        return results

    def _read_candidate(self, cdir: Path) -> CandidateSummary | None:
        manifest = self._load_json(cdir / "manifest.json")
        if not manifest:
            return None
        status_data = self._load_json(cdir / "status.json")
        status = status_data.get("status", "unknown") if status_data else "unknown"

        evidence_dir = self.root / "evidence" / cdir.name
        evidence_items = self._read_evidence(evidence_dir)

        # Certificate info
        cert_id = ""
        level = ""
        admitted_at = ""
        cert_data = self._load_json(evidence_dir / "admission_certificate.json")
        if cert_data:
            cert_id = cert_data.get("certificate_id", "")
            level = cert_data.get("level", "")
            admitted_at = cert_data.get("admitted_at", "")

        return CandidateSummary(
            candidate_id=cdir.name,
            spec_id=manifest.get("spec_id", ""),
            status=status,
            language=manifest.get("language", "python"),
            generated_by=manifest.get("generated_by", "manual"),
            source_hash=manifest.get("source_hash", ""),
            registered_at=manifest.get("registered_at") or manifest.get("created_at", ""),
            evidence=evidence_items,
            certificate_id=cert_id,
            level=level,
            admitted_at=admitted_at,
            operator_override=bool((cert_data or {}).get("operator_override")),
            override_operator=(cert_data or {}).get("override_operator", ""),
            override_reason=(cert_data or {}).get("override_reason", ""),
        )

    def _read_evidence(self, evidence_dir: Path) -> list[EvidenceItem]:
        documents = [
            ("generation_manifest.json", "generation_manifest", ""),
            ("static_verification.json", "static_verification", "verdict"),
            ("test_report.json", "test_report", "certification"),
            ("coverage_report.json", "coverage_report", ""),
            ("gate_decision.json", "gate_decision", "decision"),
            ("admission_certificate.json", "admission_certificate", "level"),
        ]
        items = []
        for filename, doc_name, verdict_field in documents:
            path = evidence_dir / filename
            if not path.exists():
                items.append(EvidenceItem(
                    document=filename,
                    present=False,
                    sidecar_ok=False,
                    sidecar_msg="not produced",
                    verdict="",
                    path="",
                ))
                continue

            ok, msg = verify_sidecar(path)
            data = self._load_json(path) or {}
            verdict = data.get(verdict_field, "") if verdict_field else ""

            items.append(EvidenceItem(
                document=filename,
                present=True,
                sidecar_ok=ok,
                sidecar_msg=msg,
                verdict=str(verdict),
                path=str(path.relative_to(evidence_dir.parent.parent)),
            ))
        return items

    def _last_audit_timestamp(self) -> str:
        log_path = self.root / "logs" / "audit.jsonl"
        if not log_path.exists():
            return ""
        lines = [l for l in log_path.read_text(encoding="utf-8").splitlines() if l.strip()]
        if not lines:
            return ""
        try:
            return json.loads(lines[-1]).get("timestamp", "")
        except (json.JSONDecodeError, KeyError):
            return ""

    def _load_json(self, path: Path) -> dict | None:
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def _load_yaml(self) -> dict:
        try:
            import yaml
            from airlock.config import config_path_for
            config_path = config_path_for(self.root)
            if config_path is not None:
                return yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except Exception:
            pass
        return {}
