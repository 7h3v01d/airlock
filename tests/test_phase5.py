# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
Phase 5 — Governance gate and admission tests.

Run from the repo root:
    pytest tests/test_phase5.py -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from airlock.main import app
from airlock.core.spec_store import create_spec, lock_spec
from airlock.core.candidate_store import register_candidate, transition_status
from airlock.core.hashing import write_sidecar
from airlock.core.governance.gate import (
    run_gate, run_admission, AdmissionError,
    ALLOW, DENY, QUARANTINE,
)

runner = CliRunner()


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init", "myproject"], catch_exceptions=False)
    project_dir = tmp_path / "myproject"
    monkeypatch.chdir(project_dir)
    return project_dir


@pytest.fixture()
def locked_spec(project: Path) -> str:
    specs_dir = project / "specs"
    spec_id, spec_dir = create_spec(specs_dir, "Test tool")
    (spec_dir / "spec.md").write_text(
        "# spec\n\n## Functional requirements\n\nDo work.\n\n"
        "## Non-functional requirements\n\nOffline.\n\n"
        "## Forbidden behaviours\n\nNo network.\n\n"
        "## Acceptance criteria\n\nIt works.\n",
        encoding="utf-8",
    )
    lock_spec(specs_dir, spec_id)
    return spec_id


def _sign(path: Path) -> None:
    from airlock.core import signing
    signing.sign_file(path, signing.load_signer())


def _make_fully_evidenced_candidate(project: Path, locked_spec: str) -> Path:
    """Create a candidate with all evidence documents present and passing."""
    candidates_dir = project / "candidates"
    _, cdir = register_candidate(candidates_dir, locked_spec)
    (cdir / "src" / "main.py").write_text('"""Main module."""\n\nx: int = 1\n', encoding="utf-8")
    (cdir / "tests" / "test_main.py").write_text("def test_x():\n    assert True\n", encoding="utf-8")

    # Write manifest with real source hash
    from airlock.core.hashing import hash_directory_tree as _hdt
    manifest_path = cdir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["source_hash"] = _hdt(cdir / "src")
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    evidence_dir = project / "evidence" / cdir.name
    evidence_dir.mkdir(parents=True)

    # Verifier report — PASS (with detached sidecar)
    ver = {"verdict": "PASS", "blocking_failures": 0, "source_hash": manifest["source_hash"]}
    ver_path = evidence_dir / "static_verification.json"
    ver_path.write_text(json.dumps(ver), encoding="utf-8")
    write_sidecar(ver_path)
    _sign(ver_path)  # v0.4: valid evidence is signed

    # Test report — CERTIFIED (with detached sidecar)
    test = {"certification": "CERTIFIED", "passed": 5, "failed": 0, "source_hash": manifest["source_hash"]}
    test_path = evidence_dir / "test_report.json"
    test_path.write_text(json.dumps(test), encoding="utf-8")
    write_sidecar(test_path)
    _sign(test_path)  # v0.4: valid evidence is signed

    # Coverage report (with detached sidecar)
    cov = {"line_coverage": 0.85, "branch_coverage": 0.75, "source_hash": manifest["source_hash"]}
    cov_path = evidence_dir / "coverage_report.json"
    cov_path.write_text(json.dumps(cov), encoding="utf-8")
    write_sidecar(cov_path)
    _sign(cov_path)  # v0.4: valid evidence is signed

    transition_status(cdir, "verified")
    transition_status(cdir, "certified")
    return cdir


def _make_missing_evidence_candidate(project: Path, locked_spec: str) -> Path:
    """Candidate with no evidence documents."""
    candidates_dir = project / "candidates"
    _, cdir = register_candidate(candidates_dir, locked_spec)
    transition_status(cdir, "verified")
    transition_status(cdir, "certified")
    return cdir


def _make_failing_verifier_candidate(project: Path, locked_spec: str) -> Path:
    """Candidate whose verifier report shows FAIL."""
    candidates_dir = project / "candidates"
    _, cdir = register_candidate(candidates_dir, locked_spec)
    (cdir / "src" / "main.py").write_text('"""Main module."""\n\nx: int = 1\n', encoding="utf-8")
    from airlock.core.hashing import hash_directory_tree as _hdt
    manifest_path = cdir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["source_hash"] = _hdt(cdir / "src")
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    evidence_dir = project / "evidence" / cdir.name
    evidence_dir.mkdir(parents=True)
    ver = {"verdict": "FAIL", "blocking_failures": 1}
    ver_path = evidence_dir / "static_verification.json"
    ver_path.write_text(json.dumps(ver), encoding="utf-8")
    write_sidecar(ver_path)
    _sign(ver_path)  # v0.4: valid evidence is signed
    test = {"certification": "CERTIFIED"}
    test_path = evidence_dir / "test_report.json"
    test_path.write_text(json.dumps(test), encoding="utf-8")
    write_sidecar(test_path)
    _sign(test_path)  # v0.4: valid evidence is signed
    cov = {"line_coverage": 0.8}
    cov_path = evidence_dir / "coverage_report.json"
    cov_path.write_text(json.dumps(cov), encoding="utf-8")
    write_sidecar(cov_path)
    _sign(cov_path)  # v0.4: valid evidence is signed

    transition_status(cdir, "verified")
    transition_status(cdir, "certified")
    return cdir


# ── Gate runner unit tests ────────────────────────────────────────────────────

class TestGateRunner:
    def test_allow_on_complete_passing_evidence(self, project: Path, locked_spec: str) -> None:
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        decision = run_gate(cdir, project, {})
        assert decision.decision == ALLOW

    def test_quarantine_on_missing_evidence(self, project: Path, locked_spec: str) -> None:
        cdir = _make_missing_evidence_candidate(project, locked_spec)
        decision = run_gate(cdir, project, {})
        assert decision.decision == QUARANTINE

    def test_deny_on_failing_verifier(self, project: Path, locked_spec: str) -> None:
        cdir = _make_failing_verifier_candidate(project, locked_spec)
        decision = run_gate(cdir, project, {})
        assert decision.decision == DENY

    def test_gate_writes_decision_file(self, project: Path, locked_spec: str) -> None:
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        run_gate(cdir, project, {})
        gate_path = project / "evidence" / cdir.name / "gate_decision.json"
        assert gate_path.exists()
        data = json.loads(gate_path.read_text())
        assert "decision" in data
        sidecar = gate_path.with_suffix(gate_path.suffix + ".sha256")
        assert sidecar.exists()

    def test_gate_appends_to_audit_log(self, project: Path, locked_spec: str) -> None:
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        run_gate(cdir, project, {})
        audit = project / "logs" / "audit.jsonl"
        assert audit.exists()
        lines = [json.loads(l) for l in audit.read_text().splitlines() if l.strip()]
        gate_entries = [l for l in lines if l.get("event") == "gate_decision"]
        assert gate_entries

    def test_gate_records_gate_id(self, project: Path, locked_spec: str) -> None:
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        decision = run_gate(cdir, project, {})
        assert decision.gate_id.startswith("gate-")

    def test_gate_records_evidence_consumed(self, project: Path, locked_spec: str) -> None:
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        decision = run_gate(cdir, project, {})
        assert "static_verification.json" in decision.evidence_consumed
        assert "test_report.json" in decision.evidence_consumed

    def test_gate_hash_sealed(self, project: Path, locked_spec: str) -> None:
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        decision = run_gate(cdir, project, {})
        assert decision.evidence_hash.startswith("sha256:")

    def test_deny_populates_reasons(self, project: Path, locked_spec: str) -> None:
        cdir = _make_failing_verifier_candidate(project, locked_spec)
        decision = run_gate(cdir, project, {})
        assert len(decision.reasons) > 0


# ── Admission unit tests ──────────────────────────────────────────────────────

class TestAdmission:
    def test_admission_copies_to_trusted_tree(self, project: Path, locked_spec: str) -> None:
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        run_gate(cdir, project, {})
        run_admission(cdir, project)
        trusted = project / "trusted" / "src" / cdir.name
        assert trusted.exists()
        assert (trusted / "main.py").exists()

    def test_admission_issues_certificate(self, project: Path, locked_spec: str) -> None:
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        run_gate(cdir, project, {})
        cert = run_admission(cdir, project)
        assert cert["admitted"] is True
        assert cert["level"] == "L4_GOVERNANCE_ADMITTED"
        assert cert["certificate_id"].startswith("al-cert-")

    def test_admission_writes_certificate_file(self, project: Path, locked_spec: str) -> None:
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        run_gate(cdir, project, {})
        run_admission(cdir, project)
        cert_path = project / "evidence" / cdir.name / "admission_certificate.json"
        assert cert_path.exists()
        data = json.loads(cert_path.read_text())
        sidecar = cert_path.with_suffix(cert_path.suffix + ".sha256")
        assert sidecar.exists()
        assert "admitted" in data

    def test_admission_appends_audit_log(self, project: Path, locked_spec: str) -> None:
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        run_gate(cdir, project, {})
        run_admission(cdir, project)
        audit = project / "logs" / "audit.jsonl"
        lines = [json.loads(l) for l in audit.read_text().splitlines() if l.strip()]
        admit_entries = [l for l in lines if l.get("event") == "candidate_admitted"]
        assert admit_entries

    def test_admission_fails_without_gate(self, project: Path, locked_spec: str) -> None:
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        with pytest.raises(AdmissionError, match="gate_decision"):
            run_admission(cdir, project)

    def test_admission_fails_on_deny_decision(self, project: Path, locked_spec: str) -> None:
        cdir = _make_failing_verifier_candidate(project, locked_spec)
        run_gate(cdir, project, {})
        with pytest.raises(AdmissionError, match="DENY"):
            run_admission(cdir, project)

    def test_certificate_links_hashes(self, project: Path, locked_spec: str) -> None:
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        run_gate(cdir, project, {})
        cert = run_admission(cdir, project)
        assert "source_tree" in cert["hashes"]
        assert "spec" in cert["hashes"]
        assert "gate_decision" in cert["hashes"]


# ── CLI tests ─────────────────────────────────────────────────────────────────

class TestGateCLI:
    def test_gate_allow_exits_zero(self, project: Path, locked_spec: str) -> None:
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        result = runner.invoke(app, ["gate", cdir.name], catch_exceptions=False)
        assert result.exit_code == 0
        assert "ALLOW" in result.output

    def test_gate_quarantine_exits_nonzero(self, project: Path, locked_spec: str) -> None:
        cdir = _make_missing_evidence_candidate(project, locked_spec)
        result = runner.invoke(app, ["gate", cdir.name], catch_exceptions=False)
        assert result.exit_code == 1

    def test_gate_deny_exits_nonzero(self, project: Path, locked_spec: str) -> None:
        cdir = _make_failing_verifier_candidate(project, locked_spec)
        result = runner.invoke(app, ["gate", cdir.name], catch_exceptions=False)
        assert result.exit_code == 1

    def test_gate_missing_candidate_exits(self, project: Path) -> None:
        result = runner.invoke(app, ["gate", "candidate_9999"], catch_exceptions=False)
        assert result.exit_code == 1

    def test_gate_shows_evidence_checks(self, project: Path, locked_spec: str) -> None:
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        result = runner.invoke(app, ["gate", cdir.name], catch_exceptions=False)
        assert "static_verification.json" in result.output
        assert "test_report.json" in result.output

    def test_gate_writes_decision_file(self, project: Path, locked_spec: str) -> None:
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        runner.invoke(app, ["gate", cdir.name], catch_exceptions=False)
        assert (project / "evidence" / cdir.name / "gate_decision.json").exists()


class TestAdmitCLI:
    def test_admit_after_allow_gate(self, project: Path, locked_spec: str) -> None:
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        runner.invoke(app, ["gate", cdir.name], catch_exceptions=False)
        result = runner.invoke(app, ["admit", cdir.name], catch_exceptions=False)
        assert result.exit_code == 0
        assert "admitted" in result.output.lower()

    def test_admit_advances_status(self, project: Path, locked_spec: str) -> None:
        from airlock.core.candidate_store import get_status
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        runner.invoke(app, ["gate", cdir.name], catch_exceptions=False)
        runner.invoke(app, ["admit", cdir.name], catch_exceptions=False)
        assert get_status(cdir) == "admitted"

    def test_admit_writes_certificate(self, project: Path, locked_spec: str) -> None:
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        runner.invoke(app, ["gate", cdir.name], catch_exceptions=False)
        runner.invoke(app, ["admit", cdir.name], catch_exceptions=False)
        cert_path = project / "evidence" / cdir.name / "admission_certificate.json"
        assert cert_path.exists()

    def test_admit_without_gate_fails(self, project: Path, locked_spec: str) -> None:
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        result = runner.invoke(app, ["admit", cdir.name], catch_exceptions=False)
        assert result.exit_code == 1

    def test_admit_shows_certificate_id(self, project: Path, locked_spec: str) -> None:
        cdir = _make_fully_evidenced_candidate(project, locked_spec)
        runner.invoke(app, ["gate", cdir.name], catch_exceptions=False)
        result = runner.invoke(app, ["admit", cdir.name], catch_exceptions=False)
        assert "al-cert-" in result.output

    def test_admit_missing_candidate_fails(self, project: Path) -> None:
        result = runner.invoke(app, ["admit", "candidate_9999"], catch_exceptions=False)
        assert result.exit_code == 1
