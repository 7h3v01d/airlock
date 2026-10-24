# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
Phase 1 — CLI skeleton tests.

Run from the repo root:
    pytest tests/test_phase1.py -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from airlock.main import app

runner = CliRunner()


# ── Helpers ───────────────────────────────────────────────────────────────────

def invoke_init(tmp_path: Path, name: str) -> tuple:
    """Run airlock init with cwd patched to tmp_path."""
    import airlock.commands.init as init_mod
    original_cwd = Path.cwd

    monkeypatched = False
    # Use a closure over tmp_path
    def fake_cwd():
        return tmp_path

    init_mod_cwd = init_mod  # reference for clarity
    # Patch Path.cwd in the init module's namespace
    result = runner.invoke(
        app, ["init", name],
        catch_exceptions=False,
        env={"KC_CWD_OVERRIDE": str(tmp_path)},
    )
    return result


# Better approach: patch via monkeypatch fixture
@pytest.fixture()
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Initialise a cleanroom project in tmp_path and return its root."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init", "myproject"], catch_exceptions=False)
    assert result.exit_code == 0, result.output
    return tmp_path / "myproject"


@pytest.fixture()
def project_with_config(project: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Project dir as cwd so find_project_root() succeeds."""
    monkeypatch.chdir(project)
    return project


# ── airlock init ───────────────────────────────────────────────────────────────────

class TestInit:
    def test_creates_directory_structure(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["init", "alpha"], catch_exceptions=False)
        assert result.exit_code == 0
        project = tmp_path / "alpha"
        for expected in ["specs", "candidates", "evidence", "trusted/src", "logs"]:
            assert (project / expected).is_dir(), f"Missing directory: {expected}"

    def test_creates_airlock_yaml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init", "beta"], catch_exceptions=False)
        assert (tmp_path / "beta" / "airlock.yaml").exists()

    def test_airlock_yaml_has_project_name(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init", "gamma"], catch_exceptions=False)
        text = (tmp_path / "gamma" / "airlock.yaml").read_text()
        assert 'name: "gamma"' in text

    def test_creates_audit_log(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init", "delta"], catch_exceptions=False)
        assert (tmp_path / "delta" / "logs" / "audit.jsonl").exists()

    def test_creates_gitignore(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init", "epsilon"], catch_exceptions=False)
        assert (tmp_path / "epsilon" / ".gitignore").exists()

    def test_creates_gitkeep_files(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init", "zeta"], catch_exceptions=False)
        for d in ["specs", "candidates", "evidence", "logs"]:
            assert (tmp_path / "zeta" / d / ".gitkeep").exists()

    def test_rejects_existing_directory(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init", "eta"], catch_exceptions=False)
        result = runner.invoke(app, ["init", "eta"], catch_exceptions=False)
        assert result.exit_code != 0
        assert "already exists" in result.output

    def test_project_name_in_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["init", "theta"], catch_exceptions=False)
        assert "theta" in result.output

    def test_success_message_shown(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["init", "iota"], catch_exceptions=False)
        assert "Project ready" in result.output


# ── airlock status ─────────────────────────────────────────────────────────────────

class TestStatus:
    def test_fails_gracefully_outside_project(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["status"], catch_exceptions=False)
        assert result.exit_code == 1
        assert "airlock.yaml" in result.output.lower() or "No cleanroom" in result.output

    def test_shows_project_name(self, project_with_config: Path) -> None:
        result = runner.invoke(app, ["status"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "myproject" in result.output

    def test_shows_risk_class(self, project_with_config: Path) -> None:
        result = runner.invoke(app, ["status"], catch_exceptions=False)
        assert "medium" in result.output

    def test_shows_network_blocked(self, project_with_config: Path) -> None:
        result = runner.invoke(app, ["status"], catch_exceptions=False)
        assert "blocked" in result.output

    def test_shows_zero_specs_initially(self, project_with_config: Path) -> None:
        result = runner.invoke(app, ["status"], catch_exceptions=False)
        assert "0 total" in result.output

    def test_shows_zero_admitted_initially(self, project_with_config: Path) -> None:
        result = runner.invoke(app, ["status"], catch_exceptions=False)
        assert "0 artefacts" in result.output

    def test_counts_locked_specs(self, project_with_config: Path) -> None:
        spec_dir = project_with_config / "specs" / "spec_0001"
        spec_dir.mkdir(parents=True)
        (spec_dir / "spec_meta.json").write_text(
            json.dumps({"id": "spec_0001", "status": "LOCKED", "version": "1"}),
            encoding="utf-8",
        )
        result = runner.invoke(app, ["status"], catch_exceptions=False)
        assert "1 total" in result.output
        assert "1 locked" in result.output

    def test_counts_candidates_by_status(self, project_with_config: Path) -> None:
        cand_dir = project_with_config / "candidates" / "candidate_0001"
        cand_dir.mkdir(parents=True)
        (cand_dir / "status.json").write_text(
            json.dumps({"status": "quarantined"}), encoding="utf-8"
        )
        result = runner.invoke(app, ["status"], catch_exceptions=False)
        assert "quarantined" in result.output


# ── airlock spec list ──────────────────────────────────────────────────────────────

class TestSpecList:
    def test_no_specs_message(self, project_with_config: Path) -> None:
        result = runner.invoke(app, ["spec", "list"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "No specs yet" in result.output

    def test_draft_spec_shown(self, project_with_config: Path) -> None:
        spec_dir = project_with_config / "specs" / "spec_0001"
        spec_dir.mkdir(parents=True)
        (spec_dir / "spec_meta.json").write_text(
            json.dumps({
                "id": "spec_0001",
                "version": "1",
                "status": "DRAFT",
                "description": "Test backup tool",
                "locked_at": None,
            }),
            encoding="utf-8",
        )
        result = runner.invoke(app, ["spec", "list"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "spec_0001" in result.output
        assert "Test backup tool" in result.output
        assert "DRAFT" in result.output

    def test_locked_spec_shown(self, project_with_config: Path) -> None:
        spec_dir = project_with_config / "specs" / "spec_0002"
        spec_dir.mkdir(parents=True)
        (spec_dir / "spec_meta.json").write_text(
            json.dumps({
                "id": "spec_0002",
                "version": "1",
                "status": "LOCKED",
                "description": "Locked spec",
                "locked_at": "2026-05-23T10:00:00+10:00",
            }),
            encoding="utf-8",
        )
        result = runner.invoke(app, ["spec", "list"], catch_exceptions=False)
        assert "LOCKED" in result.output
        assert "2026-05-23" in result.output

    def test_multiple_specs_all_shown(self, project_with_config: Path) -> None:
        for i in range(1, 4):
            spec_dir = project_with_config / "specs" / f"spec_000{i}"
            spec_dir.mkdir(parents=True)
            (spec_dir / "spec_meta.json").write_text(
                json.dumps({"id": f"spec_000{i}", "version": "1",
                             "status": "DRAFT", "description": f"Spec {i}"}),
                encoding="utf-8",
            )
        result = runner.invoke(app, ["spec", "list"], catch_exceptions=False)
        assert "3 spec(s) found" in result.output

    def test_malformed_meta_flagged(self, project_with_config: Path) -> None:
        spec_dir = project_with_config / "specs" / "spec_bad"
        spec_dir.mkdir(parents=True)
        (spec_dir / "spec_meta.json").write_text("not valid json{{{", encoding="utf-8")
        result = runner.invoke(app, ["spec", "list"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "malformed" in result.output


# ── airlock report ─────────────────────────────────────────────────────────────────

class TestReport:
    def test_missing_candidate_exits_nonzero(self, project_with_config: Path) -> None:
        result = runner.invoke(app, ["report", "candidate_0099"], catch_exceptions=False)
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_quarantined_candidate_no_evidence(self, project_with_config: Path) -> None:
        cand_dir = project_with_config / "candidates" / "candidate_0001"
        cand_dir.mkdir(parents=True)
        (cand_dir / "status.json").write_text(
            json.dumps({"status": "quarantined"}), encoding="utf-8"
        )
        (cand_dir / "manifest.json").write_text(
            json.dumps({"spec_id": "spec_0001", "language": "python"}), encoding="utf-8"
        )
        result = runner.invoke(app, ["report", "candidate_0001"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "quarantined" in result.output
        assert "spec_0001" in result.output
        assert "not yet produced" in result.output or "No evidence" in result.output

    def test_report_shows_admission_certificate(self, project_with_config: Path) -> None:
        cand_dir = project_with_config / "candidates" / "candidate_0001"
        cand_dir.mkdir(parents=True)
        (cand_dir / "status.json").write_text(
            json.dumps({"status": "admitted"}), encoding="utf-8"
        )
        (cand_dir / "manifest.json").write_text(
            json.dumps({"spec_id": "spec_0001", "language": "python"}), encoding="utf-8"
        )
        evidence_dir = project_with_config / "evidence" / "candidate_0001"
        evidence_dir.mkdir(parents=True)
        cert = {
            "certificate_id": "al-cert-2026-000001",
            "level": "L3_TEST_CERTIFIED",
            "admitted": True,
            "admitted_at": "2026-05-23T10:45:00+10:00",
        }
        (evidence_dir / "admission_certificate.json").write_text(
            json.dumps(cert), encoding="utf-8"
        )
        result = runner.invoke(app, ["report", "candidate_0001"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "ADMITTED" in result.output
        assert "al-cert-2026-000001" in result.output
        assert "L3_TEST_CERTIFIED" in result.output

    def test_report_shows_verifier_verdict(self, project_with_config: Path) -> None:
        cand_dir = project_with_config / "candidates" / "candidate_0001"
        cand_dir.mkdir(parents=True)
        (cand_dir / "status.json").write_text(json.dumps({"status": "verified"}), encoding="utf-8")
        (cand_dir / "manifest.json").write_text(
            json.dumps({"spec_id": "spec_0001", "language": "python"}), encoding="utf-8"
        )
        evidence_dir = project_with_config / "evidence" / "candidate_0001"
        evidence_dir.mkdir(parents=True)
        (evidence_dir / "static_verification.json").write_text(
            json.dumps({"verdict": "PASS", "rules_passed": 24, "rules_failed": 0}),
            encoding="utf-8",
        )
        result = runner.invoke(app, ["report", "candidate_0001"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "PASS" in result.output
        assert "Verifier report" in result.output
