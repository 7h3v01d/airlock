# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
Phase 4 — Test certifier tests.

Run from the repo root:
    pytest tests/test_phase4.py -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from airlock.main import app
from airlock.core.spec_store import create_spec, lock_spec
from airlock.core.candidate_store import register_candidate, transition_status, compute_source_hash
from airlock.core.certifier.runner import run_certification

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


def _make_passing_candidate(project: Path, locked_spec: str) -> Path:
    """Create a candidate with passing tests."""
    candidates_dir = project / "candidates"
    _, cdir = register_candidate(candidates_dir, locked_spec)

    (cdir / "src" / "calculator.py").write_text(
        '"""Simple calculator module."""\n\n\n'
        "def add(a: int, b: int) -> int:\n"
        '    """Add two numbers."""\n'
        "    return a + b\n\n\n"
        "def subtract(a: int, b: int) -> int:\n"
        '    """Subtract b from a."""\n'
        "    return a - b\n",
        encoding="utf-8",
    )
    (cdir / "tests" / "test_calculator.py").write_text(
        "import sys\n"
        "from pathlib import Path\n"
        "sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))\n"
        "from calculator import add, subtract\n\n"
        "def test_add():\n"
        "    assert add(1, 2) == 3\n\n"
        "def test_subtract():\n"
        "    assert subtract(5, 3) == 2\n",
        encoding="utf-8",
    )
    # Advance to verified so certifier accepts it
    compute_source_hash(cdir)  # v0.3: evidence is bound to the recorded hash
    transition_status(cdir, "verified")
    return cdir


def _make_failing_candidate(project: Path, locked_spec: str) -> Path:
    """Create a candidate with failing tests."""
    candidates_dir = project / "candidates"
    _, cdir = register_candidate(candidates_dir, locked_spec)

    (cdir / "src" / "broken.py").write_text(
        '"""Broken module."""\n\n\n'
        "def always_wrong() -> int:\n"
        '    """Always returns wrong value."""\n'
        "    return 0\n",
        encoding="utf-8",
    )
    (cdir / "tests" / "test_broken.py").write_text(
        "import sys\n"
        "from pathlib import Path\n"
        "sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))\n"
        "from broken import always_wrong\n\n"
        "def test_wrong():\n"
        "    assert always_wrong() == 42  # this will fail\n",
        encoding="utf-8",
    )
    compute_source_hash(cdir)  # v0.3: evidence is bound to the recorded hash
    transition_status(cdir, "verified")
    return cdir


def _make_no_tests_candidate(project: Path, locked_spec: str) -> Path:
    """Create a candidate with no tests at all."""
    candidates_dir = project / "candidates"
    _, cdir = register_candidate(candidates_dir, locked_spec)
    (cdir / "src" / "thing.py").write_text('"""A thing."""\n', encoding="utf-8")
    compute_source_hash(cdir)  # v0.3: evidence is bound to the recorded hash
    transition_status(cdir, "verified")
    return cdir


# ── Runner unit tests ─────────────────────────────────────────────────────────

class TestCertifierRunner:
    def test_passing_tests_certifies(self, project: Path, locked_spec: str) -> None:
        cdir = _make_passing_candidate(project, locked_spec)
        test_report, _ = run_certification(cdir, project, {})
        assert test_report.certification == "CERTIFIED"

    def test_passing_tests_all_pass(self, project: Path, locked_spec: str) -> None:
        cdir = _make_passing_candidate(project, locked_spec)
        test_report, _ = run_certification(cdir, project, {})
        assert test_report.failed == 0
        assert test_report.errors == 0
        assert test_report.passed >= 2

    def test_failing_tests_not_certified(self, project: Path, locked_spec: str) -> None:
        cdir = _make_failing_candidate(project, locked_spec)
        test_report, _ = run_certification(cdir, project, {})
        assert test_report.certification == "NOT_CERTIFIED"

    def test_failing_tests_records_failures(self, project: Path, locked_spec: str) -> None:
        cdir = _make_failing_candidate(project, locked_spec)
        test_report, _ = run_certification(cdir, project, {})
        assert test_report.failed > 0
        assert len(test_report.blocking_failures) > 0

    def test_writes_test_report_evidence(self, project: Path, locked_spec: str) -> None:
        cdir = _make_passing_candidate(project, locked_spec)
        run_certification(cdir, project, {})
        evidence = project / "evidence" / cdir.name / "test_report.json"
        assert evidence.exists()
        data = json.loads(evidence.read_text())
        assert "certification" in data
        sidecar = evidence.with_suffix(evidence.suffix + ".sha256")
        assert sidecar.exists()

    def test_writes_coverage_report_evidence(self, project: Path, locked_spec: str) -> None:
        cdir = _make_passing_candidate(project, locked_spec)
        run_certification(cdir, project, {})
        evidence = project / "evidence" / cdir.name / "coverage_report.json"
        assert evidence.exists()
        data = json.loads(evidence.read_text())
        assert "line_coverage" in data
        sidecar = evidence.with_suffix(evidence.suffix + ".sha256")
        assert sidecar.exists()

    def test_evidence_is_hash_sealed(self, project: Path, locked_spec: str) -> None:
        cdir = _make_passing_candidate(project, locked_spec)
        test_report, _ = run_certification(cdir, project, {})
        assert test_report.evidence_hash.startswith("sha256:")

    def test_coverage_reported(self, project: Path, locked_spec: str) -> None:
        cdir = _make_passing_candidate(project, locked_spec)
        _, cov_report = run_certification(cdir, project, {})
        assert 0.0 <= cov_report.line_coverage <= 1.0
        assert 0.0 <= cov_report.branch_coverage <= 1.0


# ── CLI tests ─────────────────────────────────────────────────────────────────

class TestCertifyCLI:
    def test_certify_passing_candidate(self, project: Path, locked_spec: str) -> None:
        cdir = _make_passing_candidate(project, locked_spec)
        result = runner.invoke(app, ["certify", cdir.name], catch_exceptions=False)
        assert result.exit_code == 0
        assert "CERTIFIED" in result.output

    def test_certify_advances_status(self, project: Path, locked_spec: str) -> None:
        from airlock.core.candidate_store import get_status
        cdir = _make_passing_candidate(project, locked_spec)
        runner.invoke(app, ["certify", cdir.name], catch_exceptions=False)
        assert get_status(cdir) == "certified"

    def test_certify_failing_candidate_exits_nonzero(self, project: Path, locked_spec: str) -> None:
        cdir = _make_failing_candidate(project, locked_spec)
        result = runner.invoke(app, ["certify", cdir.name], catch_exceptions=False)
        assert result.exit_code == 1
        assert "NOT_CERTIFIED" in result.output

    def test_certify_quarantined_candidate_blocked(self, project: Path, locked_spec: str) -> None:
        candidates_dir = project / "candidates"
        _, cdir = register_candidate(candidates_dir, locked_spec)
        result = runner.invoke(app, ["certify", cdir.name], catch_exceptions=False)
        assert result.exit_code == 1
        assert "verify" in result.output.lower()

    def test_certify_missing_candidate_exits(self, project: Path) -> None:
        result = runner.invoke(app, ["certify", "candidate_9999"], catch_exceptions=False)
        assert result.exit_code == 1

    def test_certify_writes_evidence(self, project: Path, locked_spec: str) -> None:
        cdir = _make_passing_candidate(project, locked_spec)
        runner.invoke(app, ["certify", cdir.name], catch_exceptions=False)
        assert (project / "evidence" / cdir.name / "test_report.json").exists()
        assert (project / "evidence" / cdir.name / "coverage_report.json").exists()

    def test_certify_shows_test_count(self, project: Path, locked_spec: str) -> None:
        cdir = _make_passing_candidate(project, locked_spec)
        result = runner.invoke(app, ["certify", cdir.name], catch_exceptions=False)
        assert "passed" in result.output

    def test_certify_shows_coverage(self, project: Path, locked_spec: str) -> None:
        cdir = _make_passing_candidate(project, locked_spec)
        result = runner.invoke(app, ["certify", cdir.name], catch_exceptions=False)
        assert "cover" in result.output.lower()
