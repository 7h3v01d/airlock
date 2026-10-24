# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
v0.3 — Source binding regression tests.

Reproduces the v0.2 source-substitution attack: clean code is verified and
certified, the source is then replaced and re-hashed, and the gate allowed
the replacement into the trusted tree. Every test here fails on v0.2.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from airlock.main import app
from airlock.core.candidate_store import (
    CandidateError, compute_source_hash, get_status, register_candidate, transition_status,
)
from airlock.core.certifier.runner import run_certification
from airlock.core.governance.gate import DENY, run_gate
from airlock.core.hashing import hash_directory_tree

runner = CliRunner()

CLEAN_SRC = '"""Adder."""\n\n\ndef add(a: int, b: int) -> int:\n    """Add."""\n    return a + b\n'
EVIL_SRC = (
    '"""Adder."""\nimport subprocess\n\n\ndef add(a: int, b: int) -> int:\n'
    '    """Add."""\n    subprocess.run(["echo", "pwned"])\n    return a + b\n'
)
TESTS = "from adder import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n"


@pytest.fixture()
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init", "proj"], catch_exceptions=False)
    root = tmp_path / "proj"
    monkeypatch.chdir(root)
    runner.invoke(app, ["spec", "new", "adder"], catch_exceptions=False)
    spec_md = root / "specs" / "spec_0001" / "spec.md"
    spec_md.write_text(
        spec_md.read_text().replace("<!-- Describe what the system must do -->", "Add two ints."),
        encoding="utf-8",
    )
    assert runner.invoke(app, ["spec", "lock", "spec_0001"]).exit_code == 0
    return root


def _certified_candidate(root: Path) -> Path:
    assert runner.invoke(app, ["candidate", "register", "spec_0001"]).exit_code == 0
    cdir = root / "candidates" / "candidate_0001"
    (cdir / "src" / "adder.py").write_text(CLEAN_SRC, encoding="utf-8")
    (cdir / "tests" / "test_adder.py").write_text(TESTS, encoding="utf-8")
    assert runner.invoke(app, ["candidate", "hash", "candidate_0001"]).exit_code == 0
    r = runner.invoke(app, ["verify", "candidate_0001"])
    assert r.exit_code == 0, r.output
    r = runner.invoke(app, ["certify", "candidate_0001"])
    assert r.exit_code == 0, r.output
    return cdir


class TestSourceSubstitution:
    def test_rehash_after_verification_is_refused(self, project: Path) -> None:
        cdir = _certified_candidate(project)
        (cdir / "src" / "adder.py").write_text(EVIL_SRC, encoding="utf-8")
        r = runner.invoke(app, ["candidate", "hash", "candidate_0001"])
        assert r.exit_code == 1
        assert "frozen" in r.output.lower()

    def test_full_attack_via_cli_is_not_admitted(self, project: Path) -> None:
        cdir = _certified_candidate(project)
        (cdir / "src" / "adder.py").write_text(EVIL_SRC, encoding="utf-8")
        runner.invoke(app, ["candidate", "hash", "candidate_0001"])
        gate = runner.invoke(app, ["gate", "candidate_0001"])
        assert "ALLOW" not in gate.output
        admit = runner.invoke(app, ["admit", "candidate_0001"])
        assert admit.exit_code == 1
        assert not (project / "trusted" / "src" / "candidate_0001").exists()

    def test_manifest_hand_edited_to_new_hash_is_denied(self, project: Path) -> None:
        """Bypassing the CLI freeze by editing manifest.json directly."""
        cdir = _certified_candidate(project)
        (cdir / "src" / "adder.py").write_text(EVIL_SRC, encoding="utf-8")
        manifest_path = cdir / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["source_hash"] = hash_directory_tree(cdir / "src")
        manifest_path.write_text(json.dumps(manifest))
        decision = run_gate(cdir, project, {})
        assert decision.decision == DENY
        assert any("not bound" in r for r in decision.reasons)

    def test_source_modified_without_rehash_is_denied_at_gate(self, project: Path) -> None:
        cdir = _certified_candidate(project)
        (cdir / "src" / "adder.py").write_text(EVIL_SRC, encoding="utf-8")
        decision = run_gate(cdir, project, {})
        assert decision.decision == DENY
        assert any("modified" in r for r in decision.reasons)

    def test_clean_pipeline_still_allows_and_admits(self, project: Path) -> None:
        _certified_candidate(project)
        gate = runner.invoke(app, ["gate", "candidate_0001"])
        assert gate.exit_code == 0 and "ALLOW" in gate.output
        admit = runner.invoke(app, ["admit", "candidate_0001"])
        assert admit.exit_code == 0, admit.output


class TestEvidenceRecordsSource:
    def test_verifier_and_certifier_record_source_hash(self, project: Path) -> None:
        cdir = _certified_candidate(project)
        expected = json.loads((cdir / "manifest.json").read_text())["source_hash"]
        ev = project / "evidence" / "candidate_0001"
        for name in ("static_verification.json", "test_report.json", "coverage_report.json"):
            assert json.loads((ev / name).read_text())["source_hash"] == expected, name

    def test_verify_records_hash_when_missing(self, project: Path) -> None:
        runner.invoke(app, ["candidate", "register", "spec_0001"])
        cdir = project / "candidates" / "candidate_0001"
        (cdir / "src" / "adder.py").write_text(CLEAN_SRC, encoding="utf-8")
        (cdir / "tests" / "test_adder.py").write_text(TESTS, encoding="utf-8")
        r = runner.invoke(app, ["verify", "candidate_0001"])
        assert r.exit_code == 0, r.output
        manifest = json.loads((cdir / "manifest.json").read_text())
        assert manifest["source_hash"] == hash_directory_tree(cdir / "src")

    def test_verify_fails_when_src_changed_after_hash(self, project: Path) -> None:
        runner.invoke(app, ["candidate", "register", "spec_0001"])
        cdir = project / "candidates" / "candidate_0001"
        (cdir / "src" / "adder.py").write_text(CLEAN_SRC, encoding="utf-8")
        (cdir / "tests" / "test_adder.py").write_text(TESTS, encoding="utf-8")
        runner.invoke(app, ["candidate", "hash", "candidate_0001"])
        (cdir / "src" / "adder.py").write_text(CLEAN_SRC + "\n# changed\n", encoding="utf-8")
        r = runner.invoke(app, ["verify", "candidate_0001"])
        assert r.exit_code == 1
        assert "SOURCE_INTEGRITY" in r.output


class TestCertifierContainment:
    def test_tests_that_modify_src_are_not_certified(self, project: Path) -> None:
        _, cdir = register_candidate(project / "candidates", "spec_0001")
        (cdir / "src" / "adder.py").write_text(CLEAN_SRC, encoding="utf-8")
        (cdir / "tests" / "test_adder.py").write_text(
            "from pathlib import Path\nfrom adder import add\n\n\ndef test_add():\n"
            "    p = Path(__file__).parent.parent / 'src' / 'adder.py'\n"
            "    p.write_text(p.read_text() + '\\n# injected\\n')\n"
            "    assert add(1, 2) == 3\n",
            encoding="utf-8",
        )
        compute_source_hash(cdir)
        transition_status(cdir, "verified")
        report, _ = run_certification(cdir, project, {})
        assert report.certification == "NOT_CERTIFIED"
        assert any("modified while the test suite ran" in f for f in report.blocking_failures)

    def test_certify_without_recorded_hash_is_not_certified(self, project: Path) -> None:
        _, cdir = register_candidate(project / "candidates", "spec_0001")
        (cdir / "src" / "adder.py").write_text(CLEAN_SRC, encoding="utf-8")
        (cdir / "tests" / "test_adder.py").write_text(TESTS, encoding="utf-8")
        transition_status(cdir, "verified")
        report, _ = run_certification(cdir, project, {})
        assert report.certification == "NOT_CERTIFIED"


class TestHashFreeze:
    def test_rehash_allowed_while_quarantined(self, project: Path) -> None:
        _, cdir = register_candidate(project / "candidates", "spec_0001")
        (cdir / "src" / "a.py").write_text("x = 1\n")
        first = compute_source_hash(cdir)
        (cdir / "src" / "a.py").write_text("x = 2\n")
        assert compute_source_hash(cdir) != first

    def test_rehash_refused_once_verified(self, project: Path) -> None:
        _, cdir = register_candidate(project / "candidates", "spec_0001")
        (cdir / "src" / "a.py").write_text("x = 1\n")
        compute_source_hash(cdir)
        transition_status(cdir, "verified")
        with pytest.raises(CandidateError, match="frozen"):
            compute_source_hash(cdir)
        assert get_status(cdir) == "verified"


class TestLegacyConfig:
    def test_project_with_legacy_cleanroom_yaml_still_loads(self, project: Path) -> None:
        (project / "airlock.yaml").rename(project / "cleanroom.yaml")
        r = runner.invoke(app, ["status"])
        assert r.exit_code == 0, r.output
