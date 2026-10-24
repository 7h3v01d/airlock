# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
Full pipeline integration test.

Runs a real candidate through the complete pipeline and asserts
every sidecar exists at each stage. This catches the class of bug
where unit tests pass but the real CLI path doesn't write sidecars.

    init → spec new → spec lock → candidate register → candidate hash
    → verify → certify → gate → admit

All evidence files must have detached .sha256 sidecars.
Gate must ALLOW on clean evidence.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from airlock.main import app

runner = CliRunner()


@pytest.fixture()
def full_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init", "myproject"], catch_exceptions=False)
    project_dir = tmp_path / "myproject"
    monkeypatch.chdir(project_dir)
    return project_dir


def _write_spec(project: Path) -> str:
    """Create a locked spec and return its ID."""
    result = runner.invoke(
        app, ["spec", "new", "Integration test module"], catch_exceptions=False
    )
    assert result.exit_code == 0
    # Extract spec_id from output
    spec_id = [
        line.split("spec_")[1].split()[0]
        for line in result.output.splitlines()
        if "spec_" in line
    ][0]
    spec_id = f"spec_{spec_id}"

    spec_md = project / "specs" / spec_id / "spec.md"
    spec_md.write_text(
        "# Integration test spec\n\n"
        "## Functional requirements\n\nAdd two numbers.\n\n"
        "## Non-functional requirements\n\nOffline.\n\n"
        "## Forbidden behaviours\n\nNo network.\n\n"
        "## Acceptance criteria\n\nGiven add(1, 2), returns 3.\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["spec", "lock", spec_id], catch_exceptions=False)
    assert result.exit_code == 0
    return spec_id


def _write_candidate(project: Path, spec_id: str) -> str:
    """Register a candidate and write clean source. Returns candidate_id."""
    result = runner.invoke(
        app, ["candidate", "register", spec_id], catch_exceptions=False
    )
    assert result.exit_code == 0
    candidate_id = [
        line.split("candidate_")[1].split()[0]
        for line in result.output.splitlines()
        if "candidate_" in line
    ][0]
    candidate_id = f"candidate_{candidate_id}"

    cdir = project / "candidates" / candidate_id

    (cdir / "src" / "calculator.py").write_text(
        '"""Calculator module."""\n\n\n'
        "def add(a: int, b: int) -> int:\n"
        '    """Add two integers."""\n'
        "    return a + b\n",
        encoding="utf-8",
    )
    (cdir / "tests" / "test_calculator.py").write_text(
        "import sys\n"
        "from pathlib import Path\n"
        "sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))\n"
        "from calculator import add\n\n"
        "def test_add():\n"
        "    assert add(1, 2) == 3\n\n"
        "def test_add_zero():\n"
        "    assert add(0, 0) == 0\n",
        encoding="utf-8",
    )
    return candidate_id


def _sidecar(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".sha256")


class TestFullPipeline:
    def test_complete_pipeline_allow(self, full_project: Path) -> None:
        """End-to-end: clean candidate should reach ALLOW at the gate."""
        spec_id = _write_spec(full_project)
        candidate_id = _write_candidate(full_project, spec_id)
        cdir = full_project / "candidates" / candidate_id
        evidence_dir = full_project / "evidence" / candidate_id

        # Hash
        result = runner.invoke(
            app, ["candidate", "hash", candidate_id], catch_exceptions=False
        )
        assert result.exit_code == 0

        # Verify
        result = runner.invoke(app, ["verify", candidate_id], catch_exceptions=False)
        assert result.exit_code == 0, result.output
        assert "PASS" in result.output

        # Verify sidecar exists after airlock verify
        ver_json = evidence_dir / "static_verification.json"
        assert ver_json.exists(), "static_verification.json missing"
        assert _sidecar(ver_json).exists(), "static_verification.json.sha256 missing"

        # Certify
        result = runner.invoke(app, ["certify", candidate_id], catch_exceptions=False)
        assert result.exit_code == 0, result.output
        assert "CERTIFIED" in result.output

        # Sidecars after airlock certify
        test_json = evidence_dir / "test_report.json"
        cov_json = evidence_dir / "coverage_report.json"
        assert test_json.exists()
        assert _sidecar(test_json).exists(), "test_report.json.sha256 missing"
        assert cov_json.exists()
        assert _sidecar(cov_json).exists(), "coverage_report.json.sha256 missing"

        # Gate
        result = runner.invoke(app, ["gate", candidate_id], catch_exceptions=False)
        assert result.exit_code == 0, result.output
        assert "ALLOW" in result.output

        # Sidecar after airlock gate
        gate_json = evidence_dir / "gate_decision.json"
        assert gate_json.exists()
        assert _sidecar(gate_json).exists(), "gate_decision.json.sha256 missing"

        # Admit
        result = runner.invoke(app, ["admit", candidate_id], catch_exceptions=False)
        assert result.exit_code == 0, result.output
        assert "admitted" in result.output.lower()

        # Certificate sidecar
        cert_json = evidence_dir / "admission_certificate.json"
        assert cert_json.exists()
        assert _sidecar(cert_json).exists(), "admission_certificate.json.sha256 missing"

        # Trusted tree populated
        trusted = full_project / "trusted" / "src" / candidate_id
        assert trusted.exists()
        assert (trusted / "calculator.py").exists()

        # Status shows admitted
        from airlock.core.candidate_store import get_status
        assert get_status(cdir) == "admitted"

    def test_tampered_verifier_report_causes_gate_deny(
        self, full_project: Path
    ) -> None:
        """Gate must DENY if verifier evidence is tampered after verify."""
        spec_id = _write_spec(full_project)
        candidate_id = _write_candidate(full_project, spec_id)
        evidence_dir = full_project / "evidence" / candidate_id

        runner.invoke(app, ["candidate", "hash", candidate_id], catch_exceptions=False)
        runner.invoke(app, ["verify", candidate_id], catch_exceptions=False)

        # Tamper with the evidence file after sealing
        ver_json = evidence_dir / "static_verification.json"
        data = json.loads(ver_json.read_text())
        data["verdict"] = "PASS"
        data["tampered"] = True
        ver_json.write_text(json.dumps(data, indent=2), encoding="utf-8")
        # Sidecar still has old hash — mismatch detected

        runner.invoke(app, ["certify", candidate_id], catch_exceptions=False)
        result = runner.invoke(app, ["gate", candidate_id], catch_exceptions=False)

        assert result.exit_code != 0
        gate_data = json.loads(
            (evidence_dir / "gate_decision.json").read_text()
        )
        assert gate_data["decision"] in ("DENY", "QUARANTINE")

    def test_all_sidecars_are_sha256sum_compatible(
        self, full_project: Path
    ) -> None:
        """Every .sha256 sidecar must be in sha256sum-compatible format."""
        spec_id = _write_spec(full_project)
        candidate_id = _write_candidate(full_project, spec_id)
        evidence_dir = full_project / "evidence" / candidate_id

        runner.invoke(app, ["candidate", "hash", candidate_id], catch_exceptions=False)
        runner.invoke(app, ["verify", candidate_id], catch_exceptions=False)
        runner.invoke(app, ["certify", candidate_id], catch_exceptions=False)
        runner.invoke(app, ["gate", candidate_id], catch_exceptions=False)
        runner.invoke(app, ["admit", candidate_id], catch_exceptions=False)

        sidecars = list(evidence_dir.glob("*.sha256"))
        assert sidecars, "No sidecars found"

        for sidecar in sidecars:
            content = sidecar.read_text(encoding="utf-8").strip()
            parts = content.split("  ")
            assert len(parts) == 2, f"{sidecar.name}: bad format"
            hex_part, name_part = parts
            assert len(hex_part) == 64, f"{sidecar.name}: hex not 64 chars"
            assert all(c in "0123456789abcdef" for c in hex_part), \
                f"{sidecar.name}: non-hex chars in digest"
            assert name_part == sidecar.stem, \
                f"{sidecar.name}: filename mismatch"
