# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
Admission hardening tests.

Verifies that run_admission() cannot be bypassed by:
  1. Presenting a gate_decision.json without a valid sidecar
  2. Tampering with gate_decision.json after gate approval
  3. Modifying candidate source after gate approval but before admission
  4. Presenting a fake ALLOW gate decision on an uncertified candidate

Run from the repo root:
    pytest tests/test_admission_hardening.py -v
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
from airlock.core.governance.gate import run_gate, run_admission, AdmissionError, ALLOW

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
    spec_id, spec_dir = create_spec(specs_dir, "Test")
    (spec_dir / "spec.md").write_text(
        "# spec\n\n## Functional requirements\n\nWork.\n\n"
        "## Non-functional requirements\n\nFast.\n\n"
        "## Forbidden behaviours\n\nNone.\n\n"
        "## Acceptance criteria\n\nPasses.\n",
        encoding="utf-8",
    )
    lock_spec(specs_dir, spec_id)
    return spec_id


def _make_gate_approved_candidate(project: Path, locked_spec: str) -> Path:
    """Run a candidate all the way through to gate ALLOW via the real CLI."""
    result = runner.invoke(
        app, ["candidate", "register", locked_spec], catch_exceptions=False
    )
    candidate_id = [
        line.split("candidate_")[1].split()[0]
        for line in result.output.splitlines()
        if "candidate_" in line
    ][0]
    candidate_id = f"candidate_{candidate_id}"
    cdir = project / "candidates" / candidate_id

    (cdir / "src" / "calc.py").write_text(
        '"""Calc."""\n\n\ndef add(a: int, b: int) -> int:\n    """Add."""\n    return a + b\n',
        encoding="utf-8",
    )
    (cdir / "tests" / "test_calc.py").write_text(
        "import sys\nfrom pathlib import Path\n"
        "sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))\n"
        "from calc import add\ndef test_add():\n    assert add(1, 2) == 3\n",
        encoding="utf-8",
    )

    runner.invoke(app, ["candidate", "hash", candidate_id], catch_exceptions=False)
    runner.invoke(app, ["verify", candidate_id], catch_exceptions=False)
    runner.invoke(app, ["certify", candidate_id], catch_exceptions=False)

    result = runner.invoke(app, ["gate", candidate_id], catch_exceptions=False)
    assert "ALLOW" in result.output, f"Gate did not ALLOW: {result.output}"

    return cdir


# ── Admission hardening tests ─────────────────────────────────────────────────

class TestAdmissionHardening:
    def test_admission_rejects_gate_decision_missing_sidecar(
        self, project: Path, locked_spec: str
    ) -> None:
        """A gate_decision.json with no .sha256 sidecar must be rejected."""
        candidates_dir = project / "candidates"
        _, cdir = register_candidate(candidates_dir, locked_spec)
        transition_status(cdir, "verified")
        transition_status(cdir, "certified")

        evidence_dir = project / "evidence" / cdir.name
        evidence_dir.mkdir(parents=True, exist_ok=True)

        # Write a gate decision without creating the sidecar
        gate_path = evidence_dir / "gate_decision.json"
        gate_path.write_text(
            json.dumps({"decision": ALLOW, "candidate_id": cdir.name}), encoding="utf-8"
        )
        # No sidecar written — verify_sidecar will return (False, "sidecar missing")

        with pytest.raises(AdmissionError, match="integrity check failed"):
            run_admission(cdir, project)

    def test_admission_rejects_tampered_gate_decision(
        self, project: Path, locked_spec: str
    ) -> None:
        """A gate_decision.json modified after sealing must be rejected."""
        cdir = _make_gate_approved_candidate(project, locked_spec)
        evidence_dir = project / "evidence" / cdir.name
        gate_path = evidence_dir / "gate_decision.json"

        # Tamper with the gate decision after the sidecar was written
        data = json.loads(gate_path.read_text())
        data["tampered"] = True
        gate_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        # Sidecar still has old hash — mismatch

        with pytest.raises(AdmissionError, match="integrity check failed"):
            run_admission(cdir, project)

    def test_admission_rejects_source_changed_after_gate(
        self, project: Path, locked_spec: str
    ) -> None:
        """Source modified after gate approval must be detected at admission."""
        cdir = _make_gate_approved_candidate(project, locked_spec)

        # Modify the source after the gate approved the original
        (cdir / "src" / "malicious.py").write_text(
            "# injected after gate approval\nx = 1\n", encoding="utf-8"
        )

        with pytest.raises(AdmissionError, match="Source tree hash mismatch"):
            run_admission(cdir, project)

    def test_admission_rejects_uncertified_candidate_with_fake_allow_gate(
        self, project: Path, locked_spec: str
    ) -> None:
        """A fake ALLOW gate_decision.json on a quarantined candidate must be rejected."""
        candidates_dir = project / "candidates"
        _, cdir = register_candidate(candidates_dir, locked_spec)
        # Candidate stays quarantined — never certified

        evidence_dir = project / "evidence" / cdir.name
        evidence_dir.mkdir(parents=True, exist_ok=True)

        # Write a convincing fake gate decision with a valid sidecar
        gate_path = evidence_dir / "gate_decision.json"
        fake_gate = {
            "decision": ALLOW,
            "candidate_id": cdir.name,
            "gate_id": "gate-fake-00000000",
        }
        gate_path.write_text(json.dumps(fake_gate, indent=2), encoding="utf-8")
        write_sidecar(gate_path)  # sidecar exists and matches — but candidate uncertified

        with pytest.raises(AdmissionError, match="certified"):
            run_admission(cdir, project)

    def test_clean_candidate_still_admitted_successfully(
        self, project: Path, locked_spec: str
    ) -> None:
        """Legitimate admission flow still works after hardening."""
        cdir = _make_gate_approved_candidate(project, locked_spec)
        cert = run_admission(cdir, project)
        assert cert["admitted"] is True
        assert cert["level"] == "L4_GOVERNANCE_ADMITTED"

        trusted = project / "trusted" / "src" / cdir.name
        assert trusted.exists()
        assert (trusted / "calc.py").exists()
