# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
v0.4 — Signed evidence.

The v0.3 residual risk: anyone able to write to the project could rewrite an
evidence file *and* its .sha256 sidecar. Every attack in this file succeeds
against sidecars alone and must be stopped by the Ed25519 signatures.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from airlock.main import app
from airlock.core import signing
from airlock.core.candidate_store import register_candidate, transition_status, compute_source_hash
from airlock.core.certifier.runner import run_certification
from airlock.core.governance.gate import ALLOW, DENY, run_gate, run_admission, AdmissionError
from airlock.core.hashing import write_sidecar
from airlock.core.verifier.runner import run_verification

runner = CliRunner()

CLEAN_SRC = '"""Adder."""\n\n\ndef add(a: int, b: int) -> int:\n    """Add."""\n    return a + b\n'
TESTS = "from adder import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n"
FAILING_TESTS = "from adder import add\n\n\ndef test_add():\n    assert add(1, 2) == 4\n"


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


def _policy(root: Path) -> dict:
    return yaml.safe_load((root / "airlock.yaml").read_text())


def _candidate(root: Path, tests: str = TESTS, certify: bool = True) -> Path:
    r = runner.invoke(app, ["candidate", "register", "spec_0001"])
    assert r.exit_code == 0
    cid = r.output.split("candidate_")[1][:4]
    cdir = root / "candidates" / f"candidate_{cid}"
    (cdir / "src" / "adder.py").write_text(CLEAN_SRC, encoding="utf-8")
    (cdir / "tests" / "test_adder.py").write_text(tests, encoding="utf-8")
    assert runner.invoke(app, ["verify", cdir.name]).exit_code == 0
    if certify:
        runner.invoke(app, ["certify", cdir.name])
    return cdir


def _forge(path: Path, **changes) -> None:
    """The v0.3-era attack: edit the evidence and recompute its sidecar."""
    data = json.loads(path.read_text())
    data.update(changes)
    path.write_text(json.dumps(data, indent=2))
    write_sidecar(path)


class TestInitAndKeys:
    def test_init_creates_operator_key_and_floor(self, project: Path, isolated_airlock_home: Path) -> None:
        assert signing.private_key_path().exists()
        assert signing.operator_config()["require_signatures"] is True
        assert len(signing.trusted_keys()) == 1

    def test_private_key_is_outside_the_project(self, project: Path) -> None:
        assert project not in signing.private_key_path().parents

    def test_pipeline_signs_every_evidence_document(self, project: Path) -> None:
        cdir = _candidate(project)
        runner.invoke(app, ["gate", cdir.name])
        runner.invoke(app, ["admit", cdir.name])
        ev = project / "evidence" / cdir.name
        for name in ("static_verification.json", "test_report.json", "coverage_report.json",
                     "gate_decision.json", "admission_certificate.json"):
            ok, msg = signing.verify_file(ev / name)
            assert ok, f"{name}: {msg}"

    @pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
    def test_private_key_permissions_are_restricted(self, project: Path) -> None:
        assert (signing.private_key_path().stat().st_mode & 0o077) == 0


class TestForgedEvidence:
    def test_rewritten_report_with_fresh_sidecar_is_denied(self, project: Path) -> None:
        cdir = _candidate(project, tests=FAILING_TESTS)
        report = project / "evidence" / cdir.name / "test_report.json"
        assert json.loads(report.read_text())["certification"] == "NOT_CERTIFIED"
        _forge(report, certification="CERTIFIED", failed=0, passed=1)
        transition_status(cdir, "certified")
        d = run_gate(cdir, project, _policy(project))
        assert d.decision == DENY
        assert any("signature invalid" in r for r in d.reasons)

    def test_deleting_the_signature_is_denied(self, project: Path) -> None:
        cdir = _candidate(project)
        sig = project / "evidence" / cdir.name / "test_report.json.sig"
        sig.unlink()
        d = run_gate(cdir, project, _policy(project))
        assert d.decision == DENY
        assert any("signature missing" in r for r in d.reasons)

    def test_signature_cannot_be_moved_between_candidates(self, project: Path) -> None:
        good = _candidate(project)
        bad = _candidate(project, tests=FAILING_TESTS)
        src, dst = project / "evidence" / good.name, project / "evidence" / bad.name
        for suffix in ("", ".sha256", ".sig"):
            shutil.copy2(src / f"test_report.json{suffix}", dst / f"test_report.json{suffix}")
        transition_status(bad, "certified")
        d = run_gate(bad, project, _policy(project))
        assert d.decision == DENY

    def test_signature_cannot_be_moved_between_documents(self, project: Path) -> None:
        cdir = _candidate(project)
        ev = project / "evidence" / cdir.name
        # Make the coverage report claim to be the test report, with its signature
        shutil.copy2(ev / "coverage_report.json.sig", ev / "test_report.json.sig")
        d = run_gate(cdir, project, _policy(project))
        assert d.decision == DENY

    def test_evidence_signed_by_an_untrusted_key_is_denied(self, project: Path, tmp_path: Path, monkeypatch) -> None:
        cdir = _candidate(project, tests=FAILING_TESTS)
        report = project / "evidence" / cdir.name / "test_report.json"
        _forge(report, certification="CERTIFIED", failed=0, passed=1)
        # The attacker has their own key pair in their own home
        real_home = os.environ[signing.HOME_ENV]
        monkeypatch.setenv(signing.HOME_ENV, str(tmp_path / "attacker_home"))
        signing.clear_cached_signer()
        signing.generate_key()
        signing.sign_file(report, signing.load_signer())
        monkeypatch.setenv(signing.HOME_ENV, real_home)
        signing.clear_cached_signer()
        transition_status(cdir, "certified")
        d = run_gate(cdir, project, _policy(project))
        assert d.decision == DENY
        assert any("untrusted key" in r for r in d.reasons)

    def test_forged_gate_decision_is_not_admitted(self, project: Path) -> None:
        cdir = _candidate(project, tests=FAILING_TESTS)
        transition_status(cdir, "certified")
        run_gate(cdir, project, _policy(project))
        gate_path = project / "evidence" / cdir.name / "gate_decision.json"
        _forge(gate_path, decision=ALLOW, reasons=[])
        with pytest.raises(AdmissionError, match="signature"):
            run_admission(cdir, project, policy=_policy(project))


class TestPolicyDowngrade:
    def test_project_cannot_switch_signatures_off_below_operator_floor(self, project: Path) -> None:
        cdir = _candidate(project, tests=FAILING_TESTS)
        policy = _policy(project)
        policy["integrity"]["require_signatures"] = False
        (project / "airlock.yaml").write_text(yaml.safe_dump(policy))
        report = project / "evidence" / cdir.name / "test_report.json"
        _forge(report, certification="CERTIFIED", failed=0, passed=1)
        (report.with_suffix(".json.sig")).unlink()
        transition_status(cdir, "certified")
        r = runner.invoke(app, ["gate", cdir.name])
        assert "DENY" in r.output and r.exit_code == 1

    def test_corrupt_operator_config_is_treated_as_required(self, project: Path) -> None:
        signing.operator_config_path().write_text("{not json")
        assert signing.signatures_required({"integrity": {"require_signatures": False}})

    def test_without_floor_or_policy_signatures_are_optional(self, project: Path) -> None:
        signing.write_operator_config({"require_signatures": False})
        assert not signing.signatures_required({})
        assert signing.signatures_required({"integrity": {"require_signatures": True}})


class TestKeyAvailability:
    def test_verify_fails_clearly_without_a_key(self, project: Path) -> None:
        r = runner.invoke(app, ["candidate", "register", "spec_0001"])
        cdir = project / "candidates" / "candidate_0001"
        (cdir / "src" / "adder.py").write_text(CLEAN_SRC)
        (cdir / "tests" / "test_adder.py").write_text(TESTS)
        signing.private_key_path().unlink()
        signing.clear_cached_signer()
        r = runner.invoke(app, ["verify", "candidate_0001"])
        assert r.exit_code == 1 and "airlock keys init" in r.output

    def test_encrypted_key_needs_passphrase(self, project: Path) -> None:
        signing.generate_key("correct horse", force=True)
        signing.clear_cached_signer()
        assert signing.key_is_encrypted()
        with pytest.raises(signing.SigningError, match="passphrase"):
            signing.load_signer()
        with pytest.raises(signing.SigningError, match="wrong passphrase"):
            signing.load_signer("nope")
        assert signing.load_signer("correct horse").key_id

    def test_cli_prompts_for_passphrase(self, project: Path) -> None:
        signing.generate_key("pw123", force=True)
        signing.clear_cached_signer()
        runner.invoke(app, ["candidate", "register", "spec_0001"])
        cdir = project / "candidates" / "candidate_0001"
        (cdir / "src" / "adder.py").write_text(CLEAN_SRC)
        (cdir / "tests" / "test_adder.py").write_text(TESTS)
        r = runner.invoke(app, ["verify", "candidate_0001"], input="pw123\n")
        assert r.exit_code == 0, r.output
        assert signing.verify_file(project / "evidence" / "candidate_0001" / "static_verification.json")[0]

    def test_passphrase_and_home_never_reach_candidate_code(self, project: Path, monkeypatch) -> None:
        monkeypatch.setenv(signing.PASSPHRASE_ENV, "s3cret")
        signing.generate_key("s3cret", force=True)
        signing.clear_cached_signer()
        _, cdir = register_candidate(project / "candidates", "spec_0001")
        (cdir / "src" / "adder.py").write_text(CLEAN_SRC)
        (cdir / "tests" / "test_adder.py").write_text(
            "import os\nfrom adder import add\n\n\ndef test_env():\n"
            "    assert 'AIRLOCK_KEY_PASSPHRASE' not in os.environ\n"
            "    assert 'AIRLOCK_HOME' not in os.environ\n"
            "    assert add(1, 2) == 3\n"
        )
        compute_source_hash(cdir)
        transition_status(cdir, "verified")
        report, _ = run_certification(cdir, project, _policy(project))
        assert report.certification == "CERTIFIED", report.failure_details


class TestKeyCommands:
    def test_keys_show_and_export_and_trust(self, project: Path, tmp_path: Path) -> None:
        r = runner.invoke(app, ["keys", "show"])
        assert r.exit_code == 0 and "required" in r.output
        pub = tmp_path / "op.pub"
        assert runner.invoke(app, ["keys", "export", "-o", str(pub)]).exit_code == 0
        assert b"BEGIN PUBLIC KEY" in pub.read_bytes()
        assert runner.invoke(app, ["keys", "trust", str(pub)]).exit_code == 0

    def test_keys_init_refuses_to_overwrite_without_force(self, project: Path) -> None:
        r = runner.invoke(app, ["keys", "init"])
        assert r.exit_code == 1 and "--force" in r.output
