# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
Phase 7B — Evidence hash integrity tests.

Verifies the detached sidecar model:
  - Sidecars are written alongside evidence files
  - Tampering is detected by sidecar mismatch
  - The gate rejects tampered evidence

Run from the repo root:
    pytest tests/test_phase7b.py -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from airlock.core.hashing import (
    seal_evidence, verify_sidecar, write_sidecar, hash_file
)
from airlock.core.spec_store import create_spec, lock_spec
from airlock.core.candidate_store import register_candidate, transition_status
from airlock.core.governance.gate import run_gate, QUARANTINE, DENY
from airlock.core.hashing import write_sidecar

runner = CliRunner()


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from airlock.main import app
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


# ── seal_evidence and verify_sidecar unit tests ───────────────────────────────

class TestSealAndVerify:
    def test_seal_creates_sidecar(self, tmp_path: Path) -> None:
        path = tmp_path / "report.json"
        seal_evidence(path, {"verdict": "PASS"})
        sidecar = tmp_path / "report.json.sha256"
        assert sidecar.exists()

    def test_seal_rejects_embedded_hash(self, tmp_path: Path) -> None:
        path = tmp_path / "report.json"
        with pytest.raises(ValueError, match="evidence_hash"):
            seal_evidence(path, {"verdict": "PASS", "evidence_hash": "sha256:abc"})

    def test_verify_passes_untampered(self, tmp_path: Path) -> None:
        path = tmp_path / "report.json"
        seal_evidence(path, {"verdict": "PASS"})
        ok, msg = verify_sidecar(path)
        assert ok is True
        assert msg == "ok"

    def test_verify_detects_content_change(self, tmp_path: Path) -> None:
        path = tmp_path / "report.json"
        seal_evidence(path, {"verdict": "PASS"})
        # Tamper with the file after sealing
        path.write_text(json.dumps({"verdict": "FAIL", "injected": True}, indent=2),
                        encoding="utf-8")
        ok, msg = verify_sidecar(path)
        assert ok is False
        assert "mismatch" in msg

    def test_verify_detects_missing_sidecar(self, tmp_path: Path) -> None:
        path = tmp_path / "report.json"
        path.write_text(json.dumps({"verdict": "PASS"}), encoding="utf-8")
        # No sidecar written
        ok, msg = verify_sidecar(path)
        assert ok is False
        assert "missing" in msg

    def test_verify_detects_malformed_sidecar(self, tmp_path: Path) -> None:
        path = tmp_path / "report.json"
        seal_evidence(path, {"verdict": "PASS"})
        # Corrupt the sidecar
        sidecar = path.with_suffix(path.suffix + ".sha256")
        sidecar.write_text("not-a-valid-hash  report.json\n", encoding="utf-8")
        ok, msg = verify_sidecar(path)
        assert ok is False
        assert "mismatch" in msg

    def test_sidecar_format_is_sha256sum_compatible(self, tmp_path: Path) -> None:
        """Sidecar format: '<hex>  <filename>' — compatible with sha256sum --check."""
        path = tmp_path / "report.json"
        seal_evidence(path, {"data": 1})
        sidecar = path.with_suffix(path.suffix + ".sha256")
        content = sidecar.read_text().strip()
        parts = content.split("  ")
        assert len(parts) == 2
        hex_part, name_part = parts
        assert len(hex_part) == 64  # SHA-256 hex is 64 chars
        assert name_part == "report.json"

    def test_seal_returns_digest_string(self, tmp_path: Path) -> None:
        path = tmp_path / "report.json"
        digest = seal_evidence(path, {"x": 1})
        assert digest.startswith("sha256:")
        assert len(digest) == 71  # "sha256:" + 64 hex chars


# ── Gate integrity enforcement tests ─────────────────────────────────────────

class TestGateIntegrityEnforcement:
    def _make_evidenced(self, project: Path, locked_spec: str) -> Path:
        candidates_dir = project / "candidates"
        _, cdir = register_candidate(candidates_dir, locked_spec)
        manifest_path = cdir / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        from airlock.core.hashing import hash_directory_tree
        (cdir / "src" / "main.py").write_text('"""m."""\n', encoding="utf-8")
        manifest["source_hash"] = hash_directory_tree(cdir / "src")
        bound = manifest["source_hash"]
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        evidence_dir = project / "evidence" / cdir.name
        evidence_dir.mkdir(parents=True)

        def write_ev(name: str, data: dict) -> None:
            p = evidence_dir / name
            p.write_text(json.dumps(data), encoding="utf-8")
            write_sidecar(p)
            from airlock.core import signing
            signing.sign_file(p, signing.load_signer())  # v0.4: valid evidence is signed

        write_ev("static_verification.json", {"verdict": "PASS", "source_hash": bound})
        write_ev("test_report.json", {"certification": "CERTIFIED", "source_hash": bound})
        write_ev("coverage_report.json", {"line_coverage": 0.85, "source_hash": bound})
        transition_status(cdir, "verified")
        transition_status(cdir, "certified")
        return cdir

    def test_gate_allows_clean_evidence(self, project: Path, locked_spec: str) -> None:
        cdir = self._make_evidenced(project, locked_spec)
        decision = run_gate(cdir, project, {})
        assert decision.decision == "ALLOW"

    def test_gate_denies_tampered_verifier_report(
        self, project: Path, locked_spec: str
    ) -> None:
        cdir = self._make_evidenced(project, locked_spec)
        # Tamper with the verifier report AFTER sidecar was written
        ver_path = project / "evidence" / cdir.name / "static_verification.json"
        ver_path.write_text(
            json.dumps({"verdict": "PASS", "tampered": True}), encoding="utf-8"
        )
        decision = run_gate(cdir, project, {})
        # Gate should detect integrity failure
        assert decision.decision in (DENY, QUARANTINE)

    def test_gate_denies_tampered_test_report(
        self, project: Path, locked_spec: str
    ) -> None:
        cdir = self._make_evidenced(project, locked_spec)
        # Tamper with the test report
        test_path = project / "evidence" / cdir.name / "test_report.json"
        test_path.write_text(
            json.dumps({"certification": "CERTIFIED", "tampered": True}),
            encoding="utf-8"
        )
        decision = run_gate(cdir, project, {})
        assert decision.decision in (DENY, QUARANTINE)

    def test_tampered_evidence_reason_recorded(
        self, project: Path, locked_spec: str
    ) -> None:
        cdir = self._make_evidenced(project, locked_spec)
        ver_path = project / "evidence" / cdir.name / "static_verification.json"
        ver_path.write_text(json.dumps({"verdict": "INJECTED"}), encoding="utf-8")
        decision = run_gate(cdir, project, {})
        # Reasons should mention integrity or hash
        all_reasons = " ".join(decision.reasons).lower()
        assert any(word in all_reasons for word in
                   ["integrity", "hash", "tamper", "invalid", "fail"])
