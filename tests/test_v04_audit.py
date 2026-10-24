# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
v0.4 — Hash-chained, signed, anchored audit log.

v0.3's audit.jsonl was a plain append file: entries could be edited, deleted,
reordered or the whole file rewritten without trace.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from airlock.main import app
from airlock.core import audit, signing
from airlock.core.governance.gate import DENY, run_gate, run_admission, AdmissionError

runner = CliRunner()

CLEAN_SRC = '"""Adder."""\n\n\ndef add(a: int, b: int) -> int:\n    """Add."""\n    return a + b\n'
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
    runner.invoke(app, ["spec", "lock", "spec_0001"])
    return root


def _policy(root: Path) -> dict:
    return yaml.safe_load((root / "airlock.yaml").read_text())


def _certified(root: Path, n: int = 1) -> Path:
    runner.invoke(app, ["candidate", "register", "spec_0001"])
    cdir = root / "candidates" / f"candidate_{n:04d}"
    (cdir / "src" / "adder.py").write_text(CLEAN_SRC)
    (cdir / "tests" / "test_adder.py").write_text(TESTS)
    for step in ("verify", "certify"):
        r = runner.invoke(app, [step, cdir.name])
        assert r.exit_code == 0, r.output
    return cdir


def _log_with_entries(root: Path, n: int = 4) -> Path:
    """Produce n chained audit entries via real gate runs."""
    cdir = _certified(root)
    for _ in range(n):
        run_gate(cdir, root, _policy(root))
    return cdir


def _lines(root: Path) -> list[dict]:
    return [json.loads(l) for l in audit.audit_path(root).read_text().splitlines() if l.strip()]


def _write(root: Path, entries: list[dict]) -> None:
    audit.audit_path(root).write_text("".join(json.dumps(e) + "\n" for e in entries))


class TestIntactChain:
    def test_pipeline_produces_signed_anchored_chain(self, project: Path) -> None:
        cdir = _certified(project)
        runner.invoke(app, ["gate", cdir.name])
        runner.invoke(app, ["admit", cdir.name])
        status = audit.verify_chain(project, require_signatures=True)
        assert status.ok, status.problems
        assert status.entries == 2 and status.signed_entries == 2 and status.anchored
        r = runner.invoke(app, ["audit", "verify"])
        assert r.exit_code == 0 and "intact" in r.output

    def test_gate_and_certificate_record_the_audit_head(self, project: Path) -> None:
        cdir = _log_with_entries(project, 2)
        head_before = audit.verify_chain(project).head_seq
        d = run_gate(cdir, project, _policy(project))
        assert d.audit_head["seq"] == head_before
        cert = run_admission(cdir, project, policy=_policy(project))
        assert cert["audit_head"]["seq"] == head_before + 1


class TestTampering:
    def test_edited_entry_is_detected(self, project: Path) -> None:
        _log_with_entries(project)
        entries = _lines(project)
        entries[1]["decision"] = "ALLOW" if entries[1]["decision"] != "ALLOW" else "DENY"
        _write(project, entries)
        problems = audit.verify_chain(project, require_signatures=True).problems
        assert any("edited" in p for p in problems)

    def test_deleted_middle_entry_is_detected(self, project: Path) -> None:
        _log_with_entries(project)
        entries = _lines(project)
        del entries[1]
        _write(project, entries)
        assert not audit.verify_chain(project).ok

    def test_reordered_entries_are_detected(self, project: Path) -> None:
        _log_with_entries(project)
        entries = _lines(project)
        entries[1], entries[2] = entries[2], entries[1]
        _write(project, entries)
        assert not audit.verify_chain(project).ok

    def test_rebuilt_chain_without_operator_key_is_detected(self, project: Path) -> None:
        """Attacker recomputes every hash after editing, but cannot sign."""
        _log_with_entries(project)
        entries = _lines(project)
        entries[0]["decision"] = "ALLOW"
        prev = audit.GENESIS
        for e in entries:
            e.pop("sig", None)
            e["prev_hash"] = prev
            e["entry_hash"] = audit.compute_entry_hash(e)
            prev = e["entry_hash"]
        _write(project, entries)
        problems = audit.verify_chain(project, require_signatures=True).problems
        assert any("unsigned" in p for p in problems)

    def test_truncated_tail_is_detected_by_anchor(self, project: Path) -> None:
        _log_with_entries(project)
        entries = _lines(project)
        _write(project, entries[:2])
        problems = audit.verify_chain(project).problems
        assert any("truncated" in p for p in problems)

    def test_truncation_stays_detected_after_more_events(self, project: Path) -> None:
        """The anchor must not follow a shortened chain."""
        cdir = _log_with_entries(project)
        _write(project, _lines(project)[:2])
        first = run_gate(cdir, project, _policy(project))
        second = run_gate(cdir, project, _policy(project))
        assert first.decision == DENY and second.decision == DENY
        assert any("Audit log integrity" in r for r in second.reasons)

    def test_wiped_log_is_detected(self, project: Path) -> None:
        cdir = _log_with_entries(project)
        audit.audit_path(project).write_text("")
        d = run_gate(cdir, project, _policy(project))
        assert d.decision == DENY

    def test_admission_refuses_when_chain_is_broken(self, project: Path) -> None:
        cdir = _certified(project)
        run_gate(cdir, project, _policy(project))
        entries = _lines(project)
        entries[0]["operator_id"] = "someone_else"
        _write(project, entries)
        with pytest.raises(AdmissionError, match="Audit log"):
            run_admission(cdir, project, policy=_policy(project))

    def test_cli_reports_problems_with_exit_code(self, project: Path) -> None:
        _log_with_entries(project)
        entries = _lines(project)
        del entries[0]
        _write(project, entries)
        r = runner.invoke(app, ["audit", "verify"])
        assert r.exit_code == 1 and "problems" in r.output


class TestLegacyAndAnchors:
    def test_legacy_prefix_is_tolerated_and_reported(self, project: Path) -> None:
        audit.audit_path(project).write_text(json.dumps({"event": "gate_decision", "decision": "ALLOW"}) + "\n")
        audit.append_entry(project, {"event": "x"}, signer=signing.load_signer())
        status = audit.verify_chain(project, require_signatures=True)
        assert status.ok and status.legacy_entries == 1 and status.entries == 1

    def test_unchained_line_after_chain_is_detected(self, project: Path) -> None:
        audit.append_entry(project, {"event": "x"}, signer=signing.load_signer())
        with audit.audit_path(project).open("a") as f:
            f.write(json.dumps({"event": "gate_decision", "decision": "ALLOW"}) + "\n")
        assert any("unchained" in p for p in audit.verify_chain(project).problems)

    def test_missing_anchor_requires_explicit_reanchor(self, project: Path) -> None:
        _log_with_entries(project, 2)
        anchor = signing.airlock_home() / "anchors" / f"{audit.project_id(project)}.json"
        anchor.unlink()
        assert not audit.verify_chain(project, require_signatures=True).ok
        r = runner.invoke(app, ["audit", "verify", "--reanchor"])
        assert r.exit_code == 0, r.output
        assert audit.verify_chain(project, require_signatures=True).ok

    def test_reanchor_refuses_a_broken_chain(self, project: Path) -> None:
        _log_with_entries(project)
        entries = _lines(project)
        del entries[1]
        _write(project, entries)
        r = runner.invoke(app, ["audit", "verify", "--reanchor"])
        assert r.exit_code == 1


class TestDashboardIntegrity:
    def test_integrity_endpoint_reports_intact_then_broken(self, project: Path) -> None:
        from fastapi.testclient import TestClient
        from airlock.dashboard.server import create_app
        cdir = _certified(project)
        run_gate(cdir, project, _policy(project))
        client = TestClient(create_app(project))
        body = client.get("/api/integrity").json()
        assert body["ok"] and body["signed_entries"] == 1 and body["signatures_required"]
        entries = _lines(project)
        entries[0]["operator_id"] = "mallory"
        _write(project, entries)
        body = client.get("/api/integrity").json()
        assert not body["ok"] and body["problems"]

    def test_evidence_items_carry_signature_status(self, project: Path) -> None:
        from airlock.dashboard.reader import ProjectReader
        cdir = _certified(project)
        items = {e.document: e for e in ProjectReader(project).candidate_detail(cdir.name).evidence}
        assert items["test_report.json"].sig_ok
        (project / "evidence" / cdir.name / "test_report.json.sig").unlink()
        items = {e.document: e for e in ProjectReader(project).candidate_detail(cdir.name).evidence}
        assert not items["test_report.json"].sig_ok
