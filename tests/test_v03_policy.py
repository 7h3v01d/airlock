# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
v0.3 — Policy enforcement, escalation and operator override.

In v0.2 ESCALATE_TO_OPERATOR was unreachable, `--override` was advertised
but did not exist, and most airlock.yaml keys (including the coverage
minimums) were never read.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from airlock.main import app
from airlock.commands.init import _CONFIG_TEMPLATE
from airlock.core.candidate_store import register_candidate, transition_status, compute_source_hash
from airlock.core.certifier.runner import run_certification
from airlock.core.governance.gate import (
    ALLOW, DENY, ESCALATE, run_gate, run_override, run_admission, OverrideError,
)
from airlock.core.verifier.runner import run_verification

runner = CliRunner()

ENV_SRC = (
    '"""Reads config from the environment."""\nimport os\n\n\n'
    'def home() -> str:\n    """Return HOME."""\n    return os.getenv("HOME", "")\n'
)
ENV_TESTS = "from envmod import home\n\n\ndef test_home():\n    assert isinstance(home(), str)\n"


@pytest.fixture()
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init", "proj"], catch_exceptions=False)
    root = tmp_path / "proj"
    monkeypatch.chdir(root)
    runner.invoke(app, ["spec", "new", "env reader"], catch_exceptions=False)
    spec_md = root / "specs" / "spec_0001" / "spec.md"
    spec_md.write_text(
        spec_md.read_text().replace("<!-- Describe what the system must do -->", "Read HOME."),
        encoding="utf-8",
    )
    assert runner.invoke(app, ["spec", "lock", "spec_0001"]).exit_code == 0
    return root


def _policy(root: Path) -> dict:
    return yaml.safe_load((root / "airlock.yaml").read_text())


def _env_candidate(root: Path) -> Path:
    runner.invoke(app, ["candidate", "register", "spec_0001"])
    cdir = root / "candidates" / "candidate_0001"
    (cdir / "src" / "envmod.py").write_text(ENV_SRC, encoding="utf-8")
    (cdir / "tests" / "test_envmod.py").write_text(ENV_TESTS, encoding="utf-8")
    for step in (["verify"], ["certify"]):
        r = runner.invoke(app, [*step, "candidate_0001"])
        assert r.exit_code == 0, r.output
    return cdir


class TestEscalation:
    def test_env_access_escalates_under_default_policy(self, project: Path) -> None:
        _env_candidate(project)
        r = runner.invoke(app, ["gate", "candidate_0001"])
        assert r.exit_code == 2
        assert ESCALATE in r.output and "ENV_ACCESS" in r.output

    def test_no_escalation_when_category_not_listed(self, project: Path) -> None:
        cdir = _env_candidate(project)
        policy = _policy(project)
        policy["governance"]["require_human_approval_for"] = []
        assert run_gate(cdir, project, policy).decision == ALLOW

    def test_escalated_candidate_cannot_be_admitted_without_override(self, project: Path) -> None:
        _env_candidate(project)
        runner.invoke(app, ["gate", "candidate_0001"])
        r = runner.invoke(app, ["admit", "candidate_0001"])
        assert r.exit_code == 1


class TestOverride:
    def test_override_requires_named_operator_and_reason(self, project: Path) -> None:
        cdir = _env_candidate(project)
        with pytest.raises(OverrideError, match="operator"):
            run_override(cdir, project, _policy(project), "", "ok")
        with pytest.raises(OverrideError, match="reason"):
            run_override(cdir, project, _policy(project), "leon", "  ")

    def test_override_via_cli_then_admit(self, project: Path) -> None:
        _env_candidate(project)
        r = runner.invoke(app, [
            "gate", "candidate_0001", "--override",
            "--operator", "leon", "--reason", "reads HOME only",
        ])
        assert r.exit_code == 0, r.output
        assert "ALLOW" in r.output and "override" in r.output.lower()
        a = runner.invoke(app, ["admit", "candidate_0001"])
        assert a.exit_code == 0, a.output
        cert = json.loads((project / "evidence" / "candidate_0001" / "admission_certificate.json").read_text())
        assert cert["operator_override"] is True
        assert cert["override_operator"] == "leon"
        assert cert["override_reason"] == "reads HOME only"

    def test_override_is_audited(self, project: Path) -> None:
        cdir = _env_candidate(project)
        run_override(cdir, project, _policy(project), "leon", "reviewed")
        events = [json.loads(l) for l in (project / "logs" / "audit.jsonl").read_text().splitlines() if l]
        ov = [e for e in events if e["event"] == "operator_override"]
        assert ov and ov[-1]["operator_id"] == "leon" and ov[-1]["overridden_decision"] == ESCALATE

    def test_deny_cannot_be_overridden(self, project: Path) -> None:
        cdir = _env_candidate(project)
        (cdir / "src" / "envmod.py").write_text(ENV_SRC + "\n# tampered\n", encoding="utf-8")
        with pytest.raises(OverrideError, match="DENY"):
            run_override(cdir, project, _policy(project), "leon", "please")


class TestCoveragePolicy:
    BRANCHY = (
        '"""m."""\n\n\ndef pick(x: int) -> int:\n    """Pick."""\n'
        "    if x > 0:\n        return 1\n    return 2\n"
    )

    def _certify(self, root: Path, src: str, tests: str) -> Path:
        _, cdir = register_candidate(root / "candidates", "spec_0001")
        (cdir / "src" / "m.py").write_text(src, encoding="utf-8")
        (cdir / "tests" / "test_m.py").write_text(tests, encoding="utf-8")
        compute_source_hash(cdir)
        run_verification(cdir, root, {})
        transition_status(cdir, "verified")
        run_certification(cdir, root, {})
        transition_status(cdir, "certified")
        return cdir

    def test_branch_minimum_is_enforced(self, project: Path) -> None:
        cdir = self._certify(project, self.BRANCHY, "from m import pick\n\n\ndef test_pos():\n    assert pick(1) == 1\n")
        policy = {"certification": {"minimum_branch_coverage": 0.9}}
        d = run_gate(cdir, project, policy)
        assert d.decision == DENY
        assert any("Branch coverage" in r for r in d.reasons)

    def test_minimum_met_allows(self, project: Path) -> None:
        cdir = self._certify(
            project, self.BRANCHY,
            "from m import pick\n\n\ndef test_both():\n    assert pick(1) == 1\n    assert pick(0) == 2\n",
        )
        policy = {"certification": {"minimum_branch_coverage": 0.9, "minimum_line_coverage": 0.9}}
        assert run_gate(cdir, project, policy).decision == ALLOW

    def test_code_without_branches_has_full_branch_coverage(self, project: Path) -> None:
        cdir = self._certify(
            project, '"""m."""\n\n\ndef one() -> int:\n    """One."""\n    return 1\n',
            "from m import one\n\n\ndef test_one():\n    assert one() == 1\n",
        )
        cov = json.loads((project / "evidence" / cdir.name / "coverage_report.json").read_text())
        assert cov["branch_coverage"] == 1.0

    def test_line_coverage_is_not_blended_with_branches(self, project: Path) -> None:
        cdir = self._certify(project, self.BRANCHY, "from m import pick\n\n\ndef test_pos():\n    assert pick(1) == 1\n")
        cov = json.loads((project / "evidence" / cdir.name / "coverage_report.json").read_text())
        assert cov["branch_coverage"] == 0.5
        assert cov["line_coverage"] > cov["branch_coverage"]


class TestVerificationPolicy:
    def _candidate(self, root: Path, with_tests: bool) -> Path:
        _, cdir = register_candidate(root / "candidates", "spec_0001")
        (cdir / "src" / "m.py").write_text('"""m."""\n\n\ndef f(x):\n    """F."""\n    return x\n')
        if with_tests:
            (cdir / "tests" / "test_m.py").write_text("def test_x():\n    assert True\n")
        return cdir

    def test_require_tests_makes_missing_tests_blocking(self, project: Path) -> None:
        cdir = self._candidate(project, with_tests=False)
        assert run_verification(cdir, project, {"verification": {"require_tests": True}}).verdict == "FAIL"

    def test_require_type_hints_makes_hints_blocking(self, project: Path) -> None:
        cdir = self._candidate(project, with_tests=True)
        assert run_verification(cdir, project, {}).verdict == "PASS"
        assert run_verification(cdir, project, {"verification": {"require_type_hints": True}}).verdict == "FAIL"


class TestTemplateHonesty:
    def _leaves(self, data: dict, prefix: str = "") -> list[str]:
        out = []
        for k, v in data.items():
            if isinstance(v, dict):
                out += self._leaves(v, f"{prefix}{k}.")
            else:
                out.append(k)
        return out

    def test_every_template_key_is_read_by_code(self) -> None:
        """Guard against policy theatre: no key may sit in the template unenforced."""
        pkg = Path(__file__).resolve().parent.parent / "airlock"
        code = "\n".join(
            p.read_text(encoding="utf-8") for p in pkg.rglob("*.py") if p.name != "init.py"
        )
        template = yaml.safe_load(_CONFIG_TEMPLATE.replace("{project_name}", "x"))
        unread = [k for k in self._leaves(template) if f'"{k}"' not in code]
        assert unread == [], f"template keys never read: {unread}"

    @pytest.mark.parametrize("edit, needle", [
        (("local_first", "allow_telemetry", True), "allow_telemetry"),
        (("llm", "provider", "openai"), "llm.provider"),
    ])
    def test_unsupported_settings_are_rejected(self, project: Path, edit, needle) -> None:
        section, key, value = edit
        policy = _policy(project)
        policy[section][key] = value
        (project / "airlock.yaml").write_text(yaml.safe_dump(policy))
        r = runner.invoke(app, ["status"])
        assert r.exit_code == 1 and needle in r.output


class TestDashboardReader:
    def test_reader_surfaces_override_and_registration(self, project: Path) -> None:
        from airlock.dashboard.reader import ProjectReader
        cdir = _env_candidate(project)
        run_override(cdir, project, _policy(project), "leon", "reviewed")
        run_admission(cdir, project)
        reader = ProjectReader(project)
        summary = reader.candidate_detail(cdir.name)
        assert summary.operator_override and summary.override_operator == "leon"
        assert summary.registered_at
        override = [e for e in reader.audit_log() if e.event == "operator_override"][0]
        assert override.reason == "reviewed" and override.overridden_decision == ESCALATE
