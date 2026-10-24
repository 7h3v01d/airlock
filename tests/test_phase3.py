# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
Phase 3 — Python verifier tests.

Tests AST scanner rules, the runner, and the CLI command.
Run from the repo root:
    pytest tests/test_phase3.py -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from airlock.main import app
from airlock.core.spec_store import create_spec, lock_spec
from airlock.core.candidate_store import register_candidate
from airlock.core.verifier.ast_scanner import scan_candidate, scan_tests_dir
from airlock.core.verifier.runner import run_verification

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


@pytest.fixture()
def clean_candidate(project: Path, locked_spec: str) -> Path:
    """A candidate with clean source that passes all critical rules."""
    candidates_dir = project / "candidates"
    _, cdir = register_candidate(candidates_dir, locked_spec)
    src = cdir / "src"
    (src / "backup.py").write_text(
        '"""Backup module."""\n\n'
        "import os\n"
        "import shutil\n"
        "from pathlib import Path\n\n\n"
        "def copy_files(source: Path, dest: Path) -> None:\n"
        '    """Copy files from source to dest."""\n'
        "    shutil.copytree(str(source), str(dest))\n",
        encoding="utf-8",
    )
    tests = cdir / "tests"
    (tests / "test_backup.py").write_text(
        "def test_placeholder():\n    assert True\n",
        encoding="utf-8",
    )
    return cdir


# ── AST scanner — import rules ────────────────────────────────────────────────

class TestImportRules:
    def _scan(self, tmp_path: Path, code: str) -> list:
        src = tmp_path / "src"
        src.mkdir()
        (src / "main.py").write_text(code, encoding="utf-8")
        return scan_candidate(src)

    def test_subprocess_import_fails(self, tmp_path: Path) -> None:
        results = self._scan(tmp_path, "import subprocess\n")
        failures = [r for r in results if r.rule_id == "IMPORT_SUBPROCESS" and not r.passed]
        assert failures

    def test_socket_import_fails(self, tmp_path: Path) -> None:
        results = self._scan(tmp_path, "import socket\n")
        failures = [r for r in results if r.rule_id == "IMPORT_SOCKET" and not r.passed]
        assert failures

    def test_requests_import_fails(self, tmp_path: Path) -> None:
        results = self._scan(tmp_path, "import requests\n")
        failures = [r for r in results if r.rule_id == "IMPORT_REQUESTS" and not r.passed]
        assert failures

    def test_urllib_import_fails(self, tmp_path: Path) -> None:
        results = self._scan(tmp_path, "from urllib import request\n")
        failures = [r for r in results if r.rule_id == "IMPORT_URLLIB" and not r.passed]
        assert failures

    def test_pickle_import_fails(self, tmp_path: Path) -> None:
        results = self._scan(tmp_path, "import pickle\n")
        failures = [r for r in results if r.rule_id == "IMPORT_PICKLE" and not r.passed]
        assert failures

    def test_clean_imports_pass(self, tmp_path: Path) -> None:
        results = self._scan(tmp_path, "import os\nimport shutil\nfrom pathlib import Path\n")
        import_failures = [
            r for r in results
            if r.rule_id.startswith("IMPORT_") and not r.passed
        ]
        assert not import_failures


# ── AST scanner — call rules ──────────────────────────────────────────────────

class TestCallRules:
    def _scan(self, tmp_path: Path, code: str) -> list:
        src = tmp_path / "src"
        src.mkdir()
        (src / "main.py").write_text(code, encoding="utf-8")
        return scan_candidate(src)

    def test_eval_fails(self, tmp_path: Path) -> None:
        results = self._scan(tmp_path, "x = eval('1+1')\n")
        failures = [r for r in results if r.rule_id == "CALL_EVAL" and not r.passed]
        assert failures

    def test_exec_fails(self, tmp_path: Path) -> None:
        results = self._scan(tmp_path, "exec('print(1)')\n")
        failures = [r for r in results if r.rule_id == "CALL_EXEC" and not r.passed]
        assert failures

    def test_os_system_fails(self, tmp_path: Path) -> None:
        results = self._scan(tmp_path, "import os\nos.system('ls')\n")
        failures = [r for r in results if r.rule_id == "CALL_OS_SYSTEM" and not r.passed]
        assert failures

    def test_safe_calls_pass(self, tmp_path: Path) -> None:
        results = self._scan(tmp_path, "x = len([1, 2, 3])\ny = str(x)\n")
        call_failures = [
            r for r in results
            if r.rule_id in ("CALL_EVAL", "CALL_EXEC", "CALL_OS_SYSTEM") and not r.passed
        ]
        assert not call_failures


# ── AST scanner — path traversal ──────────────────────────────────────────────

class TestPathTraversal:
    def _scan(self, tmp_path: Path, code: str) -> list:
        src = tmp_path / "src"
        src.mkdir()
        (src / "main.py").write_text(code, encoding="utf-8")
        return scan_candidate(src)

    def test_dotdot_slash_fails(self, tmp_path: Path) -> None:
        results = self._scan(tmp_path, 'path = "../secret"\n')
        failures = [r for r in results if r.rule_id == "FS_PATH_TRAVERSAL" and not r.passed]
        assert failures

    def test_dotdot_backslash_fails(self, tmp_path: Path) -> None:
        results = self._scan(tmp_path, 'path = "..\\\\secret"\n')
        failures = [r for r in results if r.rule_id == "FS_PATH_TRAVERSAL" and not r.passed]
        assert failures

    def test_safe_path_passes(self, tmp_path: Path) -> None:
        results = self._scan(tmp_path, 'path = "/safe/path/file.txt"\n')
        failures = [r for r in results if r.rule_id == "FS_PATH_TRAVERSAL" and not r.passed]
        assert not failures


# ── AST scanner — dynamic import ─────────────────────────────────────────────

class TestDynamicImport:
    def _scan(self, tmp_path: Path, code: str) -> list:
        src = tmp_path / "src"
        src.mkdir()
        (src / "main.py").write_text(code, encoding="utf-8")
        return scan_candidate(src)

    def test_dunder_import_fails(self, tmp_path: Path) -> None:
        results = self._scan(tmp_path, "m = __import__('os')\n")
        failures = [r for r in results if r.rule_id == "DYNAMIC_IMPORT" and not r.passed]
        assert failures

    def test_importlib_fails(self, tmp_path: Path) -> None:
        results = self._scan(tmp_path, "import importlib\nm = importlib.import_module('os')\n")
        failures = [r for r in results if r.rule_id == "DYNAMIC_IMPORT" and not r.passed]
        assert failures


# ── AST scanner — structural rules ────────────────────────────────────────────

class TestStructuralRules:
    def _scan(self, tmp_path: Path, code: str) -> list:
        src = tmp_path / "src"
        src.mkdir()
        (src / "main.py").write_text(code, encoding="utf-8")
        return scan_candidate(src)

    def test_missing_type_hints_flagged(self, tmp_path: Path) -> None:
        results = self._scan(tmp_path, "def foo(x):\n    return x\n")
        failures = [r for r in results if r.rule_id == "MISSING_TYPE_HINTS" and not r.passed]
        assert failures

    def test_private_functions_exempt_from_hints(self, tmp_path: Path) -> None:
        results = self._scan(tmp_path, "def _private(x):\n    return x\n")
        failures = [r for r in results if r.rule_id == "MISSING_TYPE_HINTS" and not r.passed]
        assert not failures

    def test_typed_function_passes(self, tmp_path: Path) -> None:
        results = self._scan(tmp_path, "def foo(x: int) -> str:\n    return str(x)\n")
        failures = [r for r in results if r.rule_id == "MISSING_TYPE_HINTS" and not r.passed]
        assert not failures

    def test_missing_docstring_flagged(self, tmp_path: Path) -> None:
        results = self._scan(tmp_path, "def foo(x: int) -> str:\n    return str(x)\n")
        failures = [r for r in results if r.rule_id == "MISSING_DOCSTRINGS" and not r.passed]
        assert failures

    def test_tests_present_passes(self, tmp_path: Path) -> None:
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "test_main.py").write_text("def test_x(): pass\n", encoding="utf-8")
        results = scan_tests_dir(tests)
        assert all(r.passed for r in results)

    def test_no_tests_flagged(self, tmp_path: Path) -> None:
        tests = tmp_path / "tests"
        tests.mkdir()
        results = scan_tests_dir(tests)
        failures = [r for r in results if not r.passed]
        assert failures


# ── Runner ────────────────────────────────────────────────────────────────────

class TestVerifierRunner:
    def test_clean_candidate_passes(self, project: Path, clean_candidate: Path, locked_spec: str) -> None:
        config = {"_project_root": project}
        report = run_verification(clean_candidate, project, config)
        assert report.verdict == "PASS"
        assert report.blocking_failures == 0

    def test_writes_evidence_file(self, project: Path, clean_candidate: Path, locked_spec: str) -> None:
        config = {"_project_root": project}
        run_verification(clean_candidate, project, config)
        evidence = project / "evidence" / clean_candidate.name / "static_verification.json"
        assert evidence.exists()
        data = json.loads(evidence.read_text())
        assert data["verdict"] == "PASS"
        sidecar = evidence.with_suffix(evidence.suffix + ".sha256")
        assert sidecar.exists()  # detached sidecar proves integrity

    def test_evidence_file_has_hash(self, project: Path, clean_candidate: Path) -> None:
        config = {"_project_root": project}
        report = run_verification(clean_candidate, project, config)
        assert report.evidence_hash.startswith("sha256:")

    def test_subprocess_import_fails_runner(self, project: Path, locked_spec: str) -> None:
        candidates_dir = project / "candidates"
        _, cdir = register_candidate(candidates_dir, locked_spec)
        (cdir / "src" / "bad.py").write_text("import subprocess\n", encoding="utf-8")
        config = {"_project_root": project}
        report = run_verification(cdir, project, config)
        assert report.verdict == "FAIL"
        assert report.blocking_failures > 0

    def test_missing_spec_link_fails(self, project: Path) -> None:
        """Candidate with no locked spec fails MISSING_SPEC_LINK."""
        candidates_dir = project / "candidates"
        _, cdir = register_candidate(candidates_dir, "spec_9999")
        (cdir / "src" / "main.py").write_text("x = 1\n", encoding="utf-8")
        config = {"_project_root": project}
        report = run_verification(cdir, project, config)
        assert report.verdict == "FAIL"
        blocking_ids = [r["rule_id"] for r in report.results if not r["passed"] and r["blocking"]]
        assert "MISSING_SPEC_LINK" in blocking_ids


# ── CLI ───────────────────────────────────────────────────────────────────────

class TestVerifyCLI:
    def test_verify_clean_candidate_passes(self, project: Path, clean_candidate: Path) -> None:
        result = runner.invoke(
            app, ["verify", clean_candidate.name], catch_exceptions=False
        )
        assert result.exit_code == 0
        assert "PASS" in result.output

    def test_verify_advances_status_to_verified(self, project: Path, clean_candidate: Path) -> None:
        from airlock.core.candidate_store import get_status
        runner.invoke(app, ["verify", clean_candidate.name], catch_exceptions=False)
        assert get_status(clean_candidate) == "verified"

    def test_verify_bad_candidate_fails(self, project: Path, locked_spec: str) -> None:
        candidates_dir = project / "candidates"
        _, cdir = register_candidate(candidates_dir, locked_spec)
        (cdir / "src" / "bad.py").write_text("import subprocess\n", encoding="utf-8")
        result = runner.invoke(app, ["verify", cdir.name], catch_exceptions=False)
        assert result.exit_code == 1
        assert "FAIL" in result.output
        assert "IMPORT_SUBPROCESS" in result.output

    def test_verify_bad_candidate_sets_rejected(self, project: Path, locked_spec: str) -> None:
        from airlock.core.candidate_store import get_status
        candidates_dir = project / "candidates"
        _, cdir = register_candidate(candidates_dir, locked_spec)
        (cdir / "src" / "bad.py").write_text("import subprocess\n", encoding="utf-8")
        runner.invoke(app, ["verify", cdir.name], catch_exceptions=False)
        assert get_status(cdir) == "rejected"

    def test_verify_missing_candidate_exits(self, project: Path) -> None:
        result = runner.invoke(app, ["verify", "candidate_9999"], catch_exceptions=False)
        assert result.exit_code == 1

    def test_verify_writes_evidence(self, project: Path, clean_candidate: Path) -> None:
        runner.invoke(app, ["verify", clean_candidate.name], catch_exceptions=False)
        evidence = project / "evidence" / clean_candidate.name / "static_verification.json"
        assert evidence.exists()
