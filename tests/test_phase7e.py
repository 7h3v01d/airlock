# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
Phase 7E — Verifier expansion tests.

Tests the three new rules:
  FS_FILE_DELETION   — file deletion calls
  ENV_ACCESS         — environment variable access
  FS_SHUTIL_MUTATION — dangerous shutil operations

Run from the repo root:
    pytest tests/test_phase7e.py -v
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from airlock.core.verifier.ast_scanner import scan_candidate
from airlock.core.verifier.rules import (
    FS_FILE_DELETION,
    ENV_ACCESS,
    FS_SHUTIL_MUTATION,
    ALL_RULES,
)

runner = CliRunner()


def _make_src(tmp_path: Path, code: str) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.py").write_text(code, encoding="utf-8")
    return src


def _failures(results: list, rule_id: str) -> list:
    return [r for r in results if r.rule_id == rule_id and not r.passed]


# ── Rule registry checks ──────────────────────────────────────────────────────

class TestRuleRegistry:
    def test_fs_file_deletion_in_all_rules(self) -> None:
        ids = [r.rule_id for r in ALL_RULES]
        assert "FS_FILE_DELETION" in ids

    def test_env_access_in_all_rules(self) -> None:
        ids = [r.rule_id for r in ALL_RULES]
        assert "ENV_ACCESS" in ids

    def test_fs_shutil_mutation_in_all_rules(self) -> None:
        ids = [r.rule_id for r in ALL_RULES]
        assert "FS_SHUTIL_MUTATION" in ids

    def test_fs_file_deletion_is_high_blocking(self) -> None:
        assert FS_FILE_DELETION.severity == "high"
        assert FS_FILE_DELETION.blocking is True

    def test_env_access_is_medium_non_blocking(self) -> None:
        assert ENV_ACCESS.severity == "medium"
        assert ENV_ACCESS.blocking is False

    def test_fs_shutil_mutation_is_medium_non_blocking(self) -> None:
        assert FS_SHUTIL_MUTATION.severity == "medium"
        assert FS_SHUTIL_MUTATION.blocking is False

    def test_total_rule_count_is_22(self) -> None:
        assert len(ALL_RULES) == 22  # v0.3: + SOURCE_INTEGRITY, SRC_UNSCANNED_CONTENT, IMPORT_NOT_ALLOWED, DANGEROUS_CALL


# ── FS_FILE_DELETION ──────────────────────────────────────────────────────────

class TestFileDeletion:
    def test_os_remove_fails(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path, "import os\nos.remove('file.txt')\n")
        results = scan_candidate(src)
        assert _failures(results, "FS_FILE_DELETION")

    def test_os_unlink_fails(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path, "import os\nos.unlink('file.txt')\n")
        results = scan_candidate(src)
        assert _failures(results, "FS_FILE_DELETION")

    def test_os_rmdir_fails(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path, "import os\nos.rmdir('mydir')\n")
        results = scan_candidate(src)
        assert _failures(results, "FS_FILE_DELETION")

    def test_shutil_rmtree_fails(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path, "import shutil\nshutil.rmtree('mydir')\n")
        results = scan_candidate(src)
        assert _failures(results, "FS_FILE_DELETION")

    def test_path_unlink_fails(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path,
            "from pathlib import Path\np = Path('file.txt')\np.unlink()\n")
        results = scan_candidate(src)
        assert _failures(results, "FS_FILE_DELETION")

    def test_path_rmdir_fails(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path,
            "from pathlib import Path\np = Path('mydir')\np.rmdir()\n")
        results = scan_candidate(src)
        assert _failures(results, "FS_FILE_DELETION")

    def test_clean_file_passes(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path,
            '"""Module."""\n\n\ndef add(a: int, b: int) -> int:\n    """Add."""\n    return a + b\n')
        results = scan_candidate(src)
        assert not _failures(results, "FS_FILE_DELETION")

    def test_failure_is_blocking(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path, "import os\nos.remove('x')\n")
        results = scan_candidate(src)
        failures = _failures(results, "FS_FILE_DELETION")
        assert all(r.blocking for r in failures)


# ── ENV_ACCESS ────────────────────────────────────────────────────────────────

class TestEnvAccess:
    def test_os_environ_access_fails(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path,
            "import os\ntoken = os.environ['SECRET']\n")
        results = scan_candidate(src)
        assert _failures(results, "ENV_ACCESS")

    def test_os_getenv_fails(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path,
            "import os\ntoken = os.getenv('API_KEY')\n")
        results = scan_candidate(src)
        assert _failures(results, "ENV_ACCESS")

    def test_os_putenv_fails(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path,
            "import os\nos.putenv('MY_VAR', 'value')\n")
        results = scan_candidate(src)
        assert _failures(results, "ENV_ACCESS")

    def test_clean_file_passes(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path,
            '"""Module."""\n\n\ndef work(x: int) -> int:\n    """Do work."""\n    return x * 2\n')
        results = scan_candidate(src)
        assert not _failures(results, "ENV_ACCESS")

    def test_env_access_is_non_blocking(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path, "import os\nx = os.environ.get('VAR')\n")
        results = scan_candidate(src)
        failures = _failures(results, "ENV_ACCESS")
        assert all(not r.blocking for r in failures)


# ── FS_SHUTIL_MUTATION ────────────────────────────────────────────────────────

class TestShutilMutation:
    def test_shutil_move_fails(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path,
            "import shutil\nshutil.move('src', 'dst')\n")
        results = scan_candidate(src)
        assert _failures(results, "FS_SHUTIL_MUTATION")

    def test_shutil_copytree_fails(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path,
            "import shutil\nshutil.copytree('src', 'dst')\n")
        results = scan_candidate(src)
        assert _failures(results, "FS_SHUTIL_MUTATION")

    def test_shutil_chown_fails(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path,
            "import shutil\nshutil.chown('file', user='root')\n")
        results = scan_candidate(src)
        assert _failures(results, "FS_SHUTIL_MUTATION")

    def test_shutil_copy2_does_not_fail(self, tmp_path: Path) -> None:
        # shutil.copy2 is a standard copy — not flagged
        src = _make_src(tmp_path,
            "import shutil\nshutil.copy2('src', 'dst')\n")
        results = scan_candidate(src)
        assert not _failures(results, "FS_SHUTIL_MUTATION")

    def test_clean_file_passes(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path,
            '"""Module."""\n\n\ndef work(x: int) -> int:\n    """Do work."""\n    return x\n')
        results = scan_candidate(src)
        assert not _failures(results, "FS_SHUTIL_MUTATION")

    def test_shutil_mutation_is_non_blocking(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path,
            "import shutil\nshutil.move('a', 'b')\n")
        results = scan_candidate(src)
        failures = _failures(results, "FS_SHUTIL_MUTATION")
        assert all(not r.blocking for r in failures)


# ── Interaction: existing rules still work ────────────────────────────────────

class TestExistingRulesUnchanged:
    def test_subprocess_still_blocked(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path, "import subprocess\n")
        results = scan_candidate(src)
        assert _failures(results, "IMPORT_SUBPROCESS")

    def test_eval_still_blocked(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path, "eval('x')\n")
        results = scan_candidate(src)
        assert _failures(results, "CALL_EVAL")

    def test_clean_module_passes_all_rules(self, tmp_path: Path) -> None:
        src = _make_src(tmp_path,
            '"""Clean module."""\n\n\ndef compute(x: int, y: int) -> int:\n    """Compute sum."""\n    return x + y\n')
        results = scan_candidate(src)
        failures = [r for r in results if not r.passed and r.blocking]
        assert not failures
