# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
Tests for FS_HARDCODED_PATHS verifier rule.

Covers all acceptance criteria from spec_dogfood_001.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

# Add src to path for direct import
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from hardcoded_paths_rule import (
    RULE_ID,
    SEVERITY,
    BLOCKING,
    is_hardcoded_absolute_path,
    scan_for_hardcoded_paths,
    scan_file,
    scan_directory,
)


# ── is_hardcoded_absolute_path ────────────────────────────────────────────────

class TestIsHardcodedAbsolutePath:
    def test_windows_path_with_backslash(self) -> None:
        assert is_hardcoded_absolute_path("C:\\Users\\leon\\file.txt") is True

    def test_windows_path_with_forward_slash(self) -> None:
        assert is_hardcoded_absolute_path("C:/Users/leon/file.txt") is True

    def test_windows_other_drive(self) -> None:
        assert is_hardcoded_absolute_path("D:\\Projects\\app") is True

    def test_unix_home_path(self) -> None:
        assert is_hardcoded_absolute_path("/home/user/data.json") is True

    def test_unix_tmp_path(self) -> None:
        assert is_hardcoded_absolute_path("/tmp/cache") is True

    def test_unix_etc_path(self) -> None:
        assert is_hardcoded_absolute_path("/etc/config.yaml") is True

    def test_unix_var_path(self) -> None:
        assert is_hardcoded_absolute_path("/var/log/app.log") is True

    def test_unix_root_path(self) -> None:
        assert is_hardcoded_absolute_path("/root/.ssh/id_rsa") is True

    def test_unix_usr_path(self) -> None:
        assert is_hardcoded_absolute_path("/usr/local/bin/python") is True

    def test_relative_path_not_flagged(self) -> None:
        assert is_hardcoded_absolute_path("data/file.txt") is False

    def test_relative_dotdot_not_flagged(self) -> None:
        assert is_hardcoded_absolute_path("../config/settings.yaml") is False

    def test_plain_filename_not_flagged(self) -> None:
        assert is_hardcoded_absolute_path("output.json") is False

    def test_api_url_path_not_flagged(self) -> None:
        assert is_hardcoded_absolute_path("/api/v1/endpoint") is False

    def test_empty_string_not_flagged(self) -> None:
        assert is_hardcoded_absolute_path("") is False

    def test_root_slash_alone_not_flagged(self) -> None:
        assert is_hardcoded_absolute_path("/") is False


# ── scan_for_hardcoded_paths ──────────────────────────────────────────────────

class TestScanForHardcodedPaths:
    def _parse(self, code: str) -> ast.Module:
        return ast.parse(code)

    def test_windows_path_returns_failure(self) -> None:
        tree = self._parse('path = "C:\\\\Users\\\\leon\\\\file.txt"\n')
        results = scan_for_hardcoded_paths(tree, "src/main.py")
        failures = [r for r in results if not r["passed"]]
        assert failures
        assert failures[0]["rule_id"] == RULE_ID

    def test_unix_home_path_returns_failure(self) -> None:
        tree = self._parse('path = "/home/user/data.json"\n')
        results = scan_for_hardcoded_paths(tree, "src/main.py")
        failures = [r for r in results if not r["passed"]]
        assert failures

    def test_unix_tmp_path_returns_failure(self) -> None:
        tree = self._parse('cache = "/tmp/cache"\n')
        results = scan_for_hardcoded_paths(tree, "src/main.py")
        failures = [r for r in results if not r["passed"]]
        assert failures

    def test_relative_path_returns_pass(self) -> None:
        tree = self._parse('path = "data/file.txt"\n')
        results = scan_for_hardcoded_paths(tree, "src/main.py")
        assert all(r["passed"] for r in results)

    def test_dynamic_path_home_returns_pass(self) -> None:
        # Path.home() is dynamic — not a string literal
        tree = self._parse("from pathlib import Path\npath = Path.home() / 'file'\n")
        results = scan_for_hardcoded_paths(tree, "src/main.py")
        assert all(r["passed"] for r in results)

    def test_no_string_literals_returns_pass(self) -> None:
        tree = self._parse("x = 1\ny = x + 2\n")
        results = scan_for_hardcoded_paths(tree, "src/main.py")
        assert all(r["passed"] for r in results)

    def test_failure_includes_line_number(self) -> None:
        tree = self._parse('x = 1\npath = "/tmp/file"\n')
        results = scan_for_hardcoded_paths(tree, "src/main.py")
        failures = [r for r in results if not r["passed"]]
        assert failures[0]["line"] == 2

    def test_failure_includes_file_path(self) -> None:
        tree = self._parse('path = "/home/user/x"\n')
        results = scan_for_hardcoded_paths(tree, "src/main.py")
        failures = [r for r in results if not r["passed"]]
        assert failures[0]["file"] == "src/main.py"

    def test_failure_includes_detail(self) -> None:
        tree = self._parse('path = "/tmp/cache"\n')
        results = scan_for_hardcoded_paths(tree, "src/main.py")
        failures = [r for r in results if not r["passed"]]
        assert "/tmp/cache" in failures[0]["detail"]

    def test_multiple_paths_multiple_failures(self) -> None:
        code = 'a = "/tmp/a"\nb = "/home/user/b"\n'
        tree = self._parse(code)
        results = scan_for_hardcoded_paths(tree, "src/main.py")
        failures = [r for r in results if not r["passed"]]
        assert len(failures) == 2


# ── Rule metadata ─────────────────────────────────────────────────────────────

class TestRuleMetadata:
    def test_rule_id_correct(self) -> None:
        assert RULE_ID == "FS_HARDCODED_PATHS"

    def test_severity_is_medium(self) -> None:
        assert SEVERITY == "medium"

    def test_blocking_is_false(self) -> None:
        assert BLOCKING is False


# ── scan_file ─────────────────────────────────────────────────────────────────

class TestScanFile:
    def test_scans_file_with_hardcoded_path(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        f = src / "main.py"
        f.write_text('path = "/tmp/data"\n', encoding="utf-8")
        results = scan_file(f, src)
        failures = [r for r in results if not r["passed"]]
        assert failures

    def test_scans_clean_file(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        f = src / "main.py"
        f.write_text('path = "relative/path"\n', encoding="utf-8")
        results = scan_file(f, src)
        assert all(r["passed"] for r in results)


# ── scan_directory ────────────────────────────────────────────────────────────

class TestScanDirectory:
    def test_scans_multiple_files(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "a.py").write_text('x = "/tmp/a"\n', encoding="utf-8")
        (src / "b.py").write_text('y = "relative"\n', encoding="utf-8")
        results = scan_directory(src)
        failures = [r for r in results if not r["passed"]]
        assert len(failures) == 1
        assert "a.py" in failures[0]["file"]

    def test_empty_directory_returns_no_results(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        results = scan_directory(src)
        assert results == []
