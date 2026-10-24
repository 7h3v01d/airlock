# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
Phase 7C — Certifier timeout and execution containment tests.

Run from the repo root:
    pytest tests/test_phase7c.py -v
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from airlock.main import app
from airlock.core.spec_store import create_spec, lock_spec
from airlock.core.candidate_store import register_candidate, transition_status, compute_source_hash
from airlock.core.certifier.runner import (
    run_certification,
    _build_scrubbed_env,
    DEFAULT_TIMEOUT_SECONDS,
)

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


def _make_candidate(project: Path, spec_id: str, src: str, tests: str) -> Path:
    candidates_dir = project / "candidates"
    _, cdir = register_candidate(candidates_dir, spec_id)
    (cdir / "src" / "module.py").write_text(src, encoding="utf-8")
    (cdir / "tests" / "test_module.py").write_text(tests, encoding="utf-8")
    compute_source_hash(cdir)  # v0.3: evidence is bound to the recorded hash
    transition_status(cdir, "verified")
    return cdir


# ── Environment scrubbing tests ───────────────────────────────────────────────

class TestEnvironmentScrubbing:
    def test_scrubbed_env_contains_pythonpath(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        env = _build_scrubbed_env(src_dir)
        assert "PYTHONPATH" in env
        assert env["PYTHONPATH"] == str(src_dir)

    def test_scrubbed_env_does_not_inherit_pythonpath(self, tmp_path: Path) -> None:
        """Host PYTHONPATH must not leak into candidate env."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        original = os.environ.get("PYTHONPATH")
        os.environ["PYTHONPATH"] = "/some/trusted/path:/another/trusted/path"
        try:
            env = _build_scrubbed_env(src_dir)
            # PYTHONPATH should be ONLY src_dir, not combined with host
            assert "/some/trusted/path" not in env["PYTHONPATH"]
            assert env["PYTHONPATH"] == str(src_dir)
        finally:
            if original is None:
                os.environ.pop("PYTHONPATH", None)
            else:
                os.environ["PYTHONPATH"] = original

    def test_scrubbed_env_strips_sensitive_vars(self, tmp_path: Path) -> None:
        """Secret env vars must not appear in candidate environment."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        os.environ["KC_TEST_SECRET_TOKEN"] = "super-secret-12345"
        os.environ["KC_TEST_API_KEY"] = "sk-fake-key"
        try:
            env = _build_scrubbed_env(src_dir)
            assert "KC_TEST_SECRET_TOKEN" not in env
            assert "KC_TEST_API_KEY" not in env
        finally:
            os.environ.pop("KC_TEST_SECRET_TOKEN", None)
            os.environ.pop("KC_TEST_API_KEY", None)

    def test_scrubbed_env_retains_path(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        env = _build_scrubbed_env(src_dir)
        # PATH needed to find Python and pytest executables
        assert "PATH" in env

    def test_scrubbed_env_is_dict_of_strings(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        env = _build_scrubbed_env(src_dir)
        assert isinstance(env, dict)
        for k, v in env.items():
            assert isinstance(k, str)
            assert isinstance(v, str)


# ── Timeout tests ─────────────────────────────────────────────────────────────

class TestTimeout:
    def test_default_timeout_is_reasonable(self) -> None:
        assert DEFAULT_TIMEOUT_SECONDS >= 30
        assert DEFAULT_TIMEOUT_SECONDS <= 300

    def test_timeout_reported_in_test_report(
        self, project: Path, locked_spec: str
    ) -> None:
        """A candidate that hangs should be killed and reported as NOT_CERTIFIED."""
        # Use a very short timeout so the test completes quickly
        # We simulate timeout by passing a policy with 1s timeout
        # and a test that sleeps — but we mock the subprocess call instead
        # to avoid actually waiting.
        from unittest.mock import patch
        import subprocess as sp

        cdir = _make_candidate(
            project, locked_spec,
            src='"""Module."""\n\nx: int = 1\n',
            tests='def test_x():\n    assert True\n',
        )

        # Patch subprocess.run to raise TimeoutExpired
        with patch("airlock.core.certifier.runner.subprocess.run") as mock_run:
            mock_run.side_effect = sp.TimeoutExpired(cmd=["pytest"], timeout=1)
            test_report, _ = run_certification(cdir, project, {
                "certification": {"test_timeout_seconds": 1}
            })

        assert test_report.certification == "NOT_CERTIFIED"
        assert test_report.timed_out is True
        assert test_report.timeout_seconds == 1
        assert len(test_report.blocking_failures) > 0
        assert "timed out" in test_report.blocking_failures[0].lower()

    def test_timeout_recorded_in_evidence(
        self, project: Path, locked_spec: str
    ) -> None:
        from unittest.mock import patch
        import subprocess as sp

        cdir = _make_candidate(
            project, locked_spec,
            src='"""Module."""\n\nx: int = 1\n',
            tests='def test_x():\n    assert True\n',
        )

        with patch("airlock.core.certifier.runner.subprocess.run") as mock_run:
            mock_run.side_effect = sp.TimeoutExpired(cmd=["pytest"], timeout=1)
            run_certification(cdir, project, {
                "certification": {"test_timeout_seconds": 1}
            })

        evidence = project / "evidence" / cdir.name / "test_report.json"
        assert evidence.exists()
        data = json.loads(evidence.read_text())
        assert data["timed_out"] is True
        assert data["certification"] == "NOT_CERTIFIED"

    def test_policy_timeout_respected(
        self, project: Path, locked_spec: str
    ) -> None:
        """Policy can configure a custom timeout value."""
        from unittest.mock import patch, MagicMock

        cdir = _make_candidate(
            project, locked_spec,
            src='"""Module."""\n\nx: int = 1\n',
            tests='def test_x():\n    assert True\n',
        )

        captured_timeout = []

        def fake_run(*args, **kwargs):
            captured_timeout.append(kwargs.get("timeout"))
            mock = MagicMock()
            mock.returncode = 0
            mock.stdout = ""
            mock.stderr = ""
            return mock

        with patch("airlock.core.certifier.runner.subprocess.run", side_effect=fake_run):
            run_certification(cdir, project, {
                "certification": {"test_timeout_seconds": 45}
            })

        assert captured_timeout[0] == 45

    def test_default_timeout_used_when_not_in_policy(
        self, project: Path, locked_spec: str
    ) -> None:
        from unittest.mock import patch, MagicMock

        cdir = _make_candidate(
            project, locked_spec,
            src='"""Module."""\n\nx: int = 1\n',
            tests='def test_x():\n    assert True\n',
        )

        captured_timeout = []

        def fake_run(*args, **kwargs):
            captured_timeout.append(kwargs.get("timeout"))
            mock = MagicMock()
            mock.returncode = 0
            mock.stdout = ""
            mock.stderr = ""
            return mock

        with patch("airlock.core.certifier.runner.subprocess.run", side_effect=fake_run):
            run_certification(cdir, project, {})  # no policy

        assert captured_timeout[0] == DEFAULT_TIMEOUT_SECONDS


# ── Working directory containment ─────────────────────────────────────────────

class TestWorkingDirectory:
    def test_subprocess_cwd_is_candidate_dir(
        self, project: Path, locked_spec: str
    ) -> None:
        """Candidate subprocess must run with cwd = candidate dir, not repo root."""
        from unittest.mock import patch, MagicMock

        cdir = _make_candidate(
            project, locked_spec,
            src='"""Module."""\n\nx: int = 1\n',
            tests='def test_x():\n    assert True\n',
        )

        captured_cwd = []

        def fake_run(*args, **kwargs):
            captured_cwd.append(kwargs.get("cwd"))
            mock = MagicMock()
            mock.returncode = 0
            mock.stdout = ""
            mock.stderr = ""
            return mock

        with patch("airlock.core.certifier.runner.subprocess.run", side_effect=fake_run):
            run_certification(cdir, project, {})

        assert captured_cwd[0] == str(cdir)


# ── Integration: passing candidate still certifies ────────────────────────────

class TestContainedCertification:
    def test_passing_candidate_certifies_with_containment(
        self, project: Path, locked_spec: str
    ) -> None:
        """Verify containment doesn't break legitimate certification."""
        cdir = _make_candidate(
            project, locked_spec,
            src=(
                '"""Calculator."""\n\n\n'
                "def add(a: int, b: int) -> int:\n"
                '    """Add two numbers."""\n'
                "    return a + b\n"
            ),
            tests=(
                "import sys\n"
                "from pathlib import Path\n"
                "sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))\n"
                "from module import add\n\n"
                "def test_add():\n"
                "    assert add(1, 2) == 3\n"
            ),
        )
        test_report, _ = run_certification(cdir, project, {})
        assert test_report.certification == "CERTIFIED"
        assert test_report.timed_out is False
        assert test_report.passed >= 1
