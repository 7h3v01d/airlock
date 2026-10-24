# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
Phase 6 — LLM integration tests.

Uses mocked Ollama responses — no live Ollama instance required.

Run from the repo root:
    pytest tests/test_phase6.py -v
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from airlock.main import app
from airlock.core.spec_store import create_spec, lock_spec
from airlock.core.candidate_store import register_candidate
from airlock.llm.provider import LLMCapabilityProfile, ALLOWED_ROLES, FORBIDDEN_ROLES
from airlock.llm.ollama_provider import OllamaProvider
from airlock.llm.prompt_contracts import build_spec_draft_prompt, build_generate_prompt, build_explain_prompt
from airlock.llm.generator import draft_spec, generate_candidate, _parse_generated_files, GenerationError

runner = CliRunner()

# ── Sample LLM responses ──────────────────────────────────────────────────────

SAMPLE_SPEC_DRAFT = """## Functional requirements

1. Scan a source directory recursively and copy changed files to a destination.
2. Preserve relative directory structure.
3. Skip files whose content hash matches the destination copy.
4. Support dry-run mode that reports what would be copied without copying.
5. Generate a JSON manifest of all operations performed.

## Non-functional requirements

- Must run fully offline with no network access.
- Must handle permission errors gracefully without crashing.
- Must complete within 30 seconds for directories up to 10,000 files.

## Forbidden behaviours

- Must not delete any source files.
- Must not follow symlinks outside the source root.
- Must not execute any discovered files.
- Must not use subprocess, socket, or network operations.

## Acceptance criteria

1. Given a source directory with 3 files, the destination receives 3 matching copies.
2. Given an unchanged file already in the destination, the file is skipped.
3. Given dry-run mode, no files are written to the destination.
4. Given a permission error, the error is recorded in the manifest and execution continues.
"""

SAMPLE_GENERATED_CODE = '''### FILE: src/backup.py
```python
"""Local file backup module."""

import hashlib
import json
import shutil
from pathlib import Path


def compute_hash(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def backup(source: Path, destination: Path, dry_run: bool = False) -> dict:
    """Copy files from source to destination."""
    manifest: dict = {"copied": [], "skipped": [], "errors": []}
    for src in source.rglob("*"):
        if src.is_file():
            rel = src.relative_to(source)
            dst = destination / rel
            if dst.exists() and compute_hash(src) == compute_hash(dst):
                manifest["skipped"].append(str(rel))
            elif not dry_run:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(src), str(dst))
                manifest["copied"].append(str(rel))
            else:
                manifest["copied"].append(str(rel))
    return manifest
```

### FILE: tests/test_backup.py
```python
"""Tests for backup module."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from backup import backup, compute_hash


def test_backup_copies_files(tmp_path):
    """Test that files are copied."""
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "a.txt").write_text("hello")
    backup(src, dst)
    assert (dst / "a.txt").exists()


def test_dry_run_no_copy(tmp_path):
    """Test dry run does not copy."""
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "a.txt").write_text("hello")
    backup(src, dst, dry_run=True)
    assert not (dst / "a.txt").exists()
```
'''

SAMPLE_EXPLANATION = """The IMPORT_SUBPROCESS rule is blocking because subprocess allows
shell command execution, which violates the cleanroom's execution policy.

Fix: Replace subprocess with a pure Python alternative.
"""


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
    spec_id, spec_dir = create_spec(specs_dir, "Test backup tool")
    (spec_dir / "spec.md").write_text(
        "# spec\n\n## Functional requirements\n\nBackup files.\n\n"
        "## Non-functional requirements\n\nOffline.\n\n"
        "## Forbidden behaviours\n\nNo network.\n\n"
        "## Acceptance criteria\n\nFiles are copied.\n",
        encoding="utf-8",
    )
    lock_spec(specs_dir, spec_id)
    return spec_id


@pytest.fixture()
def mock_provider() -> MagicMock:
    provider = MagicMock()
    provider.profile = LLMCapabilityProfile(
        model="deepseek-coder-v2:16b",
        provider_name="ollama",
        local=True,
        network_access=False,
        context_window=32768,
        allowed_roles=set(ALLOWED_ROLES),
    )
    provider.is_available.return_value = True
    provider.complete.return_value = SAMPLE_SPEC_DRAFT
    return provider


# ── Provider and capability tests ─────────────────────────────────────────────

class TestLLMProvider:
    def test_capability_profile_rejects_forbidden_roles(self) -> None:
        with pytest.raises(ValueError, match="forbidden roles"):
            LLMCapabilityProfile(
                model="test",
                provider_name="test",
                local=True,
                network_access=False,
                context_window=4096,
                allowed_roles={"certify"},  # forbidden
            )

    def test_capability_profile_rejects_approve(self) -> None:
        with pytest.raises(ValueError, match="forbidden roles"):
            LLMCapabilityProfile(
                model="test",
                provider_name="test",
                local=True,
                network_access=False,
                context_window=4096,
                allowed_roles={"approve"},
            )

    def test_capability_profile_accepts_allowed_roles(self) -> None:
        profile = LLMCapabilityProfile(
            model="test",
            provider_name="test",
            local=True,
            network_access=False,
            context_window=4096,
            allowed_roles={"draft_spec", "generate_candidate"},
        )
        assert profile.can("draft_spec")
        assert not profile.can("certify")

    def test_all_forbidden_roles_rejected(self) -> None:
        for role in FORBIDDEN_ROLES:
            with pytest.raises(ValueError):
                LLMCapabilityProfile(
                    model="test", provider_name="test",
                    local=True, network_access=False,
                    context_window=4096,
                    allowed_roles={role},
                )

    def test_ollama_provider_has_correct_roles(self) -> None:
        provider = OllamaProvider()
        for role in FORBIDDEN_ROLES:
            assert not provider.profile.can(role)
        for role in ALLOWED_ROLES:
            assert provider.profile.can(role)

    def test_ollama_provider_is_local(self) -> None:
        provider = OllamaProvider()
        assert provider.profile.local is True
        assert provider.profile.network_access is False


# ── Prompt contracts ──────────────────────────────────────────────────────────

class TestPromptContracts:
    def test_spec_draft_prompt_contains_intent(self) -> None:
        _, prompt = build_spec_draft_prompt("Build a backup tool")
        assert "Build a backup tool" in prompt

    def test_spec_draft_system_forbids_approval(self) -> None:
        system, _ = build_spec_draft_prompt("test")
        assert "may NOT" in system
        assert "Approve" in system or "approve" in system

    def test_generate_prompt_contains_spec(self) -> None:
        _, prompt = build_generate_prompt("## Spec content here", "backup")
        assert "## Spec content here" in prompt
        assert "backup" in prompt

    def test_generate_system_forbids_subprocess(self) -> None:
        system, _ = build_generate_prompt("spec", "mod")
        assert "subprocess" in system

    def test_explain_prompt_contains_failures(self) -> None:
        failures = [{"rule_id": "IMPORT_SUBPROCESS", "file": "src/bad.py", "line": 1, "detail": "import subprocess"}]
        _, prompt = build_explain_prompt("candidate_0001", "verifier", failures)
        assert "IMPORT_SUBPROCESS" in prompt
        assert "candidate_0001" in prompt

    def test_explain_system_forbids_override(self) -> None:
        system, _ = build_explain_prompt("c", "verifier", [])
        assert "may NOT" in system
        assert "Override" in system or "override" in system


# ── Response parser ───────────────────────────────────────────────────────────

class TestResponseParser:
    def test_parses_file_blocks_with_fences(self) -> None:
        files = _parse_generated_files(SAMPLE_GENERATED_CODE, "backup")
        assert "src/backup.py" in files
        assert "tests/test_backup.py" in files

    def test_parsed_src_contains_function(self) -> None:
        files = _parse_generated_files(SAMPLE_GENERATED_CODE, "backup")
        assert "def backup" in files["src/backup.py"]

    def test_parsed_tests_contain_test_function(self) -> None:
        files = _parse_generated_files(SAMPLE_GENERATED_CODE, "backup")
        assert "def test_" in files["tests/test_backup.py"]

    def test_empty_response_returns_empty(self) -> None:
        files = _parse_generated_files("", "backup")
        assert files == {}

    def test_fallback_for_raw_python(self) -> None:
        files = _parse_generated_files("def foo():\n    pass\n", "mymod")
        assert "src/mymod.py" in files


# ── Spec drafting ─────────────────────────────────────────────────────────────

class TestSpecDrafting:
    def test_draft_creates_spec_directory(self, project: Path, mock_provider: MagicMock) -> None:
        with patch("airlock.commands.llm.provider_from_config", return_value=mock_provider):
            result = runner.invoke(app, ["spec", "draft", "Build a backup CLI"], catch_exceptions=False)
        assert result.exit_code == 0
        assert any((project / "specs").iterdir())

    def test_draft_writes_spec_md(self, project: Path, mock_provider: MagicMock) -> None:
        with patch("airlock.commands.llm.provider_from_config", return_value=mock_provider):
            runner.invoke(app, ["spec", "draft", "Build a backup CLI"], catch_exceptions=False)
        spec_dirs = [d for d in (project / "specs").iterdir() if d.is_dir() and not d.name.startswith(".")]
        assert spec_dirs
        spec_md = spec_dirs[0] / "spec.md"
        assert spec_md.exists()
        assert "Functional requirements" in spec_md.read_text()

    def test_draft_status_is_draft(self, project: Path, mock_provider: MagicMock) -> None:
        with patch("airlock.commands.llm.provider_from_config", return_value=mock_provider):
            runner.invoke(app, ["spec", "draft", "Build a backup CLI"], catch_exceptions=False)
        spec_dirs = [d for d in (project / "specs").iterdir() if d.is_dir() and not d.name.startswith(".")]
        assert spec_dirs
        meta = json.loads((spec_dirs[0] / "spec_meta.json").read_text())
        assert meta["status"] == "DRAFT"

    def test_draft_warns_operator_review_required(self, project: Path, mock_provider: MagicMock) -> None:
        with patch("airlock.commands.llm.provider_from_config", return_value=mock_provider):
            result = runner.invoke(app, ["spec", "draft", "Build a backup CLI"], catch_exceptions=False)
        assert "review" in result.output.lower() or "LLM DRAFT" in result.output

    def test_draft_logs_llm_call(self, project: Path, mock_provider: MagicMock) -> None:
        with patch("airlock.commands.llm.provider_from_config", return_value=mock_provider):
            runner.invoke(app, ["spec", "draft", "Build a backup CLI"], catch_exceptions=False)
        log_path = project / "logs" / "llm_calls.jsonl"
        assert log_path.exists()
        entry = json.loads(log_path.read_text().strip())
        assert entry["role"] == "draft_spec"
        assert entry["success"] is True


# ── Candidate generation ──────────────────────────────────────────────────────

class TestCandidateGeneration:
    def test_generate_creates_candidate(self, project: Path, locked_spec: str, mock_provider: MagicMock) -> None:
        mock_provider.complete.return_value = SAMPLE_GENERATED_CODE
        with patch("airlock.commands.llm.provider_from_config", return_value=mock_provider):
            result = runner.invoke(
                app, ["generate", locked_spec, "backup"], catch_exceptions=False
            )
        assert result.exit_code == 0
        candidates = list((project / "candidates").iterdir())
        assert candidates

    def test_generate_writes_src_file(self, project: Path, locked_spec: str, mock_provider: MagicMock) -> None:
        mock_provider.complete.return_value = SAMPLE_GENERATED_CODE
        with patch("airlock.commands.llm.provider_from_config", return_value=mock_provider):
            runner.invoke(app, ["generate", locked_spec, "backup"], catch_exceptions=False)
        cands = [d for d in (project / "candidates").iterdir() if d.is_dir() and not d.name.startswith(".")]
        assert cands
        assert (cands[0] / "src" / "backup.py").exists()

    def test_generate_writes_test_file(self, project: Path, locked_spec: str, mock_provider: MagicMock) -> None:
        mock_provider.complete.return_value = SAMPLE_GENERATED_CODE
        with patch("airlock.commands.llm.provider_from_config", return_value=mock_provider):
            runner.invoke(app, ["generate", locked_spec, "backup"], catch_exceptions=False)
        cands = [d for d in (project / "candidates").iterdir() if d.is_dir() and not d.name.startswith(".")]
        assert (cands[0] / "tests" / "test_backup.py").exists()

    def test_generate_writes_generation_manifest(self, project: Path, locked_spec: str, mock_provider: MagicMock) -> None:
        mock_provider.complete.return_value = SAMPLE_GENERATED_CODE
        with patch("airlock.commands.llm.provider_from_config", return_value=mock_provider):
            runner.invoke(app, ["generate", locked_spec, "backup"], catch_exceptions=False)
        cands = [d for d in (project / "candidates").iterdir() if d.is_dir() and not d.name.startswith(".")]
        cand_id = cands[0].name
        manifest = project / "evidence" / cand_id / "generation_manifest.json"
        assert manifest.exists()
        data = json.loads(manifest.read_text())
        assert data["spec_id"] == locked_spec
        assert "deepseek-coder-v2" in data["model"]

    def test_generate_candidate_is_quarantined(self, project: Path, locked_spec: str, mock_provider: MagicMock) -> None:
        from airlock.core.candidate_store import get_status
        mock_provider.complete.return_value = SAMPLE_GENERATED_CODE
        with patch("airlock.commands.llm.provider_from_config", return_value=mock_provider):
            runner.invoke(app, ["generate", locked_spec, "backup"], catch_exceptions=False)
        cands = [d for d in (project / "candidates").iterdir() if d.is_dir() and not d.name.startswith(".")]
        assert get_status(cands[0]) == "quarantined"

    def test_generate_warns_llm_output_quarantined(self, project: Path, locked_spec: str, mock_provider: MagicMock) -> None:
        mock_provider.complete.return_value = SAMPLE_GENERATED_CODE
        with patch("airlock.commands.llm.provider_from_config", return_value=mock_provider):
            result = runner.invoke(app, ["generate", locked_spec, "backup"], catch_exceptions=False)
        assert "quarantined" in result.output.lower() or "LLM OUTPUT" in result.output

    def test_generate_logs_llm_call(self, project: Path, locked_spec: str, mock_provider: MagicMock) -> None:
        mock_provider.complete.return_value = SAMPLE_GENERATED_CODE
        with patch("airlock.commands.llm.provider_from_config", return_value=mock_provider):
            runner.invoke(app, ["generate", locked_spec, "backup"], catch_exceptions=False)
        log_path = project / "logs" / "llm_calls.jsonl"
        assert log_path.exists()
        entries = [json.loads(l) for l in log_path.read_text().splitlines() if l.strip()]
        gen_entries = [e for e in entries if e["role"] == "generate_candidate"]
        assert gen_entries

    def test_generate_fails_on_unlocked_spec(self, project: Path, mock_provider: MagicMock) -> None:
        specs_dir = project / "specs"
        spec_id, _ = create_spec(specs_dir, "Draft spec")
        mock_provider.complete.return_value = SAMPLE_GENERATED_CODE
        with patch("airlock.commands.llm.provider_from_config", return_value=mock_provider):
            result = runner.invoke(app, ["generate", spec_id, "backup"], catch_exceptions=False)
        assert result.exit_code == 1


# ── Explain failures ──────────────────────────────────────────────────────────

class TestExplainFailures:
    def _setup_failing_candidate(self, project: Path, locked_spec: str) -> str:
        candidates_dir = project / "candidates"
        _, cdir = register_candidate(candidates_dir, locked_spec)
        evidence_dir = project / "evidence" / cdir.name
        evidence_dir.mkdir(parents=True)
        ver = {
            "verdict": "FAIL",
            "results": [
                {"rule_id": "IMPORT_SUBPROCESS", "passed": False, "blocking": True,
                 "file": "src/bad.py", "line": 1, "detail": "import subprocess"}
            ],
            "evidence_hash": "sha256:abc",
        }
        (evidence_dir / "static_verification.json").write_text(json.dumps(ver), encoding="utf-8")
        return cdir.name

    def test_explain_produces_output(self, project: Path, locked_spec: str, mock_provider: MagicMock) -> None:
        mock_provider.complete.return_value = SAMPLE_EXPLANATION
        cand_id = self._setup_failing_candidate(project, locked_spec)
        with patch("airlock.commands.llm.provider_from_config", return_value=mock_provider):
            result = runner.invoke(app, ["explain", cand_id], catch_exceptions=False)
        assert result.exit_code == 0
        assert "subprocess" in result.output.lower() or "IMPORT_SUBPROCESS" in result.output

    def test_explain_warns_advisory_only(self, project: Path, locked_spec: str, mock_provider: MagicMock) -> None:
        mock_provider.complete.return_value = SAMPLE_EXPLANATION
        cand_id = self._setup_failing_candidate(project, locked_spec)
        with patch("airlock.commands.llm.provider_from_config", return_value=mock_provider):
            result = runner.invoke(app, ["explain", cand_id], catch_exceptions=False)
        assert "advisory" in result.output.lower() or "LLM advisory" in result.output

    def test_explain_logs_llm_call(self, project: Path, locked_spec: str, mock_provider: MagicMock) -> None:
        mock_provider.complete.return_value = SAMPLE_EXPLANATION
        cand_id = self._setup_failing_candidate(project, locked_spec)
        with patch("airlock.commands.llm.provider_from_config", return_value=mock_provider):
            runner.invoke(app, ["explain", cand_id], catch_exceptions=False)
        log_path = project / "logs" / "llm_calls.jsonl"
        assert log_path.exists()

    def test_explain_no_failures_exits(self, project: Path, locked_spec: str, mock_provider: MagicMock) -> None:
        candidates_dir = project / "candidates"
        _, cdir = register_candidate(candidates_dir, locked_spec)
        with patch("airlock.commands.llm.provider_from_config", return_value=mock_provider):
            result = runner.invoke(app, ["explain", cdir.name], catch_exceptions=False)
        assert result.exit_code == 1

    def test_explain_missing_candidate_exits(self, project: Path, mock_provider: MagicMock) -> None:
        with patch("airlock.commands.llm.provider_from_config", return_value=mock_provider):
            result = runner.invoke(app, ["explain", "candidate_9999"], catch_exceptions=False)
        assert result.exit_code == 1
