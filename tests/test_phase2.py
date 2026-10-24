# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
Phase 2 — Candidate quarantine and spec lifecycle tests.

Run from the repo root:
    pytest tests/test_phase2.py -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from airlock.main import app
from airlock.core.spec_store import create_spec, lock_spec, SpecLockError
from airlock.core.candidate_store import (
    register_candidate, get_status, transition_status,
    compute_source_hash, CandidateError,
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
    """Create and lock a spec, return spec_id."""
    specs_dir = project / "specs"
    spec_id, spec_dir = create_spec(specs_dir, "Test backup tool")
    # Write real content to replace placeholder
    (spec_dir / "spec.md").write_text(
        "# spec_0001\n\n> Test backup tool\n\n"
        "## Functional requirements\n\nBackup files.\n\n"
        "## Non-functional requirements\n\nOffline only.\n\n"
        "## Forbidden behaviours\n\nNo network access.\n\n"
        "## Acceptance criteria\n\nFiles are copied.\n",
        encoding="utf-8",
    )
    lock_spec(specs_dir, spec_id)
    return spec_id


# ── Hashing module ────────────────────────────────────────────────────────────

class TestHashing:
    def test_hash_text_is_stable(self) -> None:
        from airlock.core.hashing import hash_text
        h1 = hash_text("hello world")
        h2 = hash_text("hello world")
        assert h1 == h2
        assert h1.startswith("sha256:")

    def test_hash_text_differs_for_different_input(self) -> None:
        from airlock.core.hashing import hash_text
        assert hash_text("abc") != hash_text("xyz")

    def test_hash_file(self, tmp_path: Path) -> None:
        from airlock.core.hashing import hash_file
        f = tmp_path / "test.txt"
        f.write_text("content", encoding="utf-8")
        h = hash_file(f)
        assert h.startswith("sha256:")
        assert hash_file(f) == h  # stable

    def test_hash_directory_tree(self, tmp_path: Path) -> None:
        from airlock.core.hashing import hash_directory_tree
        (tmp_path / "a.py").write_text("print('a')", encoding="utf-8")
        (tmp_path / "b.py").write_text("print('b')", encoding="utf-8")
        h = hash_directory_tree(tmp_path)
        assert h.startswith("sha256:")

    def test_hash_directory_tree_changes_on_file_change(self, tmp_path: Path) -> None:
        from airlock.core.hashing import hash_directory_tree
        (tmp_path / "a.py").write_text("original", encoding="utf-8")
        h1 = hash_directory_tree(tmp_path)
        (tmp_path / "a.py").write_text("modified", encoding="utf-8")
        h2 = hash_directory_tree(tmp_path)
        assert h1 != h2


# ── Spec store — unit ─────────────────────────────────────────────────────────

class TestSpecStore:
    def test_create_spec_produces_directory(self, project: Path) -> None:
        specs_dir = project / "specs"
        spec_id, spec_dir = create_spec(specs_dir, "My spec")
        assert spec_dir.exists()
        assert (spec_dir / "spec.md").exists()
        assert (spec_dir / "spec_meta.json").exists()

    def test_create_spec_status_is_draft(self, project: Path) -> None:
        specs_dir = project / "specs"
        spec_id, spec_dir = create_spec(specs_dir, "My spec")
        meta = json.loads((spec_dir / "spec_meta.json").read_text())
        assert meta["status"] == "DRAFT"

    def test_create_spec_ids_are_sequential(self, project: Path) -> None:
        specs_dir = project / "specs"
        id1, _ = create_spec(specs_dir, "First")
        id2, _ = create_spec(specs_dir, "Second")
        assert id1 == "spec_0001"
        assert id2 == "spec_0002"

    def test_lock_spec_requires_edited_content(self, project: Path) -> None:
        specs_dir = project / "specs"
        spec_id, _ = create_spec(specs_dir, "Unedited spec")
        with pytest.raises(SpecLockError, match="placeholder"):
            lock_spec(specs_dir, spec_id)

    def test_lock_spec_succeeds_with_real_content(self, project: Path, locked_spec: str) -> None:
        specs_dir = project / "specs"
        meta = json.loads((specs_dir / locked_spec / "spec_meta.json").read_text())
        assert meta["status"] == "LOCKED"
        assert meta["spec_hash"] is not None
        assert meta["locked_at"] is not None

    def test_lock_spec_writes_hash_file(self, project: Path, locked_spec: str) -> None:
        hash_file = project / "specs" / locked_spec / "spec_hash.txt"
        assert hash_file.exists()
        assert hash_file.read_text().startswith("sha256:")

    def test_lock_spec_twice_raises(self, project: Path, locked_spec: str) -> None:
        specs_dir = project / "specs"
        with pytest.raises(SpecLockError, match="already locked"):
            lock_spec(specs_dir, locked_spec)

    def test_lock_nonexistent_spec_raises(self, project: Path) -> None:
        specs_dir = project / "specs"
        with pytest.raises(SpecLockError, match="not found"):
            lock_spec(specs_dir, "spec_9999")


# ── Candidate store — unit ────────────────────────────────────────────────────

class TestCandidateStore:
    def test_register_creates_directory(self, project: Path, locked_spec: str) -> None:
        candidates_dir = project / "candidates"
        cid, cdir = register_candidate(candidates_dir, locked_spec)
        assert cdir.exists()
        assert (cdir / "src").exists()
        assert (cdir / "tests").exists()

    def test_register_writes_manifest(self, project: Path, locked_spec: str) -> None:
        candidates_dir = project / "candidates"
        cid, cdir = register_candidate(candidates_dir, locked_spec)
        manifest = json.loads((cdir / "manifest.json").read_text())
        assert manifest["spec_id"] == locked_spec
        assert manifest["language"] == "python"
        assert manifest["status"] if "status" in manifest else True  # not in manifest

    def test_register_initial_status_is_quarantined(self, project: Path, locked_spec: str) -> None:
        candidates_dir = project / "candidates"
        cid, cdir = register_candidate(candidates_dir, locked_spec)
        assert get_status(cdir) == "quarantined"

    def test_register_ids_sequential(self, project: Path, locked_spec: str) -> None:
        candidates_dir = project / "candidates"
        id1, _ = register_candidate(candidates_dir, locked_spec)
        id2, _ = register_candidate(candidates_dir, locked_spec)
        assert id1 == "candidate_0001"
        assert id2 == "candidate_0002"

    def test_valid_status_transition(self, project: Path, locked_spec: str) -> None:
        candidates_dir = project / "candidates"
        _, cdir = register_candidate(candidates_dir, locked_spec)
        transition_status(cdir, "verified")
        assert get_status(cdir) == "verified"

    def test_invalid_status_transition_raises(self, project: Path, locked_spec: str) -> None:
        candidates_dir = project / "candidates"
        _, cdir = register_candidate(candidates_dir, locked_spec)
        with pytest.raises(CandidateError, match="Invalid transition"):
            transition_status(cdir, "admitted")  # must go through verified→certified first

    def test_terminal_status_cannot_transition(self, project: Path, locked_spec: str) -> None:
        candidates_dir = project / "candidates"
        _, cdir = register_candidate(candidates_dir, locked_spec)
        transition_status(cdir, "rejected")
        with pytest.raises(CandidateError, match="terminal"):
            transition_status(cdir, "verified")

    def test_compute_source_hash(self, project: Path, locked_spec: str) -> None:
        candidates_dir = project / "candidates"
        _, cdir = register_candidate(candidates_dir, locked_spec)
        (cdir / "src" / "main.py").write_text("print('hello')", encoding="utf-8")
        source_hash = compute_source_hash(cdir)
        assert source_hash.startswith("sha256:")
        manifest = json.loads((cdir / "manifest.json").read_text())
        assert manifest["source_hash"] == source_hash

    def test_compute_source_hash_no_src_raises(self, tmp_path: Path) -> None:
        fake_dir = tmp_path / "candidate_fake"
        fake_dir.mkdir()
        with pytest.raises(CandidateError, match="src/"):
            compute_source_hash(fake_dir)


# ── CLI — spec new ────────────────────────────────────────────────────────────

class TestSpecNewCLI:
    def test_creates_spec_directory(self, project: Path) -> None:
        result = runner.invoke(app, ["spec", "new", "Build a backup tool"], catch_exceptions=False)
        assert result.exit_code == 0
        assert (project / "specs" / "spec_0001").exists()

    def test_output_shows_spec_id(self, project: Path) -> None:
        result = runner.invoke(app, ["spec", "new", "My feature"], catch_exceptions=False)
        assert "spec_0001" in result.output

    def test_output_shows_draft_status(self, project: Path) -> None:
        result = runner.invoke(app, ["spec", "new", "My feature"], catch_exceptions=False)
        assert "DRAFT" in result.output

    def test_second_spec_gets_next_id(self, project: Path) -> None:
        runner.invoke(app, ["spec", "new", "First"], catch_exceptions=False)
        result = runner.invoke(app, ["spec", "new", "Second"], catch_exceptions=False)
        assert "spec_0002" in result.output


# ── CLI — spec lock ───────────────────────────────────────────────────────────

class TestSpecLockCLI:
    def test_lock_unedited_spec_fails(self, project: Path) -> None:
        runner.invoke(app, ["spec", "new", "My spec"], catch_exceptions=False)
        result = runner.invoke(app, ["spec", "lock", "spec_0001"], catch_exceptions=False)
        assert result.exit_code == 1
        assert "placeholder" in result.output

    def test_lock_edited_spec_succeeds(self, project: Path, locked_spec: str) -> None:
        result = runner.invoke(app, ["spec", "list"], catch_exceptions=False)
        assert "LOCKED" in result.output

    def test_lock_shows_hash(self, project: Path) -> None:
        specs_dir = project / "specs"
        spec_id, spec_dir = create_spec(specs_dir, "Test")
        (spec_dir / "spec.md").write_text(
            "# spec\n\n## Functional requirements\n\nDo something.\n\n"
            "## Non-functional requirements\n\nFast.\n\n"
            "## Forbidden behaviours\n\nNo crashes.\n\n"
            "## Acceptance criteria\n\nWorks.\n",
            encoding="utf-8",
        )
        result = runner.invoke(app, ["spec", "lock", spec_id], catch_exceptions=False)
        assert result.exit_code == 0
        assert "sha256:" in result.output

    def test_lock_nonexistent_spec_fails(self, project: Path) -> None:
        result = runner.invoke(app, ["spec", "lock", "spec_9999"], catch_exceptions=False)
        assert result.exit_code == 1
        assert "not found" in result.output


# ── CLI — candidate register ──────────────────────────────────────────────────

class TestCandidateRegisterCLI:
    def test_register_creates_candidate(self, project: Path, locked_spec: str) -> None:
        result = runner.invoke(
            app, ["candidate", "register", locked_spec], catch_exceptions=False
        )
        assert result.exit_code == 0
        assert (project / "candidates" / "candidate_0001").exists()

    def test_register_shows_candidate_id(self, project: Path, locked_spec: str) -> None:
        result = runner.invoke(
            app, ["candidate", "register", locked_spec], catch_exceptions=False
        )
        assert "candidate_0001" in result.output

    def test_register_against_unlocked_spec_fails(self, project: Path) -> None:
        specs_dir = project / "specs"
        create_spec(specs_dir, "Draft spec")
        result = runner.invoke(
            app, ["candidate", "register", "spec_0001"], catch_exceptions=False
        )
        assert result.exit_code == 1
        assert "not locked" in result.output

    def test_register_against_missing_spec_fails(self, project: Path) -> None:
        result = runner.invoke(
            app, ["candidate", "register", "spec_9999"], catch_exceptions=False
        )
        assert result.exit_code == 1
        assert "not found" in result.output


# ── CLI — candidate list ──────────────────────────────────────────────────────

class TestCandidateListCLI:
    def test_empty_list_message(self, project: Path) -> None:
        result = runner.invoke(app, ["candidate", "list"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "No candidates yet" in result.output

    def test_registered_candidate_appears(self, project: Path, locked_spec: str) -> None:
        runner.invoke(app, ["candidate", "register", locked_spec], catch_exceptions=False)
        result = runner.invoke(app, ["candidate", "list"], catch_exceptions=False)
        assert "candidate_0001" in result.output
        assert "quarantined" in result.output


# ── CLI — candidate hash ──────────────────────────────────────────────────────

class TestCandidateHashCLI:
    def test_hash_missing_candidate_fails(self, project: Path) -> None:
        result = runner.invoke(
            app, ["candidate", "hash", "candidate_9999"], catch_exceptions=False
        )
        assert result.exit_code == 1

    def test_hash_records_in_manifest(self, project: Path, locked_spec: str) -> None:
        runner.invoke(app, ["candidate", "register", locked_spec], catch_exceptions=False)
        src = project / "candidates" / "candidate_0001" / "src"
        (src / "main.py").write_text("print('hello')", encoding="utf-8")
        result = runner.invoke(
            app, ["candidate", "hash", "candidate_0001"], catch_exceptions=False
        )
        assert result.exit_code == 0
        assert "sha256:" in result.output
        manifest = json.loads(
            (project / "candidates" / "candidate_0001" / "manifest.json").read_text()
        )
        assert manifest["source_hash"].startswith("sha256:")
