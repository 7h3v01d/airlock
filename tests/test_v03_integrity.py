# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
v0.3 — Evidence and tree integrity regression tests.

Covers: forged .pyc smuggled into the trusted tree, unscannable files in
src/, symlinks, tree-hash framing collisions, spec edits after lock, and
the admission certificate's empty gate-decision hash.
"""

from __future__ import annotations

import json
import os
import py_compile
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from airlock.main import app
from airlock.core.governance.gate import DENY, ALLOW, run_gate, run_admission, AdmissionError
from airlock.core.hashing import hash_directory_tree, hash_file

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
    assert runner.invoke(app, ["spec", "lock", "spec_0001"]).exit_code == 0
    return root


def _candidate(root: Path) -> Path:
    assert runner.invoke(app, ["candidate", "register", "spec_0001"]).exit_code == 0
    cdir = root / "candidates" / "candidate_0001"
    (cdir / "src" / "adder.py").write_text(CLEAN_SRC, encoding="utf-8")
    (cdir / "tests" / "test_adder.py").write_text(TESTS, encoding="utf-8")
    return cdir


def _through_certify(root: Path) -> Path:
    cdir = _candidate(root)
    for step in (["candidate", "hash"], ["verify"], ["certify"]):
        r = runner.invoke(app, [*step, "candidate_0001"])
        assert r.exit_code == 0, r.output
    return cdir


def _forge_pyc(cdir: Path, tmp_path: Path) -> None:
    """A .pyc whose header matches the clean source but whose bytecode differs."""
    clean = cdir / "src" / "adder.py"
    evil = 'def add(a, b):\n    print("EVIL BYTECODE RAN")\n    return a + b\n'
    evil += "#" * (len(CLEAN_SRC) - len(evil) - 1) + "\n"
    evil_dir = tmp_path / "evil"
    evil_dir.mkdir()
    (evil_dir / "adder.py").write_text(evil, encoding="utf-8")
    st = clean.stat()
    os.utime(evil_dir / "adder.py", (st.st_atime, st.st_mtime))
    (cdir / "src" / "__pycache__").mkdir()
    py_compile.compile(
        str(evil_dir / "adder.py"),
        cfile=str(cdir / "src" / "__pycache__" / f"adder.{sys.implementation.cache_tag}.pyc"),
    )


class TestForgedBytecode:
    def test_forged_pyc_never_reaches_trusted_tree(self, project: Path, tmp_path: Path) -> None:
        cdir = _candidate(project)
        _forge_pyc(cdir, tmp_path)
        for step in (["candidate", "hash"], ["verify"], ["certify"], ["gate"], ["admit"]):
            runner.invoke(app, [*step, "candidate_0001"])
        trusted = project / "trusted" / "src" / "candidate_0001"
        assert not list(trusted.rglob("*.pyc")) if trusted.exists() else True
        if trusted.exists():
            r = subprocess.run(
                [sys.executable, "-c", "import adder; adder.add(1, 2)"],
                cwd=trusted, capture_output=True, text=True,
            )
            assert "EVIL" not in r.stdout

    def test_verifier_blocks_pycache_in_src(self, project: Path, tmp_path: Path) -> None:
        cdir = _candidate(project)
        _forge_pyc(cdir, tmp_path)
        r = runner.invoke(app, ["verify", "candidate_0001"])
        assert r.exit_code == 1
        assert "SRC_UNSCANNED_CONTENT" in r.output

    def test_pyc_dropped_after_certify_is_denied(self, project: Path, tmp_path: Path) -> None:
        cdir = _through_certify(project)
        _forge_pyc(cdir, tmp_path)
        decision = run_gate(cdir, project, {})
        assert decision.decision == DENY
        assert any("outside the source hash" in r for r in decision.reasons)

    def test_admission_refuses_pyc_dropped_after_gate(self, project: Path, tmp_path: Path) -> None:
        cdir = _through_certify(project)
        assert run_gate(cdir, project, {}).decision == ALLOW
        _forge_pyc(cdir, tmp_path)
        with pytest.raises(AdmissionError, match="outside the source hash"):
            run_admission(cdir, project)

    def test_honest_certify_leaves_no_bytecode_in_src(self, project: Path) -> None:
        cdir = _through_certify(project)
        assert not list((cdir / "src").rglob("*.pyc"))


class TestUnscannableFiles:
    @pytest.mark.parametrize("name", ["evil.so", "evil.pyd", "hook.pth", "blob.zip", "tool.exe"])
    def test_binary_or_hook_files_fail_verification(self, project: Path, name: str) -> None:
        cdir = _candidate(project)
        (cdir / "src" / name).write_bytes(b"\x7fELF")
        r = runner.invoke(app, ["verify", "candidate_0001"])
        assert r.exit_code == 1
        assert "SRC_UNSCANNED_CONTENT" in r.output and name in r.output

    def test_data_files_are_allowed(self, project: Path) -> None:
        cdir = _candidate(project)
        (cdir / "src" / "defaults.json").write_text("{}")
        (cdir / "src" / "py.typed").write_text("")
        r = runner.invoke(app, ["verify", "candidate_0001"])
        assert r.exit_code == 0, r.output

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
    def test_symlink_in_src_fails_verification(self, project: Path, tmp_path: Path) -> None:
        cdir = _candidate(project)
        outside = tmp_path / "outside.py"
        outside.write_text("x = 1\n")
        (cdir / "src" / "linked.py").symlink_to(outside)
        r = runner.invoke(app, ["verify", "candidate_0001"])
        assert r.exit_code == 1
        assert "symlinks are not allowed" in r.output


class TestTreeHashFraming:
    def test_path_content_boundary_does_not_collide(self, tmp_path: Path) -> None:
        a = tmp_path / "a"; a.mkdir(); (a / "a").write_bytes(b"bX")
        b = tmp_path / "b"; b.mkdir(); (b / "ab").write_bytes(b"X")
        assert hash_directory_tree(a) != hash_directory_tree(b)

    def test_file_split_does_not_collide(self, tmp_path: Path) -> None:
        a = tmp_path / "a"; a.mkdir(); (a / "x").write_bytes(b"12"); (a / "y").write_bytes(b"")
        b = tmp_path / "b"; b.mkdir(); (b / "x").write_bytes(b"1"); (b / "y").write_bytes(b"2")
        assert hash_directory_tree(a) != hash_directory_tree(b)

    def test_hash_is_stable(self, tmp_path: Path) -> None:
        (tmp_path / "m.py").write_text("x = 1\n")
        assert hash_directory_tree(tmp_path) == hash_directory_tree(tmp_path)


class TestSpecDrift:
    def _edit_spec(self, root: Path) -> None:
        spec_md = root / "specs" / "spec_0001" / "spec.md"
        spec_md.write_text(spec_md.read_text() + "\nAlso allow network access.\n")

    def test_verify_fails_if_spec_edited_after_lock(self, project: Path) -> None:
        _candidate(project)
        self._edit_spec(project)
        r = runner.invoke(app, ["verify", "candidate_0001"])
        assert r.exit_code == 1
        assert "MISSING_SPEC_LINK" in r.output

    def test_gate_denies_if_spec_edited_after_certify(self, project: Path) -> None:
        cdir = _through_certify(project)
        self._edit_spec(project)
        decision = run_gate(cdir, project, {})
        assert decision.decision == DENY
        assert any("edited since it was locked" in r for r in decision.reasons)

    def test_admission_refuses_if_spec_edited_after_gate(self, project: Path) -> None:
        cdir = _through_certify(project)
        assert run_gate(cdir, project, {}).decision == ALLOW
        self._edit_spec(project)
        with pytest.raises(AdmissionError, match="Spec"):
            run_admission(cdir, project)


class TestCertificate:
    def test_certificate_records_real_gate_decision_hash(self, project: Path) -> None:
        cdir = _through_certify(project)
        run_gate(cdir, project, {})
        gate_path = project / "evidence" / "candidate_0001" / "gate_decision.json"
        expected = hash_file(gate_path)
        cert = run_admission(cdir, project)
        assert cert["hashes"]["gate_decision"] == expected
        on_disk = json.loads((project / "evidence" / "candidate_0001" / "admission_certificate.json").read_text())
        assert on_disk["hashes"]["gate_decision"] == expected

    def test_certificate_id_uses_airlock_prefix(self, project: Path) -> None:
        cdir = _through_certify(project)
        run_gate(cdir, project, {})
        assert run_admission(cdir, project)["certificate_id"].startswith("al-cert-")

    def test_gate_decision_records_source_and_spec(self, project: Path) -> None:
        cdir = _through_certify(project)
        d = run_gate(cdir, project, {})
        manifest = json.loads((cdir / "manifest.json").read_text())
        meta = json.loads((project / "specs" / "spec_0001" / "spec_meta.json").read_text())
        assert d.source_hash == manifest["source_hash"]
        assert d.spec_hash == meta["spec_hash"]

    def test_admission_copies_exactly_the_hashed_tree(self, project: Path) -> None:
        cdir = _through_certify(project)
        run_gate(cdir, project, {})
        run_admission(cdir, project)
        trusted = project / "trusted" / "src" / "candidate_0001"
        assert hash_directory_tree(trusted) == json.loads((cdir / "manifest.json").read_text())["source_hash"]
