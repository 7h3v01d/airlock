# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
Phase 8 — Dashboard tests.

Tests reader, API routes, security, and integrity display.
Requires: pip install httpx fastapi uvicorn

Run from the repo root:
    pytest tests/test_dashboard.py -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from airlock.main import app as cli_app
from airlock.core.spec_store import create_spec, lock_spec
from airlock.core.candidate_store import register_candidate, transition_status
from airlock.core.hashing import write_sidecar
from airlock.dashboard.reader import ProjectReader
from airlock.dashboard.server import create_app

runner = CliRunner()


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    runner.invoke(cli_app, ["init", "myproject"], catch_exceptions=False)
    project_dir = tmp_path / "myproject"
    monkeypatch.chdir(project_dir)
    return project_dir


@pytest.fixture()
def client(project: Path) -> TestClient:
    dash_app = create_app(project)
    return TestClient(dash_app)


@pytest.fixture()
def populated_project(project: Path) -> Path:
    """Project with a spec and candidate."""
    specs_dir = project / "specs"
    spec_id, spec_dir = create_spec(specs_dir, "Test dashboard spec")
    (spec_dir / "spec.md").write_text(
        "# spec\n\n## Functional requirements\n\nWork.\n\n"
        "## Non-functional requirements\n\nFast.\n\n"
        "## Forbidden behaviours\n\nNone.\n\n"
        "## Acceptance criteria\n\nPasses.\n",
        encoding="utf-8",
    )
    lock_spec(specs_dir, spec_id)
    _, cdir = register_candidate(project / "candidates", spec_id)
    (cdir / "src" / "main.py").write_text('"""Main."""\n\nx: int = 1\n', encoding="utf-8")
    transition_status(cdir, "verified")
    return project


@pytest.fixture()
def populated_client(populated_project: Path) -> TestClient:
    dash_app = create_app(populated_project)
    return TestClient(dash_app)


# ── Reader tests ──────────────────────────────────────────────────────────────

class TestDashboardReader:
    def test_overview_empty_project(self, project: Path) -> None:
        reader = ProjectReader(project)
        ov = reader.overview()
        assert ov.total_specs == 0
        assert ov.total_candidates == 0
        assert ov.admitted_count == 0

    def test_overview_project_name(self, project: Path) -> None:
        reader = ProjectReader(project)
        ov = reader.overview()
        assert ov.project_name == "myproject"

    def test_lists_specs(self, populated_project: Path) -> None:
        reader = ProjectReader(populated_project)
        specs = reader.specs()
        assert len(specs) == 1
        assert specs[0].status == "LOCKED"

    def test_lists_candidates(self, populated_project: Path) -> None:
        reader = ProjectReader(populated_project)
        candidates = reader.candidates()
        assert len(candidates) == 1
        assert candidates[0].status == "verified"

    def test_candidate_detail(self, populated_project: Path) -> None:
        reader = ProjectReader(populated_project)
        candidates = reader.candidates()
        detail = reader.candidate_detail(candidates[0].candidate_id)
        assert detail is not None
        assert detail.spec_id != ""

    def test_candidate_detail_missing_returns_none(self, project: Path) -> None:
        reader = ProjectReader(project)
        assert reader.candidate_detail("candidate_9999") is None

    def test_path_traversal_blocked(self, project: Path) -> None:
        reader = ProjectReader(project)
        # Attempt directory traversal via candidate_id
        result = reader.candidate_detail("../specs")
        assert result is None

    def test_path_traversal_blocked_absolute(self, project: Path) -> None:
        reader = ProjectReader(project)
        result = reader.candidate_detail("/etc/passwd")
        assert result is None

    def test_evidence_reports_sidecar_failure(self, populated_project: Path) -> None:
        """Evidence with a tampered file shows sidecar_ok=False."""
        reader = ProjectReader(populated_project)
        candidates = reader.candidates()
        cid = candidates[0].candidate_id
        evidence_dir = populated_project / "evidence" / cid
        evidence_dir.mkdir(parents=True, exist_ok=True)

        # Write evidence with a sidecar, then tamper with it
        ev_path = evidence_dir / "static_verification.json"
        ev_path.write_text(json.dumps({"verdict": "PASS"}), encoding="utf-8")
        write_sidecar(ev_path)
        ev_path.write_text(json.dumps({"verdict": "TAMPERED"}), encoding="utf-8")

        detail = reader.candidate_detail(cid)
        ver_item = next(e for e in detail.evidence if "static_verification" in e.document)
        assert ver_item.sidecar_ok is False
        assert "mismatch" in ver_item.sidecar_msg

    def test_audit_log_empty(self, project: Path) -> None:
        reader = ProjectReader(project)
        assert reader.audit_log() == []

    def test_llm_calls_empty(self, project: Path) -> None:
        reader = ProjectReader(project)
        assert reader.llm_calls() == []


# ── API route tests ───────────────────────────────────────────────────────────

class TestDashboardServer:
    def test_overview_returns_200(self, client: TestClient) -> None:
        r = client.get("/api/overview")
        assert r.status_code == 200

    def test_overview_has_project_name(self, client: TestClient) -> None:
        r = client.get("/api/overview")
        assert "project_name" in r.json()

    def test_specs_returns_200(self, client: TestClient) -> None:
        assert client.get("/api/specs").status_code == 200

    def test_candidates_returns_200(self, client: TestClient) -> None:
        assert client.get("/api/candidates").status_code == 200

    def test_audit_returns_200(self, client: TestClient) -> None:
        assert client.get("/api/audit").status_code == 200

    def test_llm_calls_returns_200(self, client: TestClient) -> None:
        assert client.get("/api/llm-calls").status_code == 200

    def test_ui_returns_html(self, client: TestClient) -> None:
        r = client.get("/")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert "Airlock" in r.text

    def test_candidate_detail_404_for_missing(self, client: TestClient) -> None:
        r = client.get("/api/candidates/candidate_9999")
        assert r.status_code == 404

    def test_candidate_detail_lists_evidence(self, populated_client: TestClient) -> None:
        candidates = populated_client.get("/api/candidates").json()
        assert candidates
        cid = candidates[0]["candidate_id"]
        r = populated_client.get(f"/api/candidates/{cid}")
        assert r.status_code == 200
        data = r.json()
        assert "evidence" in data
        assert isinstance(data["evidence"], list)


# ── Security tests ────────────────────────────────────────────────────────────

class TestDashboardSecurity:
    def test_invalid_candidate_id_rejected(self, client: TestClient) -> None:
        r = client.get("/api/candidates/../../etc/passwd")
        assert r.status_code in (400, 404, 422)

    def test_candidate_id_with_slash_rejected(self, client: TestClient) -> None:
        # FastAPI will handle this as path routing, but the format check should block it
        r = client.get("/api/candidates/invalid-format")
        assert r.status_code == 400

    def test_candidate_id_with_special_chars_rejected(self, client: TestClient) -> None:
        r = client.get("/api/candidates/candidate_00%00")
        assert r.status_code in (400, 404, 422)

    def test_candidate_id_too_short_rejected(self, client: TestClient) -> None:
        # candidate_001 is only 3 digits — must be 4+
        r = client.get("/api/candidates/candidate_001")
        assert r.status_code == 400

    def test_valid_candidate_id_format_accepted(self, populated_client: TestClient) -> None:
        candidates = populated_client.get("/api/candidates").json()
        assert candidates
        cid = candidates[0]["candidate_id"]
        # Must match candidate_XXXX pattern
        assert cid.startswith("candidate_")
        r = populated_client.get(f"/api/candidates/{cid}")
        assert r.status_code == 200

    def test_no_write_endpoints_exist(self, client: TestClient) -> None:
        """Dashboard must have no POST/PUT/DELETE/PATCH routes."""
        for method, path in [
            ("POST", "/api/candidates"),
            ("PUT", "/api/candidates/candidate_0001"),
            ("DELETE", "/api/candidates/candidate_0001"),
            ("PATCH", "/api/overview"),
            ("POST", "/api/audit"),
        ]:
            r = client.request(method, path)
            assert r.status_code == 405, \
                f"{method} {path} should return 405 Method Not Allowed, got {r.status_code}"

    def test_ui_contains_escape_function(self, client: TestClient) -> None:
        """The UI must include the escapeHtml function for XSS protection."""
        r = client.get("/")
        assert "escapeHtml" in r.text
        assert "replaceAll" in r.text
