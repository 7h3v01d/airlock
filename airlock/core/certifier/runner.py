# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock.core.certifier.runner

Runs the test certifier for a verified candidate.

Executes pytest against the candidate's tests/ directory with coverage
measurement against src/. Produces:
  - test_report.json       Unit test results
  - coverage_report.json   Branch coverage data

Both are written to evidence/<candidate_id>/ and hash-sealed.

Execution containment (v0.2):
  - Configurable timeout (default 120s) — hangs are killed and reported
  - Scrubbed environment — only a minimal safe set of vars is passed
  - PYTHONPATH restricted to candidate src/ only
  - No trusted platform environment variables leaked to candidate code
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

from airlock.core.hashing import (
    seal_evidence, hash_directory_tree, find_unhashed_files, find_symlinks,
)

VERSION = "0.1.0"

# Default execution timeout in seconds.
# Overridden by policy: certification.test_timeout_seconds
DEFAULT_TIMEOUT_SECONDS = 120

# Minimum safe environment variables passed to the candidate subprocess.
# Everything else is stripped. This prevents leaking API keys, tokens,
# proxy configs, or other sensitive env vars into candidate execution.
_SAFE_ENV_KEYS = {
    "PATH",           # needed to find executables
    "SYSTEMROOT",     # Windows: needed for basic process creation
    "SYSTEMDRIVE",    # Windows
    "WINDIR",         # Windows
    "TEMP",           # Windows temp dir
    "TMP",            # Windows/Linux temp dir
    "TMPDIR",         # Linux/macOS temp dir
    "HOME",           # Linux/macOS home (needed by some tools)
    "USERPROFILE",    # Windows home
    "LOCALAPPDATA",   # Windows: needed by some tools
    "APPDATA",        # Windows
    "PROGRAMFILES",   # Windows
    "COMSPEC",        # Windows: cmd.exe path
    "PATHEXT",        # Windows: executable extensions
    "LANG",           # locale
    "LC_ALL",         # locale
    "LC_CTYPE",       # locale
    "PYTHONUTF8",     # Python UTF-8 mode
    "VIRTUAL_ENV",    # active venv path (needed so pytest finds the right Python)
    "CONDA_PREFIX",   # conda env path
}


# ── Report dataclasses ────────────────────────────────────────────────────────

@dataclass
class TestReport:
    candidate_id: str
    spec_id: str
    certifier_version: str
    timestamp: str
    certification: str              # "CERTIFIED" | "NOT_CERTIFIED"
    total_tests: int
    passed: int
    failed: int
    errors: int
    skipped: int
    timed_out: bool = False
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    blocking_failures: list[str] = field(default_factory=list)
    failure_details: list[dict] = field(default_factory=list)
    source_hash: str = ""           # hash of the src/ tree the tests ran against
    evidence_hash: str = ""


@dataclass
class CoverageReport:
    candidate_id: str
    certifier_version: str
    timestamp: str
    branch_coverage: float
    line_coverage: float
    files: list[dict] = field(default_factory=list)
    source_hash: str = ""
    evidence_hash: str = ""


# ── Runner ────────────────────────────────────────────────────────────────────

def run_certification(
    candidate_dir: Path,
    project_root: Path,
    policy: dict,
) -> tuple[TestReport, CoverageReport]:
    """
    Run the test certifier against a verified candidate.
    Returns (TestReport, CoverageReport) and writes evidence files.
    """
    candidate_id = candidate_dir.name
    manifest_path = candidate_dir / "manifest.json"
    manifest = {}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    spec_id = manifest.get("spec_id", "")

    src_dir = candidate_dir / "src"
    tests_dir = candidate_dir / "tests"

    # Read timeout from policy, fall back to default
    cert_policy = policy.get("certification", {})
    timeout_seconds = int(
        cert_policy.get("test_timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    )

    # ── Bind to the source tree ───────────────────────────────────────────────
    source_hash_before = hash_directory_tree(src_dir) if src_dir.exists() else ""
    unhashed_before = find_unhashed_files(src_dir) + find_symlinks(src_dir)

    # ── Build scrubbed environment ────────────────────────────────────────────
    scrubbed_env = _build_scrubbed_env(src_dir)

    # ── Run pytest with coverage ──────────────────────────────────────────────
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        json_report_path = tmp_path / "pytest_report.json"
        cov_json_path = tmp_path / "coverage.json"

        cmd = [
            sys.executable, "-m", "pytest",
            str(tests_dir),
            f"--rootdir={candidate_dir}",
            "--tb=short",
            "-q",
            "--json-report",
            f"--json-report-file={json_report_path}",
            f"--cov={src_dir}",
            "--cov-branch",
            f"--cov-report=json:{cov_json_path}",
            "--no-header",
            "--import-mode=importlib",
            "-p", "no:cacheprovider",
        ]

        timed_out = False
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=scrubbed_env,
                timeout=timeout_seconds,
                cwd=str(candidate_dir),    # working dir is candidate root
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            # Create a synthetic proc-like result for the parser
            proc = _TimeoutResult(timeout_seconds)

        # ── Parse pytest JSON report ──────────────────────────────────────────
        test_report = _parse_pytest_report(
            json_report_path, candidate_id, spec_id, proc,
            timed_out=timed_out, timeout_seconds=timeout_seconds,
        )

        # ── Parse coverage report ─────────────────────────────────────────────
        cov_report = _parse_coverage_report(cov_json_path, candidate_id)

    # ── Source integrity: before, during and against the manifest ─────────────
    source_hash_after = hash_directory_tree(src_dir) if src_dir.exists() else ""
    integrity_failures: list[str] = []
    recorded = manifest.get("source_hash")
    if not recorded:
        integrity_failures.append(
            "No source hash recorded in manifest.json — run verify first"
        )
    elif recorded != source_hash_before:
        integrity_failures.append(
            "src/ differs from the source hash recorded in manifest.json"
        )
    if source_hash_after != source_hash_before:
        integrity_failures.append("src/ was modified while the test suite ran")
    if unhashed_before:
        integrity_failures.append(
            "src/ contains files outside the source hash (remove them): "
            + ", ".join(unhashed_before)
        )
    elif find_unhashed_files(src_dir):
        integrity_failures.append("src/ gained files outside the source hash during the test run")
    if integrity_failures:
        test_report.certification = "NOT_CERTIFIED"
        test_report.blocking_failures = [*test_report.blocking_failures, *integrity_failures]
    test_report.source_hash = source_hash_before
    cov_report.source_hash = source_hash_before

    # ── Write evidence ────────────────────────────────────────────────────────
    evidence_dir = project_root / "evidence" / candidate_id
    evidence_dir.mkdir(parents=True, exist_ok=True)

    _write_evidence(evidence_dir / "test_report.json", asdict(test_report), test_report)
    _write_evidence(evidence_dir / "coverage_report.json", asdict(cov_report), cov_report)

    return test_report, cov_report


# ── Environment scrubbing ─────────────────────────────────────────────────────

def _build_scrubbed_env(src_dir: Path) -> dict[str, str]:
    """
    Build a minimal scrubbed environment for the candidate subprocess.

    Only variables in _SAFE_ENV_KEYS are inherited from the host.
    PYTHONPATH is set to src_dir only — the candidate cannot see the
    platform's own source tree.
    """
    scrubbed: dict[str, str] = {}
    for key in _SAFE_ENV_KEYS:
        val = os.environ.get(key)
        if val is not None:
            scrubbed[key] = val

    # PYTHONPATH: candidate src/ only. Never inherit host PYTHONPATH.
    scrubbed["PYTHONPATH"] = str(src_dir)

    # Never write bytecode into the candidate: src/ must contain only the
    # files covered by its hash, and stale .pyc files are an attack vector.
    scrubbed["PYTHONDONTWRITEBYTECODE"] = "1"

    # Prevent pytest from writing coverage data outside the tmp dir
    scrubbed["COVERAGE_FILE"] = str(src_dir.parent / ".coverage_candidate")

    return scrubbed


class _TimeoutResult:
    """Synthetic result for a timed-out subprocess."""
    def __init__(self, timeout: int) -> None:
        self.returncode = -1
        self.stdout = f"[TIMEOUT] Test run exceeded {timeout}s limit and was killed."
        self.stderr = ""


# ── Parsers ───────────────────────────────────────────────────────────────────

def _parse_pytest_report(
    report_path: Path,
    candidate_id: str,
    spec_id: str,
    proc: subprocess.CompletedProcess | _TimeoutResult,
    timed_out: bool = False,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> TestReport:
    now = datetime.now(timezone.utc).isoformat()

    if timed_out:
        return TestReport(
            candidate_id=candidate_id,
            spec_id=spec_id,
            certifier_version=VERSION,
            timestamp=now,
            certification="NOT_CERTIFIED",
            total_tests=0,
            passed=0,
            failed=0,
            errors=0,
            skipped=0,
            timed_out=True,
            timeout_seconds=timeout_seconds,
            blocking_failures=[
                f"Test run timed out after {timeout_seconds}s — candidate killed"
            ],
            failure_details=[{
                "nodeid": "timeout",
                "outcome": "timeout",
                "message": proc.stdout,
            }],
        )

    if not report_path.exists():
        passed = proc.returncode == 0
        return TestReport(
            candidate_id=candidate_id,
            spec_id=spec_id,
            certifier_version=VERSION,
            timestamp=now,
            certification="CERTIFIED" if passed else "NOT_CERTIFIED",
            total_tests=0,
            passed=0,
            failed=0,
            errors=0,
            skipped=0,
            timed_out=False,
            timeout_seconds=timeout_seconds,
            blocking_failures=[] if passed else [
                "Tests failed (no detailed report available)"
            ],
            failure_details=[{
                "stdout": proc.stdout[-2000:],
                "stderr": proc.stderr[-1000:],
            }],
        )

    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return TestReport(
            candidate_id=candidate_id,
            spec_id=spec_id,
            certifier_version=VERSION,
            timestamp=now,
            certification="NOT_CERTIFIED",
            total_tests=0,
            passed=0,
            failed=0,
            errors=0,
            skipped=0,
            timed_out=False,
            timeout_seconds=timeout_seconds,
            blocking_failures=["Failed to parse pytest report"],
        )

    summary = data.get("summary", {})
    total = summary.get("total", 0)
    passed = summary.get("passed", 0)
    failed = summary.get("failed", 0)
    errors = summary.get("error", 0)
    skipped = summary.get("skipped", 0)

    failure_details = []
    blocking = []
    for test in data.get("tests", []):
        if test.get("outcome") in ("failed", "error"):
            detail = {
                "nodeid": test.get("nodeid", ""),
                "outcome": test.get("outcome", ""),
                "message": _extract_failure_message(test),
            }
            failure_details.append(detail)
            blocking.append(test.get("nodeid", "unknown"))

    certified = (failed == 0 and errors == 0 and total > 0)

    return TestReport(
        candidate_id=candidate_id,
        spec_id=spec_id,
        certifier_version=VERSION,
        timestamp=now,
        certification="CERTIFIED" if certified else "NOT_CERTIFIED",
        total_tests=total,
        passed=passed,
        failed=failed,
        errors=errors,
        skipped=skipped,
        timed_out=False,
        timeout_seconds=timeout_seconds,
        blocking_failures=blocking,
        failure_details=failure_details,
    )


def _extract_failure_message(test: dict) -> str:
    call = test.get("call", {})
    longrepr = call.get("longrepr", "")
    if isinstance(longrepr, str):
        return longrepr[-500:]
    return str(longrepr)[-500:]


def _parse_coverage_report(cov_path: Path, candidate_id: str) -> CoverageReport:
    now = datetime.now(timezone.utc).isoformat()

    if not cov_path.exists():
        return CoverageReport(
            candidate_id=candidate_id,
            certifier_version=VERSION,
            timestamp=now,
            branch_coverage=0.0,
            line_coverage=0.0,
            files=[],
        )

    try:
        data = json.loads(cov_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return CoverageReport(
            candidate_id=candidate_id,
            certifier_version=VERSION,
            timestamp=now,
            branch_coverage=0.0,
            line_coverage=0.0,
        )

    totals = data.get("totals", {})
    # With --cov-branch, coverage.py's "percent_covered" blends lines and
    # branches, so compute each rate from its own counts. Nothing to cover
    # (no statements / no branches) means nothing is uncovered: 100%.
    line_rate = _rate(totals.get("covered_lines", 0), totals.get("num_statements", 0))
    branch_rate = _rate(totals.get("covered_branches", 0), totals.get("num_branches", 0))

    files = []
    for fname, fdata in data.get("files", {}).items():
        fsummary = fdata.get("summary", {})
        files.append({
            "file": fname,
            "line_coverage": _rate(fsummary.get("covered_lines", 0), fsummary.get("num_statements", 0)),
        })

    return CoverageReport(
        candidate_id=candidate_id,
        certifier_version=VERSION,
        timestamp=now,
        branch_coverage=round(branch_rate, 4),
        line_coverage=round(line_rate, 4),
        files=files,
    )


# ── Evidence writer ───────────────────────────────────────────────────────────

def _write_evidence(path: Path, data: dict, report_obj: object) -> None:
    data.pop("evidence_hash", None)
    digest = seal_evidence(path, data)
    if hasattr(report_obj, "evidence_hash"):
        report_obj.evidence_hash = digest


def _rate(covered: int, total: int) -> float:
    """covered/total, treating an empty denominator as fully covered."""
    return covered / total if total else 1.0
