# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock.core.verifier.runner

Orchestrates the full verification run for a candidate.

Inputs:
  - candidate_dir   Path to the candidate directory
  - project_root    Path to the cleanroom project root
  - policy          Dict from airlock.yaml

Outputs:
  - VerificationReport dataclass
  - Writes static_verification.json to evidence/<candidate_id>/
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

from airlock.core.verifier.rules import (
    RuleResult, ALL_RULES, MISSING_SPEC_LINK, UNDECLARED_DEPENDENCY, SOURCE_INTEGRITY,
    SRC_UNSCANNED_CONTENT,
)
from airlock.core.verifier.ast_scanner import (
    scan_candidate, scan_tests_dir, collect_import_tops, local_module_names,
)
from airlock.core.hashing import (
    seal_evidence, verify_sidecar, hash_directory_tree, hash_file, find_symlinks,
    find_unhashed_files, tree_files,
)

# File types allowed in src/. Everything else is unscannable: a compiled
# extension (.so/.pyd), bytecode or .pth file would run without ever being
# read by the AST scanner.
SCANNABLE_SUFFIXES = {
    ".py", ".pyi", ".typed", ".txt", ".md", ".rst", ".json", ".toml",
    ".yaml", ".yml", ".cfg", ".ini", ".csv",
}
from airlock.core.candidate_store import compute_source_hash, CandidateError
from airlock.core import signing

VERSION = "0.1.0"


# ── Report dataclass ──────────────────────────────────────────────────────────

@dataclass
class VerificationReport:
    candidate_id: str
    spec_id: str
    verifier_version: str
    timestamp: str
    verdict: str                        # "PASS" | "FAIL"
    rules_evaluated: int
    rules_passed: int
    rules_failed: int
    blocking_failures: int
    results: list[dict] = field(default_factory=list)
    source_hash: str = ""               # hash of the src/ tree this report covers
    evidence_hash: str = ""


# ── Runner ────────────────────────────────────────────────────────────────────

def run_verification(
    candidate_dir: Path,
    project_root: Path,
    policy: dict,
) -> VerificationReport:
    """
    Run the full verifier against a candidate.
    Returns a VerificationReport and writes static_verification.json.
    """
    candidate_id = candidate_dir.name
    manifest_path = candidate_dir / "manifest.json"
    signer = signing.signer_for(policy)   # raises SigningError if required but unavailable

    # ── Load manifest ─────────────────────────────────────────────────────────
    manifest = {}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    spec_id = manifest.get("spec_id", "")
    declared_deps = set(manifest.get("dependencies", []))

    all_results: list[RuleResult] = []

    # ── Rule: MISSING_SPEC_LINK ───────────────────────────────────────────────
    rule = MISSING_SPEC_LINK
    spec_dir = project_root / "specs" / spec_id
    spec_locked = False
    if spec_id and spec_dir.exists():
        meta_path = spec_dir / "spec_meta.json"
        if meta_path.exists():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            spec_md = spec_dir / "spec.md"
            spec_locked = (
                meta.get("status") == "LOCKED"
                and spec_md.exists()
                and hash_file(spec_md) == meta.get("spec_hash")
            )

    all_results.append(RuleResult(
        rule_id=rule.rule_id,
        severity=rule.severity,
        blocking=rule.blocking,
        passed=spec_locked,
        detail="" if spec_locked else (
            f"spec_id={spec_id!r} not found, not locked, or edited since it was locked"
            if spec_id else "manifest.json has no spec_id"
        ),
    ))

    # ── Rule: SOURCE_INTEGRITY ────────────────────────────────────────────────
    # Bind this report to the exact tree being scanned. If no hash has been
    # recorded yet it is recorded now; if one has, the tree must still match.
    src_dir = candidate_dir / "src"
    source_hash = ""
    if src_dir.exists():
        source_hash = hash_directory_tree(src_dir)
        recorded = manifest.get("source_hash")
        integrity_detail = ""
        if not recorded:
            try:
                recorded = compute_source_hash(candidate_dir)
            except CandidateError as exc:
                integrity_detail = str(exc)
        links = find_symlinks(src_dir)
        if links:
            integrity_detail = f"symlinks are not allowed in src/: {', '.join(links)}"
        if not integrity_detail and recorded != source_hash:
            integrity_detail = (
                "src/ was modified after its hash was recorded "
                f"(recorded {str(recorded)[:19]}..., current {source_hash[:19]}...)"
            )
        all_results.append(RuleResult(
            rule_id=SOURCE_INTEGRITY.rule_id,
            severity=SOURCE_INTEGRITY.severity,
            blocking=SOURCE_INTEGRITY.blocking,
            passed=not integrity_detail,
            detail=integrity_detail,
        ))

    # ── Rule: SRC_UNSCANNED_CONTENT ───────────────────────────────────────────
    if src_dir.exists():
        offenders = find_unhashed_files(src_dir) + [
            p.relative_to(src_dir).as_posix()
            for p in tree_files(src_dir)
            if p.suffix.lower() not in SCANNABLE_SUFFIXES
        ]
        all_results.append(RuleResult(
            rule_id=SRC_UNSCANNED_CONTENT.rule_id,
            severity=SRC_UNSCANNED_CONTENT.severity,
            blocking=SRC_UNSCANNED_CONTENT.blocking,
            passed=not offenders,
            detail="" if not offenders else (
                "remove from src/: " + ", ".join(sorted(set(offenders)))
            ),
        ))

    # ── AST scan of src/ ──────────────────────────────────────────────────────
    if src_dir.exists():
        verifier_policy = (policy or {}).get("verifier", {}) or {}
        granted = {str(m) for m in verifier_policy.get("allowed_imports", []) or []}
        ast_results = scan_candidate(src_dir, allowed_imports=granted | declared_deps)
        all_results.extend(ast_results)

        # ── Rule: UNDECLARED_DEPENDENCY ───────────────────────────────────────
        # Every absolute import that is neither stdlib nor the candidate's own
        # module must be declared in manifest.json "dependencies". (v0.2 only
        # considered imports another rule had already flagged, so e.g.
        # `import numpy` was never reported.)
        imported_tops = collect_import_tops(src_dir)
        stdlib = _stdlib_modules()
        third_party = imported_tops - stdlib - local_module_names(src_dir) - {"__future__"}

        udep_rule = UNDECLARED_DEPENDENCY
        for mod in sorted(third_party):
            if mod not in declared_deps:
                all_results.append(RuleResult(
                    rule_id=udep_rule.rule_id,
                    severity=udep_rule.severity,
                    blocking=udep_rule.blocking,
                    passed=False,
                    detail=f"'{mod}' imported but not in manifest dependencies",
                ))
            else:
                all_results.append(RuleResult(
                    rule_id=udep_rule.rule_id,
                    severity=udep_rule.severity,
                    blocking=udep_rule.blocking,
                    passed=True,
                    detail=f"'{mod}' declared",
                ))

        if not third_party:
            all_results.append(RuleResult(
                rule_id=udep_rule.rule_id,
                severity=udep_rule.severity,
                blocking=udep_rule.blocking,
                passed=True,
                detail="No third-party imports detected",
            ))

    # ── Test presence check ───────────────────────────────────────────────────
    tests_dir = candidate_dir / "tests"
    all_results.extend(scan_tests_dir(tests_dir))   # a missing tests/ counts as no tests

    # ── Policy: promote advisory rules to blocking ───────────────────────────
    verification_policy = (policy or {}).get("verification", {}) or {}
    promoted = set()
    if verification_policy.get("require_tests"):
        promoted.add("MISSING_TESTS")
    if verification_policy.get("require_type_hints"):
        promoted.add("MISSING_TYPE_HINTS")
    if verification_policy.get("require_docstrings"):
        promoted.add("MISSING_DOCSTRINGS")
    for r in all_results:
        if r.rule_id in promoted:
            r.blocking = True

    # ── Aggregate ─────────────────────────────────────────────────────────────
    failed = [r for r in all_results if not r.passed]
    blocking = [r for r in failed if r.blocking]
    verdict = "FAIL" if blocking else "PASS"

    report = VerificationReport(
        candidate_id=candidate_id,
        spec_id=spec_id,
        verifier_version=VERSION,
        timestamp=datetime.now(timezone.utc).isoformat(),
        verdict=verdict,
        rules_evaluated=len(all_results),
        rules_passed=len([r for r in all_results if r.passed]),
        rules_failed=len(failed),
        blocking_failures=len(blocking),
        results=[_result_to_dict(r) for r in all_results],
        source_hash=source_hash,
    )

    # ── Write evidence (detached sidecar model) ─────────────────────────────
    evidence_dir = project_root / "evidence" / candidate_id
    evidence_dir.mkdir(parents=True, exist_ok=True)
    report_path = evidence_dir / "static_verification.json"
    report_data = asdict(report)
    report_data.pop("evidence_hash", None)
    digest = seal_evidence(report_path, report_data, signer=signer)
    report.evidence_hash = digest

    return report


# ── Helpers ───────────────────────────────────────────────────────────────────

def _result_to_dict(r: RuleResult) -> dict:
    return {
        "rule_id": r.rule_id,
        "severity": r.severity,
        "blocking": r.blocking,
        "passed": r.passed,
        "file": r.file,
        "line": r.line,
        "detail": r.detail,
    }


def _extract_imported_tops(results: list[RuleResult]) -> set[str]:
    """
    Extract top-level module names that were flagged by import rules.
    We use the detail field which contains the import statement.
    """
    tops: set[str] = set()
    import_rule_ids = {
        "IMPORT_SUBPROCESS", "IMPORT_SOCKET", "IMPORT_REQUESTS",
        "IMPORT_URLLIB", "IMPORT_PICKLE",
    }
    for r in results:
        if r.rule_id in import_rule_ids and not r.passed:
            # detail is like "import subprocess" or "from urllib import ..."
            detail = r.detail
            if detail.startswith("import "):
                tops.add(detail.split()[1].split(".")[0])
            elif detail.startswith("from "):
                tops.add(detail.split()[1].split(".")[0])
    return tops


def _stdlib_modules() -> set[str]:
    """Return a set of known stdlib top-level module names."""
    import sys
    if hasattr(sys, "stdlib_module_names"):
        return set(sys.stdlib_module_names)
    # Fallback for Python < 3.10
    return {
        "abc", "ast", "asyncio", "builtins", "collections", "contextlib",
        "copy", "dataclasses", "datetime", "enum", "functools", "hashlib",
        "importlib", "inspect", "io", "itertools", "json", "logging",
        "math", "operator", "os", "pathlib", "re", "shutil", "signal",
        "string", "sys", "tempfile", "threading", "time", "traceback",
        "typing", "unittest", "uuid", "warnings", "weakref",
    }
