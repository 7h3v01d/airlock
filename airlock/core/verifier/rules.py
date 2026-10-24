# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock.core.verifier.rules

Verifier rule definitions.

Each rule is a dataclass describing:
  - rule_id       Canonical identifier (e.g. "IMPORT_SUBPROCESS")
  - severity      "critical" | "high" | "medium"
  - blocking      Whether a failure is a pipeline stop
  - description   What the rule checks
  - category      Grouping for reporting

Rules are evaluated by the AST scanner against candidate source files.
Results are collected into RuleResult instances.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str          # "critical" | "high" | "medium"
    blocking: bool
    description: str
    category: str


@dataclass
class RuleResult:
    rule_id: str
    severity: str
    blocking: bool
    passed: bool
    file: str = ""
    line: int = 0
    detail: str = ""


# ── Rule registry ─────────────────────────────────────────────────────────────

# Critical — pipeline stop on any failure
IMPORT_SUBPROCESS = Rule(
    rule_id="IMPORT_SUBPROCESS",
    severity="critical",
    blocking=True,
    description="subprocess imported without policy grant",
    category="import_policy",
)

IMPORT_SOCKET = Rule(
    rule_id="IMPORT_SOCKET",
    severity="critical",
    blocking=True,
    description="socket imported without policy grant",
    category="import_policy",
)

IMPORT_REQUESTS = Rule(
    rule_id="IMPORT_REQUESTS",
    severity="critical",
    blocking=True,
    description="requests imported without policy grant",
    category="import_policy",
)

IMPORT_URLLIB = Rule(
    rule_id="IMPORT_URLLIB",
    severity="critical",
    blocking=True,
    description="urllib imported without policy grant",
    category="import_policy",
)

CALL_EVAL = Rule(
    rule_id="CALL_EVAL",
    severity="critical",
    blocking=True,
    description="eval() called — dangerous code execution",
    category="execution_policy",
)

CALL_EXEC = Rule(
    rule_id="CALL_EXEC",
    severity="critical",
    blocking=True,
    description="exec() called — dangerous code execution",
    category="execution_policy",
)

CALL_OS_SYSTEM = Rule(
    rule_id="CALL_OS_SYSTEM",
    severity="critical",
    blocking=True,
    description="os.system() called — shell execution without policy grant",
    category="execution_policy",
)

FS_PATH_TRAVERSAL = Rule(
    rule_id="FS_PATH_TRAVERSAL",
    severity="critical",
    blocking=True,
    description="Path traversal pattern (..) detected in string construction",
    category="filesystem",
)

MISSING_SPEC_LINK = Rule(
    rule_id="MISSING_SPEC_LINK",
    severity="critical",
    blocking=True,
    description="Candidate manifest does not reference a locked spec",
    category="structural",
)

# High — pipeline stop
DYNAMIC_IMPORT = Rule(
    rule_id="DYNAMIC_IMPORT",
    severity="high",
    blocking=True,
    description="Dynamic import (__import__ or importlib) detected",
    category="import_policy",
)

IMPORT_PICKLE = Rule(
    rule_id="IMPORT_PICKLE",
    severity="high",
    blocking=True,
    description="pickle imported — unsafe deserialisation risk",
    category="import_policy",
)

UNDECLARED_DEPENDENCY = Rule(
    rule_id="UNDECLARED_DEPENDENCY",
    severity="high",
    blocking=True,
    description="Import not in candidate's declared dependency list",
    category="dependency",
)

# Medium — surfaced in report, non-blocking
MISSING_TYPE_HINTS = Rule(
    rule_id="MISSING_TYPE_HINTS",
    severity="medium",
    blocking=False,
    description="Public functions missing type annotations",
    category="structural",
)

MISSING_DOCSTRINGS = Rule(
    rule_id="MISSING_DOCSTRINGS",
    severity="medium",
    blocking=False,
    description="Public functions or modules missing docstrings",
    category="structural",
)

MISSING_TESTS = Rule(
    rule_id="MISSING_TESTS",
    severity="medium",
    blocking=False,
    description="No test files found in candidate tests/ directory",
    category="structural",
)



FS_FILE_DELETION = Rule(
    rule_id="FS_FILE_DELETION",
    severity="high",
    blocking=True,
    description="File deletion call detected (os.remove, os.unlink, shutil.rmtree, Path.unlink, Path.rmdir)",
    category="filesystem",
)

ENV_ACCESS = Rule(
    rule_id="ENV_ACCESS",
    severity="medium",
    blocking=False,
    description="Environment variable access detected (os.environ, os.getenv)",
    category="env_access",
)

FS_SHUTIL_MUTATION = Rule(
    rule_id="FS_SHUTIL_MUTATION",
    severity="medium",
    blocking=False,
    description="Potentially dangerous shutil operation detected (move, copytree, chown)",
    category="filesystem",
)


# Critical (v0.3) — source tree must match the hash recorded in the manifest
SOURCE_INTEGRITY = Rule(
    rule_id="SOURCE_INTEGRITY",
    severity="critical",
    blocking=True,
    description="src/ tree differs from the source hash recorded in manifest.json",
    category="integrity",
)


# Critical (v0.3) — src/ may only contain files the verifier can actually read
SRC_UNSCANNED_CONTENT = Rule(
    rule_id="SRC_UNSCANNED_CONTENT",
    severity="critical",
    blocking=True,
    description="src/ contains bytecode, binaries or other files the verifier cannot scan",
    category="integrity",
)


# Critical (v0.3) — deny-first import policy
IMPORT_NOT_ALLOWED = Rule(
    rule_id="IMPORT_NOT_ALLOWED",
    severity="critical",
    blocking=True,
    description=(
        "stdlib module outside the import allowlist "
        "(grant explicitly via verifier.allowed_imports in airlock.yaml)"
    ),
    category="import_policy",
)

# Critical (v0.3) — process execution, code compilation and reflection escapes
DANGEROUS_CALL = Rule(
    rule_id="DANGEROUS_CALL",
    severity="critical",
    blocking=True,
    description=(
        "process spawning (os.exec*/spawn*/popen/fork), compile(), "
        "reflective access to dangerous attributes, or interpreter escape hatches"
    ),
    category="call_policy",
)


# ── All rules in evaluation order ─────────────────────────────────────────────

ALL_RULES: list[Rule] = [
    # Critical
    IMPORT_SUBPROCESS,
    IMPORT_SOCKET,
    IMPORT_REQUESTS,
    IMPORT_URLLIB,
    CALL_EVAL,
    CALL_EXEC,
    CALL_OS_SYSTEM,
    FS_PATH_TRAVERSAL,
    MISSING_SPEC_LINK,
    SOURCE_INTEGRITY,
    SRC_UNSCANNED_CONTENT,
    IMPORT_NOT_ALLOWED,
    DANGEROUS_CALL,
    # High
    DYNAMIC_IMPORT,
    IMPORT_PICKLE,
    UNDECLARED_DEPENDENCY,
    # High (new 7E)
    FS_FILE_DELETION,
    # Medium (new 7E)
    ENV_ACCESS,
    FS_SHUTIL_MUTATION,
    # Medium
    MISSING_TYPE_HINTS,
    MISSING_DOCSTRINGS,
    MISSING_TESTS,
]

RULE_MAP: dict[str, Rule] = {r.rule_id: r for r in ALL_RULES}
