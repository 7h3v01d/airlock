# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock.core.verifier.ast_scanner

AST-based scanner for Python candidate source files.

Walks every .py file in the candidate's src/ directory and evaluates
each applicable rule against the parsed AST and raw source text.

Returns a list of RuleResult instances — one per rule per file where
the rule applies. Rules that pass produce a passing RuleResult.
Rules that fail produce a failing RuleResult with file/line/detail.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

from airlock.core.verifier.rules import (
    RuleResult,
    IMPORT_SUBPROCESS,
    IMPORT_SOCKET,
    IMPORT_REQUESTS,
    IMPORT_URLLIB,
    CALL_EVAL,
    CALL_EXEC,
    CALL_OS_SYSTEM,
    FS_PATH_TRAVERSAL,
    DYNAMIC_IMPORT,
    IMPORT_PICKLE,
    MISSING_TYPE_HINTS,
    MISSING_DOCSTRINGS,
    MISSING_TESTS,
    FS_FILE_DELETION,
    ENV_ACCESS,
    FS_SHUTIL_MUTATION,
    IMPORT_NOT_ALLOWED,
    DANGEROUS_CALL,
)


# ── Deny-first import allowlist (v0.3) ────────────────────────────────────────
# Standard-library modules a candidate may import without an explicit grant.
# These are pure computation, data formats, or local filesystem access that
# is already governed by the call rules below. Anything else in the stdlib
# (ctypes, multiprocessing, asyncio, http, pty, marshal, inspect, ...) must be
# granted per project via `verifier.allowed_imports` in airlock.yaml, which is
# recorded in every gate decision's policy hash.

SAFE_STDLIB: frozenset[str] = frozenset({
    "__future__", "abc", "argparse", "array", "ast", "base64", "binascii",
    "bisect", "bz2", "calendar", "cmath", "codecs", "collections", "colorsys",
    "configparser", "contextlib", "contextvars", "copy", "csv", "dataclasses",
    "datetime", "decimal", "difflib", "enum", "errno", "fnmatch", "fractions",
    "functools", "gettext", "glob", "graphlib", "gzip", "hashlib", "heapq",
    "hmac", "html", "io", "ipaddress", "itertools", "json", "keyword",
    "locale", "logging", "lzma", "math", "mimetypes", "numbers", "operator",
    "os", "pathlib", "pprint", "queue", "random", "re", "secrets", "shlex",
    "shutil", "sqlite3", "statistics", "string", "stringprep", "struct",
    "sys", "tempfile", "textwrap", "threading", "time", "timeit", "tomllib",
    "traceback", "types", "typing", "unicodedata", "uuid", "warnings",
    "weakref", "zipfile", "zlib", "zoneinfo",
})

STDLIB_MODULES: frozenset[str] = frozenset(getattr(sys, "stdlib_module_names", ()))

# Fully-qualified callables that spawn processes, replace the interpreter,
# compile code, or otherwise escape static review.
_DANGEROUS_CALLABLES: frozenset[str] = frozenset({
    "os.popen", "os.fork", "os.forkpty", "os.startfile", "os.kill", "os.killpg",
    "os.execl", "os.execle", "os.execlp", "os.execlpe",
    "os.execv", "os.execve", "os.execvp", "os.execvpe",
    "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe",
    "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
    "os.posix_spawn", "os.posix_spawnp",
    "compile", "breakpoint", "globals", "locals", "vars",
})

# Attribute names that are never legitimate targets of reflective access.
_DANGEROUS_ATTR_NAMES: frozenset[str] = frozenset({
    "system", "popen", "eval", "exec", "compile", "__import__",
    "__builtins__", "__subclasses__", "__globals__", "__code__",
    "__closure__", "__loader__", "__spec__", "__getattribute__",
    *(name.split(".", 1)[1] for name in _DANGEROUS_CALLABLES if name.startswith("os.")),
})

# Modules whose attributes may not be fetched reflectively at all.
_REFLECTION_SENSITIVE_MODULES: frozenset[str] = frozenset({"os", "sys", "shutil", "builtins"})


# ── Blocked import names → rule mapping ───────────────────────────────────────

_BLOCKED_IMPORTS: dict[str, object] = {
    "subprocess": IMPORT_SUBPROCESS,
    "socket":     IMPORT_SOCKET,
    "requests":   IMPORT_REQUESTS,
    "urllib":     IMPORT_URLLIB,
    "pickle":     IMPORT_PICKLE,
}

# Blocked call patterns: (module_attr or bare_name, rule)
_BLOCKED_CALLS: list[tuple[str, object]] = [
    ("eval",             CALL_EVAL),
    ("exec",             CALL_EXEC),
    ("os.system",        CALL_OS_SYSTEM),
    # File deletion (high, blocking)
    ("os.remove",        FS_FILE_DELETION),
    ("os.unlink",        FS_FILE_DELETION),
    ("os.rmdir",         FS_FILE_DELETION),
    ("os.removedirs",    FS_FILE_DELETION),
    ("shutil.rmtree",    FS_FILE_DELETION),
    # Pathlib mutation (high, blocking) — caught by attribute check
    # Handled separately in _check_pathlib_deletion
    # Shutil mutation (medium, non-blocking)
    ("shutil.move",      FS_SHUTIL_MUTATION),
    ("shutil.copytree",  FS_SHUTIL_MUTATION),
    ("shutil.chown",     FS_SHUTIL_MUTATION),
    # Env access (medium, non-blocking)
    ("os.getenv",        ENV_ACCESS),
    ("os.putenv",        ENV_ACCESS),
    ("os.getenvb",       ENV_ACCESS),
]


# ── Main scanner ──────────────────────────────────────────────────────────────

def scan_candidate(
    src_dir: Path,
    allowed_imports: frozenset[str] | set[str] = frozenset(),
) -> list[RuleResult]:
    """
    Scan all .py files in src_dir and return a list of RuleResult instances.
    One result per (rule, file) pair where the rule fires or is checked.

    allowed_imports: extra top-level modules granted for this candidate
    (declared dependencies plus `verifier.allowed_imports` from policy).
    """
    results: list[RuleResult] = []
    py_files = sorted(src_dir.rglob("*.py"))

    if not py_files:
        return results

    local = local_module_names(src_dir)
    allowed = SAFE_STDLIB | frozenset(allowed_imports) | local
    for py_file in py_files:
        file_results = _scan_file(py_file, src_dir, allowed)
        results.extend(file_results)

    return results


def local_module_names(src_dir: Path) -> frozenset[str]:
    """Top-level importable names provided by the candidate's own src/."""
    names = set()
    for child in src_dir.iterdir() if src_dir.exists() else ():
        if child.is_file() and child.suffix == ".py":
            names.add(child.stem)
        elif child.is_dir() and child.name != "__pycache__":
            names.add(child.name)
    return frozenset(names)


def collect_import_tops(src_dir: Path) -> set[str]:
    """Top-level module names of every absolute import in src/."""
    tops: set[str] = set()
    for py_file in sorted(src_dir.rglob("*.py")):
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                tops.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                tops.add(node.module.split(".")[0])
    return tops


def scan_tests_dir(tests_dir: Path) -> list[RuleResult]:
    """
    Check whether any test files exist. Returns a single RuleResult
    for MISSING_TESTS.
    """
    rule = MISSING_TESTS
    test_files = list(tests_dir.rglob("test_*.py")) + list(tests_dir.rglob("*_test.py"))
    if test_files:
        return [RuleResult(
            rule_id=rule.rule_id,
            severity=rule.severity,
            blocking=rule.blocking,
            passed=True,
        )]
    return [RuleResult(
        rule_id=rule.rule_id,
        severity=rule.severity,
        blocking=rule.blocking,
        passed=False,
        detail="No test files (test_*.py or *_test.py) found in tests/",
    )]


# ── Per-file scanner ──────────────────────────────────────────────────────────

def _scan_file(
    py_file: Path,
    src_dir: Path,
    allowed: frozenset[str] = SAFE_STDLIB,
) -> list[RuleResult]:
    rel_path = py_file.relative_to(src_dir).as_posix()
    results: list[RuleResult] = []

    try:
        source = py_file.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(py_file))
    except SyntaxError as exc:
        # Can't parse — flag as a structural issue but don't crash
        results.append(RuleResult(
            rule_id="SYNTAX_ERROR",
            severity="critical",
            blocking=True,
            passed=False,
            file=rel_path,
            line=exc.lineno or 0,
            detail=f"Syntax error: {exc.msg}",
        ))
        return results

    aliases = _import_aliases(tree)

    # Import checks
    results.extend(_check_imports(tree, rel_path))
    results.extend(_check_import_allowlist(tree, rel_path, allowed))

    # Call checks
    results.extend(_check_calls(tree, rel_path, aliases))
    results.extend(_check_dangerous(tree, rel_path, aliases))

    # Path traversal in string literals
    results.extend(_check_path_traversal(tree, source, rel_path))

    # Dynamic import
    results.extend(_check_dynamic_import(tree, rel_path))

    # Pathlib deletion methods (.unlink, .rmdir)
    results.extend(_check_pathlib_deletion(tree, rel_path))

    # Environment variable attribute access (os.environ[...])
    results.extend(_check_env_access(tree, rel_path))

    # Type hints
    results.extend(_check_type_hints(tree, rel_path))

    # Docstrings
    results.extend(_check_docstrings(tree, rel_path))

    return results


# ── Import checks ─────────────────────────────────────────────────────────────

def _check_imports(tree: ast.Module, rel_path: str) -> list[RuleResult]:
    results = []
    fired: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in _BLOCKED_IMPORTS and top not in fired:
                    rule = _BLOCKED_IMPORTS[top]
                    results.append(RuleResult(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        blocking=rule.blocking,
                        passed=False,
                        file=rel_path,
                        line=node.lineno,
                        detail=f"import {alias.name}",
                    ))
                    fired.add(top)

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            top = module.split(".")[0]
            if top in _BLOCKED_IMPORTS and top not in fired:
                rule = _BLOCKED_IMPORTS[top]
                results.append(RuleResult(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    blocking=rule.blocking,
                    passed=False,
                    file=rel_path,
                    line=node.lineno,
                    detail=f"from {module} import ...",
                ))
                fired.add(top)

    # Emit pass results for rules that didn't fire
    for name, rule in _BLOCKED_IMPORTS.items():
        if name not in fired:
            results.append(RuleResult(
                rule_id=rule.rule_id,
                severity=rule.severity,
                blocking=rule.blocking,
                passed=True,
                file=rel_path,
            ))

    return results


# ── Call checks ───────────────────────────────────────────────────────────────

def _check_calls(
    tree: ast.Module, rel_path: str, aliases: dict[str, str] | None = None,
) -> list[RuleResult]:
    results = []
    fired: set[str] = set()
    aliases = aliases or {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        call_str = _resolve(_call_to_str(node.func), aliases)

        for pattern, rule in _BLOCKED_CALLS:
            if rule.rule_id in fired:
                continue
            if call_str == pattern or call_str.endswith(f".{pattern}"):
                results.append(RuleResult(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    blocking=rule.blocking,
                    passed=False,
                    file=rel_path,
                    line=node.lineno,
                    detail=f"Call to {call_str}()",
                ))
                fired.add(rule.rule_id)

    for _, rule in _BLOCKED_CALLS:
        if rule.rule_id not in fired:
            results.append(RuleResult(
                rule_id=rule.rule_id,
                severity=rule.severity,
                blocking=rule.blocking,
                passed=True,
                file=rel_path,
            ))

    return results


def _import_aliases(tree: ast.Module) -> dict[str, str]:
    """
    Map local names bound by imports to their fully-qualified origin, so
    `from os import system as s; s()` is checked as `os.system()` and
    `import shutil as sh; sh.rmtree()` as `shutil.rmtree()`.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    aliases[a.asname] = a.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for a in node.names:
                if a.name != "*":
                    aliases[a.asname or a.name] = f"{node.module}.{a.name}"
    return aliases


def _resolve(call_str: str, aliases: dict[str, str]) -> str:
    """Expand the first segment of a dotted name through the import aliases."""
    if not call_str:
        return call_str
    head, _, rest = call_str.partition(".")
    if head in aliases:
        return aliases[head] + (f".{rest}" if rest else "")
    return call_str


def _check_import_allowlist(
    tree: ast.Module, rel_path: str, allowed: frozenset[str],
) -> list[RuleResult]:
    """
    Deny-first: any standard-library import outside the allowlist fails.
    Modules with their own dedicated rule (subprocess, socket, ...) are left
    to that rule; third-party imports are governed by UNDECLARED_DEPENDENCY.
    """
    rule = IMPORT_NOT_ALLOWED
    findings: list[RuleResult] = []
    seen: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [(a.name.split(".")[0], node.lineno) for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [(node.module.split(".")[0], node.lineno)]
        else:
            continue
        for top, line in names:
            if (top in seen or top in allowed or top in _BLOCKED_IMPORTS
                    or top not in STDLIB_MODULES):
                continue
            seen.add(top)
            findings.append(RuleResult(
                rule_id=rule.rule_id, severity=rule.severity, blocking=rule.blocking,
                passed=False, file=rel_path, line=line,
                detail=f"'{top}' is not on the import allowlist",
            ))
    return findings or [RuleResult(
        rule_id=rule.rule_id, severity=rule.severity, blocking=rule.blocking,
        passed=True, file=rel_path,
    )]


def _check_dangerous(
    tree: ast.Module, rel_path: str, aliases: dict[str, str],
) -> list[RuleResult]:
    """Process spawning, compile(), reflective escapes and dunder escape hatches."""
    rule = DANGEROUS_CALL
    findings: list[RuleResult] = []

    def flag(node: ast.AST, detail: str) -> None:
        findings.append(RuleResult(
            rule_id=rule.rule_id, severity=rule.severity, blocking=rule.blocking,
            passed=False, file=rel_path, line=getattr(node, "lineno", 0), detail=detail,
        ))

    for node in ast.walk(tree):
        # from os import popen  /  from os import system  (even if never called)
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for a in node.names:
                full = f"{node.module}.{a.name}"
                if full in _DANGEROUS_CALLABLES or full in {"os.system", "builtins.eval", "builtins.exec"}:
                    flag(node, f"import of {full}")

        elif isinstance(node, ast.Call):
            name = _resolve(_call_to_str(node.func), aliases)
            bare = name.removeprefix("builtins.")
            if name in _DANGEROUS_CALLABLES or bare in _DANGEROUS_CALLABLES:
                flag(node, f"Call to {name}()")
            elif bare in ("getattr", "setattr", "delattr", "hasattr") and len(node.args) >= 2:
                target, attr = node.args[0], node.args[1]
                target_name = _resolve(_call_to_str(target), aliases)
                if isinstance(attr, ast.Constant) and isinstance(attr.value, str):
                    if attr.value in _DANGEROUS_ATTR_NAMES:
                        flag(node, f"{bare}(..., {attr.value!r})")
                elif target_name.split(".")[0] in _REFLECTION_SENSITIVE_MODULES:
                    flag(node, f"{bare}({target_name}, <dynamic>) on a sensitive module")

        elif isinstance(node, ast.Attribute) and node.attr in {
            "__builtins__", "__subclasses__", "__globals__", "__code__",
            "__closure__", "__loader__", "__spec__",
        }:
            flag(node, f"access to .{node.attr}")

        elif isinstance(node, ast.Name) and node.id == "__builtins__":
            flag(node, "access to __builtins__")

    return findings or [RuleResult(
        rule_id=rule.rule_id, severity=rule.severity, blocking=rule.blocking,
        passed=True, file=rel_path,
    )]


def _call_to_str(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_call_to_str(node.value)}.{node.attr}"
    return ""


# ── Path traversal ────────────────────────────────────────────────────────────

_PATH_TRAVERSAL_RE = re.compile(r"\.\.[/\\]|\.\.$")

def _check_path_traversal(
    tree: ast.Module, source: str, rel_path: str
) -> list[RuleResult]:
    rule = FS_PATH_TRAVERSAL
    findings = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if _PATH_TRAVERSAL_RE.search(node.value):
                findings.append(RuleResult(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    blocking=rule.blocking,
                    passed=False,
                    file=rel_path,
                    line=node.lineno,
                    detail=f"Path traversal pattern in string: {node.value!r}",
                ))

    if not findings:
        findings.append(RuleResult(
            rule_id=rule.rule_id,
            severity=rule.severity,
            blocking=rule.blocking,
            passed=True,
            file=rel_path,
        ))

    return findings


# ── Dynamic import ────────────────────────────────────────────────────────────

def _check_dynamic_import(tree: ast.Module, rel_path: str) -> list[RuleResult]:
    rule = DYNAMIC_IMPORT
    findings = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_str = _resolve(_call_to_str(node.func), _import_aliases(tree))
            if call_str in ("__import__", "importlib.import_module",
                            "importlib.util.spec_from_file_location",
                            "builtins.__import__"):
                findings.append(RuleResult(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    blocking=rule.blocking,
                    passed=False,
                    file=rel_path,
                    line=node.lineno,
                    detail=f"Dynamic import: {call_str}()",
                ))

    if not findings:
        findings.append(RuleResult(
            rule_id=rule.rule_id,
            severity=rule.severity,
            blocking=rule.blocking,
            passed=True,
            file=rel_path,
        ))

    return findings


# ── Type hints ────────────────────────────────────────────────────────────────

def _check_type_hints(tree: ast.Module, rel_path: str) -> list[RuleResult]:
    rule = MISSING_TYPE_HINTS
    missing = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name.startswith("_"):
            continue  # private functions exempt

        args_missing = [
            a.arg for a in node.args.args
            if a.annotation is None and a.arg != "self"
        ]
        return_missing = node.returns is None

        if args_missing or return_missing:
            parts = []
            if args_missing:
                parts.append(f"args without hints: {', '.join(args_missing)}")
            if return_missing:
                parts.append("missing return type")
            missing.append(RuleResult(
                rule_id=rule.rule_id,
                severity=rule.severity,
                blocking=rule.blocking,
                passed=False,
                file=rel_path,
                line=node.lineno,
                detail=f"def {node.name}(): {'; '.join(parts)}",
            ))

    if not missing:
        return [RuleResult(
            rule_id=rule.rule_id,
            severity=rule.severity,
            blocking=rule.blocking,
            passed=True,
            file=rel_path,
        )]
    return missing


# ── Docstrings ────────────────────────────────────────────────────────────────

def _check_docstrings(tree: ast.Module, rel_path: str) -> list[RuleResult]:
    rule = MISSING_DOCSTRINGS
    missing = []

    # Module-level docstring
    if not (tree.body and isinstance(tree.body[0], ast.Expr)
            and isinstance(tree.body[0].value, ast.Constant)
            and isinstance(tree.body[0].value.value, str)):
        missing.append(RuleResult(
            rule_id=rule.rule_id,
            severity=rule.severity,
            blocking=rule.blocking,
            passed=False,
            file=rel_path,
            line=1,
            detail="Module missing docstring",
        ))

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name.startswith("_"):
            continue
        if not (node.body and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)):
            missing.append(RuleResult(
                rule_id=rule.rule_id,
                severity=rule.severity,
                blocking=rule.blocking,
                passed=False,
                file=rel_path,
                line=node.lineno,
                detail=f"def {node.name}() missing docstring",
            ))

    if not missing:
        return [RuleResult(
            rule_id=rule.rule_id,
            severity=rule.severity,
            blocking=rule.blocking,
            passed=True,
            file=rel_path,
        )]
    return missing


# ── Pathlib deletion ──────────────────────────────────────────────────────────

# pathlib methods that permanently delete or mutate filesystem structure
_PATHLIB_DELETION_METHODS = {"unlink", "rmdir"}


def _check_pathlib_deletion(tree: ast.Module, rel_path: str) -> list[RuleResult]:
    """Detect Path.unlink() and Path.rmdir() calls — permanent file deletion."""
    rule = FS_FILE_DELETION
    findings = []
    fired = False

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _PATHLIB_DELETION_METHODS
            and not fired
        ):
            findings.append(RuleResult(
                rule_id=rule.rule_id,
                severity=rule.severity,
                blocking=rule.blocking,
                passed=False,
                file=rel_path,
                line=node.lineno,
                detail=f"Pathlib deletion: .{node.func.attr}()",
            ))
            fired = True

    if not findings:
        findings.append(RuleResult(
            rule_id=rule.rule_id,
            severity=rule.severity,
            blocking=rule.blocking,
            passed=True,
            file=rel_path,
        ))

    return findings


# ── Environment variable access ───────────────────────────────────────────────

def _check_env_access(tree: ast.Module, rel_path: str) -> list[RuleResult]:
    """Detect os.environ attribute access and subscript operations."""
    rule = ENV_ACCESS
    findings = []
    fired = False
    aliases = _import_aliases(tree)

    for node in ast.walk(tree):
        if fired:
            break

        # Detect: os.environ (attribute access), or `environ` imported from os
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "environ"
            and isinstance(node.value, ast.Name)
            and _resolve(node.value.id, aliases) == "os"
        ) or (
            isinstance(node, ast.Name)
            and _resolve(node.id, aliases) in ("os.environ", "os.environb")
        ):
            # Make sure it's not just a reference inside a getenv call
            # (already caught by _BLOCKED_CALLS for os.getenv)
            # Only flag direct os.environ attribute access
            findings.append(RuleResult(
                rule_id=rule.rule_id,
                severity=rule.severity,
                blocking=rule.blocking,
                passed=False,
                file=rel_path,
                line=node.lineno,
                detail="Direct os.environ access",
            ))
            fired = True

    if not findings:
        findings.append(RuleResult(
            rule_id=rule.rule_id,
            severity=rule.severity,
            blocking=rule.blocking,
            passed=True,
            file=rel_path,
        ))

    return findings
