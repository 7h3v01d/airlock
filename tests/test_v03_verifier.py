# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
v0.3 — Deny-first verifier regression tests.

Every BYPASSES entry passed the v0.2 verifier with zero blocking findings.
LEGITIMATE entries are ordinary code that must keep passing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from airlock.core.verifier.ast_scanner import scan_candidate
from airlock.core.verifier.runner import run_verification

BYPASSES = {
    "from_os_import_system": "from os import system\nsystem('x')\n",
    "from_os_import_system_alias": "from os import system as s\ns('x')\n",
    "getattr_os_literal": "import os\ngetattr(os, 'system')('x')\n",
    "getattr_os_dynamic": "import os\nname = 'sys' + 'tem'\ngetattr(os, name)('x')\n",
    "os_popen": "import os\nos.popen('x')\n",
    "os_execv": "import os\nos.execv('/bin/sh', ['sh'])\n",
    "os_spawnv": "import os\nos.spawnv(os.P_WAIT, '/bin/sh', ['sh'])\n",
    "os_fork": "import os\nos.fork()\n",
    "os_posix_spawn": "import os\nos.posix_spawn('/bin/sh', ['sh'], {})\n",
    "import_os_alias_popen": "import os as o\no.popen('x')\n",
    "shutil_alias_rmtree": "import shutil as sh\nsh.rmtree('x')\n",
    "from_shutil_rmtree": "from shutil import rmtree\nrmtree('x')\n",
    "from_os_remove": "from os import remove\nremove('x')\n",
    "ctypes": "import ctypes\n",
    "http_client": "import http.client\n",
    "ftplib": "import ftplib\n",
    "marshal": "import marshal\n",
    "shelve": "import shelve\n",
    "multiprocessing": "import multiprocessing\n",
    "asyncio": "import asyncio\n",
    "pty": "import pty\n",
    "importlib": "import importlib\n",
    "inspect": "import inspect\n",
    "builtins_module": "import builtins\n",
    "compile_call": "c = compile('1', 'x', 'eval')\n",
    "dunder_builtins": "b = __builtins__\n",
    "subclasses_escape": "x = ().__class__.__bases__[0].__subclasses__()\n",
    "globals_call": "g = globals()\n",
    "func_globals": "def f():\n    pass\nf.__globals__\n",
}

LEGITIMATE = {
    "dataclass_json": (
        "import json\nfrom dataclasses import dataclass, asdict\n\n"
        "@dataclass\nclass P:\n    x: int\n\ndata = json.dumps(asdict(P(1)))\n"
    ),
    "pathlib_read": "from pathlib import Path\ntext = Path('a.txt').read_text()\n",
    "os_path": "import os\nfrom os import path\np = os.path.join('a', 'b')\nq = path.exists(p)\n",
    "getattr_object": "class A:\n    x = 1\nname = 'x'\nv = getattr(A(), name, None)\n",
    "typing_logging": "import logging\nfrom typing import Optional\nlog = logging.getLogger(__name__)\n",
    "relative_import": "from . import sibling\n",
    "local_module": "import helper\n",
    "shutil_copy": "import shutil\nshutil.copy2('a', 'b')\n",
}


def _blocking(src: Path, **kw) -> list[str]:
    return sorted({r.rule_id for r in scan_candidate(src, **kw) if not r.passed and r.blocking})


@pytest.mark.parametrize("name", sorted(BYPASSES))
def test_bypass_is_blocked(tmp_path: Path, name: str) -> None:
    (tmp_path / "m.py").write_text('"""m."""\n' + BYPASSES[name], encoding="utf-8")
    assert _blocking(tmp_path), f"{name} produced no blocking finding"


@pytest.mark.parametrize("name", sorted(LEGITIMATE))
def test_legitimate_code_passes(tmp_path: Path, name: str) -> None:
    (tmp_path / "m.py").write_text('"""m."""\n' + LEGITIMATE[name], encoding="utf-8")
    (tmp_path / "helper.py").write_text('"""h."""\n', encoding="utf-8")
    (tmp_path / "sibling.py").write_text('"""s."""\n', encoding="utf-8")
    assert _blocking(tmp_path) == []


def test_policy_grant_allows_stdlib_module(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text('"""m."""\nimport asyncio\n', encoding="utf-8")
    assert "IMPORT_NOT_ALLOWED" in _blocking(tmp_path)
    assert _blocking(tmp_path, allowed_imports={"asyncio"}) == []


class TestUndeclaredDependency:
    def _candidate(self, tmp_path: Path, deps: list[str]) -> tuple[Path, Path]:
        root = tmp_path / "proj"
        spec = root / "specs" / "spec_0001"
        spec.mkdir(parents=True)
        cdir = root / "candidates" / "candidate_0001"
        (cdir / "src").mkdir(parents=True)
        (cdir / "tests").mkdir()
        (cdir / "src" / "m.py").write_text('"""m."""\nimport numpy\n', encoding="utf-8")
        (cdir / "manifest.json").write_text(json.dumps({"spec_id": "spec_0001", "dependencies": deps}))
        (cdir / "status.json").write_text(json.dumps({"status": "quarantined"}))
        return root, cdir

    def test_undeclared_third_party_import_is_blocking(self, tmp_path: Path) -> None:
        root, cdir = self._candidate(tmp_path, [])
        report = run_verification(cdir, root, {})
        failed = [r for r in report.results if r["rule_id"] == "UNDECLARED_DEPENDENCY" and not r["passed"]]
        assert failed and "numpy" in failed[0]["detail"]

    def test_declared_third_party_import_passes_that_rule(self, tmp_path: Path) -> None:
        root, cdir = self._candidate(tmp_path, ["numpy"])
        report = run_verification(cdir, root, {})
        assert not [r for r in report.results if r["rule_id"] == "UNDECLARED_DEPENDENCY" and not r["passed"]]

    def test_policy_grant_reaches_scanner_via_runner(self, tmp_path: Path) -> None:
        root, cdir = self._candidate(tmp_path, [])
        (cdir / "src" / "m.py").write_text('"""m."""\nimport asyncio\n', encoding="utf-8")
        denied = run_verification(cdir, root, {})
        granted = run_verification(cdir, root, {"verifier": {"allowed_imports": ["asyncio"]}})
        ids = lambda rep: {r["rule_id"] for r in rep.results if not r["passed"]}
        assert "IMPORT_NOT_ALLOWED" in ids(denied)
        assert "IMPORT_NOT_ALLOWED" not in ids(granted)
