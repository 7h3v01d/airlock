# spec_dogfood_001

> Airlock verifier rule: FS_HARDCODED_PATHS

## Functional requirements

1. Scan Python source files for string literals that appear to be hardcoded absolute paths.
2. Detect Windows-style absolute paths (e.g. `C:\Users\...`, `D:\Projects\...`).
3. Detect Unix-style absolute paths beginning with `/` followed by a known root segment
   (e.g. `/home/`, `/root/`, `/tmp/`, `/var/`, `/etc/`, `/usr/`).
4. Report each detected path with the file name and line number.
5. Return a list of `RuleResult` instances — one failure per detected hardcoded path,
   one passing result if no hardcoded paths are found.
6. Integrate with the existing `airlock.core.verifier.rules` module as a new `Rule` instance
   named `FS_HARDCODED_PATHS`.
7. The rule must be importable from `airlock.core.verifier.rules` and callable from
   `airlock.core.verifier.ast_scanner`.

## Non-functional requirements

- Must run fully offline with no network access.
- Must use only Python 3.11+ stdlib (ast, re, pathlib).
- Must not import subprocess, socket, requests, urllib, or pickle.
- Must complete scanning a 1000-line Python file in under 1 second.
- All public functions must have type hints and docstrings.

## Forbidden behaviours

- Must not attempt to read or write any file other than the source file being scanned.
- Must not execute any discovered path string.
- Must not follow or resolve any detected path.
- Must not use eval, exec, or os.system.
- Must not use dynamic imports.

## Acceptance criteria

1. Given a Python file containing the string `"C:\\Users\\leon\\file.txt"`,
   the scanner returns a failing `RuleResult` for `FS_HARDCODED_PATHS`.
2. Given a Python file containing the string `"/home/user/data.json"`,
   the scanner returns a failing `RuleResult` for `FS_HARDCODED_PATHS`.
3. Given a Python file containing the string `"/tmp/cache"`,
   the scanner returns a failing `RuleResult` for `FS_HARDCODED_PATHS`.
4. Given a Python file containing only relative paths such as `"data/file.txt"`,
   the scanner returns a passing `RuleResult` for `FS_HARDCODED_PATHS`.
5. Given a Python file containing `Path.home()` (dynamic path resolution),
   the scanner returns a passing `RuleResult` — dynamic resolution is acceptable.
6. Given a Python file with no string literals at all,
   the scanner returns a passing `RuleResult`.
7. The `FS_HARDCODED_PATHS` rule instance has severity `"medium"` and `blocking=False`.
