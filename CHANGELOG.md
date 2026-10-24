# Changelog

All notable changes to Airlock are documented here.

Format: `[Phase X] — Description` with date and test count.

---

## [v0.3.0] — Airlock: revival and trust-layer hardening
*2026-10-24 · 383 tests passing*

Revived from the v0.2.0 snapshot under the new name **Airlock**, and
put through an adversarial review of its own trust boundary. Every fix below
was reproduced first and has regression tests that fail when the fix is
reverted.

### Renamed
- Product renamed to **Airlock**; package `kc` → `airlock`; CLI `kc` → `airlock`.
- Certificate IDs `kc-cert-…` → `al-cert-…`.
- Project config `cleanroom.yaml` → `airlock.yaml` (legacy filename still read).
- Licensed Apache-2.0, © Leon Priest (7h3v01d); `LICENSE`, `NOTICE` and SPDX headers added.

### Security — critical
- **Source substitution after certification.** Clean code could be verified
  and certified, then replaced with arbitrary code, re-hashed with
  `candidate hash`, and the gate returned ALLOW and admitted it. Fixed: every
  evidence document records the `source_hash` it covers; the hash is frozen
  once a candidate leaves quarantine; the gate recomputes the tree hash and
  requires the manifest, the tree and all evidence to agree; the certifier
  rejects test runs that modify `src/`. (`tests/test_v03_source_binding.py`)
- **Forged bytecode in the trusted tree.** `__pycache__` was excluded from the
  source hash but copied by admission, so a `.pyc` with a matching header ran
  attacker bytecode in place of the verified source. Fixed: admission copies
  only hashed files and re-hashes the copy; new `SRC_UNSCANNED_CONTENT` rule
  blocks bytecode, `.so`/`.pyd`, `.pth` and other unscannable files; symlinks
  are refused; the certifier writes no bytecode. (`tests/test_v03_integrity.py`)
- **Verifier bypasses.** 29 patterns passed with zero blocking findings,
  including `from os import system`, `os.popen`, `os.exec*`/`spawn*`/`fork`,
  `getattr(os, "system")`, `ctypes`, `asyncio`, `marshal`, `compile()`,
  `__subclasses__` escapes and aliased `shutil.rmtree`. Fixed: deny-first
  stdlib import allowlist (`IMPORT_NOT_ALLOWED`, grants via
  `verifier.allowed_imports`), alias resolution, new `DANGEROUS_CALL` rule.
  (`tests/test_v03_verifier.py`)

### Security — high
- `spec.md` could be edited after locking; the gate only checked the LOCKED
  flag. Now verified against its locked hash at verify, gate and admission.
- Tree hash framing was ambiguous (file `a`=`bX` and file `ab`=`X` collided).
  Tree hash v2 is length-prefixed and domain-tagged. **All v0.2 source hashes
  change** — re-register candidates from v0.2 projects.
- The admission certificate's `gate_decision` hash was always empty.
- A missing source hash did not block the gate (reason strings were matched
  by keyword, and that one matched none). The gate now keeps an explicit
  blocking list.
- `UNDECLARED_DEPENDENCY` only saw imports another rule had already flagged,
  so e.g. `import numpy` was never reported. It now sees every import.

### Policy made real
- `ESCALATE_TO_OPERATOR` was unreachable. Non-blocking findings in categories
  listed under `governance.require_human_approval_for` now escalate
  (`credential_access` → `ENV_ACCESS`, `filesystem_mutation` → `FS_SHUTIL_MUTATION`).
- `airlock gate <id> --override --operator NAME --reason TEXT` — advertised in
  v0.2 but missing. Applies to ESCALATE only; audited and recorded on the
  certificate.
- `certification.minimum_line_coverage` / `minimum_branch_coverage` are
  enforced at the gate (v0.2 wrote 0.80 into every project and never read it).
- Coverage rates fixed: line coverage was coverage.py's blended line+branch
  figure; code with no branches reported 0% branch coverage.
- `verification.require_tests` / `require_type_hints` / `require_docstrings`
  promote those rules to blocking.
- `airlock init` writes only enforced keys (14 decorative keys removed); a test
  fails if any template key is unread. `allow_telemetry: true` and unsupported
  `llm.provider` values are rejected. Template model now matches the provider
  default (`deepseek-coder-v2:16b`).

### Dashboard
- Restyled to the house design system (Obsidian/Teal/Phosphor, JetBrains Mono,
  flat zero-radius controls) using local fonts only.
- Shows operator overrides on the audit log and certificate; registration date
  fixed (read the wrong manifest key); audit fields HTML-escaped.

### Upgrading a v0.2 project
1. Rename `cleanroom.yaml` to `airlock.yaml` (optional — still read).
2. Remove the unenforced keys if you like; add the `verification` and
   coverage keys from the new template to opt in to enforcement.
3. Re-register and re-run any in-flight candidates: v0.2 evidence has no
   `source_hash` and v0.2 tree hashes use the old framing, so the gate denies them.

---

## [Phase 6] — Local LLM Integration
*2026-05-23 · 175 tests passing*

### Added
- `airlock/llm/provider.py` — LLM provider interface and capability registry
  - `LLMCapabilityProfile` — declares model capabilities and enforces role boundaries
  - `ALLOWED_ROLES` — what the LLM may do: draft, generate, explain, suggest
  - `FORBIDDEN_ROLES` — what the LLM may never do: certify, approve, admit, execute, override
  - Role boundary enforcement is architectural — raises `ValueError` if forbidden roles are claimed
- `airlock/llm/ollama_provider.py` — Ollama adapter
  - Communicates with local Ollama via `urllib` (no third-party HTTP libraries)
  - `is_available()` checks Ollama is running and model is pulled before any call
  - Default model: `deepseek-coder-v2:16b`
  - Marked `local=True`, `network_access=False` (localhost only)
- `airlock/llm/prompt_contracts.py` — prompt contracts for each LLM role
  - `SPEC_DRAFT_SYSTEM` — instructs model to draft specs only, forbids approval decisions
  - `GENERATE_SYSTEM` — instructs model to generate clean Python, forbids blocked imports
  - `EXPLAIN_SYSTEM` — instructs model to explain failures, forbids override suggestions
  - All system prompts include explicit "You may NOT" sections
- `airlock/llm/call_logger.py` — append-only LLM call log
  - Logs to `logs/llm_calls.jsonl` on every call
  - Records: timestamp, model, provider, role, prompt hash, response hash, latency, success
  - Raw prompts and responses are NOT logged — only SHA-256 hashes (local-first privacy)
- `airlock/llm/generator.py` — orchestrator for LLM-assisted workflows
  - `draft_spec()` — calls LLM, writes draft to `specs/<id>/spec.md`, status stays DRAFT
  - `generate_candidate()` — calls LLM, parses response into src/ and tests/ files,
    registers quarantined candidate, writes `generation_manifest.json` to evidence store
  - `explain_failures()` — reads verifier/certifier evidence, calls LLM for explanation
  - `_parse_generated_files()` — robust parser for `### FILE: path` + code fence blocks
- `airlock/commands/llm.py` — three new CLI commands
  - `airlock spec draft <intent>` — LLM drafts spec.md, warns operator review is required
  - `airlock generate <spec_id> <module>` — LLM generates candidate, warns output is quarantined
  - `airlock explain <candidate_id>` — LLM explains failures, warns advisory only
- `tests/test_phase6.py` — 35 tests (mocked Ollama, no live instance required)
  - Provider capability enforcement tests
  - Prompt contract content tests
  - Response parser tests
  - Full CLI tests for all three LLM commands

### Changed
- `airlock/main.py` — added `generate`, `explain`, `spec draft` commands
- `airlock/commands/init.py` — updated default model from `qwen2.5-coder` to `deepseek-coder-v2:16b`

### LLM role boundary enforcement
```python
# This raises ValueError — no provider may claim forbidden roles
LLMCapabilityProfile(allowed_roles={"certify"})  # ✗ ValueError

# This is valid
LLMCapabilityProfile(allowed_roles={"draft_spec", "generate_candidate"})  # ✓
```

### New evidence document
`generation_manifest.json` — written for every LLM-generated candidate:
```json
{
  "candidate_id": "candidate_0002",
  "spec_id": "spec_0001",
  "spec_hash": "sha256:...",
  "model": "deepseek-coder-v2:16b",
  "provider": "ollama",
  "role": "generate_candidate",
  "generated_at": "2026-05-23T...",
  "files_generated": ["src/backup.py", "tests/test_backup.py"],
  "prompt_hash": "sha256:...",
  "response_hash": "sha256:..."
}
```

### Pipeline state after this phase
The pipeline now supports two entry paths — LLM-assisted and manual — that converge at `airlock verify`:

```
airlock spec draft → review → airlock spec lock ─┐
airlock spec new  → edit   → airlock spec lock ─┤
                                        ├→ airlock generate / airlock candidate register
                                        └→ airlock candidate hash
                                           → airlock verify → airlock certify → airlock gate → airlock admit
                                              ↑ airlock explain (advisory, any stage)
```

---

## [Phase 5] — Governance Gate + Admission
*2026-05-23 · 140 tests passing*

### Added
- `airlock/core/governance/gate.py` — governance gate engine
  - `run_gate()` — consumes all evidence, evaluates policy, produces binding decision
  - Four decisions: `ALLOW`, `DENY`, `QUARANTINE`, `ESCALATE_TO_OPERATOR`
  - `run_admission()` — copies `src/` to `trusted/src/`, issues L4 certificate
  - All decisions hash-sealed and appended to `logs/audit.jsonl`
- `airlock/commands/gate.py` — `airlock gate` and `airlock admit` commands
- `tests/test_phase5.py` — 28 tests

### Real-world validation
`candidate_0001` (local file backup CLI) admitted on 2026-05-23:
- Verifier: 15/15 rules PASS
- Certifier: 12/12 tests PASS, 82.3% line coverage, 75.0% branch coverage
- Gate: ALLOW — Certificate: `al-cert-2026-2ced08be`, Level L4_GOVERNANCE_ADMITTED

---

## [Phase 4] — Test Certifier
*2026-05-23 · 112 tests passing*

### Added
- `airlock/core/certifier/runner.py` — pytest + coverage runner
  - Runs tests in subprocess with isolated `PYTHONPATH`
  - Produces `test_report.json` and `coverage_report.json`, both hash-sealed
- `airlock/commands/certify.py` — `airlock certify <candidate_id>`
- `tests/test_phase4.py` — 16 tests

### Changed
- `pyproject.toml` — added `testpaths = ["tests"]` to prevent pytest collecting candidate tests

---

## [Phase 3] — Python Verifier
*2026-05-23 · 96 tests passing*

### Added
- `airlock/core/verifier/rules.py` — 15 rule definitions (critical / high / medium)
- `airlock/core/verifier/ast_scanner.py` — AST-based scanner for Python source
- `airlock/core/verifier/runner.py` — orchestrator, writes `static_verification.json`
- `airlock/commands/verify.py` — `airlock verify <candidate_id>`
- `tests/test_phase3.py` — 32 tests

---

## [Phase 2] — Spec Lifecycle + Candidate Quarantine
*2026-05-23 · 64 tests passing*

### Added
- `airlock/core/hashing.py` — SHA-256 hashing
- `airlock/core/spec_store.py` — spec lifecycle (DRAFT → LOCKED)
- `airlock/core/candidate_store.py` — candidate quarantine + status FSM
- `airlock/commands/candidate.py`, updated `airlock/commands/spec.py`
- `tests/test_phase2.py` — 38 tests

### Changed
- `pyproject.toml` — added for editable install, registers `airlock` command

---

## [Phase 1] — CLI Skeleton
*2026-05-23 · 26 tests passing*

### Added
- `airlock/main.py`, `airlock/__main__.py`, `airlock/config.py`
- `airlock/commands/` — init, status, spec, report
- `tests/test_phase1.py` — 26 tests

---

## [Phase 0] — Foundation Documents
*2026-05-23*

### Added
- `docs/VISION.md`, `docs/DOCTRINE.md`, `docs/ARCHITECTURE.md`
- `docs/THREAT_MODEL.md`, `docs/CERTIFICATION_LEVELS.md`, `docs/MVP_SCOPE.md`

---

## Upcoming

### [Phase 7] — Dogfood on real projects
Use Airlock on its own extension points and the author's other projects:
- Certify custom verifier rule modules through the pipeline
- Librarian Pro file extractor plugins
- FileTracker plugin certification
- Niles tool extension pipeline

### [Phase 8] — Dashboard
Read-only observability layer over the pipeline:
- Spec and candidate browser
- Evidence trail viewer per candidate
- Audit log viewer
- Certification level distribution
- CLI remains the primary interface

---

## [v0.2] — Evidence Integrity + Execution Containment
*2026-05-23 · 255 tests passing*

### Phase 7A — Repository Cleanup
- Fixed invalid escape sequence warning in `test_phase3.py` (`r"..\secret"` → proper escaped string) — suite now runs with 0 warnings
- Added `.gitignore` at repo root covering Python, venv, test artefacts, and cleanroom project directories
- Established that `myproject/` should not be committed to the platform source repo

### Phase 7B — True Evidence Hash Verification
- **Breaking change:** evidence files no longer embed `evidence_hash` in JSON — hash now lives exclusively in a detached `.sha256` sidecar
- `airlock/core/hashing.py` rewritten with `seal_evidence()`, `verify_sidecar()`, `write_sidecar()`
- `seal_evidence()` raises `ValueError` if called with a dict containing `evidence_hash` — architectural enforcement
- `verify_sidecar()` recomputes and compares — returns `(False, "hash mismatch: ...")` on tamper
- Sidecar format is sha256sum-compatible: `<64-hex>  <filename>`
- Governance gate now calls `verify_sidecar()` on every evidence document before evaluating it
- A tampered evidence file causes gate to `DENY` or `QUARANTINE` — not silently pass
- Updated: `airlock/core/verifier/runner.py`, `airlock/core/certifier/runner.py`, `airlock/core/governance/gate.py`
- Updated: `tests/test_phase3.py`, `tests/test_phase4.py`, `tests/test_phase5.py` (sidecar assertions)
- Added: `tests/test_phase7b.py` — 12 tests including tamper detection end-to-end

### Phase 7C — Certifier Timeout + Execution Containment
- `airlock/core/certifier/runner.py` rewritten with:
  - `subprocess.run(..., timeout=N)` — default 120s, configurable via `certification.test_timeout_seconds`
  - Environment scrubbing: only `_SAFE_ENV_KEYS` pass through; `PYTHONPATH` set to candidate `src/` only — host PYTHONPATH never inherited
  - `cwd=str(candidate_dir)` — candidate runs in its own directory, not the repo root
  - Timeout produces `NOT_CERTIFIED` with `timed_out: true` in evidence
- `airlock/commands/certify.py` — displays timeout message in output
- Added: `tests/test_phase7c.py` — 12 tests covering env scrubbing, timeout, working directory, and integration

### Phase 7D — Strict Loopback URL Enforcement
- `airlock/llm/ollama_provider.py` rewritten with:
  - `is_loopback_url()` — validates hostname against `{localhost, 127.0.0.1, ::1, [::1]}`
  - `OllamaURLError` raised at construction when `allow_remote=False` and URL is non-loopback
  - `provider_from_config()` reads `allow_remote_llm` from `local_first` config section
  - `allow_remote=True` accepts LAN addresses — but profile marks `local=False, network_access=True`
  - No config for `local_first` → defaults to strict (loopback only)
- Added: `tests/test_phase7d.py` — 27 tests including specific coverage of `192.168.0.163` (the author's LAN rig)

### Phase 7E — Verifier Expansion
- Three new rules added to `airlock/core/verifier/rules.py` (18 rules total, up from 15):
  - `FS_FILE_DELETION` — High, blocking: `os.remove`, `os.unlink`, `os.rmdir`, `os.removedirs`, `shutil.rmtree`, `Path.unlink()`, `Path.rmdir()`
  - `ENV_ACCESS` — Medium, non-blocking: `os.environ[...]`, `os.getenv()`, `os.putenv()`
  - `FS_SHUTIL_MUTATION` — Medium, non-blocking: `shutil.move`, `shutil.copytree`, `shutil.chown`
- `airlock/core/verifier/ast_scanner.py` extended with:
  - New entries in `_BLOCKED_CALLS` for deletion and shutil patterns
  - `_check_pathlib_deletion()` — detects `.unlink()` and `.rmdir()` method calls on any object
  - `_check_env_access()` — detects `os.environ` attribute access
  - Both new checks called from `_scan_file()`
- Added: `tests/test_phase7e.py` — 29 tests

### Migration note for existing projects
Evidence files created before v0.2 do not have `.sha256` sidecars. Re-run the pipeline on existing candidates:
```
airlock verify <candidate_id>
airlock certify <candidate_id>
airlock gate <candidate_id>
airlock admit <candidate_id>
```
This regenerates all evidence with proper sidecars.

Also update `myproject/airlock.yaml` if it still has `model: qwen2.5-coder` — change to `model: deepseek-coder-v2:16b`.

---

## [Phase 8] — Read-Only Dashboard
*2026-05-23 · 290 tests passing · v0.2.0*

### Added
- `airlock/dashboard/__init__.py` — dashboard package
- `airlock/dashboard/reader.py` — read-only project data reader
  - `ProjectReader` reads specs, candidates, evidence, audit log, LLM calls
  - Verifies every evidence sidecar via `verify_sidecar()` on each read
  - Path traversal guard: resolves candidate paths and checks they remain inside `candidates/`
  - All operations are non-destructive — no writes, no status transitions
- `airlock/dashboard/server.py` — FastAPI application
  - `GET /api/overview` — project summary
  - `GET /api/specs` — all specs with status and hash
  - `GET /api/candidates` — all candidates with evidence summary
  - `GET /api/candidates/{candidate_id}` — candidate detail with full evidence chain
  - `GET /api/audit` — audit log, most recent first
  - `GET /api/llm-calls` — LLM call log with hashed prompts
  - `GET /` — single-page dashboard UI
  - No POST/PUT/DELETE/PATCH endpoints — read-only by design
  - Candidate ID validated against `^candidate_[0-9]{4,}$` before any path operation
  - `escapeHtml()` applied to all user/project/LLM-derived strings in the UI
- `airlock/commands/dashboard.py` — `airlock dashboard` command
  - Binds to `127.0.0.1` by default — not exposed on LAN
  - Gracefully catches missing `fastapi` or `uvicorn` with install instructions
- `tests/test_dashboard.py` — 27 tests covering reader, API routes, and security
  - `test_path_traversal_blocked` — reader rejects `../specs` and `/etc/passwd` as candidate IDs
  - `test_evidence_reports_sidecar_failure` — tampered evidence shown as failed
  - `test_no_write_endpoints_exist` — POST/PUT/DELETE/PATCH all return 405
  - `test_ui_contains_escape_function` — XSS guard verified present in served HTML
  - `test_candidate_detail_404_for_missing` — clean 404 on unknown candidate

### Changed
- `airlock/main.py` — added `airlock dashboard` command
- `pyproject.toml` — bumped to `v0.2.0`, added optional dependency groups:
  ```toml
  [project.optional-dependencies]
  dashboard = ["fastapi>=0.100", "uvicorn>=0.23"]
  testing   = ["pytest-cov", "pytest-json-report", "httpx"]
  ```

### Dashboard security properties
- Binds localhost only by default
- No mutation endpoints
- Candidate IDs validated with strict regex before path resolution
- Path traversal blocked via `base not in cdir.parents` check
- All rendered strings escaped with `escapeHtml()`
- Evidence sidecar integrity verified on every page load — tampered evidence shown in red

### Installation
```bash
pip install -e ".[dashboard]"
airlock dashboard          # http://127.0.0.1:7842
airlock dashboard --port 8080 --host 0.0.0.0   # custom (LAN exposure — use with caution)
```

---

## [Admission Hardening] — Three Bypass Vectors Closed
*2026-05-23 · 263 tests passing*

### Fixed
Three admission-layer bypasses identified and closed:

**Bypass 1 — Fake ALLOW gate on uncertified candidate**
A hand-crafted `gate_decision.json` with `{"decision": "ALLOW"}` could previously admit a quarantined candidate. Fixed by checking `get_status(candidate_dir) == "certified"` before reading the gate decision.

**Bypass 2 — Tampered gate_decision.json admitted**
`run_admission()` previously read the gate decision without verifying its sidecar. Fixed by calling `verify_sidecar(gate_path)` before reading — a forged or edited gate decision is rejected.

**Bypass 3 — Source modified after gate approval**
A candidate's `src/` could be modified between `airlock gate` and `airlock admit`. Fixed by recomputing `hash_directory_tree(src/)` at admission time and comparing against the recorded manifest hash. Any modification is caught.

### Also fixed
- `hash_directory_tree()` now excludes `__pycache__` and `.coverage*` to prevent pytest artefacts from invalidating the recorded source hash
- Phase 5 test fixtures updated to use real source hashes instead of synthetic `sha256:abc123`

### New tests
- `tests/test_admission_hardening.py` — 5 tests
  - `test_admission_rejects_gate_decision_missing_sidecar`
  - `test_admission_rejects_tampered_gate_decision`
  - `test_admission_rejects_source_changed_after_gate`
  - `test_admission_rejects_uncertified_candidate_with_fake_allow_gate`
  - `test_clean_candidate_still_admitted_successfully`
