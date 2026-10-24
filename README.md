# Airlock

> *Local-first LLM-assisted software engineering with evidence-grade trust boundaries.*

---

## What Is This?

Airlock is a pipeline platform that turns ideas into verified, tested, governed, and certifiable software artefacts before they are allowed into trusted execution.

It is not an AI coding assistant. It is the **trust layer between a local LLM and your codebase.**

---

## Status

🟢 **v0.4.0 — Signed evidence and a hash-chained audit log.** See [CHANGELOG.md](CHANGELOG.md).

| Phase | Description | Status |
|---|---|---|
| 0 | Foundation documents | ✅ Complete |
| 1 | CLI skeleton | ✅ Complete |
| 2 | Spec lifecycle + candidate quarantine | ✅ Complete |
| 3 | Python verifier (AST scanner + policy rules — 22 as of v0.3) | ✅ Complete |
| 4 | Test certifier (pytest + coverage + evidence) | ✅ Complete |
| 5 | Governance gate + admission certificate | ✅ Complete |
| 6 | Local LLM integration (Ollama) | ✅ Complete |
| 7A | Repository cleanup + warning hygiene | ✅ Complete |
| 7B | True evidence hash verification (detached sidecar model) | ✅ Complete |
| 7C | Certifier timeout + execution containment | ✅ Complete |
| 7D | Strict loopback URL enforcement for Ollama | ✅ Complete |
| 7E | Verifier expansion (file deletion, env access, shutil) | ✅ Complete |
| 8 | Read-only FastAPI dashboard | ✅ Complete |
| 9 | v0.3 trust-layer hardening (source binding, deny-first verifier, real policy) | ✅ Complete |
| 10 | v0.4 Ed25519-signed evidence, hash-chained + anchored audit log | ✅ Complete |

---

## Core Principle

> The LLM may propose. The spec constrains. The verifier challenges. The certifier measures. The governance gate decides. The runtime only executes what has been admitted.

---

## Quick Start

```bash
# Install core
pip install -e .
pip install pytest-cov pytest-json-report

# Install dashboard (optional)
pip install -e ".[dashboard]"

# Create a cleanroom project
airlock init myproject
cd myproject

# LLM-assisted workflow (Ollama required)
airlock spec draft "Build a local file backup CLI"
# review and edit specs/spec_0001/spec.md
airlock spec lock spec_0001
airlock generate spec_0001 backup
airlock candidate hash candidate_0001
airlock verify candidate_0001
airlock certify candidate_0001
airlock gate candidate_0001
airlock admit candidate_0001

# Manual workflow (no LLM required)
airlock spec new "Build a local file backup CLI"
# edit specs/spec_0001/spec.md
airlock spec lock spec_0001
airlock candidate register spec_0001
# place src/ and tests/ manually
airlock candidate hash candidate_0001
airlock verify candidate_0001
airlock certify candidate_0001
airlock gate candidate_0001
airlock admit candidate_0001

# If a candidate fails, ask the LLM to explain
airlock explain candidate_0001

# Launch the dashboard
airlock dashboard
# open http://127.0.0.1:7842
```

---

## CLI Reference

```
airlock init <name>                   Initialise a new cleanroom project
airlock status                        Show project overview
airlock report <candidate_id>         Show full evidence summary for a candidate
airlock dashboard [--port 7842]       Start the read-only dashboard server

airlock spec draft <intent>           LLM drafts a spec from a one-line intent
airlock spec new <description>        Create a new DRAFT spec (manual)
airlock spec lock <spec_id>           Hash-seal a spec for pipeline use
airlock spec list                     List all specs and their status

airlock generate <spec_id> <module>   LLM generates a candidate from a spec
airlock candidate register <spec_id>  Register a quarantined candidate (manual)
airlock candidate hash <candidate_id> Hash the candidate's src/ tree
airlock candidate list                List all candidates and their status

airlock verify <candidate_id>         Run the static verifier (AST + 22 policy rules)
airlock certify <candidate_id>        Run the test certifier (pytest + coverage)
airlock gate <candidate_id>           Run the governance gate
airlock gate <id> --override --operator NAME --reason TEXT
                                      Approve an ESCALATE decision (audited)
airlock admit <candidate_id>          Admit to trusted tree + issue certificate

airlock explain <candidate_id>        LLM explains pipeline failures (advisory)

airlock keys init [--passphrase]      Create the operator signing key (outside the project)
airlock keys show                     Key id, trusted keys, signatures floor
airlock keys export [-o FILE]         Print/write the operator public key
airlock keys trust <FILE>             Trust another operator's public key
airlock audit verify [--reanchor]     Verify the audit chain, signatures and anchor
```

---

## Dashboard

```
airlock dashboard
```

Opens at `http://127.0.0.1:7842` (localhost only by default).

Five pages:

- **Overview** — project name, risk class, spec count, candidate status breakdown
- **Candidates** — full table with origin, pipeline status, evidence summary; click to drill down
- **Candidate detail** — complete evidence chain with per-document sidecar verification status and admission certificate
- **Audit Log** — every gate decision and admission event, most recent first
- **LLM Calls** — every LLM call with role, model, hashed prompt, token count, latency

The dashboard is **read-only** — no write, delete, or action endpoints exist. It reads live data on every refresh. Evidence sidecar integrity is verified on every load — tampered evidence is shown in red.

---

## LLM Trust Boundaries

The LLM is a speed layer, not a trust layer. Enforced in code — not convention.

**The LLM may:** draft specs, generate candidates, explain failures, suggest remediations.

**The LLM may never:** certify, approve, admit, execute, override policy, or modify evidence.

When `allow_remote_llm: false` (the default), `base_url` is validated at provider construction — non-loopback URLs raise `OllamaURLError` immediately.

---

## Verifier Rules (22 total)

The verifier is **deny-first**: standard-library imports must be on a safe
allowlist (pure computation, data formats, local file I/O governed by the call
rules) or explicitly granted in `airlock.yaml` under `verifier.allowed_imports`.
Imports are resolved through aliases, so `from os import system` is checked as
`os.system`.

| Rule | Severity | Blocking | Catches |
|---|---|---|---|
| `IMPORT_SUBPROCESS` | Critical | Yes | `import subprocess` |
| `IMPORT_SOCKET` | Critical | Yes | `import socket` |
| `IMPORT_REQUESTS` | Critical | Yes | `import requests` |
| `IMPORT_URLLIB` | Critical | Yes | `import urllib` |
| `CALL_EVAL` | Critical | Yes | `eval(...)` |
| `CALL_EXEC` | Critical | Yes | `exec(...)` |
| `CALL_OS_SYSTEM` | Critical | Yes | `os.system(...)`, including aliased imports |
| `FS_PATH_TRAVERSAL` | Critical | Yes | `../` in strings |
| `MISSING_SPEC_LINK` | Critical | Yes | Spec missing, not locked, or edited since lock |
| `SOURCE_INTEGRITY` | Critical | Yes | `src/` differs from its recorded hash; symlinks |
| `SRC_UNSCANNED_CONTENT` | Critical | Yes | `.pyc`, `__pycache__`, `.so`/`.pyd`, `.pth`, other unscannable files |
| `IMPORT_NOT_ALLOWED` | Critical | Yes | Stdlib modules off the allowlist (`ctypes`, `asyncio`, `http`, `pty`, `marshal`, …) |
| `DANGEROUS_CALL` | Critical | Yes | `os.popen/exec*/spawn*/fork`, `compile`, `getattr(os, …)`, `__subclasses__`, `__builtins__`, `globals()` |
| `DYNAMIC_IMPORT` | High | Yes | `__import__`, `importlib` |
| `IMPORT_PICKLE` | High | Yes | `import pickle` |
| `UNDECLARED_DEPENDENCY` | High | Yes | Third-party imports missing from manifest `dependencies` |
| `FS_FILE_DELETION` | High | Yes | `os.remove`, `shutil.rmtree`, `Path.unlink` |
| `ENV_ACCESS` | Medium | No¹ | `os.environ`, `os.getenv` |
| `FS_SHUTIL_MUTATION` | Medium | No¹ | `shutil.move`, `shutil.copytree` |
| `MISSING_TYPE_HINTS` | Medium | Policy² | Untyped public functions |
| `MISSING_DOCSTRINGS` | Medium | Policy² | Missing docstrings |
| `MISSING_TESTS` | Medium | Policy² | No test files |

¹ Escalates to an operator when its category is listed under `governance.require_human_approval_for`.
² Blocking when `verification.require_tests` / `require_type_hints` / `require_docstrings` is true.

An AST scanner is evidence-grade, not proof-grade: it raises the cost of
smuggling behaviour past review but cannot rule it out. Test execution during
`airlock certify` runs candidate code on the host with a scrubbed environment
and a timeout — not a sandbox.

---

## Admission Guards

Before any file is copied to `trusted/src/`, these guards run:

1. **Status check** — candidate must be `certified`. A fake ALLOW gate on a quarantined candidate is blocked.
2. **Gate sidecar verification** — `gate_decision.json` is verified against its `.sha256` sidecar. A forged or edited gate decision is rejected.
3. **Source binding** — the gate decision must cover the recorded source hash, and `src/` is re-hashed and compared. No file outside the hash (bytecode, sidecars, coverage data) or symlink may be present.
4. **Spec binding** — `spec.md` must still match its locked hash and the hash the gate decision recorded.

Only the files covered by the source hash are copied, and the copy is re-hashed.

## Source Binding

The source hash is recorded when a candidate is hashed (or on first `verify`)
and is **frozen once the candidate leaves quarantine** — to change the code,
register a new candidate. Every evidence document records the `source_hash` it
was produced against, and the gate recomputes the tree hash and requires all of
them to agree. The certifier also rejects test runs that modify `src/`.

---

## Evidence Integrity Model

Evidence files use a **detached sidecar model** — the hash never lives inside the file it covers:

```
evidence/candidate_0001/
  static_verification.json        verifier report
  static_verification.json.sha256  detached sidecar
  test_report.json
  test_report.json.sha256
  coverage_report.json
  coverage_report.json.sha256
  gate_decision.json
  gate_decision.json.sha256
  admission_certificate.json
  admission_certificate.json.sha256
  *.json.sig                        Ed25519 signature (v0.4)
```

Sidecars are sha256sum-compatible: `sha256sum --check file.json.sha256` works on any system.

Sidecars live beside the evidence, so on their own they only detect accidental
or naive edits. Since v0.4 every evidence document is also **signed**.

## Signed Evidence and Audit Chain (v0.4)

**Signatures.** Verifier and certifier reports, gate decisions and admission
certificates are signed with an Ed25519 operator key. Each signature binds the
document's SHA-256 *and* its label (`candidate_0001/test_report.json`), so a
valid signature cannot be moved to another document or another candidate.

**Trust lives outside the project**, in the operator's Airlock home
(`%APPDATA%\airlock` on Windows, `~/.config/airlock` elsewhere, or
`AIRLOCK_HOME`):

```
config.json                 {"require_signatures": true}  — the operator floor
keys/operator_ed25519.pem   private key (optionally passphrase-encrypted)
keys/trusted/*.pub          public keys whose signatures are accepted
anchors/<project_id>.json   last audit-chain head seen per project
```

`airlock init` creates the key on first use and sets the floor. A project's
`integrity.require_signatures` can raise the requirement but never lower the
floor, so editing `airlock.yaml` cannot switch signing off. With
`airlock keys init --passphrase` the key is encrypted; set
`AIRLOCK_KEY_PASSPHRASE` or enter it when prompted. Neither the passphrase nor
`AIRLOCK_HOME` is passed to candidate code during `airlock certify`.

**Audit chain.** Every `logs/audit.jsonl` entry carries `seq`, `prev_hash`,
`entry_hash` and a signature. Editing, inserting, reordering or deleting an
entry breaks the chain; cutting entries off the end is caught by the anchor in
the operator's home, which never moves onto a chain that contradicts it. The
gate and admission refuse to proceed on a broken chain, and gate decisions and
certificates record the chain head they saw. `airlock audit verify` checks it
on demand; after moving a project to a new machine, review the log and run
`airlock audit verify --reanchor`. Pre-v0.4 entries are accepted only as an
unverifiable prefix.

---

## Governance Gate Decisions

| Decision | Meaning | Next Action |
|---|---|---|
| `ALLOW` | All evidence satisfies policy | Run `airlock admit` |
| `DENY` | Blocking failure in evidence | Fix and re-run pipeline |
| `QUARANTINE` | Evidence incomplete | Produce missing evidence |
| `ESCALATE_TO_OPERATOR` | Finding in a human-approval category | `airlock gate <id> --override --operator NAME --reason TEXT` |

Only `ESCALATE_TO_OPERATOR` can be overridden. The override re-runs the gate,
records the operator and reason in the gate decision, the audit log
(`operator_override`) and the admission certificate.

---

## Certification Levels

| Level | Name | Execution Authority |
|---|---|---|
| L0 | Draft | None |
| L1 | Spec-Aligned | Sandbox only |
| L2 | Verified | Controlled test environment |
| L3 | Test-Certified | Limited trusted use |
| L4 | Governance-Admitted | Full trusted execution |
| L5 | Release-Certified | Full + distributable |

---

## Configuration

`airlock init` writes `airlock.yaml`. Every key in it is enforced (a test fails
if one is not), and its hash is recorded in each gate decision. Projects created
before the rename with `cleanroom.yaml` still load.

```yaml
project:
  name: myproject
  language: python
  risk_class: medium

local_first:
  allow_network: false
  allow_remote_llm: false     # true permits a non-loopback Ollama base_url
  allow_telemetry: false      # must be false; Airlock has no telemetry

llm:
  provider: ollama
  model: deepseek-coder-v2:16b
  base_url: http://localhost:11434

verification:
  require_tests: true
  require_type_hints: true
  require_docstrings: false
  allowed_imports: []         # e.g. [asyncio] — explicit stdlib grants

certification:
  test_timeout_seconds: 120
  minimum_line_coverage: 0.70
  minimum_branch_coverage: 0.70

governance:
  require_human_approval_for:
    - credential_access       # ENV_ACCESS findings escalate
    - filesystem_mutation     # FS_SHUTIL_MUTATION findings escalate
```

---

## Requirements

- Python 3.11+
- `pip install -e .` (installs `typer`, `pyyaml`, `cryptography`)
- `pip install pytest-cov pytest-json-report` (for test certifier)
- `pip install -e ".[dashboard]"` (for `airlock dashboard`)
- [Ollama](https://ollama.ai) with `deepseek-coder-v2:16b` (for LLM commands)

---

## Test Suite

**419 tests** across 19 test files covering every pipeline phase, the dashboard, and end-to-end integration.

```
pytest tests/
```

---

## Documentation

| Document | Description |
|---|---|
| [VISION.md](docs/VISION.md) | What this is, why it exists, and who it's for |
| [DOCTRINE.md](docs/DOCTRINE.md) | The eight laws that define the platform |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Component design, data flow, and repository structure |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Known threats and mitigations |
| [CERTIFICATION_LEVELS.md](docs/CERTIFICATION_LEVELS.md) | The L0–L5 artefact trust system |
| [MVP_SCOPE.md](docs/MVP_SCOPE.md) | Build phases, MVP rules, and success criteria |
| [CHANGELOG.md](CHANGELOG.md) | Version history and phase completion notes |

---

## Licence

Copyright 2026 Leon Priest ([7h3v01d](https://github.com/7h3v01d)). Licensed under the [Apache License, Version 2.0](LICENSE).
