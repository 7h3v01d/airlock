# Airlock — Component Architecture

---

## Structural Overview

Airlock is a **pipeline platform**, not a single application. Every major component has a defined role, defined inputs, defined outputs, and defined authority. No component may exceed its authority. No component may bypass a downstream gate.

```
User Intent
    │
    ▼
┌─────────────────────────────┐
│   LLM Workbench             │  Drafts specs, generates candidates,
│   (untrusted zone)          │  explains failures — no admission authority
└─────────────┬───────────────┘
              │  candidate package
              ▼
┌─────────────────────────────┐
│   Spec Engine               │  Formalises intent into locked spec,
│   (controlled zone)         │  contracts, risk register, usage model
└─────────────┬───────────────┘
              │  locked spec + candidate
              ▼
┌─────────────────────────────┐
│   Candidate Sandbox         │  Quarantines all generated artefacts,
│   (controlled zone)         │  prevents trusted tree contamination
└─────────────┬───────────────┘
              │  sandboxed candidate
              ▼
┌─────────────────────────────┐
│   Verifier                  │  Static analysis, AST scanning,
│   (controlled zone)         │  policy rules, import checks — PASS/FAIL
└─────────────┬───────────────┘
              │  verification report
              ▼
┌─────────────────────────────┐
│   Test Certifier            │  Runs test matrix, measures coverage,
│   (controlled zone)         │  produces evidence-grade report
└─────────────┬───────────────┘
              │  certification report
              ▼
┌─────────────────────────────┐
│   Governance Gate           │  Consumes all reports, applies policy,
│   (trusted zone)            │  decides ALLOW / DENY / QUARANTINE
└─────────────┬───────────────┘
              │  gate decision + certificate
              ▼
┌─────────────────────────────┐
│   Trusted Tree              │  Admitted artefacts only,
│   (trusted zone)            │  each with full evidence linkage
└─────────────────────────────┘
```

---

## Component 1 — LLM Workbench

**Role:** Candidate generator and operator assistant. No trust authority.

**Inputs:** User intent, project context, existing specs, verifier failure reports.

**Outputs:** Draft specs, candidate implementations, candidate tests, remediation suggestions, report summaries.

**Authority:** None. All output is quarantined by default.

### LLM Provider Interface

The Workbench must not be bound to any single model. Every model is registered through a provider interface:

```python
class LLMProvider:
    name: str
    model_id: str
    capabilities: list[str]        # ["code", "reasoning", "summarisation"]
    context_window: int
    local: bool
    network_access: bool
    allowed_roles: list[str]       # ["draft_spec", "generate_candidate", "explain_failure"]
    forbidden_roles: list[str]     # ["certify", "approve", "execute"]
```

Supported backends (Phase 1+):
- `OllamaProvider` — local Ollama instance
- `LlamaCppProvider` — local llama.cpp server
- `OpenAICompatibleLocalProvider` — any OpenAI-compatible local endpoint

**Critical rule:** `forbidden_roles` is enforced by the platform. No provider may be configured with `certify`, `approve`, or `execute` in `allowed_roles`. These roles do not exist in the provider API surface.

### Prompt Contracts

Every LLM call is governed by a prompt contract:

```python
class PromptContract:
    role: str                      # "draft_spec" | "generate_candidate" | "explain_failure"
    input_schema: dict             # What the prompt receives
    output_schema: dict            # What the response must contain
    max_tokens: int
    temperature: float
    require_structured_output: bool
    log_call: bool                 # Always true in cleanroom context
```

All LLM calls are logged. Log entries include: timestamp, model, role, prompt hash, response hash, token count, latency. Prompt and response content is stored locally. Nothing is sent externally.

---

## Component 2 — Spec Engine

**Role:** Converts user intent into a formal, locked specification that serves as the pipeline's source of truth.

**Inputs:** User intent (natural language), project policy (`airlock.yaml`), optional LLM draft.

**Outputs:** `spec.md`, `contracts.json`, `acceptance_criteria.json`, `forbidden_behaviours.json`, `risk_register.md`, `usage_model.json`, `security_policy.json`.

**Authority:** Defines what the candidate must satisfy. Once locked, the spec cannot be modified without re-opening, re-reviewing, and re-locking — which invalidates all downstream candidates.

### Spec Lifecycle

```
Draft → Spec Critic Review → Risk Expansion → Human Approval → Locked
```

**Draft:** LLM-assisted or manually authored. Status: `draft`. Cannot be used as pipeline input.

**Spec Critic Review:** A second LLM pass (or static checker) that interrogates the draft for:
- Acceptance criteria that are too easy to satisfy
- Missing forbidden behaviour clauses
- Under-specified failure modes
- Circular requirements (spec satisfied by the LLM that wrote it)

**Risk Expansion:** The risk register is populated with identified threat scenarios, edge cases, and high-risk permission categories.

**Human Approval:** Operator reviews and approves the spec. This step is mandatory. The LLM may not approve a spec.

**Locked:** Spec is hash-sealed. `spec_hash` is recorded in all downstream evidence. Any modification to a locked spec produces a new spec version and invalidates all candidates derived from the previous version.

### Spec Artefact Structure

```
specs/
  spec_0001/
    spec.md                    # Human-readable specification
    contracts.json             # Machine-readable contract clauses
    acceptance_criteria.json   # Testable acceptance conditions
    forbidden_behaviours.json  # Hard prohibitions
    risk_register.md           # Known risks and mitigations
    usage_model.json           # Scenario frequency weights
    security_policy.json       # Security constraints
    spec_meta.json             # {id, version, status, hash, approved_by, locked_at}
```

---

## Component 3 — Candidate Sandbox

**Role:** Quarantine zone for all generated artefacts. Prevents any candidate from reaching the trusted tree or executing outside a controlled environment.

**Inputs:** Generated code, generated tests, generation metadata.

**Outputs:** Quarantined candidate package with manifest, available for verifier input.

**Authority:** None over the trusted tree. Can execute code only in an isolated sandbox environment with defined resource and filesystem limits.

### Candidate Directory Structure

```
candidates/
  candidate_0001/
    src/                       # Generated source files
    tests/                     # Generated test files
    generated_by.json          # {model, provider, timestamp, prompt_hash}
    manifest.json              # {files, hashes, spec_id, language, dependencies}
    status.json                # {status: "quarantined" | "verified" | "certified" | "admitted" | "rejected"}
```

### Candidate Status FSM

```
quarantined → [verifier] → verified → [certifier] → certified → [gate] → admitted
                               │                         │
                               └──────── rejected ←──────┘
                                   (can be revised and resubmitted)
```

A rejected candidate may be revised and resubmitted as a new candidate version. It may not be admitted in its rejected state regardless of operator action.

### Filesystem Jail

The sandbox enforces these restrictions during candidate execution:

- Write access: `candidates/candidate_XXXX/` only
- Read access: `candidates/candidate_XXXX/` + declared test fixtures
- Network access: disabled by default (policy-configurable)
- Subprocess creation: disabled by default (policy-configurable)
- Environment variable access: disabled by default
- Execution time limit: configurable per risk class

---

## Component 4 — Verifier

**Role:** Static analysis gate. Determines whether a candidate violates rules before it is executed.

**Inputs:** Candidate package, locked spec, `airlock.yaml` policy, verifier rule set.

**Outputs:** `static_verification.json` — structured report with per-rule verdicts, severity levels, and blocking flags.

**Authority:** Absolute within its rule set. A critical rule failure is a pipeline stop. The verifier does not advise — it decides PASS or FAIL per rule.

### Verifier Rule Categories

**Import Policy Rules** — Check for disallowed imports relative to spec grants:
- `IMPORT_SUBPROCESS` — subprocess not granted
- `IMPORT_SOCKET` — network access not granted
- `IMPORT_REQUESTS` — network access not granted
- `IMPORT_URLLIB` — network access not granted
- `IMPORT_PICKLE` — unsafe deserialisation
- `IMPORT_CTYPES` — unsafe native access

**Execution Policy Rules:**
- `CALL_EVAL` — eval usage blocked
- `CALL_EXEC` — exec usage blocked
- `CALL_OS_SYSTEM` — OS shell execution blocked
- `DYNAMIC_IMPORT` — `__import__()` or `importlib` usage requires review

**Filesystem Rules:**
- `FS_WRITE_OUTSIDE_SCOPE` — writes outside declared filesystem scope
- `FS_PATH_TRAVERSAL` — `..` in path construction
- `FS_SYMLINK_ESCAPE` — symlink resolution not verified against root
- `FS_DELETE_UNGATED` — file deletion without explicit grant

**Structural Rules:**
- `MISSING_TYPE_HINTS` — type hints required by policy
- `MISSING_DOCSTRINGS` — docstrings required by policy
- `MISSING_TESTS` — no test files present
- `MISSING_SPEC_LINK` — candidate manifest does not reference a locked spec

**Dependency Rules:**
- `UNDECLARED_DEPENDENCY` — import not in declared dependency list
- `KNOWN_VULNERABLE_PACKAGE` — dependency flagged in local vulnerability database
- `PINNED_VERSION_MISSING` — dependency not pinned to exact version

### Verifier Report Schema

```json
{
  "candidate_id": "candidate_0001",
  "spec_id": "spec_0001",
  "verifier_version": "0.1.0",
  "timestamp": "2026-05-23T10:00:00+10:00",
  "verdict": "FAIL",
  "rules_evaluated": 24,
  "rules_passed": 22,
  "rules_failed": 2,
  "blocking_failures": 1,
  "results": [
    {
      "rule_id": "IMPORT_SUBPROCESS",
      "severity": "critical",
      "blocking": true,
      "file": "src/backup.py",
      "line": 4,
      "detail": "subprocess imported but not granted in spec security_policy.json"
    }
  ]
}
```

---

## Component 5 — Test Certifier

**Role:** Evidence producer. Runs the required test matrix for a candidate's risk class and produces a certification report. Not a test runner — a certifier.

**Inputs:** Verified candidate, locked spec (`acceptance_criteria.json`, `usage_model.json`), policy-required test classes.

**Outputs:** `test_report.json`, `coverage_report.json`, `mutation_report.json`, `contract_test_report.json`.

**Authority:** Determines whether a candidate reaches certification tier. A candidate that fails required test classes does not advance regardless of other results.

### Test Classes

| Class | Required For | Tool (Python) |
|---|---|---|
| Unit tests | All risk classes | pytest |
| Contract tests | Medium+ risk | pytest + custom fixtures |
| Property tests | Medium+ risk | hypothesis |
| Mutation tests | High risk | mutmut |
| Fuzz tests | High risk | atheris / custom |
| Regression tests | All (if history exists) | pytest |
| Security behaviour tests | High risk | custom scenarios |
| Usage-model scenario tests | All risk classes | derived from `usage_model.json` |

### Certification Report Schema

```json
{
  "candidate_id": "candidate_0001",
  "spec_id": "spec_0001",
  "risk_class": "medium",
  "certifier_version": "0.1.0",
  "timestamp": "2026-05-23T10:30:00+10:00",
  "certification": "CERTIFIED",
  "unit_tests": {"passed": 44, "failed": 0, "skipped": 0},
  "contract_tests": {"passed": 12, "failed": 0},
  "property_tests": {"passed": 200, "failed": 0, "examples": 200},
  "mutation_score": 0.83,
  "branch_coverage": 0.91,
  "usage_scenario_results": [
    {"scenario": "small_project_backup", "passed": true},
    {"scenario": "symlink_escape_attempt", "passed": true}
  ],
  "blocking_failures": [],
  "certification_level": "L3_TEST_CERTIFIED"
}
```

---

## Component 6 — Governance Gate

**Role:** Final authority. Consumes all pipeline evidence and produces a binding admission decision.

**Inputs:** Spec metadata, verification report, certification report, dependency report, risk register, policy configuration, operator approval (for high-risk categories).

**Outputs:** `gate_decision.json`, `admission_certificate.json` (on ALLOW), audit log entry.

**Authority:** Absolute. The gate decision is final for the current pipeline run. It cannot be silently overridden.

### Gate Decisions

| Decision | Meaning | Next Action |
|---|---|---|
| `ALLOW` | All evidence satisfies policy. Candidate admitted. | Generate certificate, copy to trusted tree. |
| `DENY` | One or more blocking failures. Candidate rejected. | Candidate remains quarantined. Remediation required. |
| `QUARANTINE` | Evidence incomplete. Cannot decide. | Identify and resolve missing evidence. |
| `ESCALATE_TO_OPERATOR` | High-risk permission detected. Human decision required. | Operator reviews evidence and makes explicit decision. |

### Gate Decision Schema

```json
{
  "gate_id": "gate_2026_000012",
  "candidate_id": "candidate_0001",
  "spec_id": "spec_0001",
  "timestamp": "2026-05-23T10:45:00+10:00",
  "decision": "ALLOW",
  "evidence_consumed": [
    "static_verification.json",
    "test_report.json",
    "contract_test_report.json",
    "dependency_report.json"
  ],
  "policy_version": "airlock.yaml:sha256:abc123",
  "operator_approval": null,
  "override": null
}
```

### Admission Certificate Schema

```json
{
  "certificate_id": "al-cert-2026-000001",
  "project": "local_backup_tool",
  "candidate_id": "candidate_0001",
  "spec_id": "spec_0001",
  "level": "L3_TEST_CERTIFIED",
  "admitted": true,
  "admitted_at": "2026-05-23T10:45:00+10:00",
  "admitted_by": "governance_gate_v0.1",
  "operator_id": "operator_local",
  "hashes": {
    "source_tree": "sha256:...",
    "spec": "sha256:...",
    "test_report": "sha256:...",
    "gate_decision": "sha256:..."
  }
}
```

---

## Repository Structure

```
airlock/
  core/
    spec_engine/
      parser.py
      critic.py
      risk_expander.py
      locker.py
    verifier/
      runner.py
      rules/
        import_rules.py
        filesystem_rules.py
        execution_rules.py
        structural_rules.py
        dependency_rules.py
    certifier/
      runner.py
      test_matrix.py
      coverage_collector.py
      mutation_runner.py
      report_builder.py
    governance/
      gate.py
      policy_engine.py
      certificate_builder.py
      audit_log.py
    evidence/
      store.py
      hasher.py
      validator.py
    policy/
      loader.py
      schema.py

  llm/
    providers/
      ollama_provider.py
      llama_cpp_provider.py
      openai_compatible_local_provider.py
    capability_registry.py
    prompt_contracts.py
    call_logger.py

  sandbox/
    candidate_store.py
    runner.py
    filesystem_jail.py
    process_policy.py

  languages/
    python/
      ast_scanner.py
      import_policy.py
      pytest_certifier.py
      package_analyzer.py

  cli/
    main.py
    commands/
      init.py
      spec.py
      generate.py
      verify.py
      certify.py
      gate.py
      admit.py
      report.py

  cleanroom_project_template/
    airlock.yaml
    policies/
    specs/
    candidates/
    evidence/
    trusted/

  tests/
    unit/
    integration/
    pipeline/

  docs/
    VISION.md
    DOCTRINE.md
    ARCHITECTURE.md
    THREAT_MODEL.md
    CERTIFICATION_LEVELS.md
    MVP_SCOPE.md
```

---

## Data Flow Summary

```
airlock spec new "Build a local file backup CLI"
    └── LLM drafts spec
    └── Spec critic reviews
    └── Operator approves
    └── Spec locked → specs/spec_0001/

airlock generate --spec spec_0001
    └── LLM generates candidate code + tests
    └── Candidate quarantined → candidates/candidate_0001/

airlock verify candidate_0001
    └── Verifier runs rule set against candidate
    └── Report → evidence/candidate_0001/static_verification.json

airlock certify candidate_0001
    └── Test matrix executed in sandbox
    └── Reports → evidence/candidate_0001/test_report.json

airlock gate candidate_0001
    └── Gate consumes all evidence
    └── Decision → evidence/candidate_0001/gate_decision.json

airlock admit candidate_0001
    └── Certificate issued
    └── Source copied to trusted/src/
    └── Evidence archived
```
