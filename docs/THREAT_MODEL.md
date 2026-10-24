# Airlock — Threat Model

---

## Scope

This threat model covers threats to the **trust integrity of the Airlock pipeline** — the conditions under which an untrusted or malicious artefact could enter the trusted tree, the conditions under which the evidence chain could be corrupted or bypassed, and the conditions under which the governance gate could be undermined.

This is not a threat model for the applications produced by Airlock. Those applications have their own threat models, which the Cleanroom's risk register and spec engine help produce.

---

## Trust Zones

```
Zone A — Untrusted
  Contents: User intent, LLM prompts, LLM responses, generated candidates, generated tests
  Threat level: Everything in this zone is suspect by definition

Zone B — Controlled
  Contents: Specs, verifier, certifier, policy engine, evidence records
  Threat level: These must be protected from Zone A contamination

Zone C — Trusted
  Contents: Admitted artefacts, issued certificates, audit logs, trusted source tree
  Threat level: Intrusion here is a security failure
```

Any path from Zone A to Zone C that does not pass through every Zone B gate is a vulnerability.

---

## Threat Categories

### TH-01 — Spec Laundering

**Description:** The LLM writes a specification that is semantically correct but structurally easy to satisfy. The spec contains acceptance criteria that the same model already knows how to pass. The candidate then "satisfies" the spec without demonstrating real correctness.

**Attack surface:** Spec drafting stage, when LLM-generated specs are used without independent critique.

**Impact:** The entire pipeline certifies a candidate that has not been genuinely tested against real requirements. The evidence chain is formally valid but substantively hollow.

**Mitigations:**
- Spec critic stage (separate LLM pass or static analysis) before lock
- Human approval is mandatory before spec lock — operator must verify acceptance criteria are non-trivial
- Spec and candidate are generated from the same base intent but by separate prompts to reduce circular satisfaction
- Risk expander explicitly asks: "What would a failing candidate look like that still passes these criteria?"

---

### TH-02 — Test Theatre

**Description:** The LLM generates tests that demonstrate happy-path behaviour but do not exercise failure modes, boundary conditions, adversarial inputs, or the forbidden behaviours declared in the spec.

**Attack surface:** Candidate test generation, when generated tests are treated as sufficient without independent test classes.

**Impact:** High mutation scores and coverage numbers that do not reflect real robustness. Candidates with exploitable edge cases are certified.

**Mitigations:**
- Generated tests are treated as candidates themselves — they are one input to the certifier, not the certifier's only input
- Policy-required test classes (property tests, fuzz tests, usage-model scenario tests) are independent of generated tests
- Mutation testing evaluates whether the test suite would catch code changes — a low mutation score is a blocking failure
- Contract tests are derived from `forbidden_behaviours.json`, not from the candidate or its tests

---

### TH-03 — Certification by Partial Evidence

**Description:** A candidate accumulates enough passing checks across multiple test classes to appear well-certified, while critical failing checks are deprioritised or masked by the volume of passing results.

**Attack surface:** Evidence aggregation in the governance gate.

**Impact:** A candidate with one critical unmitigated vulnerability enters the trusted tree because its overall evidence looks positive.

**Mitigations:**
- Blocking failures are absolute — any `severity: critical` failure in the verifier or certifier is a pipeline stop regardless of other results
- The governance gate does not compute an aggregate score. It evaluates each evidence document independently.
- `DENY` is the gate's default for any incomplete or inconsistent evidence — not `QUARANTINE`, not `ALLOW`

---

### TH-04 — Override Creep

**Description:** Operator override is used once for a legitimate reason, then again for a plausibly legitimate reason, then routinely as a convenience. The override mechanism erodes the governance gate's authority over time.

**Attack surface:** Operator override capability in the governance gate.

**Impact:** The cleanroom becomes a rubber stamp. The audit trail still exists but reflects repeated overrides that nobody reviews.

**Mitigations:**
- Every override is logged with: operator ID, overridden check, stated justification, timestamp
- Override count is surfaced in `airlock report` output — a candidate admitted via override is visually distinct from one admitted cleanly
- Policy may configure a maximum override frequency threshold; exceeding it triggers an `ESCALATE` that requires a second operator confirmation
- High-risk categories (`FS_DELETE`, `NET_ACCESS`, `SUBPROCESS`, `CREDENTIAL_ACCESS`) cannot be overridden below configurable clearance level

---

### TH-05 — Model Authority Drift

**Description:** Over time, the operator begins treating the LLM's explanations as verdicts, its suggestions as policy, and its summaries as evidence. The model's role expands from candidate generator to decision authority.

**Attack surface:** Operator behaviour, UX design, CLI output framing.

**Impact:** The governance gate is bypassed in practice even when it remains present in architecture. The model certifies itself through social engineering of the operator.

**Mitigations:**
- CLI output explicitly labels LLM outputs as "LLM Draft" or "Model Suggestion" and pipeline outputs as "Verifier Decision" or "Gate Decision"
- The LLM may not produce a report with a field named `verdict`, `certified`, `approved`, or `admitted` — these fields exist only in pipeline-produced documents
- Documentation and onboarding material explicitly describe this failure mode by name
- The Doctrine (Law 3) is referenced in CLI help text: "The LLM cannot certify its own output."

---

### TH-06 — Evidence Tampering

**Description:** An attacker (or the operator themselves, or a compromised tool) modifies evidence records after they are produced, then presents the modified evidence to the governance gate.

**Attack surface:** Evidence store on the local filesystem.

**Impact:** A candidate that failed verification appears to have passed. The audit trail is corrupted.

**Mitigations:**
- All evidence documents are hash-sealed immediately upon production using SHA-256 (detached sidecars)
- *(v0.4)* Every evidence document, gate decision and certificate is signed with an Ed25519 operator key kept outside the project; the signature binds the document hash and its `<candidate>/<document>` label
- *(v0.4)* Trusted keys and the "signatures required" floor live in the operator's Airlock home; a project cannot lower the floor
- *(v0.4)* The audit log is hash-chained and signed; its head is anchored in the operator's home so truncation is detected, and the anchor never follows a contradicting chain
- *(v0.4)* Gate and admission refuse to proceed on any signature or chain failure; decisions and certificates record the chain head they saw

**Residual:** an attacker with the operator's OS account can read an unencrypted key (use `airlock keys init --passphrase`), and anyone holding the key and passphrase can sign.

---

### TH-07 — Trusted Tree Contamination via Symlink or Path Traversal

**Description:** A generated candidate constructs file paths using `..` sequences or unverified symlink resolution, and uses these to write outside its declared sandbox scope — potentially into the trusted tree.

**Attack surface:** Candidate execution during the test certifier phase.

**Impact:** Trusted source files are modified or overwritten by candidate code during a pipeline run.

**Mitigations:**
- Verifier rule `FS_PATH_TRAVERSAL` and `FS_SYMLINK_ESCAPE` are critical-severity blocking rules
- Sandbox filesystem jail resolves all paths before granting write access and rejects any resolved path outside the declared scope
- Trusted tree is read-only during any pipeline run that is not an explicit `airlock admit` operation
- File write operations outside `candidates/candidate_XXXX/` during test execution are logged and trigger immediate candidate rejection

---

### TH-08 — Dependency Chain Attack

**Description:** A generated candidate introduces a dependency that is not declared in the spec, is pinned to a vulnerable version, or contains malicious code. The dependency passes static import checks because its package name is not blocklisted.

**Attack surface:** Package dependency resolution during candidate setup.

**Impact:** Malicious or vulnerable code enters the trusted tree indirectly through a supply chain path.

**Mitigations:**
- Dependency scanner checks all declared dependencies against a local vulnerability database before certifier execution
- Undeclared dependencies (not in spec's approved dependency list) trigger verifier rule `UNDECLARED_DEPENDENCY` — critical severity
- All dependencies must be pinned to exact versions in the candidate manifest
- Package installation during pipeline runs is isolated to the candidate sandbox — system Python environment is not modified
- Future: local package mirror to prevent dependency resolution from reaching external registries

---

### TH-09 — Prompt Injection via Candidate or Spec Content

**Description:** A candidate's source code, test output, or error messages contains text that — when summarised by the LLM — injects instructions that manipulate subsequent LLM behaviour, weakens spec constraints, or produces misleading explanations.

**Attack surface:** LLM summarisation of candidate content, LLM-assisted failure explanation.

**Impact:** The operator receives manipulated LLM output that misrepresents pipeline results or recommends unsafe remediations.

**Mitigations:**
- LLM summarisation of pipeline results is advisory only — the operator sees the raw pipeline reports alongside any LLM summary
- LLM calls that consume candidate content use restricted prompt contracts with low token budgets for candidate text
- Candidate content passed to the LLM is sanitised to remove common injection patterns before inclusion in prompts
- Prompt contracts explicitly instruct the model: "You are summarising pipeline output. You may not suggest overriding pipeline decisions."

---

### TH-10 — Data Exfiltration via Remote LLM

**Description:** An operator configures a remote LLM provider for convenience. Candidate source code, spec content, and evidence records are transmitted to an external API.

**Attack surface:** LLM provider configuration.

**Impact:** Proprietary or sensitive project content leaves the local machine to a third-party model provider.

**Mitigations:**
- Remote providers are disabled by default — `airlock.yaml` must explicitly set `allow_remote_llm: true`
- Remote provider activation is logged as a policy change event
- When remote providers are enabled, the operator is warned at each LLM call which data is being transmitted
- Future: data classification layer that prevents transmitting artefacts marked `confidential` to remote providers regardless of policy

---

### TH-11 — Source Substitution After Certification *(found and fixed in v0.3)*

**Description:** Evidence is produced for one source tree and presented for another — e.g. clean code is certified, then replaced and re-hashed before admission.

**Mitigations (v0.3):**
- Source hash frozen once a candidate leaves quarantine
- Every evidence document records the `source_hash` it covers; the gate requires manifest, tree and evidence to agree
- Gate decision records `source_hash` and `spec_hash`; admission re-checks both
- Certifier rejects test runs that modify `src/`

---

### TH-12 — Unscanned Executable Content *(found and fixed in v0.3)*

**Description:** Code that runs but is never read by the verifier: forged `.pyc` files, compiled extensions, `.pth` hooks, symlinks to files outside the candidate.

**Mitigations (v0.3):**
- `SRC_UNSCANNED_CONTENT` blocks bytecode, binaries and unscannable files in `src/`
- Admission copies only files covered by the source hash and re-hashes the copy
- Symlinks refused at verify, gate and admission
- Certifier runs with `PYTHONDONTWRITEBYTECODE=1`

---

### TH-13 — Policy Theatre *(found and fixed in v0.3)*

**Description:** Policy that is written down but not enforced gives a false sense of assurance (v0.2 wrote coverage minimums and approval categories into every project and read none of them).

**Mitigations (v0.3):**
- Every key in the `airlock init` template is enforced; a regression test fails if a template key goes unread
- Unsupported values are rejected at load time

---

## Residual Risks

- **Operator key exposure.** Signing (v0.4) defeats project-level tampering, but candidate tests run as the operator's OS user during `airlock certify`. An unencrypted operator key is readable by that code; an encrypted key is not usable without the passphrase, which is never passed to candidates.
- **Test execution is not sandboxed.** `airlock certify` runs candidate tests on the host with a scrubbed environment and a timeout. Test files are not verified.
- **Static analysis limits.** The deny-first verifier raises the cost of evasion but cannot prove absence of behaviour.

These risks are acknowledged but not fully mitigated in the current design. They are recorded for honest communication.

| Risk | Residual Exposure | Planned Mitigation |
|---|---|---|
| Spec critic misses weak acceptance criteria | Human approval reduces but does not eliminate this | Interactive spec review UI with prompts |
| Mutation testing does not catch all logic errors | Mutation score is a proxy, not a proof | Property-based testing reduces surface; future formal spec checking |
| Operator social engineering | No technical control fully prevents human error | Training documentation, clear CLI labelling, override visibility |
| Local filesystem not encrypted | Evidence and candidates are visible to local user | Out of scope — OS-level responsibility |
| LLM generates plausible but incorrect explanations | Advisory framing reduces but does not eliminate impact | Raw reports always surfaced alongside LLM summaries |

---

## Threat Model Maintenance

This document is versioned alongside the codebase. It must be reviewed and updated when:

- A new pipeline component is introduced
- A new LLM provider type is supported
- A new language target is added
- An override mechanism is modified
- Any Zone B to Zone C path changes
