# Airlock — Doctrine

> *These principles are not guidelines. They are the definition of what Airlock is.*

---

## The Eight Laws

### Law 1 — Generated code is untrusted by default

Any code produced by a language model — regardless of which model, which prompt, or how plausible the output appears — begins in a quarantined state. It has no execution authority. It cannot modify the trusted tree. It cannot be imported by the trusted runtime. It is material for inspection, not for use.

This law has no exceptions. A model that claims its own output is safe is not a verifier. It is a candidate generator describing its own candidate.

---

### Law 2 — The specification is the source of truth

The specification exists before the candidate. It defines what the candidate must do, what it must not do, and what constitutes acceptable behaviour. The candidate is judged against the spec. The spec is never revised to match the candidate.

If the spec is wrong, revise the spec — then regenerate the candidate. Do not silently weaken the spec to make a failing candidate pass.

---

### Law 3 — The LLM cannot certify its own output

The model may draft specs, generate candidates, suggest tests, explain failures, and propose remediations. It may not approve candidates. It may not mark tests as passed. It may not alter evidence records. It may not override policy. It may not decide certification status.

These decisions belong to the pipeline, not the model. A model that generates code and then declares it correct is not a cleanroom — it is a single point of failure wearing two hats.

---

### Law 4 — No candidate enters trusted execution without evidence

Admission requires evidence. The evidence must exist before the decision. The decision must be recorded alongside the evidence. There is no fast-path, no override-for-convenience, and no "just this once."

An admitted artefact with missing evidence is not an admitted artefact. It is an intrusion.

---

### Law 5 — Every admitted artefact is traceable

For every file in the trusted tree, the platform must be able to answer:

- Which spec required it?
- Which candidate produced it?
- Which model generated it, and when?
- Which verifier rules did it pass?
- Which tests certify it?
- Which policies governed it?
- Who or what admitted it?
- What is its current certification level?

If the platform cannot answer these questions, the artefact is not cleanroom-admitted. It is present without provenance.

---

### Law 6 — A failed check is not a suggestion

When the verifier finds a violation, the candidate is rejected. When a contract test fails, the candidate does not advance. When a policy rule triggers, the governance gate receives a denial signal. These outcomes are not advisory warnings to be reviewed and overridden at discretion.

Failed checks are pipeline decisions. They may be appealed only through formal remediation: fix the candidate, re-run the pipeline, produce new evidence, and re-submit to the gate.

---

### Law 7 — Human override is policy-bound and logged

Operator override exists. It is sometimes necessary. But it is never invisible.

Every override must state: who invoked it, which check was overridden, what justification was provided, and when it occurred. This record is immutable and part of the artefact's evidence chain.

Certain high-risk categories — filesystem deletion, network access, subprocess execution, credential handling — may not be overridden below a defined operator clearance level. These categories are declared in `airlock.yaml` and enforced by the governance gate.

---

### Law 8 — Local-first means nothing leaves without authorisation

No source code, prompt text, generated candidate, test result, evidence record, audit log, or certification status leaves the local machine without an explicit, policy-governed, operator-authorised action.

Remote LLM providers, telemetry services, cloud sync, and external APIs are disabled by default. Enabling any of them is a deliberate policy decision that is recorded, scoped, and revocable.

---

## Role Boundaries

The doctrine requires explicit role separation. These boundaries are enforced by the platform, not by convention.

### The Local LLM — What It May Do

- Draft specifications from user intent
- Suggest acceptance criteria
- Generate candidate implementations
- Generate candidate test suites
- Explain verifier failures in human-readable terms
- Suggest remediations for failing candidates
- Summarise certification reports
- Propose risk register entries

### The Local LLM — What It May Not Do

- Approve candidates for admission
- Mark tests as passed or skipped
- Alter evidence logs or reports
- Modify the trusted source tree directly
- Override policy rules
- Decide certification status
- Silently revise a locked spec
- Remove required tests to make a candidate pass

### The Pipeline — What It Decides

- Whether a candidate passes static verification
- Whether a candidate satisfies contract tests
- Whether a candidate meets the required certification tier for its risk class
- Whether a candidate's evidence is complete
- Whether the governance gate admits, denies, quarantines, or escalates

### The Operator — What They Control

- Defining and locking specifications
- Setting policy in `airlock.yaml`
- Approving high-risk categories
- Invoking and logging overrides
- Authorising external data transfer
- Promoting artefacts to Release-Certified status

---

## The Trust Hierarchy

```
Operator (highest authority)
  ↓
Governance Gate (policy executor)
  ↓
Test Certifier (evidence producer)
  ↓
Verifier (rule enforcer)
  ↓
Spec Engine (truth definer)
  ↓
Local LLM (candidate generator — no authority over the above)
```

The LLM sits at the bottom of this hierarchy. Its position is not an insult — it is the correct engineering design. A powerful tool with no authority over the trust decisions that govern its output is a safe tool.

---

## What the Doctrine Prevents

These are the failure modes the doctrine is explicitly designed to block.

**Spec laundering** — The LLM writes a spec that is easy to satisfy, then satisfies it. The spec becomes a rubber stamp rather than a constraint. Prevention: spec critic stage, human approval before lock, hash-tracked spec identity.

**Test theatre** — The LLM generates tests that demonstrate the happy path but do not exercise failure modes, edge cases, or adversarial inputs. Generated tests are treated as candidates themselves and must pass independent review.

**Certification by exhaustion** — A candidate accumulates enough passing checks to seem certified, while critical failing checks are quietly deprioritised. Prevention: blocking failures are absolute; no candidate advances past a critical failure regardless of other passing results.

**Override creep** — Operators invoke override once for legitimate reasons, then again for convenience, then routinely. Prevention: every override is logged, visible in reports, and triggers a policy review flag after a configurable threshold.

**Model authority drift** — Over time, the LLM's suggestions are treated as decisions, its explanations as verdicts, and its recommendations as policy. Prevention: role boundaries are enforced architecturally, not culturally.

---

## The Doctrine in Practice

When building with Airlock, every decision should be testable against these two questions:

> *Is this the LLM deciding, or the pipeline deciding?*

> *If this artefact fails tomorrow, can I produce evidence of why it was admitted today?*

If the answer to the first question is "the LLM," stop and redesign. If the answer to the second question is "no," the artefact is not admitted.
