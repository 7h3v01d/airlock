# Airlock — Vision

> *Local-first LLM-assisted software engineering with evidence-grade trust boundaries.*

---

## The Problem

The market is filling with AI coding assistants. Every major IDE has one. Every cloud provider is building one. They all share the same fundamental assumption: **the model's output is probably fine.**

That assumption is not engineering. It is optimism.

LLMs generate plausible code faster than humans can verify it. They produce tests that pass without proving correctness. They produce specifications that are easy to satisfy because they were written by the same system that will satisfy them. They quietly introduce dependencies, widen permissions, and weaken boundaries — not maliciously, but because that is what makes the output work.

The result is a codebase where nobody can answer:

- Why does this file exist?
- Which requirement caused it?
- Which model generated or last modified it?
- Which tests actually certify it?
- Which policies did it pass?
- What risks remain unmitigated?
- Who decided to admit it?

**That is not AI-assisted development. That is AI contamination with a productivity veneer.**

---

## The Insight

The problem is not the LLM. LLMs are genuinely useful for drafting, exploring, and generating candidates at speed.

The problem is that **nothing separates what the LLM proposes from what the system trusts.**

Cleanroom Software Engineering — developed by Harlan Mills at IBM — attacked a similar problem in traditional development. It separated idea generation from specification, specification from implementation, implementation from verification, and verification from certification. It treated correctness as something that had to be evidenced, not assumed.

Airlock applies that philosophy to LLM-assisted development:

> **The LLM may propose. The spec constrains. The verifier challenges. The certifier measures. The governance gate decides. The runtime only executes what has been admitted.**

---

## What Airlock Is

Airlock is a **local-first LLM-assisted software engineering platform** that turns ideas into verified, tested, governed, and certifiable software artefacts before they are allowed into trusted execution.

It is not:
- An AI coding assistant
- An agentic developer
- A test generator
- A static analysis wrapper
- A CI/CD plugin

It is all of those things **inside a trust pipeline that none of them individually provides.**

---

## What Makes It Different

Every existing tool treats the LLM as a developer whose output should be reviewed. Airlock treats the LLM as a **candidate generator inside a controlled environment** whose output must earn admission.

| Dimension | Existing Tools | Airlock |
|---|---|---|
| LLM role | Developer / assistant | Candidate generator |
| Trust model | Optimistic (review if you want) | Pessimistic (untrusted until evidenced) |
| Output status | Ready to use | Quarantined until certified |
| Evidence | None / implicit | Explicit, hash-linked, mandatory |
| Spec relationship | Optional documentation | Source of truth, locked before generation |
| Test relationship | Suggested by LLM | Derived from usage model, independently required |
| Admission | Developer discretion | Governance gate with policy |
| Audit trail | None | Full provenance for every admitted artefact |
| Network | Cloud-dependent | Local-first, offline-capable |

---

## The Killer Feature

The killer feature is not *AI writes code*.

The killer feature is **AI-generated software with an evidence chain**.

For every admitted artefact, Airlock can answer:

- Why does this file exist? → Linked to `spec_id`
- What model generated it? → Recorded in `generation_manifest.json`
- What did the verifier find? → Recorded in `static_verification.json`
- What tests certify it? → Recorded in `test_report.json`
- What policies did it pass? → Recorded in `policy_report.json`
- What risks remain? → Recorded in `risk_register.md`
- Who admitted it? → Recorded in `gate_decision.json`
- What is its certification level? → Recorded in `admission_certificate.json`

That evidence chain is what makes Airlock commercially and architecturally defensible — especially in enterprise, regulated, and high-stakes internal tooling contexts.

---

## Who This Is For

**Solo developers and small teams** who want to use local LLMs for real development without surrendering control of their codebase to the model.

**Regulated and high-stakes environments** where every change needs a traceable justification, a test record, and a human decision point.

**Platform builders** who want to extend their systems with AI-generated plugins, adapters, or modules — but need to certify those extensions before loading them into a trusted runtime.

**The author's own projects** — Niles, Librarian Pro, Voice Appliance, FileTracker, and others — all of which need safe plugin/module extension mechanisms that do not compromise the governance spine.

---

## Design Constraints

These constraints are non-negotiable. They define the product.

1. **Local-first.** No source code, prompt, candidate, test result, or audit record leaves the machine unless the operator explicitly authorises it.

2. **Offline-capable.** The pipeline must function completely without network access. Cloud LLM providers may be supported as optional, policy-gated alternatives.

3. **LLM-agnostic.** The platform must not be bound to any single model or provider. Ollama, llama.cpp, LM Studio, and OpenAI-compatible local endpoints are all valid backends.

4. **Pipeline-first.** The cleanroom pipeline must be trustworthy and useful independently of any LLM. The LLM is a productivity layer. The pipeline is the foundation.

5. **Evidence-mandatory.** Admission without evidence is not a valid state. Every admitted artefact must have a complete evidence record or it is not admitted.

6. **Governance-gated.** No candidate enters the trusted tree by developer convenience. Every admission passes through the governance gate.

7. **Human-in-the-loop for high-risk.** High-risk permissions — filesystem deletion, network access, subprocess execution, credential access — require explicit human approval regardless of pipeline results.

---

## The Vision in One Sentence

Airlock is the platform that answers the question nobody else is asking:

> *Not "can the AI write this?" but "can we prove this is safe to trust?"*
