# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock.llm.prompt_contracts

Prompt contracts for each LLM role in Airlock.

A prompt contract defines:
  - The role being fulfilled
  - The system instruction (constrains the model's behaviour)
  - The prompt template (structures the user input)
  - Output expectations (what the response must contain)

The LLM may not produce pipeline decisions. Prompt contracts enforce
this by explicitly telling the model what it may and may not do.
"""

from __future__ import annotations


# ── Spec drafting ─────────────────────────────────────────────────────────────

SPEC_DRAFT_SYSTEM = """You are a specification writer assistant inside a software cleanroom pipeline.

Your role is DRAFT_SPEC only. You may:
- Draft functional requirements
- Suggest acceptance criteria
- Identify forbidden behaviours
- Flag risks

You may NOT:
- Approve any code or specification
- Make certification decisions
- Override pipeline rules
- Claim that any output is ready for production

Produce output in clean Markdown using the exact section headers provided.
Be specific and testable. Acceptance criteria must be verifiable by automated tests.
Do not include placeholder text or TODO comments in your output."""


SPEC_DRAFT_TEMPLATE = """Draft a cleanroom specification for the following intent:

INTENT: {intent}

PROJECT CONTEXT:
- Language: {language}
- Risk class: {risk_class}
- Network allowed: {network_allowed}

Produce a specification using EXACTLY these sections:

## Functional requirements

(List each requirement as a numbered item. Be specific.)

## Non-functional requirements

(Performance, reliability, offline constraints, security constraints.)

## Forbidden behaviours

(What the system must never do. Each item must be enforceable.)

## Acceptance criteria

(Numbered list. Each criterion must be testable by an automated test.
Format: "Given X, when Y, then Z.")

Keep each section concise and precise. Do not add extra sections."""


# ── Candidate generation ──────────────────────────────────────────────────────

GENERATE_SYSTEM = """You are a code generation assistant inside a software cleanroom pipeline.

Your role is GENERATE_CANDIDATE only. You may:
- Generate Python source code that satisfies the given specification
- Generate pytest test files for the generated code
- Add type hints and docstrings to all public functions

You may NOT:
- Use subprocess, socket, requests, urllib, or pickle
- Use eval(), exec(), or os.system()
- Use path traversal patterns (..)
- Use dynamic imports (__import__ or importlib.import_module)
- Make any network connections
- Claim your output is correct, certified, or production-ready

CRITICAL RULES:
- Every public function MUST have type hints on all parameters and return type
- Every public function and module MUST have a docstring
- All file operations must stay within declared paths
- No hardcoded credentials or secrets

Generate clean, well-structured Python 3.11+ code."""


GENERATE_TEMPLATE = """Generate a Python implementation for the following specification.

SPECIFICATION:
{spec_content}

REQUIREMENTS:
- Language: Python 3.11+
- All public functions must have type hints
- All public functions and modules must have docstrings
- No subprocess, socket, requests, urllib, pickle
- No eval, exec, os.system
- No path traversal (..)
- Risk class: {risk_class}

Produce TWO files:

### FILE: src/{module_name}.py

(Complete Python source code)

### FILE: tests/test_{module_name}.py

(Complete pytest test file. Import from {module_name}. Cover all public functions.
Use pytest fixtures where appropriate. Test both happy path and error cases.)

Output ONLY the two file blocks above. No explanation, no preamble."""


# ── Failure explanation ───────────────────────────────────────────────────────

EXPLAIN_SYSTEM = """You are a failure analysis assistant inside a software cleanroom pipeline.

Your role is EXPLAIN_FAILURE only. You may:
- Explain what a verifier rule violation means
- Suggest how to fix the violation
- Explain why a test failed
- Suggest remediation steps

You may NOT:
- Override or dismiss any pipeline rule
- Claim that a violation is acceptable
- Suggest bypassing the cleanroom pipeline
- Approve any candidate

Be clear, specific, and constructive. Focus on what the developer needs to do."""


EXPLAIN_TEMPLATE = """Explain the following pipeline failure and suggest a fix.

CANDIDATE: {candidate_id}
FAILURE TYPE: {failure_type}

FAILURES:
{failures}

For each failure:
1. Explain what the rule checks and why it exists
2. Show the exact location in the code (file and line if available)
3. Provide a concrete fix with example code

Be specific. Do not suggest disabling or bypassing the rule."""


# ── Call logger ───────────────────────────────────────────────────────────────

def build_spec_draft_prompt(
    intent: str,
    language: str = "python",
    risk_class: str = "medium",
    network_allowed: bool = False,
) -> tuple[str, str]:
    """Return (system, prompt) for spec drafting."""
    prompt = SPEC_DRAFT_TEMPLATE.format(
        intent=intent,
        language=language,
        risk_class=risk_class,
        network_allowed=str(network_allowed).lower(),
    )
    return SPEC_DRAFT_SYSTEM, prompt


def build_generate_prompt(
    spec_content: str,
    module_name: str,
    risk_class: str = "medium",
) -> tuple[str, str]:
    """Return (system, prompt) for candidate generation."""
    prompt = GENERATE_TEMPLATE.format(
        spec_content=spec_content,
        module_name=module_name,
        risk_class=risk_class,
    )
    return GENERATE_SYSTEM, prompt


def build_explain_prompt(
    candidate_id: str,
    failure_type: str,
    failures: list[dict],
) -> tuple[str, str]:
    """Return (system, prompt) for failure explanation."""
    failures_text = "\n".join(
        f"- [{f.get('rule_id', 'unknown')}] {f.get('file', '')}:{f.get('line', '')} — {f.get('detail', '')}"
        for f in failures
    )
    prompt = EXPLAIN_TEMPLATE.format(
        candidate_id=candidate_id,
        failure_type=failure_type,
        failures=failures_text or "No detailed failure information available.",
    )
    return EXPLAIN_SYSTEM, prompt
