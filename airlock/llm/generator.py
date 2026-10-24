# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock.llm.generator

Orchestrates LLM-assisted spec drafting and candidate generation.

The generator:
1. Calls the LLM with the appropriate prompt contract
2. Parses the structured response into files
3. Registers the candidate in the cleanroom pipeline
4. Writes generation_manifest.json to the evidence store

The LLM output is NEVER trusted directly. All generated artefacts
are quarantined and must pass the full pipeline before admission.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from airlock.llm.provider import LLMProvider
from airlock.llm.prompt_contracts import build_spec_draft_prompt, build_generate_prompt
from airlock.llm.call_logger import log_call, hash_text
from airlock.core.candidate_store import register_candidate
from airlock.core.hashing import hash_text as core_hash_text


# ── Spec drafting ─────────────────────────────────────────────────────────────

def draft_spec(
    intent: str,
    provider: LLMProvider,
    project_root: Path,
    config: dict,
) -> str:
    """
    Use the LLM to draft spec content from a user intent string.
    Returns the draft markdown text. Does NOT lock the spec.
    The operator must review and lock manually.
    """
    language = config.get("project", {}).get("language", "python")
    risk_class = config.get("project", {}).get("risk_class", "medium")
    network_allowed = config.get("local_first", {}).get("allow_network", False)

    system, prompt = build_spec_draft_prompt(
        intent=intent,
        language=language,
        risk_class=risk_class,
        network_allowed=network_allowed,
    )

    with log_call(
        project_root,
        model=provider.profile.model,
        provider=provider.profile.provider_name,
        role="draft_spec",
        prompt=prompt,
    ) as entry:
        response = provider.complete(prompt, system=system, temperature=0.3)
        entry["response_hash"] = hash_text(response)
        entry["token_estimate"] = len(response.split())

    return response


# ── Candidate generation ──────────────────────────────────────────────────────

def generate_candidate(
    spec_id: str,
    module_name: str,
    provider: LLMProvider,
    project_root: Path,
    config: dict,
) -> tuple[str, Path]:
    """
    Use the LLM to generate a candidate from a locked spec.

    Returns (candidate_id, candidate_dir).
    The candidate is quarantined immediately — it has no execution authority.
    """
    specs_dir = project_root / "specs"
    spec_dir = specs_dir / spec_id

    # Load and validate spec
    spec_md = spec_dir / "spec.md"
    spec_meta_path = spec_dir / "spec_meta.json"

    if not spec_md.exists():
        raise GenerationError(f"spec.md not found for {spec_id}")

    spec_meta = json.loads(spec_meta_path.read_text(encoding="utf-8"))
    if spec_meta.get("status") != "LOCKED":
        raise GenerationError(
            f"Spec {spec_id} is not locked. Lock the spec before generating."
        )

    spec_content = spec_md.read_text(encoding="utf-8")
    risk_class = config.get("project", {}).get("risk_class", "medium")

    system, prompt = build_generate_prompt(
        spec_content=spec_content,
        module_name=module_name,
        risk_class=risk_class,
    )

    with log_call(
        project_root,
        model=provider.profile.model,
        provider=provider.profile.provider_name,
        role="generate_candidate",
        prompt=prompt,
    ) as entry:
        response = provider.complete(prompt, system=system, temperature=0.15, max_tokens=6000)
        entry["response_hash"] = hash_text(response)
        entry["token_estimate"] = len(response.split())

    # Parse response into files
    files = _parse_generated_files(response, module_name)
    if not files:
        raise GenerationError(
            "LLM did not produce any parseable file blocks. "
            "Try again or author the candidate manually."
        )

    # Register candidate
    candidates_dir = project_root / "candidates"
    candidate_id, candidate_dir = register_candidate(
        candidates_dir,
        spec_id=spec_id,
        language="python",
        generated_by=f"ollama:{provider.profile.model}",
        description=f"Generated from {spec_id} by {provider.profile.model}",
    )

    # Write files into candidate
    for rel_path, content in files.items():
        dest = candidate_dir / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")

    # Write generation manifest to evidence
    evidence_dir = project_root / "evidence" / candidate_id
    evidence_dir.mkdir(parents=True, exist_ok=True)

    gen_manifest = {
        "candidate_id": candidate_id,
        "spec_id": spec_id,
        "spec_hash": spec_meta.get("spec_hash", ""),
        "model": provider.profile.model,
        "provider": provider.profile.provider_name,
        "role": "generate_candidate",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files_generated": list(files.keys()),
        "prompt_hash": core_hash_text(prompt),
        "response_hash": core_hash_text(response),
    }
    manifest_path = evidence_dir / "generation_manifest.json"
    manifest_path.write_text(json.dumps(gen_manifest, indent=2), encoding="utf-8")

    return candidate_id, candidate_dir


# ── Failure explanation ───────────────────────────────────────────────────────

def explain_failures(
    candidate_id: str,
    failure_type: str,
    failures: list[dict],
    provider: LLMProvider,
    project_root: Path,
) -> str:
    """
    Use the LLM to explain pipeline failures and suggest remediations.
    Returns the explanation text. This is advisory only.
    """
    from airlock.llm.prompt_contracts import build_explain_prompt

    system, prompt = build_explain_prompt(
        candidate_id=candidate_id,
        failure_type=failure_type,
        failures=failures,
    )

    with log_call(
        project_root,
        model=provider.profile.model,
        provider=provider.profile.provider_name,
        role="explain_failure",
        prompt=prompt,
    ) as entry:
        response = provider.complete(prompt, system=system, temperature=0.2)
        entry["response_hash"] = hash_text(response)
        entry["token_estimate"] = len(response.split())

    return response


# ── Response parser ───────────────────────────────────────────────────────────

def _parse_generated_files(response: str, module_name: str) -> dict[str, str]:
    """
    Parse LLM response into {relative_path: content} dict.

    Looks for blocks like:
        ### FILE: src/backup.py
        ```python
        ...code...
        ```
    or just:
        ### FILE: src/backup.py
        ...code until next ### FILE or end...
    """
    files: dict[str, str] = {}

    # Pattern 1: ### FILE: path followed by code block
    pattern = re.compile(
        r"###\s*FILE:\s*([^\n]+)\n+```(?:python)?\n(.*?)```",
        re.DOTALL | re.IGNORECASE,
    )
    matches = pattern.findall(response)

    if matches:
        for rel_path, content in matches:
            rel_path = rel_path.strip()
            content = content.strip()
            if content:
                files[rel_path] = content
        return files

    # Pattern 2: ### FILE: path followed by content until next ### FILE
    pattern2 = re.compile(
        r"###\s*FILE:\s*([^\n]+)\n(.*?)(?=###\s*FILE:|$)",
        re.DOTALL | re.IGNORECASE,
    )
    matches2 = pattern2.findall(response)
    if matches2:
        for rel_path, content in matches2:
            rel_path = rel_path.strip()
            # Strip any markdown code fences
            content = re.sub(r"^```\w*\n?", "", content.strip())
            content = re.sub(r"\n?```$", "", content)
            if content.strip():
                files[rel_path] = content.strip()
        return files

    # Fallback: if we got something that looks like Python, put it in src/
    if "def " in response or "class " in response:
        files[f"src/{module_name}.py"] = response.strip()

    return files


class GenerationError(Exception):
    pass
