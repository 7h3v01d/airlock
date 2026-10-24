# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock.llm.call_logger

Records every LLM call to logs/llm_calls.jsonl.

Every call is logged with:
  - timestamp
  - model and provider
  - role fulfilled
  - prompt hash (not the prompt itself, for privacy)
  - response hash
  - token estimate
  - latency

Raw prompts and responses are NOT logged by default — only hashes.
This preserves local-first privacy while maintaining auditability.
"""

from __future__ import annotations

import hashlib
import json
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator


def hash_text(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]}..."


@contextmanager
def log_call(
    project_root: Path,
    model: str,
    provider: str,
    role: str,
    prompt: str,
) -> Generator[dict, None, None]:
    """
    Context manager that times an LLM call and logs the result.

    Usage:
        with log_call(root, model, provider, role, prompt) as entry:
            response = provider.complete(prompt)
            entry["response_hash"] = hash_text(response)
            entry["token_estimate"] = len(response.split())
    """
    entry: dict = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "provider": provider,
        "role": role,
        "prompt_hash": hash_text(prompt),
        "response_hash": "",
        "token_estimate": 0,
        "latency_ms": 0,
        "success": False,
        "error": "",
    }

    start = time.monotonic()
    try:
        yield entry
        entry["success"] = True
    except Exception as exc:
        entry["error"] = str(exc)
        raise
    finally:
        entry["latency_ms"] = int((time.monotonic() - start) * 1000)
        _append_log(project_root, entry)


def _append_log(project_root: Path, entry: dict) -> None:
    log_path = project_root / "logs" / "llm_calls.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
