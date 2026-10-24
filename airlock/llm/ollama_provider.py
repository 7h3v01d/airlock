# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock.llm.ollama_provider

Ollama LLM provider for Airlock.

Communicates with a local Ollama instance via its REST API.
No data leaves the machine. Network access is to localhost only.

URL enforcement (v0.2):
  When allow_remote_llm is False (the default), the base_url must resolve
  to a loopback address. Any non-loopback URL is rejected at construction
  time with a clear error — it cannot be silently accepted.

  Permitted loopback forms:
    http://localhost:PORT
    http://127.0.0.1:PORT
    http://[::1]:PORT

  Everything else (192.168.x.x, LAN hostnames, cloud endpoints) is
  rejected when allow_remote_llm: false.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from airlock.llm.provider import LLMCapabilityProfile, ALLOWED_ROLES

# Hostnames and addresses that are always considered local/loopback
_LOOPBACK_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "[::1]",
}


def is_loopback_url(url: str) -> bool:
    """
    Return True if the URL hostname resolves to a loopback address.

    Accepts:
      http://localhost:11434
      http://127.0.0.1:11434
      http://[::1]:11434

    Rejects:
      http://192.168.0.163:11434
      http://my-remote-server:11434
      http://ollama.example.com:11434
    """
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        return host.lower() in _LOOPBACK_HOSTS
    except Exception:
        return False


class OllamaURLError(Exception):
    """Raised when base_url violates the local-first policy."""
    pass


@dataclass
class OllamaProvider:
    """Local Ollama provider."""

    model: str = "deepseek-coder-v2:16b"
    base_url: str = "http://localhost:11434"
    allow_remote: bool = False      # mirrors allow_remote_llm from airlock.yaml

    def __post_init__(self) -> None:
        # ── URL enforcement ───────────────────────────────────────────────────
        if not self.allow_remote and not is_loopback_url(self.base_url):
            parsed = urllib.parse.urlparse(self.base_url)
            host = parsed.hostname or self.base_url
            raise OllamaURLError(
                f"OllamaProvider base_url '{self.base_url}' resolves to "
                f"non-loopback host '{host}'. "
                "This violates the local-first policy (allow_remote_llm: false). "
                "Either set base_url to localhost/127.0.0.1, or explicitly "
                "set allow_remote_llm: true in airlock.yaml to acknowledge "
                "that data will leave the local machine."
            )

        self._profile = LLMCapabilityProfile(
            model=self.model,
            provider_name="ollama",
            local=not self.allow_remote,
            network_access=self.allow_remote,
            context_window=32768,
            allowed_roles=set(ALLOWED_ROLES),
            capabilities=["code", "reasoning", "summarisation", "instruction_following"],
        )

    @property
    def profile(self) -> LLMCapabilityProfile:
        return self._profile

    def is_available(self) -> bool:
        """Return True if Ollama is running and the model is available."""
        try:
            url = f"{self.base_url}/api/tags"
            with urllib.request.urlopen(url, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            models = [m.get("name", "") for m in data.get("models", [])]
            return any(
                m == self.model or m.startswith(self.model.split(":")[0])
                for m in models
            )
        except Exception:
            return False

    def complete(
        self,
        prompt: str,
        system: str = "",
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> str:
        """Send a prompt to Ollama and return the completion."""
        payload: dict = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if system:
            payload["system"] = system

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read().decode("utf-8"))
            return result.get("response", "").strip()
        except urllib.error.URLError as exc:
            raise OllamaConnectionError(
                f"Cannot reach Ollama at {self.base_url}. "
                "Is Ollama running? Try: ollama serve"
            ) from exc
        except Exception as exc:
            raise OllamaConnectionError(f"Ollama error: {exc}") from exc


class OllamaConnectionError(Exception):
    pass


def provider_from_config(config: dict) -> OllamaProvider:
    """
    Build an OllamaProvider from airlock.yaml config.

    Reads allow_remote_llm from local_first policy and enforces it
    against the configured base_url.
    """
    llm_cfg = config.get("llm", {})
    local_first = config.get("local_first", {})
    allow_remote = local_first.get("allow_remote_llm", False)

    return OllamaProvider(
        model=llm_cfg.get("model", "deepseek-coder-v2:16b"),
        base_url=llm_cfg.get("base_url", "http://localhost:11434"),
        allow_remote=allow_remote,
    )
