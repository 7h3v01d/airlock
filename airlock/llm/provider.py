# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock.llm.provider

LLM provider interface and capability registry.

The LLM sits at the bottom of the Airlock trust hierarchy.
It may propose, draft, generate, and explain — but it may never certify,
approve, admit, or override pipeline decisions.

Every provider must declare:
  - which roles it is allowed to fulfil
  - whether it is local (offline-capable)
  - its capability profile

Forbidden roles are enforced architecturally — no provider may be
configured with certify, approve, or execute in allowed_roles.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


# ── Roles ─────────────────────────────────────────────────────────────────────

# Roles the LLM may fulfil
ALLOWED_ROLES = {
    "draft_spec",
    "generate_candidate",
    "generate_tests",
    "explain_failure",
    "suggest_remediation",
    "summarise_report",
}

# Roles that no LLM may ever be assigned
FORBIDDEN_ROLES = {
    "certify",
    "approve",
    "admit",
    "execute",
    "override_policy",
    "modify_evidence",
}


# ── Provider interface ────────────────────────────────────────────────────────

@dataclass
class LLMCapabilityProfile:
    model: str
    provider_name: str
    local: bool
    network_access: bool
    context_window: int
    allowed_roles: set[str] = field(default_factory=set)
    capabilities: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Enforce: no forbidden roles
        bad = self.allowed_roles & FORBIDDEN_ROLES
        if bad:
            raise ValueError(
                f"Provider '{self.provider_name}' attempted to claim forbidden roles: {bad}. "
                "The LLM cannot certify, approve, admit, execute, or override policy."
            )
        # Enforce: only known roles
        unknown = self.allowed_roles - ALLOWED_ROLES
        if unknown:
            raise ValueError(f"Unknown roles requested: {unknown}")

    def can(self, role: str) -> bool:
        return role in self.allowed_roles


class LLMProvider(Protocol):
    """Interface every LLM provider must implement."""

    @property
    def profile(self) -> LLMCapabilityProfile: ...

    def complete(
        self,
        prompt: str,
        system: str = "",
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> str:
        """Send a prompt and return the completion text."""
        ...

    def is_available(self) -> bool:
        """Return True if the provider is reachable."""
        ...
