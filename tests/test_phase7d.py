# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
Phase 7D — Ollama loopback URL enforcement tests.

Verifies that non-loopback URLs are rejected when allow_remote_llm is false.

Run from the repo root:
    pytest tests/test_phase7d.py -v
"""

from __future__ import annotations

import pytest

from airlock.llm.ollama_provider import (
    OllamaProvider,
    OllamaURLError,
    is_loopback_url,
    provider_from_config,
)


# ── is_loopback_url ───────────────────────────────────────────────────────────

class TestIsLoopbackUrl:
    def test_localhost_is_loopback(self) -> None:
        assert is_loopback_url("http://localhost:11434") is True

    def test_localhost_no_port_is_loopback(self) -> None:
        assert is_loopback_url("http://localhost") is True

    def test_127_0_0_1_is_loopback(self) -> None:
        assert is_loopback_url("http://127.0.0.1:11434") is True

    def test_ipv6_loopback_is_loopback(self) -> None:
        assert is_loopback_url("http://[::1]:11434") is True

    def test_lan_ip_is_not_loopback(self) -> None:
        assert is_loopback_url("http://192.168.0.163:11434") is False

    def test_lan_ip_other_subnet_is_not_loopback(self) -> None:
        assert is_loopback_url("http://10.0.0.1:11434") is False

    def test_remote_hostname_is_not_loopback(self) -> None:
        assert is_loopback_url("http://my-server.local:11434") is False

    def test_cloud_endpoint_is_not_loopback(self) -> None:
        assert is_loopback_url("https://ollama.example.com/api") is False

    def test_empty_string_is_not_loopback(self) -> None:
        assert is_loopback_url("") is False


# ── OllamaProvider URL enforcement ───────────────────────────────────────────

class TestOllamaProviderUrlEnforcement:
    def test_localhost_accepted_when_remote_not_allowed(self) -> None:
        provider = OllamaProvider(
            base_url="http://localhost:11434",
            allow_remote=False,
        )
        assert provider.base_url == "http://localhost:11434"

    def test_127_0_0_1_accepted_when_remote_not_allowed(self) -> None:
        provider = OllamaProvider(
            base_url="http://127.0.0.1:11434",
            allow_remote=False,
        )
        assert provider.base_url == "http://127.0.0.1:11434"

    def test_lan_ip_rejected_when_remote_not_allowed(self) -> None:
        with pytest.raises(OllamaURLError, match="non-loopback"):
            OllamaProvider(
                base_url="http://192.168.0.163:11434",
                allow_remote=False,
            )

    def test_lan_ip_accepted_when_remote_allowed(self) -> None:
        # When allow_remote_llm: true, LAN addresses are accepted
        provider = OllamaProvider(
            base_url="http://192.168.0.163:11434",
            allow_remote=True,
        )
        assert provider.base_url == "http://192.168.0.163:11434"

    def test_remote_hostname_rejected(self) -> None:
        with pytest.raises(OllamaURLError, match="non-loopback"):
            OllamaProvider(
                base_url="http://remote-server:11434",
                allow_remote=False,
            )

    def test_cloud_endpoint_rejected(self) -> None:
        with pytest.raises(OllamaURLError, match="non-loopback"):
            OllamaProvider(
                base_url="https://api.ollama.example.com",
                allow_remote=False,
            )

    def test_error_message_names_the_host(self) -> None:
        with pytest.raises(OllamaURLError) as exc_info:
            OllamaProvider(
                base_url="http://192.168.1.50:11434",
                allow_remote=False,
            )
        assert "192.168.1.50" in str(exc_info.value)

    def test_error_message_mentions_allow_remote_llm(self) -> None:
        with pytest.raises(OllamaURLError) as exc_info:
            OllamaProvider(
                base_url="http://192.168.1.50:11434",
                allow_remote=False,
            )
        assert "allow_remote_llm" in str(exc_info.value)

    def test_profile_marks_local_true_for_loopback(self) -> None:
        provider = OllamaProvider(
            base_url="http://localhost:11434",
            allow_remote=False,
        )
        assert provider.profile.local is True
        assert provider.profile.network_access is False

    def test_profile_marks_local_false_for_remote(self) -> None:
        provider = OllamaProvider(
            base_url="http://192.168.0.163:11434",
            allow_remote=True,
        )
        assert provider.profile.local is False
        assert provider.profile.network_access is True


# ── provider_from_config ──────────────────────────────────────────────────────

class TestProviderFromConfig:
    def test_default_config_uses_localhost(self) -> None:
        provider = provider_from_config({})
        assert is_loopback_url(provider.base_url)

    def test_loopback_url_in_config_accepted(self) -> None:
        config = {
            "llm": {"base_url": "http://127.0.0.1:11434", "model": "test"},
            "local_first": {"allow_remote_llm": False},
        }
        provider = provider_from_config(config)
        assert provider.base_url == "http://127.0.0.1:11434"

    def test_lan_url_with_remote_false_raises(self) -> None:
        config = {
            "llm": {"base_url": "http://192.168.0.163:11434"},
            "local_first": {"allow_remote_llm": False},
        }
        with pytest.raises(OllamaURLError):
            provider_from_config(config)

    def test_lan_url_with_remote_true_accepted(self) -> None:
        config = {
            "llm": {"base_url": "http://192.168.0.163:11434"},
            "local_first": {"allow_remote_llm": True},
        }
        provider = provider_from_config(config)
        assert provider.base_url == "http://192.168.0.163:11434"

    def test_missing_local_first_defaults_to_strict(self) -> None:
        """No local_first section → defaults to allow_remote=False → strict."""
        config = {
            "llm": {"base_url": "http://192.168.0.163:11434"},
        }
        with pytest.raises(OllamaURLError):
            provider_from_config(config)

    def test_model_read_from_config(self) -> None:
        config = {
            "llm": {"model": "llama3.2:3b", "base_url": "http://localhost:11434"},
        }
        provider = provider_from_config(config)
        assert provider.model == "llama3.2:3b"

    def test_your_rig_lan_address_blocked_by_default(self) -> None:
        """Specifically test the AI Power RIG address on the author's LAN rig."""
        config = {
            "llm": {"base_url": "http://192.168.0.163:11434"},
            "local_first": {"allow_remote_llm": False},
        }
        with pytest.raises(OllamaURLError, match="192.168.0.163"):
            provider_from_config(config)

    def test_your_rig_lan_address_allowed_when_explicitly_permitted(self) -> None:
        """With allow_remote_llm: true, the RIG address is accepted."""
        config = {
            "llm": {"base_url": "http://192.168.0.163:11434"},
            "local_first": {"allow_remote_llm": True},
        }
        provider = provider_from_config(config)
        assert provider.base_url == "http://192.168.0.163:11434"
        assert provider.profile.local is False  # correctly marked as non-local
