# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""Shared fixtures: every test gets its own throwaway Airlock home."""

from __future__ import annotations

from pathlib import Path

import pytest

from airlock.core import signing


@pytest.fixture(autouse=True)
def isolated_airlock_home(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path_factory.mktemp("airlock_home")
    monkeypatch.setenv(signing.HOME_ENV, str(home))
    monkeypatch.delenv(signing.PASSPHRASE_ENV, raising=False)
    signing.clear_cached_signer()
    yield home
    signing.clear_cached_signer()
