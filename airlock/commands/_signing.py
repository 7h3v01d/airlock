# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""Shared CLI helper: unlock the operator key before a signing command runs."""

from __future__ import annotations

import os

import typer

from airlock.core import signing


def prepare_signer(config: dict) -> None:
    """
    If this project needs signatures, make sure the operator key can be used,
    prompting for its passphrase when it is encrypted and
    AIRLOCK_KEY_PASSPHRASE is not set. Exits with a clear message on failure.
    """
    if not signing.signatures_required(config):
        return
    passphrase = None
    if signing.key_is_encrypted() and not os.environ.get(signing.PASSPHRASE_ENV):
        passphrase = typer.prompt("Operator key passphrase", hide_input=True)
    try:
        signing.load_signer(passphrase)
    except signing.SigningError as exc:
        typer.echo(typer.style(f"✗ {exc}", fg=typer.colors.RED))
        raise typer.Exit(1)
