# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock keys init | show | export | trust

The operator key and the trusted-key set live in the operator's Airlock
home, outside every project, so a project cannot forge or redefine trust.
"""

from __future__ import annotations

from pathlib import Path

import typer

from airlock.core import signing


def keys_init(passphrase: bool, force: bool) -> None:
    secret = None
    if passphrase:
        secret = typer.prompt("New passphrase", hide_input=True, confirmation_prompt=True)
    try:
        key_id = signing.generate_key(secret, force=force)
    except signing.SigningError as exc:
        typer.echo(typer.style(f"✗ {exc}", fg=typer.colors.RED) + "  (use --force to replace it)")
        raise typer.Exit(1)
    typer.echo(typer.style("✓ Operator key created", fg=typer.colors.GREEN, bold=True))
    typer.echo(f"  Key id     {key_id}")
    typer.echo(f"  Stored in  {signing.private_key_path()}")
    typer.echo(f"  Encrypted  {'yes' if secret else 'no — consider: airlock keys init --passphrase --force'}")
    typer.echo("  Operator floor: signatures now required for every project on this machine.")


def keys_show() -> None:
    cfg = signing.operator_config()
    typer.echo(f"Airlock home      {signing.airlock_home()}")
    key_path = signing.private_key_path()
    if key_path.exists():
        try:
            signer_id = signing.load_signer().key_id if not signing.key_is_encrypted() else "(encrypted)"
        except signing.SigningError as exc:
            signer_id = f"(unavailable: {exc})"
        typer.echo(f"Operator key      {signer_id}  [{key_path}]")
    else:
        typer.echo("Operator key      none — run: airlock keys init")
    typer.echo(f"Signatures floor  {'required' if cfg.get('require_signatures') else 'not required'}"
               + ("  (config corrupt — treated as required)" if cfg.get("_corrupt") else ""))
    trusted = signing.trusted_keys()
    typer.echo(f"Trusted keys      {len(trusted)}")
    for key_id in trusted:
        typer.echo(f"  • {key_id}")


def keys_export(output: Path | None) -> None:
    try:
        signer = signing.load_signer()
    except signing.SigningError as exc:
        typer.echo(typer.style(f"✗ {exc}", fg=typer.colors.RED))
        raise typer.Exit(1)
    from cryptography.hazmat.primitives import serialization
    pem = signer.key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if output:
        output.write_bytes(pem)
        typer.echo(f"✓ Public key {signer.key_id} written to {output}")
    else:
        typer.echo(pem.decode("ascii").rstrip())


def keys_trust(public_key_file: Path) -> None:
    try:
        key_id = signing.trust_public_key(public_key_file.read_bytes())
    except (OSError, ValueError, signing.SigningError) as exc:
        typer.echo(typer.style(f"✗ Could not trust key: {exc}", fg=typer.colors.RED))
        raise typer.Exit(1)
    typer.echo(typer.style(f"✓ Trusted {key_id}", fg=typer.colors.GREEN))
