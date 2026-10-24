# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
Airlock CLI
python -m airlock <command>
"""

from __future__ import annotations

import typer

from airlock.commands.init import init
from airlock.commands.status import status
from airlock.commands.spec import spec_list, spec_new, spec_lock
from airlock.commands.candidate import candidate_register, candidate_list, candidate_hash
from airlock.commands.report import report
from airlock.commands.verify import verify
from airlock.commands.certify import certify
from airlock.commands.gate import gate, admit
from airlock.commands.dashboard import dashboard
from airlock.commands.llm import spec_draft, generate, explain
from airlock.commands.keys import keys_init, keys_show, keys_export, keys_trust
from airlock.commands.audit_cmd import audit_verify
from pathlib import Path

app = typer.Typer(
    name="airlock",
    help=(
        "Airlock — local-first LLM-assisted software engineering "
        "with evidence-grade trust boundaries."
    ),
    no_args_is_help=True,
    rich_markup_mode=None,
)

spec_app = typer.Typer(help="Manage cleanroom specifications.", no_args_is_help=True)
app.add_typer(spec_app, name="spec")

candidate_app = typer.Typer(help="Manage pipeline candidates.", no_args_is_help=True)
app.add_typer(candidate_app, name="candidate")

keys_app = typer.Typer(help="Manage the operator signing key and trusted keys.", no_args_is_help=True)
app.add_typer(keys_app, name="keys")

audit_app = typer.Typer(help="Inspect the hash-chained audit log.", no_args_is_help=True)
app.add_typer(audit_app, name="audit")


# ── Top-level commands ────────────────────────────────────────────────────────

@app.command("init")
def init_cmd(project_name: str = typer.Argument(..., help="Name of the new cleanroom project.")) -> None:
    """Initialise a new Airlock project."""
    init(project_name)

@app.command("status")
def status_cmd() -> None:
    """Show project overview: specs, candidates, and admitted artefacts."""
    status()

@app.command("report")
def report_cmd(candidate_id: str = typer.Argument(..., help="Candidate ID to report on.")) -> None:
    """Print the full evidence summary for a candidate."""
    report(candidate_id)

@app.command("verify")
def verify_cmd(candidate_id: str = typer.Argument(..., help="Candidate ID to verify.")) -> None:
    """Run the static verifier against a quarantined candidate."""
    verify(candidate_id)

@app.command("certify")
def certify_cmd(candidate_id: str = typer.Argument(..., help="Candidate ID to certify.")) -> None:
    """Run the test certifier against a verified candidate."""
    certify(candidate_id)

@app.command("gate")
def gate_cmd(
    candidate_id: str = typer.Argument(..., help="Candidate ID to evaluate."),
    override: bool = typer.Option(
        False, "--override", help="Approve an ESCALATE decision (needs --operator and --reason).",
    ),
    operator: str = typer.Option("", "--operator", help="Name of the approving operator."),
    reason: str = typer.Option("", "--reason", help="Why the escalation is being approved."),
) -> None:
    """Run the governance gate against a certified candidate."""
    gate(candidate_id, override=override, operator=operator, reason=reason)

@app.command("dashboard")
def dashboard_cmd(
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind to."),
    port: int = typer.Option(7842, "--port", "-p", help="Port to listen on."),
) -> None:
    """Start the read-only dashboard server."""
    dashboard(host=host, port=port)


@app.command("admit")
def admit_cmd(candidate_id: str = typer.Argument(..., help="Candidate ID to admit.")) -> None:
    """Admit a gate-approved candidate into the trusted tree."""
    admit(candidate_id)

@app.command("generate")
def generate_cmd(
    spec_id: str = typer.Argument(..., help="Locked spec ID to generate from."),
    module_name: str = typer.Argument(..., help="Python module name (e.g. backup)."),
) -> None:
    """Generate a candidate from a locked spec using the local LLM."""
    generate(spec_id, module_name)

@app.command("explain")
def explain_cmd(
    candidate_id: str = typer.Argument(..., help="Candidate ID to explain failures for."),
) -> None:
    """Use the local LLM to explain pipeline failures for a candidate."""
    explain(candidate_id)


# ── Spec commands ─────────────────────────────────────────────────────────────

@spec_app.command("list")
def spec_list_cmd() -> None:
    """List all specs and their status."""
    spec_list()

@spec_app.command("new")
def spec_new_cmd(description: str = typer.Argument(..., help="One-line description of this spec.")) -> None:
    """Create a new DRAFT spec."""
    spec_new(description)

@spec_app.command("lock")
def spec_lock_cmd(spec_id: str = typer.Argument(..., help="Spec ID to lock (e.g. spec_0001).")) -> None:
    """Lock a DRAFT spec — hashes and seals spec.md."""
    spec_lock(spec_id)

@spec_app.command("draft")
def spec_draft_cmd(
    intent: str = typer.Argument(..., help="One-line intent (e.g. 'Build a local file backup CLI')."),
) -> None:
    """Use the local LLM to draft a spec from a one-line intent."""
    spec_draft(intent)


# ── Candidate commands ────────────────────────────────────────────────────────

@candidate_app.command("register")
def candidate_register_cmd(
    spec_id: str = typer.Argument(..., help="Spec ID this candidate satisfies."),
    description: str = typer.Option("", "--description", "-d", help="Short description."),
    language: str = typer.Option("python", "--language", "-l", help="Implementation language."),
    generated_by: str = typer.Option("manual", "--generated-by", "-g", help="Model or 'manual'."),
) -> None:
    """Register a new quarantined candidate linked to a spec."""
    candidate_register(spec_id, description, language, generated_by)

@candidate_app.command("list")
def candidate_list_cmd() -> None:
    """List all candidates and their pipeline status."""
    candidate_list()

@candidate_app.command("hash")
def candidate_hash_cmd(candidate_id: str = typer.Argument(..., help="Candidate ID to hash.")) -> None:
    """Compute and record the source hash for a candidate's src/ tree."""
    candidate_hash(candidate_id)


# ── Key commands ──────────────────────────────────────────────────────────────

@keys_app.command("init")
def keys_init_cmd(
    passphrase: bool = typer.Option(False, "--passphrase", help="Encrypt the private key with a passphrase."),
    force: bool = typer.Option(False, "--force", help="Replace an existing operator key."),
) -> None:
    """Create the operator signing key (stored outside every project)."""
    keys_init(passphrase, force)

@keys_app.command("show")
def keys_show_cmd() -> None:
    """Show the operator key, trusted keys and the signatures floor."""
    keys_show()

@keys_app.command("export")
def keys_export_cmd(
    output: Path = typer.Option(None, "--output", "-o", help="Write the public key here."),
) -> None:
    """Print or write the operator's public key (to trust it on another machine)."""
    keys_export(output)

@keys_app.command("trust")
def keys_trust_cmd(public_key_file: Path = typer.Argument(..., help="PEM public key file.")) -> None:
    """Trust another operator's public key."""
    keys_trust(public_key_file)


# ── Audit commands ────────────────────────────────────────────────────────────

@audit_app.command("verify")
def audit_verify_cmd(
    reanchor: bool = typer.Option(
        False, "--reanchor", help="Accept the current chain head as this project's anchor.",
    ),
) -> None:
    """Verify the audit log's hash chain, signatures and anchor."""
    audit_verify(reanchor)


if __name__ == "__main__":
    app()
