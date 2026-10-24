# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock.core.governance.gate

The governance gate — final authority in the Airlock pipeline.

Consumes all evidence for a candidate and produces a binding gate decision:
  ALLOW        All evidence satisfies policy. Candidate may be admitted.
  DENY         One or more blocking failures. Candidate remains quarantined.
  QUARANTINE   Evidence incomplete. Cannot decide.
  ESCALATE     High-risk permission detected. Human decision required.

Every decision is recorded in gate_decision.json (evidence store) and
appended to logs/audit.jsonl.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

from airlock.core.hashing import (
    hash_file, hash_directory_tree, seal_evidence, verify_sidecar,
    find_unhashed_files, find_symlinks, tree_files,
)
from airlock.core.candidate_store import get_status, CandidateError
from airlock.core import audit, signing

VERSION = "0.4.0"

# Gate decisions
ALLOW = "ALLOW"
DENY = "DENY"
QUARANTINE = "QUARANTINE"
ESCALATE = "ESCALATE_TO_OPERATOR"

# governance.require_human_approval_for categories → verifier rules whose
# (non-blocking) findings escalate to an operator instead of passing silently.
ESCALATION_CATEGORIES: dict[str, set[str]] = {
    "credential_access":   {"ENV_ACCESS"},
    "filesystem_mutation": {"FS_SHUTIL_MUTATION"},
}

# Categories the verifier already hard-blocks; listing them is valid but they
# can never reach the gate, so they add no escalation trigger.
HARD_BLOCKED_CATEGORIES = {"filesystem_delete", "network_access", "subprocess_execution"}

HIGH_RISK_CATEGORIES = set(ESCALATION_CATEGORIES) | HARD_BLOCKED_CATEGORIES


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class EvidenceCheck:
    document: str
    present: bool
    hash_valid: bool
    verdict: str = ""        # from the document's own verdict/certification field
    detail: str = ""


@dataclass
class GateDecision:
    gate_id: str
    candidate_id: str
    spec_id: str
    gate_version: str
    timestamp: str
    decision: str                           # ALLOW | DENY | QUARANTINE | ESCALATE
    evidence_consumed: list[str] = field(default_factory=list)
    evidence_checks: list[dict] = field(default_factory=list)
    policy_version: str = ""
    reasons: list[str] = field(default_factory=list)
    required_actions: list[str] = field(default_factory=list)
    operator_override: bool = False
    operator_id: str = ""
    override_reason: str = ""
    overridden_decision: str = ""           # set when an operator overrode ESCALATE
    source_hash: str = ""                   # src/ tree this decision covers
    spec_hash: str = ""                     # locked spec this decision covers
    signatures_required: bool = False       # v0.4: evidence had to be signed
    audit_head: dict = field(default_factory=dict)   # chain head this decision saw
    evidence_hash: str = ""


# ── Gate runner ───────────────────────────────────────────────────────────────

def run_gate(
    candidate_dir: Path,
    project_root: Path,
    policy: dict,
    operator_id: str = "operator_local",
) -> GateDecision:
    """
    Run the governance gate against a certified candidate.
    Returns a GateDecision and writes gate_decision.json.
    """
    candidate_id = candidate_dir.name
    evidence_dir = project_root / "evidence" / candidate_id

    manifest = _load_json(candidate_dir / "manifest.json") or {}
    spec_id = manifest.get("spec_id", "")

    gate_id = f"gate-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()
    require_sigs = signing.signatures_required(policy)
    signer = signing.signer_for(policy)   # raises SigningError if required but unavailable

    reasons: list[str] = []
    required_actions: list[str] = []
    evidence_consumed: list[str] = []
    evidence_checks: list[dict] = []
    blocking: list[str] = []

    def block(reason: str, action: str = "") -> None:
        """Record a reason that forbids ALLOW."""
        reasons.append(reason)
        blocking.append(reason)
        if action:
            required_actions.append(action)

    # ── Check 1: Verifier report ──────────────────────────────────────────────
    ver_check = _check_evidence(
        evidence_dir / "static_verification.json",
        "static_verification.json",
        verdict_field="verdict",
        passing_value="PASS",
        require_signature=require_sigs,
    )
    evidence_checks.append(asdict(ver_check))
    if ver_check.present:
        evidence_consumed.append("static_verification.json")
    if not ver_check.present:
        reasons.append("Verifier report missing")
        required_actions.append("Run airlock verify")
    elif not ver_check.hash_valid:
        block(f"Verifier report integrity failed — {ver_check.detail or 'possible tampering'}")
    elif ver_check.verdict != "PASS":
        block("Verifier report: FAIL", "Fix verifier failures and re-run airlock verify")

    # ── Check 2: Test report ──────────────────────────────────────────────────
    test_check = _check_evidence(
        evidence_dir / "test_report.json",
        "test_report.json",
        verdict_field="certification",
        passing_value="CERTIFIED",
        require_signature=require_sigs,
    )
    evidence_checks.append(asdict(test_check))
    if test_check.present:
        evidence_consumed.append("test_report.json")
    if not test_check.present:
        reasons.append("Test report missing")
        required_actions.append("Run airlock certify")
    elif not test_check.hash_valid:
        block(f"Test report integrity failed — {test_check.detail or 'possible tampering'}")
    elif test_check.verdict != "CERTIFIED":
        block("Test report: NOT_CERTIFIED", "Fix failing tests and re-run airlock certify")

    # ── Check 3: Coverage report ──────────────────────────────────────────────
    cov_check = _check_evidence(
        evidence_dir / "coverage_report.json",
        "coverage_report.json",
        require_signature=require_sigs,
    )
    evidence_checks.append(asdict(cov_check))
    if cov_check.present:
        evidence_consumed.append("coverage_report.json")
    if not cov_check.present:
        reasons.append("Coverage report missing")
    elif not cov_check.hash_valid:
        block(f"Coverage report integrity failed — {cov_check.detail or 'possible tampering'}")
    else:
        cert_policy = policy.get("certification", {}) or {}
        cov_data = _load_json(evidence_dir / "coverage_report.json") or {}
        for key, field_name, label in (
            ("minimum_line_coverage", "line_coverage", "Line"),
            ("minimum_branch_coverage", "branch_coverage", "Branch"),
        ):
            minimum = cert_policy.get(key)
            if minimum is None:
                continue
            actual = float(cov_data.get(field_name) or 0.0)
            if actual < float(minimum):
                block(
                    f"{label} coverage {actual:.1%} is below policy minimum {float(minimum):.0%}",
                    "Add tests and re-run airlock certify",
                )

    # ── Check 4: Spec is locked ───────────────────────────────────────────────
    spec_locked = False
    spec_hash = ""
    if spec_id:
        spec_meta = _load_json(project_root / "specs" / spec_id / "spec_meta.json")
        if spec_meta and spec_meta.get("status") == "LOCKED":
            spec_locked = True
            spec_hash = spec_meta.get("spec_hash") or ""
    if not spec_locked:
        block(f"Spec {spec_id!r} is not locked", f"Run airlock spec lock {spec_id}")
    elif not _spec_matches_lock(project_root, spec_id, spec_hash):
        block(
            f"Spec {spec_id!r} has been edited since it was locked",
            "Restore the locked spec.md, or create and lock a new spec",
        )

    # ── Check 5: Source binding ───────────────────────────────────────────────
    # The source tree must match the recorded hash, and every evidence
    # document must have been produced against that same hash. Otherwise
    # evidence for one tree could be presented for another.
    recorded_source_hash = manifest.get("source_hash") or ""
    src_dir = candidate_dir / "src"
    current_source_hash = hash_directory_tree(src_dir) if src_dir.exists() else ""
    stray = find_unhashed_files(src_dir) + find_symlinks(src_dir)
    if stray:
        block(
            "src/ contains files outside the source hash: " + ", ".join(stray),
            "Remove them (e.g. __pycache__) and re-run the pipeline",
        )
    if not recorded_source_hash:
        block(
            "Source hash not recorded in manifest",
            "Run airlock candidate hash <candidate_id>",
        )
    else:
        if current_source_hash != recorded_source_hash:
            block(
                "Source tree modified since its hash was recorded",
                "Register a new candidate for the modified source",
            )
        for name, check in (
            ("static_verification.json", ver_check),
            ("test_report.json", test_check),
            ("coverage_report.json", cov_check),
        ):
            if not (check.present and check.hash_valid):
                continue
            bound = (_load_json(evidence_dir / name) or {}).get("source_hash")
            if bound != recorded_source_hash:
                block(
                    f"{name} is not bound to the recorded source hash",
                    f"Re-run the pipeline stage that produces {name}",
                )

    # ── Check 6: Human-approval categories ────────────────────────────────────
    # Non-blocking verifier findings in a category listed under
    # governance.require_human_approval_for escalate to the operator.
    # (v0.2 only looked at non-blocking IMPORT_* findings — every IMPORT_*
    # rule is blocking, so ESCALATE could never happen.)
    gov_policy = policy.get("governance", {}) or {}
    escalating_rules: set[str] = set()
    for category in gov_policy.get("require_human_approval_for", []) or []:
        escalating_rules |= ESCALATION_CATEGORIES.get(str(category), set())
    escalate_triggers: list[str] = []
    if ver_check.present and ver_check.hash_valid and escalating_rules:
        ver_data = _load_json(evidence_dir / "static_verification.json") or {}
        for result in ver_data.get("results", []):
            rule_id = result.get("rule_id", "")
            if (not result.get("passed") and not result.get("blocking")
                    and rule_id in escalating_rules and rule_id not in escalate_triggers):
                escalate_triggers.append(rule_id)

    # ── Check 7: Audit log integrity ──────────────────────────────────────────
    audit_status = audit.verify_chain(project_root, require_signatures=require_sigs)
    for problem in audit_status.problems:
        block(f"Audit log integrity: {problem}", "Investigate logs/audit.jsonl (airlock audit verify)")

    # ── Determine decision ────────────────────────────────────────────────────
    if not ver_check.present or not test_check.present or not cov_check.present:
        decision = QUARANTINE
    elif blocking:
        decision = DENY
    elif escalate_triggers:
        decision = ESCALATE
        reasons.append(f"High-risk patterns detected: {', '.join(escalate_triggers)}")
        required_actions.append("Operator review required before admission")
    else:
        decision = ALLOW

    gate_decision = GateDecision(
        gate_id=gate_id,
        candidate_id=candidate_id,
        spec_id=spec_id,
        gate_version=VERSION,
        timestamp=now,
        decision=decision,
        evidence_consumed=evidence_consumed,
        evidence_checks=evidence_checks,
        policy_version=_policy_version(project_root),
        reasons=reasons,
        required_actions=required_actions,
        operator_id=operator_id,
        source_hash=recorded_source_hash,
        spec_hash=spec_hash,
        signatures_required=require_sigs,
        audit_head={"seq": audit_status.head_seq, "entry_hash": audit_status.head_hash},
    )

    # ── Write evidence ────────────────────────────────────────────────────────
    evidence_dir.mkdir(parents=True, exist_ok=True)
    gate_path = evidence_dir / "gate_decision.json"
    data = asdict(gate_decision)
    data.pop("evidence_hash", None)
    digest = seal_evidence(gate_path, data, signer=signer)
    gate_decision.evidence_hash = digest

    # ── Audit log ─────────────────────────────────────────────────────────────
    _append_audit(project_root, signer, {
        "event": "gate_decision",
        "gate_id": gate_id,
        "candidate_id": candidate_id,
        "spec_id": spec_id,
        "decision": decision,
        "timestamp": now,
        "operator_id": operator_id,
        "reasons": reasons,
    })

    return gate_decision


# ── Operator override ─────────────────────────────────────────────────────────

class OverrideError(Exception):
    pass


def run_override(
    candidate_dir: Path,
    project_root: Path,
    policy: dict,
    operator_id: str,
    reason: str,
) -> GateDecision:
    """
    Record an operator's approval of an ESCALATE decision.

    The gate is re-evaluated first, so an override only ever applies to the
    current evidence. Only ESCALATE can be overridden; DENY and QUARANTINE
    cannot. The resulting ALLOW decision records who approved it and why,
    and the original reasons are kept.
    """
    operator_id = (operator_id or "").strip()
    reason = (reason or "").strip()
    if not operator_id or operator_id == "operator_local":
        raise OverrideError("An override needs a named operator (--operator).")
    if not reason:
        raise OverrideError("An override needs a reason (--reason).")

    fresh = run_gate(candidate_dir, project_root, policy, operator_id=operator_id)
    if fresh.decision != ESCALATE:
        raise OverrideError(
            f"Gate decision is {fresh.decision}, not {ESCALATE}. "
            "Only escalated decisions can be overridden."
        )

    now = datetime.now(timezone.utc).isoformat()
    decision = GateDecision(
        **{
            **asdict(fresh),
            "gate_id": f"gate-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}",
            "timestamp": now,
            "decision": ALLOW,
            "operator_override": True,
            "operator_id": operator_id,
            "override_reason": reason,
            "overridden_decision": ESCALATE,
            "required_actions": [],
            "evidence_hash": "",
        }
    )
    evidence_dir = project_root / "evidence" / candidate_dir.name
    data = asdict(decision)
    data.pop("evidence_hash", None)
    signer = signing.signer_for(policy)
    decision.evidence_hash = seal_evidence(evidence_dir / "gate_decision.json", data, signer=signer)

    _append_audit(project_root, signer, {
        "event": "operator_override",
        "gate_id": decision.gate_id,
        "candidate_id": decision.candidate_id,
        "spec_id": decision.spec_id,
        "decision": ALLOW,
        "overridden_decision": ESCALATE,
        "timestamp": now,
        "operator_id": operator_id,
        "reason": reason,
        "escalation_reasons": fresh.reasons,
    })
    return decision


# ── Admission ─────────────────────────────────────────────────────────────────

def run_admission(
    candidate_dir: Path,
    project_root: Path,
    operator_id: str = "operator_local",
    policy: dict | None = None,
) -> dict:
    """
    Admit a gate-approved candidate into the trusted tree.

    - Verifies gate_decision.json says ALLOW
    - Copies src/ to trusted/src/<candidate_id>/
    - Issues admission_certificate.json
    - Appends to audit.jsonl
    """
    candidate_id = candidate_dir.name
    evidence_dir = project_root / "evidence" / candidate_id

    # ── Guard 1: candidate must be certified ─────────────────────────────────
    try:
        current_status = get_status(candidate_dir)
    except CandidateError as exc:
        raise AdmissionError(f"Cannot read candidate status: {exc}") from exc

    if current_status != "certified":
        raise AdmissionError(
            f"Candidate status is {current_status!r}, not 'certified'. "
            "Only certified candidates may be admitted. "
            "A candidate cannot be admitted by presenting a fake gate decision."
        )

    # ── Guard 2: gate_decision.json must exist and pass sidecar verification ──
    gate_path = evidence_dir / "gate_decision.json"
    if not gate_path.exists():
        raise AdmissionError("gate_decision.json not found. Run airlock gate first.")

    ok, msg = verify_sidecar(gate_path)
    if not ok:
        raise AdmissionError(
            f"gate_decision.json integrity check failed: {msg}. "
            "The gate decision may have been tampered with."
        )

    require_sigs = signing.signatures_required(policy)
    if require_sigs:
        ok, msg = signing.verify_file(gate_path)
        if not ok:
            raise AdmissionError(f"gate_decision.json signature check failed: {msg}.")
    audit_status = audit.verify_chain(project_root, require_signatures=require_sigs)
    if audit_status.problems:
        raise AdmissionError("Audit log integrity failed: " + "; ".join(audit_status.problems))
    try:
        signer = signing.signer_for(policy)
    except signing.SigningError as exc:
        raise AdmissionError(str(exc)) from exc

    gate_data = _load_json(gate_path)
    if not gate_data:
        raise AdmissionError("gate_decision.json is malformed.")

    if gate_data.get("decision") != ALLOW:
        raise AdmissionError(
            f"Gate decision is {gate_data.get('decision')!r}, not ALLOW. "
            "Candidate cannot be admitted."
        )

    # ── Guard 3: source tree must not have changed since gate approval ────────
    manifest = _load_json(candidate_dir / "manifest.json") or {}
    approved_source_hash = manifest.get("source_hash", "")
    if not approved_source_hash:
        raise AdmissionError(
            "No source hash in manifest. "
            "Run airlock candidate hash before entering the pipeline."
        )

    if gate_data.get("source_hash") != approved_source_hash:
        raise AdmissionError(
            "The gate decision does not cover the recorded source hash. "
            "Re-run airlock gate."
        )

    src_dir = candidate_dir / "src"
    current_source_hash = hash_directory_tree(src_dir)
    if current_source_hash != approved_source_hash:
        raise AdmissionError(
            "Source tree hash mismatch. "
            "The candidate source was modified after gate approval. "
            f"Approved: {approved_source_hash[:19]}... "
            f"Current:  {current_source_hash[:19]}..."
        )

    stray = find_unhashed_files(src_dir) + find_symlinks(src_dir)
    if stray:
        raise AdmissionError(
            "src/ contains files outside the source hash: " + ", ".join(stray)
        )

    # ── Guard 4: the locked spec must be unchanged ────────────────────────────
    spec_id = manifest.get("spec_id", "")
    spec_meta = _load_json(project_root / "specs" / spec_id / "spec_meta.json") or {}
    if (gate_data.get("spec_hash") != spec_meta.get("spec_hash")
            or not _spec_matches_lock(project_root, spec_id, spec_meta.get("spec_hash") or "")):
        raise AdmissionError(
            f"Spec {spec_id!r} has changed since the gate decision. Re-run airlock gate."
        )

    # Copy exactly the hashed files to the trusted tree — never bytecode,
    # sidecars or anything else the hash and verifier did not cover.
    import shutil
    trusted_dest = project_root / "trusted" / "src" / candidate_id
    if trusted_dest.exists():
        shutil.rmtree(trusted_dest)
    trusted_dest.mkdir(parents=True)
    for path in tree_files(src_dir):
        dest = trusted_dest / path.relative_to(src_dir)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
    if hash_directory_tree(trusted_dest) != approved_source_hash:
        shutil.rmtree(trusted_dest)
        raise AdmissionError("Copied tree does not match the approved source hash.")

    # Issue certificate
    now = datetime.now(timezone.utc).isoformat()

    cert_id = f"al-cert-{datetime.now(timezone.utc).strftime('%Y')}-{uuid.uuid4().hex[:8]}"

    certificate = {
        "certificate_id": cert_id,
        "candidate_id": candidate_id,
        "spec_id": spec_id,
        "level": "L4_GOVERNANCE_ADMITTED",
        "admitted": True,
        "admitted_at": now,
        "admitted_by": operator_id,
        "gate_id": gate_data.get("gate_id", ""),
        "operator_override": bool(gate_data.get("operator_override")),
        "override_operator": gate_data.get("operator_id", "") if gate_data.get("operator_override") else "",
        "override_reason": gate_data.get("override_reason", ""),
        "hashes": {
            "source_tree": manifest.get("source_hash", ""),
            "spec": spec_meta.get("spec_hash", ""),
            # Hash of the gate decision file as verified above. (v0.2 read an
            # "evidence_hash" field that is never written, so this was empty.)
            "gate_decision": hash_file(gate_path),
        },
    }

    cert_path = evidence_dir / "admission_certificate.json"
    certificate.pop("evidence_hash", None)
    certificate["audit_head"] = {"seq": audit_status.head_seq, "entry_hash": audit_status.head_hash}
    cert_hash = seal_evidence(cert_path, certificate, signer=signer)
    # Store digest on the dict for the return value only (not written to file)
    certificate["evidence_hash"] = cert_hash

    # Audit log
    _append_audit(project_root, signer, {
        "event": "candidate_admitted",
        "certificate_id": cert_id,
        "candidate_id": candidate_id,
        "spec_id": spec_id,
        "level": "L4_GOVERNANCE_ADMITTED",
        "timestamp": now,
        "operator_id": operator_id,
        "trusted_path": str(trusted_dest.relative_to(project_root)),
    })

    return certificate


class AdmissionError(Exception):
    pass


# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_evidence(
    path: Path,
    document: str,
    verdict_field: str = "",
    passing_value: str = "",
    require_signature: bool = False,
) -> EvidenceCheck:
    """Check evidence file presence, sidecar integrity, signature, and verdict field."""
    if not path.exists():
        return EvidenceCheck(document=document, present=False, hash_valid=False)

    # Verify against detached sidecar — true tamper detection
    ok, msg = verify_sidecar(path)
    if not ok:
        return EvidenceCheck(
            document=document,
            present=True,
            hash_valid=False,
            detail=f"Integrity check failed: {msg}",
        )

    if require_signature:
        ok, msg = signing.verify_file(path)
        if not ok:
            return EvidenceCheck(
                document=document, present=True, hash_valid=False,
                detail=f"Signature check failed: {msg}",
            )

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return EvidenceCheck(document=document, present=True, hash_valid=False,
                             detail="Malformed JSON")

    verdict = ""
    if verdict_field:
        verdict = data.get(verdict_field, "")

    return EvidenceCheck(
        document=document,
        present=True,
        hash_valid=True,
        verdict=verdict,
    )


def _spec_matches_lock(project_root: Path, spec_id: str, spec_hash: str) -> bool:
    """True if spec.md still hashes to the value recorded when it was locked."""
    spec_md = project_root / "specs" / spec_id / "spec.md"
    return bool(spec_hash) and spec_md.exists() and hash_file(spec_md) == spec_hash


def _load_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _policy_version(project_root: Path) -> str:
    from airlock.config import config_path_for
    config_path = config_path_for(project_root)
    if config_path is not None:
        h = hash_file(config_path)
        return f"{config_path.name}:{h[:19]}"
    return "unknown"


def _append_audit(project_root: Path, signer: "signing.Signer | None", entry: dict) -> None:
    audit.append_entry(project_root, entry, signer=signer)
