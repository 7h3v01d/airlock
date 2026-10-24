# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock.core.signing

Ed25519 signatures for evidence documents and audit entries.

Why: the v0.2/v0.3 ``.sha256`` sidecars sit beside the evidence they cover,
so anyone who can write to the project can rewrite both. A signature made
with a key that lives *outside* the project cannot be forged that way.

Trust lives in the operator's Airlock home, never in the project:

    <AIRLOCK_HOME>/
      config.json                 operator floor, e.g. {"require_signatures": true}
      keys/operator_ed25519.pem   private key (optionally passphrase-encrypted)
      keys/trusted/<key>.pub      public keys whose signatures are accepted
      anchors/<project_id>.json   last audit-log head seen per project

AIRLOCK_HOME defaults to %APPDATA%\\airlock on Windows and ~/.config/airlock
elsewhere; the AIRLOCK_HOME environment variable overrides it.

A project's airlock.yaml can *raise* the requirement
(integrity.require_signatures: true) but can never lower the operator floor.

Signature sidecar (<file>.sig, JSON):
    {"alg": "ed25519", "key_id": "...", "label": "...", "sha256": "<hex>",
     "signature": "<base64>"}

The signed message binds a domain tag, a label (e.g.
"candidate_0001/test_report.json") and the file's SHA-256, so a valid
signature cannot be moved to another document or another candidate.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

EVIDENCE_DOMAIN = b"airlock-evidence-v1\0"
AUDIT_DOMAIN = b"airlock-audit-v1\0"
PASSPHRASE_ENV = "AIRLOCK_KEY_PASSPHRASE"
HOME_ENV = "AIRLOCK_HOME"
SIG_SUFFIX = ".sig"


class SigningError(Exception):
    """Raised when signing is required but cannot be performed."""


# ── Locations ─────────────────────────────────────────────────────────────────

def airlock_home() -> Path:
    """The operator's Airlock home (outside any project)."""
    override = os.environ.get(HOME_ENV)
    if override:
        return Path(override)
    if sys.platform == "win32" and os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"]) / "airlock"
    return Path.home() / ".config" / "airlock"


def private_key_path() -> Path:
    return airlock_home() / "keys" / "operator_ed25519.pem"


def trusted_dir() -> Path:
    return airlock_home() / "keys" / "trusted"


def operator_config_path() -> Path:
    return airlock_home() / "config.json"


# ── Operator floor ────────────────────────────────────────────────────────────

def operator_config() -> dict:
    path = operator_config_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        # A corrupt operator config must not silently disable the floor.
        return {"require_signatures": True, "_corrupt": True}


def write_operator_config(data: dict) -> None:
    path = operator_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def signatures_required(policy: dict | None) -> bool:
    """Project policy OR operator floor — the project can raise, never lower."""
    project = bool(((policy or {}).get("integrity") or {}).get("require_signatures"))
    return project or bool(operator_config().get("require_signatures"))


# ── Keys ──────────────────────────────────────────────────────────────────────

def key_id_for(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]


def _public_pem(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _restrict_permissions(path: Path) -> None:
    if os.name == "posix":
        os.chmod(path, 0o600)


def generate_key(passphrase: str | None = None, force: bool = False) -> str:
    """
    Create the operator key pair, trust its public key, and set the operator
    floor to require signatures. Returns the key id.
    """
    path = private_key_path()
    if path.exists() and not force:
        raise SigningError(f"An operator key already exists at {path}.")
    key = Ed25519PrivateKey.generate()
    encryption = (
        serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        if passphrase else serialization.NoEncryption()
    )
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem)
    _restrict_permissions(path)

    key_id = trust_public_key(_public_pem(key.public_key()))
    config = operator_config()
    config.pop("_corrupt", None)
    config["require_signatures"] = True
    write_operator_config(config)
    return key_id


def key_is_encrypted() -> bool:
    path = private_key_path()
    return path.exists() and b"ENCRYPTED" in path.read_bytes()


def trust_public_key(pem: bytes) -> str:
    """Add a public key (PEM) to the trusted set. Returns its key id."""
    public_key = serialization.load_pem_public_key(pem)
    if not isinstance(public_key, Ed25519PublicKey):
        raise SigningError("Only Ed25519 public keys can be trusted.")
    key_id = key_id_for(public_key)
    tdir = trusted_dir()
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / (key_id.replace(":", "_") + ".pub")).write_bytes(_public_pem(public_key))
    return key_id


def trusted_keys() -> dict[str, Ed25519PublicKey]:
    keys: dict[str, Ed25519PublicKey] = {}
    tdir = trusted_dir()
    if not tdir.exists():
        return keys
    for pub in sorted(tdir.glob("*.pub")):
        try:
            k = serialization.load_pem_public_key(pub.read_bytes())
        except (ValueError, OSError):
            continue
        if isinstance(k, Ed25519PublicKey):
            keys[key_id_for(k)] = k
    return keys


@dataclass
class Signer:
    key: Ed25519PrivateKey
    key_id: str

    def sign(self, message: bytes) -> str:
        return base64.b64encode(self.key.sign(message)).decode("ascii")


_cached_signer: Signer | None = None


def load_signer(passphrase: str | None = None) -> Signer:
    """Load the operator key. Passphrase from argument or AIRLOCK_KEY_PASSPHRASE."""
    global _cached_signer
    path = private_key_path()
    if _cached_signer is not None and passphrase is None:
        return _cached_signer
    if not path.exists():
        raise SigningError(
            "Signatures are required but no operator key exists. Run: airlock keys init"
        )
    secret = passphrase if passphrase is not None else os.environ.get(PASSPHRASE_ENV)
    try:
        key = serialization.load_pem_private_key(
            path.read_bytes(), password=secret.encode("utf-8") if secret else None,
        )
    except TypeError as exc:
        raise SigningError(
            f"The operator key is passphrase-protected. Set {PASSPHRASE_ENV} "
            "or enter the passphrase when prompted."
        ) from exc
    except ValueError as exc:
        raise SigningError("Could not unlock the operator key (wrong passphrase?).") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningError("The operator key is not an Ed25519 key.")
    signer = Signer(key=key, key_id=key_id_for(key.public_key()))
    _cached_signer = signer
    return signer


def clear_cached_signer() -> None:
    global _cached_signer
    _cached_signer = None


def signer_for(policy: dict | None) -> Signer | None:
    """The signer to use for this policy, or None when signing is not required."""
    if not signatures_required(policy):
        return None
    return load_signer()


# ── Evidence signatures ───────────────────────────────────────────────────────

def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def evidence_label(path: Path) -> str:
    """'<candidate_id>/<document>' — binds a signature to one document of one candidate."""
    return f"{path.parent.name}/{path.name}"


def _evidence_message(label: str, sha256_hex: str) -> bytes:
    return EVIDENCE_DOMAIN + label.encode("utf-8") + b"\0" + bytes.fromhex(sha256_hex)


def sig_path_for(path: Path) -> Path:
    return path.with_suffix(path.suffix + SIG_SUFFIX)


def sign_file(path: Path, signer: Signer) -> Path:
    label = evidence_label(path)
    digest = _file_sha256(path)
    record = {
        "alg": "ed25519",
        "key_id": signer.key_id,
        "label": label,
        "sha256": digest,
        "signature": signer.sign(_evidence_message(label, digest)),
    }
    out = sig_path_for(path)
    out.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return out


def verify_file(path: Path) -> tuple[bool, str]:
    """
    Verify <path>.sig against the file and the operator's trusted keys.

    The label is recomputed from the file's own location, so a signature
    copied from another document or candidate does not verify.
    """
    sig_path = sig_path_for(path)
    if not sig_path.exists():
        return False, "signature missing"
    try:
        record = json.loads(sig_path.read_text(encoding="utf-8"))
        key_id = record["key_id"]
        signature = base64.b64decode(record["signature"], validate=True)
    except (OSError, json.JSONDecodeError, KeyError, ValueError):
        return False, "signature malformed"
    if record.get("alg") != "ed25519":
        return False, "unsupported signature algorithm"
    public_key = trusted_keys().get(key_id)
    if public_key is None:
        return False, f"signed by untrusted key {key_id}"
    digest = _file_sha256(path)
    try:
        public_key.verify(signature, _evidence_message(evidence_label(path), digest))
    except InvalidSignature:
        return False, "signature invalid"
    return True, f"signed by {key_id}"


# ── Audit-entry signatures ────────────────────────────────────────────────────

def sign_audit_hash(entry_hash: str, signer: Signer) -> dict:
    sig = signer.sign(AUDIT_DOMAIN + entry_hash.encode("ascii"))
    return {"key_id": signer.key_id, "signature": sig}


def verify_audit_hash(entry_hash: str, sig: dict) -> tuple[bool, str]:
    try:
        key_id = sig["key_id"]
        signature = base64.b64decode(sig["signature"], validate=True)
    except (KeyError, TypeError, ValueError):
        return False, "malformed signature"
    public_key = trusted_keys().get(key_id)
    if public_key is None:
        return False, f"untrusted key {key_id}"
    try:
        public_key.verify(signature, AUDIT_DOMAIN + entry_hash.encode("ascii"))
    except InvalidSignature:
        return False, "invalid signature"
    return True, "ok"
