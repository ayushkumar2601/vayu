"""Cryptographic SLSA v1.0 Provenance Attestation and In-Toto signing."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def generate_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate an ECDSA (P-256) private/public keypair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def sign_provenance_payload(
    payload: dict[str, object], private_key: ec.EllipticCurvePrivateKey
) -> str:
    """Sign a JSON payload using ECDSA SHA-256 and return base64 signature."""
    serialized = json.dumps(payload, sort_keys=True).encode("utf-8")
    signature = private_key.sign(serialized, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode("utf-8")


def verify_provenance_signature(
    payload: dict[str, object],
    signature_b64: str,
    public_key: ec.EllipticCurvePublicKey,
) -> bool:
    """Verify an ECDSA SHA-256 signature against a JSON payload."""
    serialized = json.dumps(payload, sort_keys=True).encode("utf-8")
    signature = base64.b64decode(signature_b64.encode("utf-8"))
    try:
        public_key.verify(signature, serialized, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def build_slsa_attestation(
    record: dict[str, object],
    private_key: ec.EllipticCurvePrivateKey | None = None,
) -> dict[str, object]:
    """Wrap a CRS run record into an in-toto SLSA v1.0 predicate attestation."""
    target = record.get("target", {})
    patch = record.get("patch", {})

    predicate = {
        "buildDefinition": {
            "buildType": "https://aikavach.ai/vayu/crs-remediation/v1",
            "externalParameters": {
                "repository_sha256": target.get("repository_sha256"),
                "target_file": patch.get("target_file"),
            },
            "systemParameters": {
                "verification_policy": "fail-closed",
                "final_decision": record.get("final_decision"),
            },
        },
        "runDetails": {
            "builder": {"id": "https://github.com/aikavach/vayu-crs"},
            "metadata": {
                "invocationId": record.get("run_id"),
                "startedOn": record.get("timestamp_utc"),
                "finishedOn": record.get("timestamp_utc"),
            },
        },
    }

    statement: dict[str, object] = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [
            {
                "name": target.get("name") or "target-repository",
                "digest": {"sha256": target.get("repository_sha256") or ""},
            },
            {
                "name": patch.get("target_file") or "patch",
                "digest": {"sha256": patch.get("patch_sha256") or ""},
            },
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": predicate,
    }

    if private_key is not None:
        pub_pem = (
            private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )
        sig = sign_provenance_payload(statement, private_key)
        statement["signatures"] = [
            {
                "keyid": hashlib.sha256(pub_pem.encode("utf-8")).hexdigest()[:16],
                "sig": sig,
            }
        ]

    return statement
