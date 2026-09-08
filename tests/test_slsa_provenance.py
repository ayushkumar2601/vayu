"""Unit tests for cryptographic SLSA provenance and ECDSA signing."""

from crs.reporting.slsa_provenance import (
    build_slsa_attestation,
    generate_keypair,
    sign_provenance_payload,
    verify_provenance_signature,
)


def test_slsa_provenance_signing_and_verification():
    private_key, public_key = generate_keypair()

    dummy_record = {
        "run_id": "test-run-123",
        "timestamp_utc": "2026-09-08T08:00:00Z",
        "target": {
            "name": "sample-repo",
            "repository_sha256": "abc123sha256",
        },
        "patch": {
            "target_file": "app.py",
            "patch_sha256": "def456sha256",
        },
        "final_decision": "VERIFIED",
    }

    attestation = build_slsa_attestation(dummy_record, private_key=private_key)
    assert attestation["_type"] == "https://in-toto.io/Statement/v0.1"
    assert attestation["predicateType"] == "https://slsa.dev/provenance/v1"
    assert "signatures" in attestation

    sig_b64 = attestation["signatures"][0]["sig"]
    
    # Verify valid signature
    clean_statement = {k: v for k, v in attestation.items() if k != "signatures"}
    assert verify_provenance_signature(clean_statement, sig_b64, public_key) is True

    # Verify invalid signature or modified payload
    modified_statement = dict(clean_statement)
    modified_statement["_type"] = "tampered"
    assert verify_provenance_signature(modified_statement, sig_b64, public_key) is False
