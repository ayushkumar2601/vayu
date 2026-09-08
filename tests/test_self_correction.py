"""Unit tests for multi-iterative patch retries and self-correction."""

from pathlib import Path
from unittest.mock import Mock
import pytest
from crs.orchestrator import CRSPipeline
from crs.reasoning.llm_client import FakeLLMClient
from crs.patching.patch_generator import FakePatchLLMClient
from crs.core.schemas import VulnerabilityFinding, Severity, Evidence, VerificationResult


def test_self_correction_retry_loop(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app_file = repo / "app.py"
    app_file.write_text("subprocess.run(command, shell=True, check=False)\n", encoding="utf-8")

    dummy_finding = VulnerabilityFinding(
        finding_id="SF-TEST",
        title="Unsafe shell execution",
        vulnerability_type="Subprocess Shell True",
        severity=Severity.HIGH,
        confidence=0.9,
        file=str(app_file),
        line_start=1,
        line_end=1,
        evidence=[
            Evidence(
                source="semgrep",
                description="shell=True",
                file=str(app_file),
                line=1,
                raw_reference="rules.semgrep.subprocess-shell-true",
            )
        ],
    )

    mock_scanner = Mock()
    mock_scanner.scan.return_value = [dummy_finding]

    mock_verifier = Mock()
    # First attempt fails, second attempt succeeds
    mock_verifier.verify.side_effect = [
        VerificationResult(
            build_passed=True,
            tests_passed=False,
            security_test_passed=True,
            static_rescan_clean=True,
            approved=False,
            reason="Syntax or test failed on attempt 1",
        ),
        VerificationResult(
            build_passed=True,
            tests_passed=True,
            security_test_passed=True,
            static_rescan_clean=True,
            approved=True,
            reason="Verified safe on attempt 2",
        ),
    ]

    reasoning_client = FakeLLMClient()
    patch_client = FakePatchLLMClient(
        {"replacement_line": "subprocess.run(command.split(), shell=False, check=False)"}
    )

    pipeline = CRSPipeline(
        reasoning_client=reasoning_client,
        patch_client=patch_client,
        scanner=mock_scanner,
        verifier=mock_verifier,
    )

    result = pipeline.run(str(repo), max_retries=2)
    assert result.verification.approved is True
    assert mock_verifier.verify.call_count == 2
