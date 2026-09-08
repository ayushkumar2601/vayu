"""Unit tests for the Multi-Model Ensemble Client."""

import pytest
from crs.reasoning.ensemble_client import EnsembleClient
from crs.reasoning.llm_client import FakeLLMClient
from crs.core.schemas import EvidencePackage, VulnerabilityFinding, CodeContext, Severity


class FailingLLMClient:
    def reason(self, evidence: EvidencePackage):
        raise RuntimeError("Provider connection failed")


def test_ensemble_client_fallback():
    failing = FailingLLMClient()
    successful = FakeLLMClient()

    ensemble = EnsembleClient([failing, successful])

    dummy_finding = VulnerabilityFinding(
        finding_id="TEST-1",
        title="Test",
        vulnerability_type="Injection",
        severity=Severity.HIGH,
        confidence=0.9,
        file="app.py",
        line_start=1,
        evidence=[],
    )
    dummy_context = CodeContext(
        file="app.py",
        start_line=1,
        end_line=10,
        content="print('test')",
        snippet="print('test')",
        repository_hash="hash",
    )
    evidence = EvidencePackage(
        finding=dummy_finding,
        code_context=dummy_context,
        scanner_evidence=[],
    )

    result = ensemble.reason(evidence)
    assert result.finding_id == "TEST-1"
    assert result.confidence == 0.9
