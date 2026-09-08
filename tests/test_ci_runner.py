"""Unit tests for CI/CD integration and SARIF report generation."""

import json
from pathlib import Path
from crs.cicd.ci_runner import export_sarif_report, format_github_annotations
from crs.core.schemas import CRSRunResult, VulnerabilityFinding, VerificationResult, AnalysisTarget, ReasoningResult, PatchProposal, Severity


def test_sarif_and_github_annotations(tmp_path: Path):
    dummy_target = AnalysisTarget(
        name="test-repo", path=str(tmp_path), languages=["python"], file_count=1, repository_hash="sha"
    )
    dummy_finding = VulnerabilityFinding(
        finding_id="V-1",
        title="Cmd Injection",
        vulnerability_type="Command Injection",
        severity=Severity.HIGH,
        confidence=0.9,
        file="app.py",
        line_start=10,
        evidence=[],
    )
    dummy_reasoning = ReasoningResult(
        finding_id="V-1",
        vulnerability_class="Command Injection",
        root_cause="Shell True",
        security_impact="RCE",
        remediation_strategy="Use list args",
        assumptions=[],
        evidence_references=["app.py:10"],
        confidence=0.9,
    )
    dummy_patch = PatchProposal(
        finding_id="V-1",
        target_file="app.py",
        rationale="Fix shell=True",
        unified_diff="--- app.py\n+++ app.py\n@@ -10 +10 @@\n-eval(x)\n+x",
        expected_security_effect="Safe execution",
        confidence=0.9,
    )
    dummy_verification = VerificationResult(
        build_passed=True,
        tests_passed=True,
        security_test_passed=True,
        static_rescan_clean=True,
        approved=True,
        reason="Verified safe",
    )
    result = CRSRunResult(
        target=dummy_target,
        finding=dummy_finding,
        reasoning=dummy_reasoning,
        patch=dummy_patch,
        verification=dummy_verification,
    )

    sarif_file = tmp_path / "report.sarif"
    export_sarif_report(result, sarif_file)
    assert sarif_file.exists()

    sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "AIKavach VAYU CRS"

    annotation = format_github_annotations(result)
    assert "::notice file=app.py,line=10::" in annotation
