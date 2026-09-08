"""CI/CD integration, SARIF report exporter, and GitHub Action runner."""

from __future__ import annotations

import json
from pathlib import Path
from crs.core.schemas import CRSRunResult


def export_sarif_report(result: CRSRunResult, output_path: Path) -> Path:
    """Export a SARIF v2.1.0 security report for GitHub Security Tab / CI pipelines."""
    finding = result.finding
    rule_id = finding.vulnerability_type.lower().replace(" ", "-")

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AIKavach VAYU CRS",
                        "version": "1.0.0",
                        "rules": [
                            {
                                "id": rule_id,
                                "shortDescription": {"text": finding.vulnerability_type},
                                "fullDescription": {"text": finding.title},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": rule_id,
                        "level": "error" if str(finding.severity).upper() in ("HIGH", "CRITICAL") else "warning",
                        "message": {"text": f"Remediated by AIKavach: {result.verification.approved}"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": finding.file},
                                    "region": {"startLine": finding.line_start},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }

    output_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return output_path


def format_github_annotations(result: CRSRunResult) -> str:
    """Format GitHub Actions workflow annotations for PR comments."""
    finding = result.finding
    decision = "VERIFIED" if result.verification.approved else "REJECTED"
    level = "notice" if result.verification.approved else "error"

    return f"::{level} file={finding.file},line={finding.line_start}::AIKavach VAYU Remediation {decision}: {finding.vulnerability_type}"
