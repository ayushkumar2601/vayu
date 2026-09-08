"""Multi-provider LLM Ensemble Client for reasoning and patching."""

from __future__ import annotations

from typing import Protocol
from crs.core.schemas import EvidencePackage, ReasoningResult, PatchProposal, VulnerabilityFinding
from crs.reasoning.llm_client import LLMClient
from crs.patching.patch_generator import PatchLLMClient


class EnsembleClient:
    """Orchestrates primary and fallback LLMs for vulnerability reasoning and patching."""

    def __init__(self, clients: list[LLMClient]) -> None:
        if not clients:
            raise ValueError("EnsembleClient requires at least one client provider.")
        self.clients = clients

    def reason(self, evidence: EvidencePackage) -> ReasoningResult:
        """Query clients in sequence until a valid reasoning result is produced."""
        errors = []
        for client in self.clients:
            try:
                res = client.reason(evidence)
                if res and res.confidence > 0.0:
                    return res
            except Exception as exc:
                errors.append(str(exc))
        raise RuntimeError(f"All ensemble reasoning providers failed: {'; '.join(errors)}")

    def generate_patch(
        self,
        finding: VulnerabilityFinding,
        reasoning: ReasoningResult,
        code_context: object,
    ) -> PatchProposal:
        """Query patch clients in sequence until a valid patch proposal is returned."""
        errors = []
        for client in self.clients:
            if hasattr(client, "generate_patch"):
                try:
                    patch = client.generate_patch(finding, reasoning, code_context)
                    if patch and patch.unified_diff:
                        return patch
                except Exception as exc:
                    errors.append(str(exc))
        raise RuntimeError(f"All ensemble patch providers failed: {'; '.join(errors)}")
