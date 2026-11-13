from dataclasses import dataclass

from sec_agent.schemas import GeminiInvestigationResult, SeverityLevel, SubQTriageResult

ALLOWED_READONLY_TOOLS = frozenset({"parse_log", "lookup_ioc_local", "write_audit_log"})
CONSEQUENTIAL_ACTIONS = frozenset({"isolate_host", "disable_user", "block_ip", "revoke_token", "execute_shell"})


@dataclass(frozen=True)
class ToolPermissionPolicy:
    """Enforces least-privilege tool boundaries; arbitrary shell execution is always denied."""

    @staticmethod
    def is_tool_allowed(tool_name: str) -> bool:
        normalized = tool_name.strip().lower()
        if normalized in CONSEQUENTIAL_ACTIONS:
            return False
        return normalized in ALLOWED_READONLY_TOOLS


class HumanApprovalGate:
    """Determines whether an assessment requires explicit human review before any action."""

    def __init__(self, confidence_floor: float = 0.65) -> None:
        self.confidence_floor = confidence_floor

    def evaluate(
        self,
        subq: SubQTriageResult,
        gemini: GeminiInvestigationResult | None,
        models_agreed: bool,
        sanitization_warnings: list[str],
        routing_reasons: list[str] | None = None,
    ) -> tuple[bool, str | None]:
        reasons: list[str] = []

        gemini_high = gemini is not None and gemini.severity in {SeverityLevel.HIGH, SeverityLevel.CRITICAL}
        if (
            subq.severity in {SeverityLevel.HIGH, SeverityLevel.CRITICAL}
            or gemini_high
            or subq.escalate_probability >= 0.70
        ):
            reasons.append("high_or_critical_severity")

        if not models_agreed:
            reasons.append("model_disagreement")

        min_conf = min(subq.confidence, gemini.confidence) if gemini is not None else subq.confidence
        if min_conf < self.confidence_floor:
            reasons.append("low_model_confidence")

        if subq.prompt_injection_probability >= 0.5 or any(
            w.startswith("suspected_prompt_injection:") for w in sanitization_warnings
        ):
            reasons.append("suspected_prompt_injection")

        if routing_reasons and any(r.startswith("deterministic_rule:") for r in routing_reasons):
            if "high_or_critical_severity" not in reasons:
                reasons.append("deterministic_high_impact_rule")

        if reasons:
            return True, ", ".join(reasons)
        return False, None
