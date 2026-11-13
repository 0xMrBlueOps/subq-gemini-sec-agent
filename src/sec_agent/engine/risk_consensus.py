from sec_agent.schemas import (
    ConsensusAssessment,
    GeminiInvestigationResult,
    SecurityEvent,
    SeverityLevel,
    SubQTriageResult,
    ThreatCategory,
)
from sec_agent.security.guardrails import HumanApprovalGate

_SEVERITY_RANK = {
    SeverityLevel.LOW: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.HIGH: 3,
    SeverityLevel.CRITICAL: 4,
}


def evaluate_consensus(
    event: SecurityEvent,
    subq: SubQTriageResult,
    gemini: GeminiInvestigationResult | None,
    sanitization_warnings: list[str],
    approval_gate: HumanApprovalGate,
    routing_decision: str = "escalated_to_gemini",
    routing_reasons: list[str] | None = None,
) -> ConsensusAssessment:
    """Compare SubQ Snap and optional Gemini outputs; never let BENIGN override a detected threat on disagreement."""
    disagreements: list[str] = []
    reasons_list = routing_reasons or []

    if gemini is None:
        models_agreed = True
        final_severity = subq.severity
        final_category = subq.category
        avg_confidence = subq.confidence
    else:
        if subq.category != gemini.category:
            disagreements.append(f"category_mismatch: subq={subq.category.value} vs gemini={gemini.category.value}")

        if subq.severity != gemini.severity:
            disagreements.append(f"severity_mismatch: subq={subq.severity.value} vs gemini={gemini.severity.value}")

        models_agreed = len(disagreements) == 0
        subq_rank = _SEVERITY_RANK[subq.severity]
        gem_rank = _SEVERITY_RANK[gemini.severity]
        final_severity = subq.severity if subq_rank >= gem_rank else gemini.severity

        if models_agreed:
            final_category = subq.category
        elif gemini.category == ThreatCategory.BENIGN and subq.category != ThreatCategory.BENIGN:
            # Never allow a BENIGN classification to erase a threat flagged by SubQ
            final_category = subq.category
        elif subq.category == ThreatCategory.BENIGN and gemini.category != ThreatCategory.BENIGN:
            final_category = gemini.category
        else:
            final_category = subq.category if subq_rank >= gem_rank else gemini.category

        avg_confidence = (subq.confidence + gemini.confidence) / 2.0

    risk_score = round(min(100.0, (subq.severity_score * 10.0) * (0.5 + 0.5 * avg_confidence)), 2)

    requires_approval, approval_reason = approval_gate.evaluate(
        subq=subq,
        gemini=gemini,
        models_agreed=models_agreed,
        sanitization_warnings=sanitization_warnings,
        routing_reasons=reasons_list,
    )

    return ConsensusAssessment(
        event_id=event.event_id,
        final_category=final_category,
        final_severity=final_severity,
        risk_score=risk_score,
        models_agreed=models_agreed,
        disagreements=disagreements,
        requires_human_approval=requires_approval,
        approval_reason=approval_reason,
        routing_decision=routing_decision,
        routing_reasons=reasons_list,
        subq_result=subq,
        gemini_result=gemini,
        sanitization_warnings=sanitization_warnings,
    )
