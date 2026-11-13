from sec_agent.audit import AuditLogger
from sec_agent.engine import RoutingPolicy, evaluate_consensus
from sec_agent.gateway import DecisionModelClient, ReasoningModelClient
from sec_agent.schemas import ApprovalRequest, ConsensusAssessment, GeminiInvestigationResult, SecurityEvent
from sec_agent.security import HumanApprovalGate, isolate_untrusted_log


class TriageOrchestrator:
    """Coordinates untrusted input isolation, normalization, SubQ triage, selective Gemini investigation, and auditing."""

    def __init__(
        self,
        decision_client: DecisionModelClient,
        reasoning_client: ReasoningModelClient,
        audit_logger: AuditLogger,
        approval_gate: HumanApprovalGate | None = None,
        routing_policy: RoutingPolicy | None = None,
        enable_intelligent_routing: bool = True,
        deduplicate_events: bool = True,
    ) -> None:
        self.decision_client = decision_client
        self.reasoning_client = reasoning_client
        self.audit_logger = audit_logger
        self.approval_gate = approval_gate or HumanApprovalGate()
        self.routing_policy = routing_policy or RoutingPolicy()
        self.enable_intelligent_routing = enable_intelligent_routing
        self.deduplicate_events = deduplicate_events
        self._pending_assessments: dict[str, ConsensusAssessment] = {}
        self._processed_by_event_id: dict[str, ConsensusAssessment] = {}

    async def process_event(self, event: SecurityEvent) -> ConsensusAssessment:
        if self.deduplicate_events and event.event_id in self._processed_by_event_id:
            return self._processed_by_event_id[event.event_id]

        sanitized = isolate_untrusted_log(event.raw_log)
        subq_result = await self.decision_client.triage_event(event, sanitized.isolated_text)

        gemini_result: GeminiInvestigationResult | None = None
        if self.enable_intelligent_routing:
            route = self.routing_policy.decide(
                subq_result,
                sanitized.isolated_text,
                sanitized.warnings,
                obfuscation_signals=sanitized.obfuscation_signals,
            )
            routing_decision = route.decision_label
            routing_reasons = route.reasons
            if route.invoke_gemini:
                gemini_result = await self.reasoning_client.investigate_event(event, sanitized.isolated_text)
        else:
            routing_decision = "unconditional_combined"
            routing_reasons = ["routing_disabled"]
            gemini_result = await self.reasoning_client.investigate_event(event, sanitized.isolated_text)

        assessment = evaluate_consensus(
            event=event,
            subq=subq_result,
            gemini=gemini_result,
            sanitization_warnings=sanitized.warnings,
            approval_gate=self.approval_gate,
            routing_decision=routing_decision,
            routing_reasons=routing_reasons,
        )
        self._pending_assessments[assessment.assessment_id] = assessment
        self._processed_by_event_id[event.event_id] = assessment
        self.audit_logger.record(assessment)
        return assessment

    def record_human_approval(self, assessment_id: str, request: ApprovalRequest) -> ConsensusAssessment:
        if assessment_id not in self._pending_assessments:
            raise KeyError(f"Unknown assessment_id: {assessment_id}")
        current = self._pending_assessments[assessment_id]
        if hasattr(current, "model_copy"):
            updated = current.model_copy(update={"approved_by_human": request.approved})
        else:
            updated = current.copy(update={"approved_by_human": request.approved})
        self._pending_assessments[assessment_id] = updated
        self.audit_logger.record(updated)
        return updated
