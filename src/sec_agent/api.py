from fastapi import FastAPI, HTTPException

from sec_agent.audit import AuditLogger
from sec_agent.config import Settings
from sec_agent.engine import RoutingPolicy, UncertaintyPolicy
from sec_agent.gateway import (
    DecisionModelClient,
    GeminiHydrogenAdapter,
    MockGeminiHydrogenClient,
    MockSubQSnapClient,
    ReasoningModelClient,
    SubQSnapAdapter,
)
from sec_agent.orchestrator import TriageOrchestrator
from sec_agent.schemas import ApprovalRequest, ConsensusAssessment, SecurityEvent
from sec_agent.security import HumanApprovalGate


def build_orchestrator(settings: Settings) -> TriageOrchestrator:
    if settings.use_mock_models:
        decision_client: DecisionModelClient = MockSubQSnapClient()
        reasoning_client: ReasoningModelClient = MockGeminiHydrogenClient()
    else:
        decision_client = SubQSnapAdapter(
            api_key=settings.subq_api_key or "",
            base_url=settings.subq_base_url,
            model_id=settings.subq_model_id,
        )
        reasoning_client = GeminiHydrogenAdapter(
            api_key=settings.gemini_api_key or "",
            model_id=settings.gemini_model_id,
            base_url=settings.gemini_base_url,
            thinking_level=settings.gemini_thinking_level,
        )

    routing_policy = RoutingPolicy(
        escalate_threshold=settings.routing_escalate_threshold,
        injection_threshold=settings.routing_injection_threshold,
        uncertainty_policy=UncertaintyPolicy(
            confidence_threshold=settings.routing_confidence_threshold,
            calibration_margin=settings.routing_calibration_margin,
            require_gemini_on_obfuscation=settings.require_gemini_on_obfuscation,
        ),
    )

    return TriageOrchestrator(
        decision_client=decision_client,
        reasoning_client=reasoning_client,
        audit_logger=AuditLogger(settings.audit_log_path),
        approval_gate=HumanApprovalGate(confidence_floor=settings.disagreement_escalation_threshold),
        routing_policy=routing_policy,
        enable_intelligent_routing=settings.enable_intelligent_routing,
    )


settings = Settings()
app = FastAPI(title="SubQ + Gemini Cybersecurity Triage Agent", version="0.3.0")
orchestrator = build_orchestrator(settings)


@app.get("/health")
async def health() -> dict[str, str | bool]:
    return {
        "status": "ok",
        "mock_mode": settings.use_mock_models,
        "intelligent_routing": settings.enable_intelligent_routing,
        "subq_model": settings.subq_model_id,
        "gemini_model": settings.gemini_model_id,
    }


@app.post("/v1/triage", response_model=ConsensusAssessment)
async def triage_event(event: SecurityEvent) -> ConsensusAssessment:
    return await orchestrator.process_event(event)


@app.post("/v1/approvals/{assessment_id}", response_model=ConsensusAssessment)
async def approve_assessment(assessment_id: str, request: ApprovalRequest) -> ConsensusAssessment:
    try:
        return orchestrator.record_human_approval(assessment_id, request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
