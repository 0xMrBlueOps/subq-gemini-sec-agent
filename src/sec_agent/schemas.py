from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class ThreatCategory(str, Enum):
    BRUTE_FORCE = "brute_force"
    SUSPICIOUS_LOGIN = "suspicious_login"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUSPICIOUS_EXECUTION = "suspicious_execution"
    DATA_EXFILTRATION = "data_exfiltration"
    PROMPT_INJECTION = "prompt_injection"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: f"evt_{uuid4().hex[:12]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = Field(..., min_length=1, max_length=128)
    host: str = Field(default="unknown", max_length=128)
    user: str = Field(default="unknown", max_length=128)
    raw_log: str = Field(..., min_length=1, max_length=200_000)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SubQTriageResult(BaseModel):
    model: str
    category: ThreatCategory
    category_probabilities: dict[str, float] = Field(default_factory=dict)
    severity: SeverityLevel
    severity_score: float = Field(..., ge=0.0, le=10.0)
    escalate_probability: float = Field(..., ge=0.0, le=1.0)
    prompt_injection_probability: float = Field(..., ge=0.0, le=1.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    input_tokens: int = 0
    latency_ms: float = 0.0


class GeminiInvestigationResult(BaseModel):
    model: str
    category: ThreatCategory
    severity: SeverityLevel
    summary: str
    indicators_of_compromise: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    uncertainty_notes: list[str] = Field(default_factory=list)
    confidence: float = Field(..., ge=0.0, le=1.0)
    input_tokens: int = 0
    output_tokens: int = 0
    thoughts_tokens: int = 0
    latency_ms: float = 0.0


class ConsensusAssessment(BaseModel):
    assessment_id: str = Field(default_factory=lambda: f"asm_{uuid4().hex[:12]}")
    event_id: str
    final_category: ThreatCategory
    final_severity: SeverityLevel
    risk_score: float = Field(..., ge=0.0, le=100.0)
    models_agreed: bool
    disagreements: list[str] = Field(default_factory=list)
    requires_human_approval: bool
    approval_reason: str | None = None
    approved_by_human: bool | None = None
    routing_decision: str = "escalated_to_gemini"
    routing_reasons: list[str] = Field(default_factory=list)
    subq_result: SubQTriageResult
    gemini_result: GeminiInvestigationResult | None = None
    sanitization_warnings: list[str] = Field(default_factory=list)


class ApprovalRequest(BaseModel):
    reviewer: str = Field(..., min_length=1, max_length=100)
    approved: bool
    notes: str = Field(default="", max_length=1000)


class AuditRecord(BaseModel):
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    assessment: ConsensusAssessment
