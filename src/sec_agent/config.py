import os
from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()


def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


class Settings(BaseModel):
    """Application settings loaded from environment variables."""

    subq_api_key: str | None = Field(default_factory=lambda: os.getenv("SUBQ_API_KEY"))
    subq_base_url: str = Field(default_factory=lambda: os.getenv("SUBQ_BASE_URL", "https://api.subq.ai/v1"))
    subq_model_id: str = Field(default_factory=lambda: os.getenv("SUBQ_MODEL_ID", "subq-snap-1.2"))

    gemini_api_key: str | None = Field(default_factory=lambda: os.getenv("GEMINI_API_KEY"))
    gemini_model_id: str = Field(default_factory=lambda: os.getenv("GEMINI_MODEL_ID", "gemini-4-hydrogen"))

    use_mock_models: bool = Field(default_factory=lambda: _env_bool("USE_MOCK_MODELS", True))
    audit_log_path: str = Field(default_factory=lambda: os.getenv("AUDIT_LOG_PATH", "audit_logs/decisions.jsonl"))
    disagreement_escalation_threshold: float = Field(
        default_factory=lambda: float(os.getenv("DISAGREEMENT_ESCALATION_THRESHOLD", "0.65"))
    )

    # Phase 8-9: Configurable Intelligent Routing & Uncertainty Policy
    enable_intelligent_routing: bool = Field(default_factory=lambda: _env_bool("ENABLE_INTELLIGENT_ROUTING", True))
    routing_confidence_threshold: float = Field(
        default_factory=lambda: float(os.getenv("ROUTING_CONFIDENCE_THRESHOLD", "0.85"))
    )
    routing_escalate_threshold: float = Field(
        default_factory=lambda: float(os.getenv("ROUTING_ESCALATE_THRESHOLD", "0.50"))
    )
    routing_injection_threshold: float = Field(
        default_factory=lambda: float(os.getenv("ROUTING_INJECTION_THRESHOLD", "0.35"))
    )
    routing_calibration_margin: float = Field(
        default_factory=lambda: float(os.getenv("ROUTING_CALIBRATION_MARGIN", "0.20"))
    )
    require_gemini_on_obfuscation: bool = Field(
        default_factory=lambda: _env_bool("REQUIRE_GEMINI_ON_OBFUSCATION", True)
    )
