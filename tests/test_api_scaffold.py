import asyncio
from pathlib import Path

from fastapi.testclient import TestClient

from sec_agent.api import app
from sec_agent.audit import AuditLogger
from sec_agent.gateway import MockGeminiHydrogenClient, MockSubQSnapClient
from sec_agent.orchestrator import TriageOrchestrator
from sec_agent.schemas import SecurityEvent


def test_health_endpoint() -> None:
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["subq_model"] == "subq-snap-1.2"
    assert body["gemini_model"] == "gemini-4-hydrogen"


def test_orchestrator_end_to_end_mock(tmp_path: Path) -> None:
    audit_file = tmp_path / "decisions.jsonl"
    orch = TriageOrchestrator(
        decision_client=MockSubQSnapClient(),
        reasoning_client=MockGeminiHydrogenClient(),
        audit_logger=AuditLogger(audit_file),
    )
    event = SecurityEvent(
        source="windows-sysmon",
        host="ws-042",
        user="jdoe",
        raw_log="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ...",
    )
    assessment = asyncio.run(orch.process_event(event))
    assert assessment.models_agreed is True
    assert assessment.requires_human_approval is True
    assert assessment.approval_reason == "high_or_critical_severity"
    assert audit_file.exists()
    assert len(audit_file.read_text(encoding="utf-8").splitlines()) == 1
