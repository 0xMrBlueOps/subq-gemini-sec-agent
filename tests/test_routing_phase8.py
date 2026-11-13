import asyncio
import tempfile
import unittest
from pathlib import Path

from sec_agent.audit import AuditLogger
from sec_agent.engine import RoutingPolicy
from sec_agent.gateway import MockGeminiHydrogenClient, MockSubQSnapClient, ReasoningModelClient
from sec_agent.orchestrator import TriageOrchestrator
from sec_agent.schemas import GeminiInvestigationResult, SecurityEvent, SeverityLevel, SubQTriageResult, ThreatCategory


class _SpyGeminiClient(ReasoningModelClient):
    def __init__(self, forced_category: ThreatCategory = ThreatCategory.BENIGN, forced_sev: SeverityLevel = SeverityLevel.LOW) -> None:
        self.calls = 0
        self.forced_category = forced_category
        self.forced_sev = forced_sev

    async def investigate_event(self, event: SecurityEvent, isolated_log: str) -> GeminiInvestigationResult:
        self.calls += 1
        return GeminiInvestigationResult(
            model="spy-gemini",
            category=self.forced_category,
            severity=self.forced_sev,
            summary="Spy investigation",
            confidence=0.88,
        )


class _FixedSubQClient:
    def __init__(self, result: SubQTriageResult) -> None:
        self.result = result

    async def triage_event(self, event: SecurityEvent, isolated_log: str) -> SubQTriageResult:
        return self.result


class TestIntelligentRoutingPhase8(unittest.TestCase):
    def test_routine_high_confidence_benign_uses_subq_fast_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            spy = _SpyGeminiClient()
            orch = TriageOrchestrator(
                decision_client=MockSubQSnapClient(),
                reasoning_client=spy,
                audit_logger=AuditLogger(Path(tmp) / "audit.jsonl"),
                enable_intelligent_routing=True,
            )
            ev = SecurityEvent(
                source="linux-auth",
                host="app-01",
                user="deploy",
                raw_log="sshd[1012]: Accepted publickey for deploy from 10.20.1.5 port 51200 ssh2",
            )
            asm = asyncio.run(orch.process_event(ev))
            self.assertEqual(spy.calls, 0)
            self.assertEqual(asm.routing_decision, "subq_fast_path")
            self.assertIsNone(asm.gemini_result)
            self.assertFalse(asm.requires_human_approval)

    def test_low_confidence_benign_invokes_gemini(self) -> None:
        policy = RoutingPolicy(confidence_threshold=0.85)
        subq = SubQTriageResult(
            model="subq",
            category=ThreatCategory.BENIGN,
            severity=SeverityLevel.LOW,
            severity_score=1.0,
            escalate_probability=0.1,
            prompt_injection_probability=0.0,
            confidence=0.60,
        )
        route = policy.decide(subq, "routine check", [])
        self.assertTrue(route.invoke_gemini)
        self.assertTrue(any(r.startswith("low_confidence:") for r in route.reasons))

    def test_medium_severity_invokes_gemini(self) -> None:
        policy = RoutingPolicy()
        subq = SubQTriageResult(
            model="subq",
            category=ThreatCategory.BENIGN,
            severity=SeverityLevel.MEDIUM,
            severity_score=5.0,
            escalate_probability=0.2,
            prompt_injection_probability=0.0,
            confidence=0.95,
        )
        route = policy.decide(subq, "ordinary log", [])
        self.assertTrue(route.invoke_gemini)
        self.assertIn("elevated_severity:medium", route.reasons)

    def test_prompt_injection_invokes_gemini(self) -> None:
        policy = RoutingPolicy(injection_threshold=0.35)
        subq = SubQTriageResult(
            model="subq",
            category=ThreatCategory.BENIGN,
            severity=SeverityLevel.LOW,
            severity_score=1.0,
            escalate_probability=0.1,
            prompt_injection_probability=0.45,
            confidence=0.95,
        )
        route = policy.decide(subq, "benign looking text", [])
        self.assertTrue(route.invoke_gemini)
        self.assertIn("prompt_injection_indicator", route.reasons)

    def test_deterministic_high_impact_rule_overrides_benign_subq(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            spy = _SpyGeminiClient(forced_category=ThreatCategory.PRIVILEGE_ESCALATION, forced_sev=SeverityLevel.CRITICAL)
            benign_subq = _FixedSubQClient(
                SubQTriageResult(
                    model="subq",
                    category=ThreatCategory.BENIGN,
                    severity=SeverityLevel.LOW,
                    severity_score=1.0,
                    escalate_probability=0.05,
                    prompt_injection_probability=0.0,
                    confidence=0.99,
                )
            )
            orch = TriageOrchestrator(
                decision_client=benign_subq,  # type: ignore[arg-type]
                reasoning_client=spy,
                audit_logger=AuditLogger(Path(tmp) / "audit.jsonl"),
                enable_intelligent_routing=True,
            )
            ev = SecurityEvent(
                source="linux-audit",
                raw_log="user intern01 edited /etc/sudoers with NOPASSWD:ALL",
            )
            asm = asyncio.run(orch.process_event(ev))
            self.assertEqual(spy.calls, 1)
            self.assertEqual(asm.routing_decision, "escalated_to_gemini")
            self.assertFalse(asm.models_agreed)
            self.assertTrue(asm.requires_human_approval)
            self.assertIn("model_disagreement", asm.approval_reason or "")


if __name__ == "__main__":
    unittest.main()
