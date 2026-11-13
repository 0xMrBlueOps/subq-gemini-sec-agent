import asyncio
import json
import tempfile
import unittest
from pathlib import Path

import httpx

from sec_agent.audit import AuditLogger
from sec_agent.config import Settings
from sec_agent.eval.preflight import run_preflight
from sec_agent.gateway import MockGeminiHydrogenClient, MockSubQSnapClient
from sec_agent.gateway.gemini_hydrogen import GeminiAPIError, GeminiHydrogenAdapter
from sec_agent.gateway.subq_snap import SubQAPIError, SubQSnapAdapter
from sec_agent.orchestrator import TriageOrchestrator
from sec_agent.schemas import SecurityEvent


class TestPhase10ReliabilityAndPreflight(unittest.TestCase):
    def test_subq_retries_429_then_succeeds(self) -> None:
        attempts = {"count": 0}

        def handler(_: httpx.Request) -> httpx.Response:
            attempts["count"] += 1
            if attempts["count"] == 1:
                return httpx.Response(429, text="rate limited")
            return httpx.Response(
                200,
                json={
                    "model": "subq-snap-1.2",
                    "answers": {
                        "category": {"choice": "benign", "probabilities": {"benign": 0.95}, "confidence": 0.95},
                        "severity": {"score": 0.0, "confidence": 0.95},
                        "escalate": {"noul": 0.02},
                        "prompt_injection": {"noul": 0.01},
                    },
                    "usage": {"input_tokens": 100},
                },
            )

        adapter = SubQSnapAdapter(
            api_key="test-key",
            max_retries=2,
            retry_backoff_seconds=0.01,
            transport=httpx.MockTransport(handler),
        )
        res = asyncio.run(adapter.triage_event(SecurityEvent(source="test", raw_log="ok"), "ok"))
        self.assertEqual(attempts["count"], 2)
        self.assertEqual(res.input_tokens, 100)

    def test_subq_timeout_raises_504_after_retries(self) -> None:
        attempts = {"count": 0}

        def handler(_: httpx.Request) -> httpx.Response:
            attempts["count"] += 1
            raise httpx.ReadTimeout("timed out")

        adapter = SubQSnapAdapter(
            api_key="test-key",
            max_retries=1,
            retry_backoff_seconds=0.01,
            transport=httpx.MockTransport(handler),
        )
        with self.assertRaises(SubQAPIError) as ctx:
            asyncio.run(adapter.triage_event(SecurityEvent(source="test", raw_log="ok"), "ok"))
        self.assertEqual(attempts["count"], 2)
        self.assertEqual(ctx.exception.status_code, 504)

    def test_subq_402_fails_fast_without_retry(self) -> None:
        attempts = {"count": 0}

        def handler(_: httpx.Request) -> httpx.Response:
            attempts["count"] += 1
            return httpx.Response(402, text="no credits")

        adapter = SubQSnapAdapter(
            api_key="test-key",
            max_retries=2,
            retry_backoff_seconds=0.01,
            transport=httpx.MockTransport(handler),
        )
        with self.assertRaises(SubQAPIError) as ctx:
            asyncio.run(adapter.triage_event(SecurityEvent(source="test", raw_log="ok"), "ok"))
        self.assertEqual(attempts["count"], 1)
        self.assertEqual(ctx.exception.status_code, 402)

    def test_gemini_missing_or_nan_confidence_clamps_to_zero(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "candidates": [
                        {
                            "content": {
                                "parts": [
                                    {
                                        "text": json.dumps(
                                            {
                                                "category": "brute_force",
                                                "severity": "medium",
                                                "summary": "Possible brute force",
                                                "confidence": "not-a-number",
                                            }
                                        )
                                    }
                                ]
                            }
                        }
                    ],
                    "usageMetadata": {"promptTokenCount": 50, "candidatesTokenCount": 20},
                },
            )

        adapter = GeminiHydrogenAdapter(
            api_key="test-key",
            max_retries=0,
            transport=httpx.MockTransport(handler),
        )
        res = asyncio.run(adapter.investigate_event(SecurityEvent(source="auth", raw_log="fail"), "fail"))
        self.assertEqual(res.confidence, 0.0)

    def test_orchestrator_deduplicates_identical_event_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit_file = Path(tmp) / "audit.jsonl"
            orch = TriageOrchestrator(
                decision_client=MockSubQSnapClient(),
                reasoning_client=MockGeminiHydrogenClient(),
                audit_logger=AuditLogger(audit_file),
                deduplicate_events=True,
            )
            ev = SecurityEvent(event_id="evt_dup_1", source="auth", raw_log="Accepted publickey for deploy")
            a1 = asyncio.run(orch.process_event(ev))
            a2 = asyncio.run(orch.process_event(ev))
            self.assertEqual(a1.assessment_id, a2.assessment_id)
            self.assertEqual(len(audit_file.read_text(encoding="utf-8").splitlines()), 1)

    def test_preflight_masks_secrets_and_reports_not_ready_without_keys(self) -> None:
        cfg = Settings(subq_api_key="sk-secret-value-123456", gemini_api_key=None)
        rep = asyncio.run(run_preflight(settings=cfg, check_network=False))
        dumped = json.dumps(rep)
        self.assertNotIn("sk-secret-value-123456", dumped)
        self.assertEqual(rep["config"]["gemini_api_key"], "missing")
        self.assertFalse(rep["ready_for_live_eval"])


if __name__ == "__main__":
    unittest.main()
