import asyncio
import json
import unittest

import httpx

from sec_agent.gateway.gemini_hydrogen import GeminiAPIError, GeminiHydrogenAdapter
from sec_agent.gateway.subq_snap import SubQAPIError, SubQSnapAdapter
from sec_agent.schemas import SecurityEvent, SeverityLevel, ThreatCategory


class TestLiveAdapterContracts(unittest.TestCase):
    def test_subq_snap_adapter_parses_systemone_response(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.path, "/v1/systemone")
            self.assertEqual(request.headers["Authorization"], "Bearer test-subq-key")
            body = json.loads(request.content.decode("utf-8"))
            self.assertEqual(body["model"], "subq-snap-1.2")
            self.assertIn("category", body["questions"])
            return httpx.Response(
                200,
                json={
                    "model": "subq-snap-1.2",
                    "answers": {
                        "category": {
                            "type": "choice",
                            "choice": "suspicious_execution",
                            "probabilities": {"suspicious_execution": 0.94, "benign": 0.06},
                            "confidence": 0.94,
                        },
                        "severity": {
                            "type": "score",
                            "score": 2.4,
                            "probabilities": {"0": 0.0, "1": 0.1, "2": 0.4, "3": 0.5},
                            "confidence": 0.85,
                        },
                        "escalate": {"type": "noul", "noul": 0.92},
                        "prompt_injection": {"type": "noul", "noul": 0.02},
                    },
                    "usage": {"input_tokens": 310, "output_tokens": 0},
                },
            )

        adapter = SubQSnapAdapter(api_key="test-subq-key", transport=httpx.MockTransport(handler))
        event = SecurityEvent(source="sysmon", host="ws-1", user="alice", raw_log="powershell -enc AAAA")
        result = asyncio.run(adapter.triage_event(event, event.raw_log))
        self.assertEqual(result.category, ThreatCategory.SUSPICIOUS_EXECUTION)
        self.assertEqual(result.severity, SeverityLevel.HIGH)
        self.assertEqual(result.input_tokens, 310)
        self.assertAlmostEqual(result.confidence, 0.85)

    def test_subq_snap_adapter_raises_on_402(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(402, json={"detail": {"error_type": "insufficient_credits"}})

        adapter = SubQSnapAdapter(api_key="test-subq-key", transport=httpx.MockTransport(handler))
        event = SecurityEvent(source="sysmon", raw_log="test")
        with self.assertRaises(SubQAPIError) as ctx:
            asyncio.run(adapter.triage_event(event, event.raw_log))
        self.assertEqual(ctx.exception.status_code, 402)

    def test_gemini_hydrogen_adapter_parses_json_response(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertIn("gemini-4-hydrogen:generateContent", str(request.url))
            self.assertEqual(request.headers["x-goog-api-key"], "test-gemini-key")
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
                                                "category": "data_exfiltration",
                                                "severity": "critical",
                                                "summary": "Large outbound transfer to unknown external IP.",
                                                "indicators_of_compromise": ["198.51.100.77"],
                                                "recommended_actions": ["Review firewall egress logs"],
                                                "uncertainty_notes": [],
                                                "confidence": 0.91,
                                            }
                                        )
                                    }
                                ]
                            }
                        }
                    ],
                    "usageMetadata": {"promptTokenCount": 420, "candidatesTokenCount": 95},
                },
            )

        adapter = GeminiHydrogenAdapter(api_key="test-gemini-key", transport=httpx.MockTransport(handler))
        event = SecurityEvent(source="zeek", host="db-01", user="svc_backup", raw_log="outbound 4.2GB to 198.51.100.77")
        result = asyncio.run(adapter.investigate_event(event, event.raw_log))
        self.assertEqual(result.category, ThreatCategory.DATA_EXFILTRATION)
        self.assertEqual(result.severity, SeverityLevel.CRITICAL)
        self.assertEqual(result.input_tokens, 420)
        self.assertEqual(result.output_tokens, 95)

    def test_gemini_hydrogen_adapter_raises_on_429(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(429, text="Rate limit exceeded")

        adapter = GeminiHydrogenAdapter(api_key="test-gemini-key", transport=httpx.MockTransport(handler))
        event = SecurityEvent(source="zeek", raw_log="test")
        with self.assertRaises(GeminiAPIError) as ctx:
            asyncio.run(adapter.investigate_event(event, event.raw_log))
        self.assertEqual(ctx.exception.status_code, 429)


if __name__ == "__main__":
    unittest.main()
