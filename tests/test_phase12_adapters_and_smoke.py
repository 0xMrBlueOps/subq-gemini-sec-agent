import asyncio
import json
import unittest

import httpx

from sec_agent.eval.metrics import CaseEvalRecord, compute_mode_metrics
from sec_agent.eval.smoke_test import main as smoke_main, run_one_event_smoke
from sec_agent.gateway.gemini_hydrogen import GeminiAPIError, GeminiHydrogenAdapter
from sec_agent.gateway.subq_snap import SubQAPIError, SubQSnapAdapter
from sec_agent.schemas import SecurityEvent, ThreatCategory


class TestPhase12AdaptersAndSmoke(unittest.TestCase):
    def test_gemini_payload_uses_thinking_level_schema_and_no_temperature(self) -> None:
        adapter = GeminiHydrogenAdapter(api_key="test-key", thinking_level="LOW")
        payload = adapter.build_payload(SecurityEvent(source="sysmon", raw_log="test"), "test")
        gen_cfg = payload["generationConfig"]
        self.assertNotIn("temperature", gen_cfg)
        self.assertEqual(gen_cfg["thinkingConfig"], {"thinkingLevel": "LOW"})
        self.assertIn("responseSchema", gen_cfg)
        self.assertIn("category", gen_cfg["responseSchema"]["properties"])

        with self.assertRaises(ValueError):
            GeminiHydrogenAdapter(api_key="test-key", thinking_level="MINIMAL")

    def test_gemini_multipart_skips_thoughts_and_tracks_thoughts_token_count(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "candidates": [
                        {
                            "finishReason": "STOP",
                            "content": {
                                "parts": [
                                    {"thought": True, "text": "internal reasoning..."},
                                    {
                                        "text": json.dumps(
                                            {
                                                "category": "brute_force",
                                                "severity": "high",
                                                "summary": "SSH brute force",
                                                "indicators_of_compromise": ["203.0.113.1"],
                                                "recommended_actions": ["Review logs"],
                                                "uncertainty_notes": [],
                                                "confidence": 0.91,
                                            }
                                        )
                                    },
                                ]
                            },
                        }
                    ],
                    "usageMetadata": {
                        "promptTokenCount": 200,
                        "candidatesTokenCount": 50,
                        "thoughtsTokenCount": 150,
                    },
                },
            )

        adapter = GeminiHydrogenAdapter(api_key="test-key", transport=httpx.MockTransport(handler))
        res = asyncio.run(adapter.investigate_event(SecurityEvent(source="auth", raw_log="fail"), "fail"))
        self.assertEqual(res.category, ThreatCategory.BRUTE_FORCE)
        self.assertEqual(res.output_tokens, 50)
        self.assertEqual(res.thoughts_tokens, 150)

    def test_gemini_handles_safety_block_and_empty_candidates(self) -> None:
        blocked = httpx.MockTransport(
            lambda _: httpx.Response(200, json={"promptFeedback": {"blockReason": "SAFETY"}})
        )
        adapter_blocked = GeminiHydrogenAdapter(api_key="k", transport=blocked)
        with self.assertRaises(GeminiAPIError) as ctx1:
            asyncio.run(adapter_blocked.investigate_event(SecurityEvent(source="s", raw_log="x"), "x"))
        self.assertEqual(ctx1.exception.status_code, 422)

        safety_finish = httpx.MockTransport(
            lambda _: httpx.Response(200, json={"candidates": [{"finishReason": "SAFETY"}]})
        )
        adapter_finish = GeminiHydrogenAdapter(api_key="k", transport=safety_finish)
        with self.assertRaises(GeminiAPIError) as ctx2:
            asyncio.run(adapter_finish.investigate_event(SecurityEvent(source="s", raw_log="x"), "x"))
        self.assertEqual(ctx2.exception.status_code, 422)

        empty_cands = httpx.MockTransport(lambda _: httpx.Response(200, json={"candidates": []}))
        adapter_empty = GeminiHydrogenAdapter(api_key="k", transport=empty_cands)
        with self.assertRaises(GeminiAPIError) as ctx3:
            asyncio.run(adapter_empty.investigate_event(SecurityEvent(source="s", raw_log="x"), "x"))
        self.assertEqual(ctx3.exception.status_code, 502)

    def test_subq_structured_error_diagnostics_and_retry_after(self) -> None:
        attempts = {"count": 0}

        def handler(_: httpx.Request) -> httpx.Response:
            attempts["count"] += 1
            if attempts["count"] == 1:
                return httpx.Response(429, headers={"Retry-After": "0.01"}, json={"detail": {"error_type": "rate_limit", "message": "slow down"}})
            return httpx.Response(
                422,
                json={"detail": {"error_type": "validation_error", "message": "invalid state"}},
            )

        adapter = SubQSnapAdapter(
            api_key="k",
            max_retries=1,
            retry_backoff_seconds=0.01,
            transport=httpx.MockTransport(handler),
        )
        with self.assertRaises(SubQAPIError) as ctx:
            asyncio.run(adapter.triage_event(SecurityEvent(source="s", raw_log="x"), "x"))
        self.assertEqual(attempts["count"], 2)
        self.assertEqual(ctx.exception.status_code, 422)
        self.assertEqual(ctx.exception.error_type, "validation_error")
        self.assertIn("validation_error: invalid state", str(ctx.exception))

    def test_thoughts_tokens_billed_exactly_once_in_metrics(self) -> None:
        rec = CaseEvalRecord(
            case_id="c1",
            mode="gemini_only",
            execution_type="live",
            expected_category="brute_force",
            predicted_category="brute_force",
            expected_severity="high",
            predicted_severity="high",
            expected_malicious=True,
            predicted_malicious=True,
            expected_escalate=True,
            escalated=True,
            model_confidence=0.9,
            latency_ms=100.0,
            input_tokens=1_000_000,
            output_tokens=100_000,
            gemini_input_tokens=1_000_000,
            gemini_output_tokens=100_000,
            gemini_thoughts_tokens=200_000,
        )
        m = compute_mode_metrics([rec])
        self.assertEqual(m.total_thoughts_tokens, 200_000)
        # $1.50 (1M input) + $7.50 * 0.3 (100k out + 200k thoughts) = $1.50 + $2.25 = $3.75
        self.assertAlmostEqual(m.estimated_cost_usd, 3.75, places=6)

    def test_smoke_test_cli_guards_and_mock_mode(self) -> None:
        self.assertEqual(smoke_main([]), 2)
        self.assertEqual(smoke_main(["--mock"]), 0)
        res = asyncio.run(run_one_event_smoke(use_mock=True))
        self.assertEqual(res["execution_type"], "mock")
        self.assertEqual(res["event_id"], "smoke_evt_001")


if __name__ == "__main__":
    unittest.main()
