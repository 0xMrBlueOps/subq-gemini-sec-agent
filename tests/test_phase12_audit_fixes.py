import asyncio
import json
import tempfile
import unittest
from pathlib import Path

import httpx

from sec_agent.api import build_orchestrator
from sec_agent.config import Settings
from sec_agent.eval.report_gen import generate_live_markdown_report
from sec_agent.eval.runner import run_benchmark
from sec_agent.gateway.gemini_hydrogen import GeminiHydrogenAdapter
from sec_agent.gateway.subq_snap import SubQSnapAdapter
from sec_agent.schemas import SecurityEvent


class TestPhase12AuditFixes(unittest.TestCase):
    def test_runner_25_populates_tokens_confidence_and_nonzero_costs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summaries = asyncio.run(run_benchmark(output_dir=tmp, use_mock=True))
            self.assertGreater(summaries["subq_only"].total_input_tokens, 0)
            self.assertGreater(summaries["gemini_only"].estimated_cost_usd, 0.0)
            self.assertGreater(summaries["combined"].estimated_cost_usd, 0.0)
            self.assertGreater(summaries["routed"].estimated_cost_usd, 0.0)
            # Brier score should reflect real confidence (~0.02-0.06), not defaulted 0.0 (~0.84-1.0)
            self.assertLess(summaries["gemini_only"].brier_score, 0.20)
            self.assertLess(summaries["combined"].brier_score, 0.20)
            self.assertLess(summaries["routed"].brier_score, 0.20)

    def test_build_orchestrator_propagates_uncertainty_settings(self) -> None:
        cfg = Settings(
            use_mock_models=True,
            routing_confidence_threshold=0.91,
            routing_calibration_margin=0.42,
            require_gemini_on_obfuscation=False,
        )
        orch = build_orchestrator(cfg)
        self.assertAlmostEqual(orch.routing_policy.uncertainty.confidence_threshold, 0.91)
        self.assertAlmostEqual(orch.routing_policy.uncertainty.calibration_margin, 0.42)
        self.assertFalse(orch.routing_policy.uncertainty.require_gemini_on_obfuscation)

    def test_adapters_handle_missing_and_null_usage_fields(self) -> None:
        gemini_null = httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "candidates": [
                        {
                            "finishReason": "STOP",
                            "content": {
                                "parts": [
                                    {
                                        "text": json.dumps(
                                            {
                                                "category": "benign",
                                                "severity": "low",
                                                "summary": "ok",
                                                "indicators_of_compromise": [],
                                                "recommended_actions": [],
                                                "uncertainty_notes": [],
                                                "confidence": 0.9,
                                            }
                                        )
                                    }
                                ]
                            },
                        }
                    ],
                    "usageMetadata": {
                        "promptTokenCount": None,
                        "candidatesTokenCount": None,
                        "thoughtsTokenCount": None,
                    },
                },
            )
        )
        gem_res = asyncio.run(
            GeminiHydrogenAdapter(api_key="k", transport=gemini_null).investigate_event(
                SecurityEvent(source="s", raw_log="x"), "x"
            )
        )
        self.assertEqual((gem_res.input_tokens, gem_res.output_tokens, gem_res.thoughts_tokens), (0, 0, 0))

        subq_null = httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "model": "subq-snap-1.2",
                    "answers": {
                        "category": {"choice": "benign", "probabilities": {"benign": 0.95}, "confidence": 0.95},
                        "severity": {"score": 0.0, "confidence": 0.95},
                        "escalate": {"noul": 0.02},
                        "prompt_injection": {"noul": 0.01},
                    },
                    "usage": None,
                },
            )
        )
        subq_res = asyncio.run(
            SubQSnapAdapter(api_key="k", transport=subq_null).triage_event(
                SecurityEvent(source="s", raw_log="x"), "x"
            )
        )
        self.assertEqual(subq_res.input_tokens, 0)

    def test_markdown_report_includes_three_token_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "summary.csv"
            md_path = Path(tmp) / "report.md"
            csv_path.write_text(
                "split,mode,tp,fp,tn,fn,precision,recall,escalation_recall,avg_latency_ms,p95_latency_ms,total_input_tokens,total_output_tokens,total_thoughts_tokens,estimated_cost_usd\n"
                "held_out,routed,60,0,60,0,1.0,1.0,1.0,120.0,255.0,8000,1500,300,0.0255\n",
                encoding="utf-8",
            )
            generate_live_markdown_report(csv_path, md_path)
            content = md_path.read_text(encoding="utf-8")
            self.assertIn("Input Tokens", content)
            self.assertIn("Output Tokens", content)
            self.assertIn("Thinking Tokens", content)
            self.assertIn("| 8000 | 1500 | 300 |", content)


if __name__ == "__main__":
    unittest.main()
