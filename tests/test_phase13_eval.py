import asyncio
import json
import tempfile
import unittest
from pathlib import Path

import httpx

from sec_agent.config import Settings
from sec_agent.eval.dataset_phase13 import build_phase13_dataset
from sec_agent.eval.phase13_runner import main as p13_main, run_phase13_evaluation
from sec_agent.gateway.gemini_hydrogen import GeminiHydrogenAdapter
from sec_agent.gateway.subq_snap import SubQSnapAdapter


class TestPhase13Evaluation(unittest.TestCase):
    def test_dataset_16_cases_balance_and_neutral_ids(self) -> None:
        cases = build_phase13_dataset()
        self.assertEqual(len(cases), 16)
        self.assertEqual(sum(1 for c in cases if c.expected_malicious), 10)
        self.assertEqual(sum(1 for c in cases if not c.expected_malicious), 6)
        for idx, c in enumerate(cases, start=1):
            expected_id = f"p13_evt_{idx:02d}"
            self.assertEqual(c.case_id, expected_id)
            self.assertEqual(c.event.event_id, expected_id)

        # Verify Argon's 3 dataset corrections
        by_id = {c.case_id: c for c in cases}
        self.assertIn("suspected ntlm-based lateral movement", by_id["p13_evt_09"].technique_or_rationale.lower())
        self.assertNotIn("pass-the-hash is proven", by_id["p13_evt_09"].technique_or_rationale.lower())
        self.assertIn("t1543.002", by_id["p13_evt_11"].technique_or_rationale.lower())
        self.assertIn("iam user", by_id["p13_evt_15"].technique_or_rationale.lower())

    def test_ground_truth_labels_never_enter_model_payloads(self) -> None:
        cases = build_phase13_dataset()
        subq = SubQSnapAdapter(api_key="test-key")
        gem = GeminiHydrogenAdapter(api_key="test-key")
        for c in cases:
            s_payload = json.dumps(subq.build_payload(c.event, c.event.raw_log))
            g_payload = json.dumps(gem.build_payload(c.event, c.event.raw_log))
            for forbidden in ("expected_category", "expected_severity", "expected_malicious", "expected_escalate", "subq_only", "gemini_only"):
                self.assertNotIn(forbidden, s_payload)
                self.assertNotIn(forbidden, g_payload)

    def test_mock_mode_evaluates_all_four_modes_without_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            res = asyncio.run(run_phase13_evaluation(output_base=tmp, use_mock=True, max_cases=16))
            self.assertEqual(set(res["summaries"].keys()), {"subq_only", "gemini_only", "combined", "routed"})
            run_dir = Path(res["run_dir"])
            self.assertTrue((run_dir / "results.jsonl").exists())
            self.assertTrue((run_dir / "summary.csv").exists())
            self.assertTrue((run_dir / "meta.json").exists())
            self.assertTrue((run_dir / "PHASE13_REPORT.md").exists())
            self.assertEqual(len((run_dir / "results.jsonl").read_text(encoding="utf-8").splitlines()), 64)
            self.assertEqual(p13_main(["--output-base", tmp, "--max-cases", "4"]), 0)

    def test_scoped_idempotency_keys_and_per_case_error_resilience(self) -> None:
        seen_keys: list[str] = []
        seen_event_ids: list[str] = []

        def subq_handler(request: httpx.Request) -> httpx.Response:
            seen_keys.append(request.headers["X-Idempotency-Key"])
            body = json.loads(request.content.decode("utf-8"))
            ev_id = body["state"]["event_id"]
            seen_event_ids.append(ev_id)
            if ev_id == "p13_evt_02":
                return httpx.Response(422, json={"detail": {"error_type": "validation_error", "message": "simulated failure"}})
            return httpx.Response(
                200,
                json={
                    "model": "subq-snap-1.2",
                    "answers": {
                        "category": {"choice": "benign", "probabilities": {"benign": 0.95}, "confidence": 0.95},
                        "severity": {"score": 0.0, "confidence": 0.95},
                        "escalate": {"noul": 0.05},
                        "prompt_injection": {"noul": 0.01},
                    },
                    "usage": {"input_tokens": 100},
                },
            )

        def gem_handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
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
                    "usageMetadata": {"promptTokenCount": 120, "candidatesTokenCount": 40, "thoughtsTokenCount": 10},
                },
            )

        with tempfile.TemporaryDirectory() as tmp:
            cfg = Settings(subq_api_key="test-subq", gemini_api_key="test-gem", use_mock_models=False)
            res = asyncio.run(
                run_phase13_evaluation(
                    output_base=tmp,
                    use_mock=False,
                    max_cases=2,
                    delay_seconds=0.0,
                    settings=cfg,
                    subq_transport=httpx.MockTransport(subq_handler),
                    gemini_transport=httpx.MockTransport(gem_handler),
                )
            )
            # p13_evt_02 failed in subq_only, combined, routed (3 errors), while p13_evt_01 succeeded in all 4 modes
            self.assertEqual(len(res["errors"]), 3)
            self.assertEqual(len(seen_keys), len(set(seen_keys)))
            self.assertTrue(all(ev in {"p13_evt_01", "p13_evt_02"} for ev in seen_event_ids))


if __name__ == "__main__":
    unittest.main()
