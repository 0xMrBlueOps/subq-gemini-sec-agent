import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

from sec_agent.config import Settings
from sec_agent.eval.dataset_phase13 import build_phase13_dataset
from sec_agent.eval.phase13_runner import (
    _ScopedIdempotencyTransport,
    main as p13_main,
    run_phase13_evaluation,
)
from sec_agent.gateway.gemini_hydrogen import GeminiHydrogenAdapter
from sec_agent.gateway.subq_snap import SubQSnapAdapter


class _TrackingTransport(httpx.AsyncBaseTransport):
    """Test transport that fails if aclose() is called prematurely before subsequent requests."""

    def __init__(self, handler) -> None:
        self._handler = handler
        self.closed = False
        self.aclose_calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self.closed:
            raise RuntimeError("Transport was prematurely closed before request!")
        return self._handler(request)

    async def aclose(self) -> None:
        self.closed = True
        self.aclose_calls += 1


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

    def test_mock_mode_evaluates_all_four_modes_without_live_delay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            t0 = time.monotonic()
            res = asyncio.run(run_phase13_evaluation(output_base=tmp, use_mock=True, max_cases=16))
            elapsed = time.monotonic() - t0
            self.assertLess(elapsed, 2.0)
            self.assertEqual(set(res["summaries"].keys()), {"subq_only", "gemini_only", "combined", "routed"})
            run_dir = Path(res["run_dir"])
            md = (run_dir / "PHASE13_REPORT.md").read_text(encoding="utf-8")
            self.assertIn("Phase 13 Evaluation Integrity & Routing Summary", md)
            self.assertIn("Benign Fast-Path Count", md)
            self.assertIn("Malicious Fast-Path Count", md)
            self.assertIn("Gemini Escalation Count", md)
            self.assertIn("Benign Fast-Path Rate", md)
            self.assertEqual(p13_main(["--output-base", tmp, "--max-cases", "4"]), 0)

    def test_failed_malicious_case_penalizes_recall_and_appears_in_report(self) -> None:
        seen_keys: list[str] = []

        def subq_handler(request: httpx.Request) -> httpx.Response:
            seen_keys.append(request.headers["X-Idempotency-Key"])
            body = json.loads(request.content.decode("utf-8"))
            ev_id = body["state"]["event_id"]
            # p13_evt_07 is malicious; fail it with 422 while p13_evt_01..06 succeed
            if ev_id == "p13_evt_07":
                return httpx.Response(422, json={"detail": {"error_type": "validation_error", "message": "forced failure"}})
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
                    "usageMetadata": {"promptTokenCount": 100, "candidatesTokenCount": 20, "thoughtsTokenCount": 5},
                },
            )

        subq_tr = _TrackingTransport(subq_handler)
        gem_tr = httpx.MockTransport(gem_handler)

        with tempfile.TemporaryDirectory() as tmp:
            cfg = Settings(subq_api_key="test-subq", gemini_api_key="test-gem", use_mock_models=False)
            res = asyncio.run(
                run_phase13_evaluation(
                    output_base=tmp,
                    use_mock=False,
                    max_cases=7,  # 6 benign + 1 malicious (p13_evt_07 fails)
                    delay_seconds=0.0,
                    settings=cfg,
                    subq_transport=subq_tr,
                    gemini_transport=gem_tr,
                )
            )
            # Underlying transport stayed open across all cases and was closed once in finally
            self.assertTrue(subq_tr.closed)
            self.assertEqual(subq_tr.aclose_calls, 1)

            # No readable mode names in X-Idempotency-Key headers
            for k in seen_keys:
                for forbidden_mode in ("subq_only", "gemini_only", "combined", "routed"):
                    self.assertNotIn(forbidden_mode, k)

            # Honest recall must be 0.0 (not 1.0) because the 1 malicious case failed
            st = res["honest_stats"]["subq_only"]
            self.assertEqual(st["attempted_cases"], 7)
            self.assertEqual(st["completed_cases"], 6)
            self.assertEqual(st["failed_cases"], 1)
            self.assertEqual(st["honest_recall"], 0.0)

            md = (Path(res["run_dir"]) / "PHASE13_REPORT.md").read_text(encoding="utf-8")
            self.assertIn("WARNING — INCOMPLETE EVALUATION", md)
            self.assertIn("Total Errors:** `3`", md)

    def test_retries_preserve_same_idempotency_key_and_live_pacing_fires_between_calls(self) -> None:
        seen_keys: list[str] = []
        gem_headers: list[dict[str, str]] = []
        subq_attempts = {"n": 0}
        gem_attempts = {"n": 0}
        sleep_calls: list[float] = []

        def subq_handler(request: httpx.Request) -> httpx.Response:
            seen_keys.append(request.headers["X-Idempotency-Key"])
            subq_attempts["n"] += 1
            if subq_attempts["n"] == 1:
                return httpx.Response(429, headers={"Retry-After": "0.01"}, text="rate limited")
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

        def gem_handler(request: httpx.Request) -> httpx.Response:
            gem_headers.append({k.lower(): v for k, v in request.headers.items()})
            gem_attempts["n"] += 1
            if gem_attempts["n"] == 1:
                return httpx.Response(429, headers={"Retry-After": "0.02"}, text="gemini rate limited")
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
                    "usageMetadata": {"promptTokenCount": 100, "candidatesTokenCount": 20, "thoughtsTokenCount": 5},
                },
            )

        orig_sleep = asyncio.sleep

        async def fake_sleep(delay: float) -> None:
            sleep_calls.append(delay)
            await orig_sleep(0)

        subq_tr = _TrackingTransport(subq_handler)
        gem_tr = _TrackingTransport(gem_handler)

        with tempfile.TemporaryDirectory() as tmp:
            cfg = Settings(subq_api_key="test-subq", gemini_api_key="test-gem", use_mock_models=False)
            with patch("sec_agent.eval.phase13_runner.asyncio.sleep", side_effect=fake_sleep):
                asyncio.run(
                    run_phase13_evaluation(
                        output_base=tmp,
                        use_mock=False,
                        max_cases=1,
                        delay_seconds=1.5,
                        settings=cfg,
                        subq_transport=subq_tr,
                        gemini_transport=gem_tr,
                    )
                )
        # First 2 keys are the retry pair for subq_only p13_evt_01 and must be identical
        self.assertEqual(seen_keys[0], seen_keys[1])
        # Distinct modes must have distinct keys
        self.assertNotEqual(seen_keys[0], seen_keys[2])
        # Gemini requests must NEVER receive SubQ idempotency headers
        for hdrs in gem_headers:
            self.assertNotIn("x-idempotency-key", hdrs)
        # Total outbound HTTP requests = 4 SubQ (3 + 1 retry) + 3 Gemini (2 + 1 retry) = 7
        # So shared pacer must fire 6 times (>= 1.4s each), including SubQ retry, Gemini retry, and SubQ->Gemini transitions
        pacer_sleeps = [d for d in sleep_calls if d > 1.0]
        self.assertEqual(len(pacer_sleeps), 6)
        self.assertIn(0.01, sleep_calls)
        self.assertIn(0.02, sleep_calls)
        # Both underlying transports closed exactly once
        self.assertTrue(subq_tr.closed)
        self.assertEqual(subq_tr.aclose_calls, 1)
        self.assertTrue(gem_tr.closed)
        self.assertEqual(gem_tr.aclose_calls, 1)

    def test_underlying_transport_closed_on_unexpected_exception(self) -> None:
        subq_tr = _TrackingTransport(lambda _: httpx.Response(200, json={}))
        gem_tr = _TrackingTransport(lambda _: httpx.Response(200, json={}))

        with tempfile.TemporaryDirectory() as tmp:
            cfg = Settings(subq_api_key="test-subq", gemini_api_key="test-gem", use_mock_models=False)
            with patch(
                "sec_agent.eval.phase13_runner._compute_honest_mode_stats",
                side_effect=RuntimeError("boom"),
            ):
                with self.assertRaisesRegex(RuntimeError, "boom"):
                    asyncio.run(
                        run_phase13_evaluation(
                            output_base=tmp,
                            use_mock=False,
                            max_cases=1,
                            delay_seconds=0.0,
                            settings=cfg,
                            subq_transport=subq_tr,
                            gemini_transport=gem_tr,
                        )
                    )
        self.assertTrue(subq_tr.closed)
        self.assertEqual(subq_tr.aclose_calls, 1)
        self.assertTrue(gem_tr.closed)
        self.assertEqual(gem_tr.aclose_calls, 1)

    def test_malicious_fast_path_cannot_inflate_benign_fast_path_rate_and_failed_benign_visible(self) -> None:
        # max_cases=7 -> p13_evt_01..06 are benign, p13_evt_07 is malicious.
        # Fail p13_evt_01 (benign) with 422, let p13_evt_02..06 (benign) take fast path,
        # and let p13_evt_07 (malicious) falsely take fast path too.
        def subq_handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content.decode("utf-8"))
            ev_id = body["state"]["event_id"]
            if ev_id == "p13_evt_01":
                return httpx.Response(422, json={"detail": {"error_type": "validation_error", "message": "benign failed"}})
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
                    "usageMetadata": {"promptTokenCount": 100, "candidatesTokenCount": 20, "thoughtsTokenCount": 5},
                },
            )

        from sec_agent.engine.router import RoutingDecision

        with tempfile.TemporaryDirectory() as tmp:
            cfg = Settings(subq_api_key="test-subq", gemini_api_key="test-gem", use_mock_models=False)
            with patch(
                "sec_agent.eval.phase13_runner.RoutingPolicy.decide",
                return_value=RoutingDecision(invoke_gemini=False, decision_label="subq_fast_path", reasons=["simulated_fast_path"]),
            ):
                res = asyncio.run(
                    run_phase13_evaluation(
                        output_base=tmp,
                        use_mock=False,
                        max_cases=7,
                        delay_seconds=0.0,
                        settings=cfg,
                        subq_transport=httpx.MockTransport(subq_handler),
                        gemini_transport=httpx.MockTransport(gem_handler),
                    )
                )
            rs = res["routing_stats"]
            self.assertEqual(rs["benign_attempted"], 6)
            self.assertEqual(rs["benign_completed"], 5)
            self.assertEqual(rs["benign_fast_path"], 5)
            self.assertEqual(rs["malicious_fast_path"], 1)

            md = (Path(res["run_dir"]) / "PHASE13_REPORT.md").read_text(encoding="utf-8")
            self.assertIn("Benign Attempted:** 6", md)
            self.assertIn("Benign Completed:** 5", md)
            self.assertIn("Benign Fast-Path Count:** 5", md)
            self.assertIn("Malicious Fast-Path Count:** 1", md)
            # Must be 83.33% (5/6), NOT 120% (6/5) or 100% (5/5) as primary attempted rate
            self.assertIn("Benign Fast-Path Rate (attempted benign):** 83.33% (5/6)", md)
            self.assertIn("Benign Fast-Path Rate (completed benign only):** 100.0% (5/5)", md)
            self.assertIn("WARNING — MALICIOUS FAST-PATH BYPASS", md)


if __name__ == "__main__":
    unittest.main()
