import asyncio
import json
import tempfile
import unittest
from pathlib import Path

import httpx

from sec_agent.engine import evaluate_consensus
from sec_agent.eval import build_synthetic_dataset, run_benchmark
from sec_agent.eval.dataset import CaseVariant
from sec_agent.gateway.gemini_hydrogen import GeminiAPIError, GeminiHydrogenAdapter
from sec_agent.gateway.subq_snap import SubQAPIError, SubQSnapAdapter
from sec_agent.schemas import (
    GeminiInvestigationResult,
    SecurityEvent,
    SeverityLevel,
    SubQTriageResult,
    ThreatCategory,
)
from sec_agent.security import HumanApprovalGate


class TestBenchmarkAndRegressions(unittest.TestCase):
    def test_synthetic_dataset_has_25_cases_and_balanced_variants(self) -> None:
        dataset = build_synthetic_dataset()
        self.assertEqual(len(dataset), 25)
        families = {tc.attack_family for tc in dataset}
        variants = {tc.variant for tc in dataset}
        self.assertEqual(len(families), 5)
        self.assertEqual(len(variants), 5)
        self.assertEqual(sum(1 for tc in dataset if tc.variant == CaseVariant.PROMPT_INJECTION), 5)

    def test_three_mode_benchmark_writes_jsonl_and_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summaries = asyncio.run(run_benchmark(output_dir=tmp, use_mock=True))
            self.assertEqual(set(summaries.keys()), {"subq_only", "gemini_only", "combined", "routed"})
            for mode_metrics in summaries.values():
                self.assertEqual(mode_metrics.execution_type, "mock")
                self.assertEqual(mode_metrics.total_cases, 25)
            jsonl_lines = (Path(tmp) / "benchmark_results.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(jsonl_lines), 100)
            self.assertTrue((Path(tmp) / "benchmark_summary.csv").exists())

    def test_disagreement_and_low_confidence_high_impact_escalation(self) -> None:
        gate = HumanApprovalGate(confidence_floor=0.65)
        event = SecurityEvent(source="zeek", raw_log="suspicious outbound transfer")
        subq = SubQTriageResult(
            model="subq-snap-1.2",
            category=ThreatCategory.DATA_EXFILTRATION,
            severity=SeverityLevel.CRITICAL,
            severity_score=9.5,
            escalate_probability=0.88,
            prompt_injection_probability=0.01,
            confidence=0.22,  # Low confidence, but CRITICAL severity
        )
        gemini = GeminiInvestigationResult(
            model="gemini-4-hydrogen",
            category=ThreatCategory.BENIGN,  # Disagrees with SubQ
            severity=SeverityLevel.LOW,
            summary="Unclear transfer",
            confidence=0.30,
        )
        asm = evaluate_consensus(event, subq, gemini, [], gate)
        self.assertFalse(asm.models_agreed)
        self.assertTrue(asm.requires_human_approval)
        self.assertIn("high_or_critical_severity", asm.approval_reason or "")
        self.assertIn("model_disagreement", asm.approval_reason or "")
        self.assertIn("low_model_confidence", asm.approval_reason or "")

    def test_malformed_subq_and_gemini_responses_raise_clean_errors(self) -> None:
        bad_transport = httpx.MockTransport(lambda _: httpx.Response(200, text="not-json{{{"))
        subq = SubQSnapAdapter(api_key="k", transport=bad_transport)
        gemini = GeminiHydrogenAdapter(api_key="k", transport=bad_transport)
        ev = SecurityEvent(source="test", raw_log="sample")

        with self.assertRaises(SubQAPIError) as s_ctx:
            asyncio.run(subq.triage_event(ev, ev.raw_log))
        self.assertEqual(s_ctx.exception.status_code, 502)

        with self.assertRaises(GeminiAPIError) as g_ctx:
            asyncio.run(gemini.investigate_event(ev, ev.raw_log))
        self.assertEqual(g_ctx.exception.status_code, 502)

    def test_api_500_and_429_handling(self) -> None:
        err_500 = httpx.MockTransport(lambda _: httpx.Response(500, text="Internal Server Error"))
        subq = SubQSnapAdapter(api_key="k", transport=err_500)
        ev = SecurityEvent(source="test", raw_log="sample")
        with self.assertRaises(SubQAPIError) as ctx:
            asyncio.run(subq.triage_event(ev, ev.raw_log))
        self.assertEqual(ctx.exception.status_code, 500)


if __name__ == "__main__":
    unittest.main()
