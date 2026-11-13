from __future__ import annotations

import asyncio
import csv
from pathlib import Path

from sec_agent.audit import AuditLogger
from sec_agent.config import Settings
from sec_agent.engine import RoutingPolicy, UncertaintyPolicy
from sec_agent.eval.dataset_phase9 import Phase9TestCase, build_phase9_dataset, build_soc_workload_dataset
from sec_agent.eval.metrics import CaseEvalRecord, ModeMetrics, compute_mode_metrics
from sec_agent.gateway import (
    DecisionModelClient,
    GeminiHydrogenAdapter,
    MockGeminiHydrogenClient,
    MockSubQSnapClient,
    ReasoningModelClient,
    SubQSnapAdapter,
)
from sec_agent.orchestrator import TriageOrchestrator
from sec_agent.schemas import SeverityLevel, ThreatCategory
from sec_agent.security import isolate_untrusted_log


def _is_malicious(cat: ThreatCategory) -> bool:
    return cat != ThreatCategory.BENIGN


def _should_escalate_single(sev: SeverityLevel, inj_prob: float = 0.0) -> bool:
    return sev in {SeverityLevel.HIGH, SeverityLevel.CRITICAL} or inj_prob >= 0.5


def _dump_json(model_obj: object) -> str:
    return model_obj.model_dump_json() if hasattr(model_obj, "model_dump_json") else model_obj.json()  # type: ignore[attr-defined]


def _dump_dict(model_obj: object) -> dict:
    return model_obj.model_dump() if hasattr(model_obj, "model_dump") else model_obj.dict()  # type: ignore[attr-defined]


async def _evaluate_split(
    split_name: str,
    cases: list[Phase9TestCase],
    subq_client: DecisionModelClient,
    gemini_client: ReasoningModelClient,
    out_path: Path,
    exec_type: str,
    cfg: Settings,
) -> tuple[list[CaseEvalRecord], list[ModeMetrics]]:
    all_records: list[CaseEvalRecord] = []
    summaries: list[ModeMetrics] = []

    # 1. SubQ Only
    subq_recs: list[CaseEvalRecord] = []
    for tc in cases:
        san = isolate_untrusted_log(tc.event.raw_log)
        res = await subq_client.triage_event(tc.event, san.isolated_text)
        subq_recs.append(
            CaseEvalRecord(
                case_id=tc.case_id,
                split=split_name,
                mode="subq_only",
                execution_type=exec_type,
                expected_category=tc.expected_category.value,
                predicted_category=res.category.value,
                expected_severity=tc.expected_severity.value,
                predicted_severity=res.severity.value,
                expected_malicious=tc.expected_malicious,
                predicted_malicious=_is_malicious(res.category),
                expected_escalate=tc.expected_escalate,
                escalated=_should_escalate_single(res.severity, res.prompt_injection_probability) or res.escalate_probability >= 0.6,
                is_adversarial=tc.is_adversarial,
                model_confidence=res.confidence,
                latency_ms=res.latency_ms,
                input_tokens=res.input_tokens,
                output_tokens=0,
                subq_input_tokens=res.input_tokens,
            )
        )
    summaries.append(compute_mode_metrics(subq_recs))
    all_records.extend(subq_recs)

    # 2. Gemini Only
    gem_recs: list[CaseEvalRecord] = []
    for tc in cases:
        san = isolate_untrusted_log(tc.event.raw_log)
        res = await gemini_client.investigate_event(tc.event, san.isolated_text)
        gem_recs.append(
            CaseEvalRecord(
                case_id=tc.case_id,
                split=split_name,
                mode="gemini_only",
                execution_type=exec_type,
                expected_category=tc.expected_category.value,
                predicted_category=res.category.value,
                expected_severity=tc.expected_severity.value,
                predicted_severity=res.severity.value,
                expected_malicious=tc.expected_malicious,
                predicted_malicious=_is_malicious(res.category),
                expected_escalate=tc.expected_escalate,
                escalated=_should_escalate_single(res.severity),
                is_adversarial=tc.is_adversarial,
                model_confidence=res.confidence,
                latency_ms=res.latency_ms,
                input_tokens=res.input_tokens,
                output_tokens=res.output_tokens,
                gemini_input_tokens=res.input_tokens,
                gemini_output_tokens=res.output_tokens,
                gemini_thoughts_tokens=res.thoughts_tokens,
            )
        )
    summaries.append(compute_mode_metrics(gem_recs))
    all_records.extend(gem_recs)

    # 3. Unconditional Combined
    comb_recs: list[CaseEvalRecord] = []
    comb_orch = TriageOrchestrator(
        decision_client=subq_client,
        reasoning_client=gemini_client,
        audit_logger=AuditLogger(out_path / f"audit_{split_name}_combined.jsonl"),
        enable_intelligent_routing=False,
    )
    for tc in cases:
        asm = await comb_orch.process_event(tc.event)
        g_lat = asm.gemini_result.latency_ms if asm.gemini_result else 0.0
        g_in = asm.gemini_result.input_tokens if asm.gemini_result else 0
        g_out = asm.gemini_result.output_tokens if asm.gemini_result else 0
        g_tho = asm.gemini_result.thoughts_tokens if asm.gemini_result else 0
        conf = asm.gemini_result.confidence if asm.gemini_result else asm.subq_result.confidence
        comb_recs.append(
            CaseEvalRecord(
                case_id=tc.case_id,
                split=split_name,
                mode="combined",
                execution_type=exec_type,
                expected_category=tc.expected_category.value,
                predicted_category=asm.final_category.value,
                expected_severity=tc.expected_severity.value,
                predicted_severity=asm.final_severity.value,
                expected_malicious=tc.expected_malicious,
                predicted_malicious=_is_malicious(asm.final_category),
                expected_escalate=tc.expected_escalate,
                escalated=asm.requires_human_approval,
                is_adversarial=tc.is_adversarial,
                model_confidence=conf,
                models_agreed=asm.models_agreed,
                latency_ms=round(asm.subq_result.latency_ms + g_lat, 2),
                input_tokens=asm.subq_result.input_tokens + g_in,
                output_tokens=g_out,
                subq_input_tokens=asm.subq_result.input_tokens,
                gemini_input_tokens=g_in,
                gemini_output_tokens=g_out,
                gemini_thoughts_tokens=g_tho,
            )
        )
    summaries.append(compute_mode_metrics(comb_recs))
    all_records.extend(comb_recs)

    # 4. Intelligent Routed
    routed_recs: list[CaseEvalRecord] = []
    routed_orch = TriageOrchestrator(
        decision_client=subq_client,
        reasoning_client=gemini_client,
        audit_logger=AuditLogger(out_path / f"audit_{split_name}_routed.jsonl"),
        routing_policy=RoutingPolicy(
            escalate_threshold=cfg.routing_escalate_threshold,
            injection_threshold=cfg.routing_injection_threshold,
            uncertainty_policy=UncertaintyPolicy(
                confidence_threshold=cfg.routing_confidence_threshold,
                calibration_margin=cfg.routing_calibration_margin,
                require_gemini_on_obfuscation=cfg.require_gemini_on_obfuscation,
            ),
        ),
        enable_intelligent_routing=True,
    )
    for tc in cases:
        asm = await routed_orch.process_event(tc.event)
        g_lat = asm.gemini_result.latency_ms if asm.gemini_result else 0.0
        g_in = asm.gemini_result.input_tokens if asm.gemini_result else 0
        g_out = asm.gemini_result.output_tokens if asm.gemini_result else 0
        g_tho = asm.gemini_result.thoughts_tokens if asm.gemini_result else 0
        conf = asm.gemini_result.confidence if asm.gemini_result else asm.subq_result.confidence
        routed_recs.append(
            CaseEvalRecord(
                case_id=tc.case_id,
                split=split_name,
                mode="routed",
                execution_type=exec_type,
                expected_category=tc.expected_category.value,
                predicted_category=asm.final_category.value,
                expected_severity=tc.expected_severity.value,
                predicted_severity=asm.final_severity.value,
                expected_malicious=tc.expected_malicious,
                predicted_malicious=_is_malicious(asm.final_category),
                expected_escalate=tc.expected_escalate,
                escalated=asm.requires_human_approval,
                is_adversarial=tc.is_adversarial,
                model_confidence=conf,
                models_agreed=asm.models_agreed,
                latency_ms=round(asm.subq_result.latency_ms + g_lat, 2),
                input_tokens=asm.subq_result.input_tokens + g_in,
                output_tokens=g_out,
                subq_input_tokens=asm.subq_result.input_tokens,
                gemini_input_tokens=g_in,
                gemini_output_tokens=g_out,
                gemini_thoughts_tokens=g_tho,
            )
        )
    summaries.append(compute_mode_metrics(routed_recs))
    all_records.extend(routed_recs)

    return all_records, summaries


async def run_phase9_benchmark(
    output_dir: str | Path = "eval_results",
    use_mock: bool = True,
    settings: Settings | None = None,
) -> list[ModeMetrics]:
    cfg = settings or Settings()
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    exec_type = "mock" if use_mock else "live"

    if use_mock:
        subq_client: DecisionModelClient = MockSubQSnapClient()
        gemini_client: ReasoningModelClient = MockGeminiHydrogenClient()
    else:
        subq_client = SubQSnapAdapter(api_key=cfg.subq_api_key or "", base_url=cfg.subq_base_url, model_id=cfg.subq_model_id)
        gemini_client = GeminiHydrogenAdapter(api_key=cfg.gemini_api_key or "", model_id=cfg.gemini_model_id, base_url=cfg.gemini_base_url, thinking_level=cfg.gemini_thinking_level)

    full_ds = build_phase9_dataset()
    dev_cases = [c for c in full_ds if c.split.value == "dev"]
    held_out_cases = [c for c in full_ds if c.split.value == "held_out"]
    soc_cases = build_soc_workload_dataset()

    all_records: list[CaseEvalRecord] = []
    all_summaries: list[ModeMetrics] = []

    for split_name, split_cases in [("dev", dev_cases), ("held_out", held_out_cases), ("soc_workload", soc_cases)]:
        recs, sums = await _evaluate_split(split_name, split_cases, subq_client, gemini_client, out_path, exec_type, cfg)
        all_records.extend(recs)
        all_summaries.extend(sums)

    prefix = "phase9" if use_mock else "live_phase9"
    with (out_path / f"{prefix}_results.jsonl").open("w", encoding="utf-8") as fh:
        for r in all_records:
            fh.write(_dump_json(r) + "\n")

    fieldnames = list(ModeMetrics.__fields__.keys()) if hasattr(ModeMetrics, "__fields__") else list(ModeMetrics.model_fields.keys())
    with (out_path / f"{prefix}_summary.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for m in all_summaries:
            writer.writerow(_dump_dict(m))

    return all_summaries


if __name__ == "__main__":
    summaries = asyncio.run(run_phase9_benchmark(use_mock=True))
    for m in summaries:
        print(
            f"[{m.split}:{m.mode}] ({m.execution_type}) n={m.total_cases} "
            f"TP={m.tp} FP={m.fp} TN={m.tn} FN={m.fn} "
            f"P={m.precision} R={m.recall} EscR={m.escalation_recall} AdvR={m.adversarial_recall} "
            f"Brier={m.brier_score} p50={m.p50_latency_ms}ms p95={m.p95_latency_ms}ms "
            f"Cost=${m.estimated_cost_usd:.6f}"
        )
