from __future__ import annotations

import asyncio
import csv
from pathlib import Path

from sec_agent.audit import AuditLogger
from sec_agent.config import Settings
from sec_agent.engine import RoutingPolicy
from sec_agent.eval.dataset import build_synthetic_dataset
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


async def run_benchmark(
    output_dir: str | Path = "eval_results",
    use_mock: bool = True,
    settings: Settings | None = None,
) -> dict[str, ModeMetrics]:
    cfg = settings or Settings()
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    exec_type = "mock" if use_mock else "live"

    if use_mock:
        subq_client: DecisionModelClient = MockSubQSnapClient()
        gemini_client: ReasoningModelClient = MockGeminiHydrogenClient()
    else:
        subq_client = SubQSnapAdapter(
            api_key=cfg.subq_api_key or "",
            base_url=cfg.subq_base_url,
            model_id=cfg.subq_model_id,
        )
        gemini_client = GeminiHydrogenAdapter(
            api_key=cfg.gemini_api_key or "",
            model_id=cfg.gemini_model_id,
        )

    dataset = build_synthetic_dataset()
    all_records: list[CaseEvalRecord] = []
    summaries: dict[str, ModeMetrics] = {}

    # 1. SubQ Snap Only
    subq_records: list[CaseEvalRecord] = []
    for tc in dataset:
        san = isolate_untrusted_log(tc.event.raw_log)
        res = await subq_client.triage_event(tc.event, san.isolated_text)
        subq_records.append(
            CaseEvalRecord(
                case_id=tc.case_id,
                mode="subq_only",
                execution_type=exec_type,
                expected_category=tc.expected_category.value,
                predicted_category=res.category.value,
                expected_severity=tc.expected_severity.value,
                predicted_severity=res.severity.value,
                expected_malicious=tc.expected_malicious,
                predicted_malicious=_is_malicious(res.category),
                expected_escalate=tc.expected_escalate,
                escalated=_should_escalate_single(res.severity, res.prompt_injection_probability)
                or res.escalate_probability >= 0.6,
                latency_ms=res.latency_ms,
                input_tokens=res.input_tokens,
                output_tokens=0,
            )
        )
    summaries["subq_only"] = compute_mode_metrics(subq_records)
    all_records.extend(subq_records)

    # 2. Gemini Only
    gemini_records: list[CaseEvalRecord] = []
    for tc in dataset:
        san = isolate_untrusted_log(tc.event.raw_log)
        res = await gemini_client.investigate_event(tc.event, san.isolated_text)
        gemini_records.append(
            CaseEvalRecord(
                case_id=tc.case_id,
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
                latency_ms=res.latency_ms,
                input_tokens=res.input_tokens,
                output_tokens=res.output_tokens,
            )
        )
    summaries["gemini_only"] = compute_mode_metrics(gemini_records)
    all_records.extend(gemini_records)

    # 3. Unconditional Combined (SubQ + Gemini on every event)
    combined_records: list[CaseEvalRecord] = []
    uncond_orch = TriageOrchestrator(
        decision_client=subq_client,
        reasoning_client=gemini_client,
        audit_logger=AuditLogger(out_path / "benchmark_audit_combined.jsonl"),
        enable_intelligent_routing=False,
    )
    for tc in dataset:
        asm = await uncond_orch.process_event(tc.event)
        g_lat = asm.gemini_result.latency_ms if asm.gemini_result else 0.0
        g_in = asm.gemini_result.input_tokens if asm.gemini_result else 0
        g_out = asm.gemini_result.output_tokens if asm.gemini_result else 0
        combined_records.append(
            CaseEvalRecord(
                case_id=tc.case_id,
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
                models_agreed=asm.models_agreed,
                latency_ms=round(asm.subq_result.latency_ms + g_lat, 2),
                input_tokens=asm.subq_result.input_tokens + g_in,
                output_tokens=g_out,
            )
        )
    summaries["combined"] = compute_mode_metrics(combined_records)
    all_records.extend(combined_records)

    # 4. Intelligent Routed (Phase 8: SubQ first, Gemini selectively)
    routed_records: list[CaseEvalRecord] = []
    routed_orch = TriageOrchestrator(
        decision_client=subq_client,
        reasoning_client=gemini_client,
        audit_logger=AuditLogger(out_path / "benchmark_audit_routed.jsonl"),
        routing_policy=RoutingPolicy(
            confidence_threshold=cfg.routing_confidence_threshold,
            escalate_threshold=cfg.routing_escalate_threshold,
            injection_threshold=cfg.routing_injection_threshold,
        ),
        enable_intelligent_routing=True,
    )
    for tc in dataset:
        asm = await routed_orch.process_event(tc.event)
        g_lat = asm.gemini_result.latency_ms if asm.gemini_result else 0.0
        g_in = asm.gemini_result.input_tokens if asm.gemini_result else 0
        g_out = asm.gemini_result.output_tokens if asm.gemini_result else 0
        routed_records.append(
            CaseEvalRecord(
                case_id=tc.case_id,
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
                models_agreed=asm.models_agreed,
                latency_ms=round(asm.subq_result.latency_ms + g_lat, 2),
                input_tokens=asm.subq_result.input_tokens + g_in,
                output_tokens=g_out,
            )
        )
    summaries["routed"] = compute_mode_metrics(routed_records)
    all_records.extend(routed_records)

    jsonl_path = out_path / "benchmark_results.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for rec in all_records:
            fh.write(_dump_json(rec) + "\n")

    csv_path = out_path / "benchmark_summary.csv"
    fieldnames = list(ModeMetrics.__fields__.keys()) if hasattr(ModeMetrics, "__fields__") else list(ModeMetrics.model_fields.keys())
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for m in summaries.values():
            writer.writerow(_dump_dict(m))

    return summaries


if __name__ == "__main__":
    results = asyncio.run(run_benchmark(use_mock=True))
    for mode_name, metrics in results.items():
        print(
            f"[{mode_name}] ({metrics.execution_type}) P={metrics.precision} R={metrics.recall} "
            f"FPR={metrics.false_positive_rate} FNR={metrics.false_negative_rate} "
            f"EscR={metrics.escalation_recall} Lat={metrics.avg_latency_ms}ms "
            f"InTok={metrics.total_input_tokens} OutTok={metrics.total_output_tokens}"
        )
