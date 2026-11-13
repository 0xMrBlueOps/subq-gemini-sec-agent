from __future__ import annotations

import argparse
import asyncio
import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from sec_agent.audit import AuditLogger
from sec_agent.config import Settings
from sec_agent.engine import RoutingPolicy, UncertaintyPolicy
from sec_agent.eval.dataset_phase13 import Phase13TestCase, build_phase13_dataset
from sec_agent.eval.metrics import CaseEvalRecord, ModeMetrics, compute_mode_metrics
from sec_agent.eval.report_gen import generate_live_markdown_report
from sec_agent.gateway import (
    DecisionModelClient,
    GeminiHydrogenAdapter,
    MockGeminiHydrogenClient,
    MockSubQSnapClient,
    ReasoningModelClient,
    SubQSnapAdapter,
)
from sec_agent.orchestrator import TriageOrchestrator
from sec_agent.schemas import (
    SecurityEvent,
    SeverityLevel,
    SubQTriageResult,
    ThreatCategory,
)
from sec_agent.security import isolate_untrusted_log

_OPAQUE_MODE_IDS: dict[str, str] = {
    "subq_only": "m1",
    "gemini_only": "m2",
    "combined": "m3",
    "routed": "m4",
}


class _SharedPacer:
    """Thread/async-safe pacer enforcing minimum delay between consecutive outbound provider calls."""

    def __init__(self, delay_seconds: float) -> None:
        self.delay_seconds = max(0.0, delay_seconds)
        self._lock = asyncio.Lock()
        self._last_request_ts: float | None = None

    async def wait_turn(self) -> None:
        if self.delay_seconds <= 0.0:
            return
        async with self._lock:
            now = time.monotonic()
            if self._last_request_ts is not None:
                elapsed = now - self._last_request_ts
                remaining = self.delay_seconds - elapsed
                if remaining > 0.0:
                    await asyncio.sleep(remaining)
            self._last_request_ts = time.monotonic()


class _PacedTransport(httpx.AsyncBaseTransport):
    """Enforces shared pacing on every outbound HTTP attempt without premature pool closure."""

    def __init__(
        self,
        inner: httpx.AsyncBaseTransport | None = None,
        pacer: _SharedPacer | None = None,
    ) -> None:
        self._inner = inner or httpx.AsyncHTTPTransport()
        self._pacer = pacer
        self.underlying_closed: bool = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self._pacer is not None:
            await self._pacer.wait_turn()
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        # Per-event httpx.AsyncClient.__aexit__ calls aclose(); keep shared pool open until run finishes.
        return None

    async def close_underlying(self) -> None:
        if not self.underlying_closed:
            await self._inner.aclose()
            self.underlying_closed = True


class _ScopedIdempotencyTransport(_PacedTransport):
    """Paced transport that also scopes SubQ X-Idempotency-Key per (run_id, case_id, opaque_mode)."""

    def __init__(
        self,
        inner: httpx.AsyncBaseTransport | None = None,
        pacer: _SharedPacer | None = None,
    ) -> None:
        super().__init__(inner=inner, pacer=pacer)
        self.current_scope_key: str | None = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self._pacer is not None:
            await self._pacer.wait_turn()
        if self.current_scope_key:
            request.headers["X-Idempotency-Key"] = self.current_scope_key
        return await self._inner.handle_async_request(request)


class _ScopedDecisionWrapper(DecisionModelClient):
    """Sets opaque per-request idempotency scope while keeping event_id neutral."""

    def __init__(
        self,
        client: DecisionModelClient,
        transport: _ScopedIdempotencyTransport | None,
        run_id: str,
        mode: str,
    ) -> None:
        self._client = client
        self._transport = transport
        self._run_id = run_id
        self._opaque_mode = _OPAQUE_MODE_IDS[mode]

    async def triage_event(self, event: SecurityEvent, isolated_log: str) -> SubQTriageResult:
        if self._transport is not None:
            self._transport.current_scope_key = f"{self._run_id}:{event.event_id}:{self._opaque_mode}"
        return await self._client.triage_event(event, isolated_log)


def _is_malicious(cat: ThreatCategory) -> bool:
    return cat != ThreatCategory.BENIGN


def _should_escalate_single(sev: SeverityLevel, inj_prob: float = 0.0) -> bool:
    return sev in {SeverityLevel.HIGH, SeverityLevel.CRITICAL} or inj_prob >= 0.5


def _dump_json(model_obj: object) -> str:
    return model_obj.model_dump_json() if hasattr(model_obj, "model_dump_json") else model_obj.json()  # type: ignore[attr-defined]


def _dump_dict(model_obj: object) -> dict:
    return model_obj.model_dump() if hasattr(model_obj, "model_dump") else model_obj.dict()  # type: ignore[attr-defined]


def _compute_honest_mode_stats(
    mode: str,
    cases: list[Phase13TestCase],
    completed_recs: list[CaseEvalRecord],
    failed_cases: list[Phase13TestCase],
) -> dict[str, Any]:
    """Compute denominator-honest stats where failed malicious cases count as missed detections/escalations."""
    attempted = len(cases)
    completed = len(completed_recs)
    failed = len(failed_cases)

    tp = sum(1 for r in completed_recs if r.expected_malicious and r.predicted_malicious)
    fp = sum(1 for r in completed_recs if not r.expected_malicious and r.predicted_malicious)
    tn = sum(1 for r in completed_recs if not r.expected_malicious and not r.predicted_malicious)
    fn_completed = sum(1 for r in completed_recs if r.expected_malicious and not r.predicted_malicious)

    failed_malicious = sum(1 for c in failed_cases if c.expected_malicious)
    failed_benign = sum(1 for c in failed_cases if not c.expected_malicious)
    failed_escalate = sum(1 for c in failed_cases if c.expected_escalate)

    total_malicious = sum(1 for c in cases if c.expected_malicious)
    total_benign = sum(1 for c in cases if not c.expected_malicious)
    total_escalate = sum(1 for c in cases if c.expected_escalate)

    escalated_hits = sum(1 for r in completed_recs if r.expected_escalate and r.escalated)

    honest_recall = round(tp / total_malicious, 4) if total_malicious else 0.0
    honest_fnr = round((fn_completed + failed_malicious) / total_malicious, 4) if total_malicious else 0.0
    honest_esc_recall = round(escalated_hits / total_escalate, 4) if total_escalate else 1.0
    honest_fpr = round(fp / total_benign, 4) if total_benign else 0.0
    coverage = round(completed / attempted, 4) if attempted else 0.0

    return {
        "mode": mode,
        "attempted_cases": attempted,
        "completed_cases": completed,
        "failed_cases": failed,
        "failed_malicious": failed_malicious,
        "failed_benign": failed_benign,
        "coverage_rate": coverage,
        "honest_recall": honest_recall,
        "honest_fnr": honest_fnr,
        "honest_fpr": honest_fpr,
        "honest_escalation_recall": honest_esc_recall,
        "failed_escalate": failed_escalate,
    }


def _append_phase13_report_section(
    md_path: Path,
    run_id: str,
    exec_type: str,
    honest_stats: list[dict[str, Any]],
    routing_stats: dict[str, int],
    errors_count: int,
) -> None:
    lines = [
        "",
        "## Phase 13 Evaluation Integrity & Routing Summary",
        "",
        f"- **Run ID:** `{run_id}` (`{exec_type}`)",
        f"- **Total Errors:** `{errors_count}`",
    ]
    if errors_count > 0:
        lines.append(
            "- **WARNING — INCOMPLETE EVALUATION:** One or more provider calls failed. "
            "Failed malicious cases are counted as missed detections/escalations in the honest-denominator table below."
        )

    lines.extend(
        [
            "",
            "| Mode | Attempted | Completed | Failed | Coverage | Honest Recall | Honest FNR | Honest FPR | Honest Esc Recall |",
            "| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for st in honest_stats:
        lines.append(
            f"| `{st['mode']}` | {st['attempted_cases']} | {st['completed_cases']} | {st['failed_cases']} | "
            f"{st['coverage_rate']} | {st['honest_recall']} | {st['honest_fnr']} | {st['honest_fpr']} | {st['honest_escalation_recall']} |"
        )

    benign_attempted = routing_stats.get("benign_attempted", 0)
    benign_completed = routing_stats.get("benign_completed", 0)
    benign_fast_path = routing_stats.get("benign_fast_path", 0)
    malicious_fast_path = routing_stats.get("malicious_fast_path", 0)
    gemini_esc = routing_stats.get("escalated_to_gemini", 0)
    fast_pct_attempted = round((benign_fast_path / benign_attempted) * 100.0, 2) if benign_attempted else 0.0
    fast_pct_completed = round((benign_fast_path / benign_completed) * 100.0, 2) if benign_completed else 0.0
    routing_lines = [
        "",
        "### Routing Efficiency (`routed` mode)",
        f"- **Benign Attempted:** {benign_attempted}",
        f"- **Benign Completed:** {benign_completed}",
        f"- **Benign Fast-Path Count:** {benign_fast_path}",
        f"- **Malicious Fast-Path Count:** {malicious_fast_path}",
        f"- **Gemini Escalation Count:** {gemini_esc}",
        f"- **Benign Fast-Path Rate (attempted benign):** {fast_pct_attempted}% ({benign_fast_path}/{benign_attempted})",
    ]
    if benign_completed != benign_attempted:
        routing_lines.append(
            f"- **Benign Fast-Path Rate (completed benign only):** {fast_pct_completed}% ({benign_fast_path}/{benign_completed})"
        )
    if malicious_fast_path > 0:
        routing_lines.append(
            f"- **WARNING — MALICIOUS FAST-PATH BYPASS:** {malicious_fast_path} malicious case(s) took `subq_fast_path` without Gemini escalation."
        )
    lines.extend(
        routing_lines
        + [
            "",
            "### Failed-Case Metric Policy",
            "- Provider exceptions are logged to `errors.jsonl` and excluded from genuine model-latency/cost averages, "
            "while failed malicious cases penalize `Honest Recall`, `Honest FNR`, and `Honest Escalation Recall` over the full attempted denominator.",
        ]
    )
    with md_path.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


async def run_phase13_evaluation(
    output_base: str | Path = "eval_results",
    use_mock: bool = True,
    max_cases: int = 16,
    delay_seconds: float | None = None,
    settings: Settings | None = None,
    subq_transport: httpx.AsyncBaseTransport | None = None,
    gemini_transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    if max_cases < 1 or max_cases > 16:
        raise ValueError("max_cases must be between 1 and 16.")

    cfg = settings or Settings()
    run_id = f"p13_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{uuid4().hex[:6]}"
    exec_type = "mock" if use_mock else "live"
    pace = (0.0 if use_mock else 1.5) if delay_seconds is None else max(0.0, delay_seconds)
    pacer = _SharedPacer(pace)

    run_dir = Path(output_base) / f"phase13_{exec_type}_{run_id}"
    run_dir.mkdir(parents=True, exist_ok=True)

    scoped_subq_transport = None if use_mock else _ScopedIdempotencyTransport(subq_transport, pacer=pacer)
    paced_gemini_transport = None if use_mock else _PacedTransport(gemini_transport, pacer=pacer)
    if use_mock:
        base_subq: DecisionModelClient = MockSubQSnapClient()
        base_gemini: ReasoningModelClient = MockGeminiHydrogenClient()
    else:
        base_subq = SubQSnapAdapter(
            api_key=cfg.subq_api_key or "",
            base_url=cfg.subq_base_url,
            model_id=cfg.subq_model_id,
            transport=scoped_subq_transport,
        )
        base_gemini = GeminiHydrogenAdapter(
            api_key=cfg.gemini_api_key or "",
            model_id=cfg.gemini_model_id,
            base_url=cfg.gemini_base_url,
            thinking_level=cfg.gemini_thinking_level,
            transport=paced_gemini_transport,
        )

    cases: list[Phase13TestCase] = build_phase13_dataset()[:max_cases]
    all_records: list[CaseEvalRecord] = []
    error_records: list[dict[str, str]] = []
    summaries: dict[str, ModeMetrics] = {}
    honest_stats: list[dict[str, Any]] = []
    routing_stats = {
        "benign_attempted": sum(1 for c in cases if not c.expected_malicious),
        "benign_completed": 0,
        "benign_fast_path": 0,
        "malicious_fast_path": 0,
        "subq_fast_path": 0,
        "escalated_to_gemini": 0,
    }

    try:
        # 1. subq_only
        subq_recs: list[CaseEvalRecord] = []
        subq_failed: list[Phase13TestCase] = []
        scoped_subq_only = _ScopedDecisionWrapper(base_subq, scoped_subq_transport, run_id, "subq_only")
        for tc in cases:
            try:
                san = isolate_untrusted_log(tc.event.raw_log)
                res = await scoped_subq_only.triage_event(tc.event, san.isolated_text)
                subq_recs.append(
                    CaseEvalRecord(
                        case_id=tc.case_id,
                        split="phase13",
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
                        is_adversarial=tc.is_adversarial,
                        model_confidence=res.confidence,
                        latency_ms=res.latency_ms,
                        input_tokens=res.input_tokens,
                        output_tokens=0,
                        subq_input_tokens=res.input_tokens,
                    )
                )
            except Exception as exc:
                subq_failed.append(tc)
                error_records.append(
                    {"run_id": run_id, "mode": "subq_only", "case_id": tc.case_id, "error": f"{type(exc).__name__}: {exc}"}
                )
        honest_stats.append(_compute_honest_mode_stats("subq_only", cases, subq_recs, subq_failed))
        if subq_recs:
            summaries["subq_only"] = compute_mode_metrics(subq_recs)
            all_records.extend(subq_recs)

        # 2. gemini_only
        gem_recs: list[CaseEvalRecord] = []
        gem_failed: list[Phase13TestCase] = []
        for tc in cases:
            try:
                san = isolate_untrusted_log(tc.event.raw_log)
                res = await base_gemini.investigate_event(tc.event, san.isolated_text)
                gem_recs.append(
                    CaseEvalRecord(
                        case_id=tc.case_id,
                        split="phase13",
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
            except Exception as exc:
                gem_failed.append(tc)
                error_records.append(
                    {"run_id": run_id, "mode": "gemini_only", "case_id": tc.case_id, "error": f"{type(exc).__name__}: {exc}"}
                )
        honest_stats.append(_compute_honest_mode_stats("gemini_only", cases, gem_recs, gem_failed))
        if gem_recs:
            summaries["gemini_only"] = compute_mode_metrics(gem_recs)
            all_records.extend(gem_recs)

        # 3. combined (isolated TriageOrchestrator instance)
        comb_recs: list[CaseEvalRecord] = []
        comb_failed: list[Phase13TestCase] = []
        comb_orch = TriageOrchestrator(
            decision_client=_ScopedDecisionWrapper(base_subq, scoped_subq_transport, run_id, "combined"),
            reasoning_client=base_gemini,
            audit_logger=AuditLogger(run_dir / "audit_combined.jsonl"),
            enable_intelligent_routing=False,
            deduplicate_events=True,
        )
        for tc in cases:
            try:
                asm = await comb_orch.process_event(tc.event)
                g_lat = asm.gemini_result.latency_ms if asm.gemini_result else 0.0
                g_in = asm.gemini_result.input_tokens if asm.gemini_result else 0
                g_out = asm.gemini_result.output_tokens if asm.gemini_result else 0
                g_tho = asm.gemini_result.thoughts_tokens if asm.gemini_result else 0
                conf = asm.gemini_result.confidence if asm.gemini_result else asm.subq_result.confidence
                comb_recs.append(
                    CaseEvalRecord(
                        case_id=tc.case_id,
                        split="phase13",
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
            except Exception as exc:
                comb_failed.append(tc)
                error_records.append(
                    {"run_id": run_id, "mode": "combined", "case_id": tc.case_id, "error": f"{type(exc).__name__}: {exc}"}
                )
        honest_stats.append(_compute_honest_mode_stats("combined", cases, comb_recs, comb_failed))
        if comb_recs:
            summaries["combined"] = compute_mode_metrics(comb_recs)
            all_records.extend(comb_recs)

        # 4. routed (isolated TriageOrchestrator instance)
        routed_recs: list[CaseEvalRecord] = []
        routed_failed: list[Phase13TestCase] = []
        routed_orch = TriageOrchestrator(
            decision_client=_ScopedDecisionWrapper(base_subq, scoped_subq_transport, run_id, "routed"),
            reasoning_client=base_gemini,
            audit_logger=AuditLogger(run_dir / "audit_routed.jsonl"),
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
            deduplicate_events=True,
        )
        for tc in cases:
            try:
                asm = await routed_orch.process_event(tc.event)
                if not tc.expected_malicious:
                    routing_stats["benign_completed"] += 1
                if asm.routing_decision == "subq_fast_path":
                    routing_stats["subq_fast_path"] += 1
                    if tc.expected_malicious:
                        routing_stats["malicious_fast_path"] += 1
                    else:
                        routing_stats["benign_fast_path"] += 1
                else:
                    routing_stats["escalated_to_gemini"] += 1

                g_lat = asm.gemini_result.latency_ms if asm.gemini_result else 0.0
                g_in = asm.gemini_result.input_tokens if asm.gemini_result else 0
                g_out = asm.gemini_result.output_tokens if asm.gemini_result else 0
                g_tho = asm.gemini_result.thoughts_tokens if asm.gemini_result else 0
                conf = asm.gemini_result.confidence if asm.gemini_result else asm.subq_result.confidence
                routed_recs.append(
                    CaseEvalRecord(
                        case_id=tc.case_id,
                        split="phase13",
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
            except Exception as exc:
                routed_failed.append(tc)
                error_records.append(
                    {"run_id": run_id, "mode": "routed", "case_id": tc.case_id, "error": f"{type(exc).__name__}: {exc}"}
                )
        honest_stats.append(_compute_honest_mode_stats("routed", cases, routed_recs, routed_failed))
        if routed_recs:
            summaries["routed"] = compute_mode_metrics(routed_recs)
            all_records.extend(routed_recs)

        results_jsonl = run_dir / "results.jsonl"
        with results_jsonl.open("w", encoding="utf-8") as fh:
            for r in all_records:
                fh.write(_dump_json(r) + "\n")

        errors_jsonl = run_dir / "errors.jsonl"
        with errors_jsonl.open("w", encoding="utf-8") as fh:
            for e in error_records:
                fh.write(json.dumps(e) + "\n")

        summary_csv = run_dir / "summary.csv"
        fieldnames = (
            list(ModeMetrics.__fields__.keys())
            if hasattr(ModeMetrics, "__fields__")
            else list(ModeMetrics.model_fields.keys())
        )
        with summary_csv.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for m in summaries.values():
                writer.writerow(_dump_dict(m))

        md_path = run_dir / "PHASE13_REPORT.md"
        if summaries:
            generate_live_markdown_report(summary_csv, md_path)
        else:
            md_path.write_text("# Live Model Evaluation Report (SubQ Snap 1.2 + Gemini 4 Hydrogen)\n", encoding="utf-8")
        _append_phase13_report_section(md_path, run_id, exec_type, honest_stats, routing_stats, len(error_records))

        meta = {
            "run_id": run_id,
            "execution_type": exec_type,
            "max_cases": len(cases),
            "delay_seconds": pace,
            "subq_model": cfg.subq_model_id,
            "gemini_model": cfg.gemini_model_id,
            "gemini_thinking_level": cfg.gemini_thinking_level,
            "routing_confidence_threshold": cfg.routing_confidence_threshold,
            "routing_calibration_margin": cfg.routing_calibration_margin,
            "require_gemini_on_obfuscation": cfg.require_gemini_on_obfuscation,
            "errors_count": len(error_records),
            "honest_stats": honest_stats,
            "routing_stats": routing_stats,
        }
        (run_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

        return {
            "run_id": run_id,
            "run_dir": str(run_dir),
            "summaries": summaries,
            "honest_stats": {st["mode"]: st for st in honest_stats},
            "routing_stats": routing_stats,
            "errors": error_records,
        }
    finally:
        for tr in (scoped_subq_transport, paced_gemini_transport):
            if tr is not None:
                await tr.close_underlying()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Phase 13 controlled 16-case 4-mode security evaluation.")
    parser.add_argument("--confirm-live", action="store_true", help="Enable live API calls (default is mock mode).")
    parser.add_argument("--max-cases", type=int, default=16, help="Number of cases to run (1..16).")
    parser.add_argument("--delay-seconds", type=float, default=None, help="Delay between calls (default 1.5s live, 0s mock).")
    parser.add_argument("--output-base", default="eval_results", help="Base output directory.")
    args = parser.parse_args(argv)

    use_mock = not args.confirm_live
    cfg = Settings()
    if not use_mock and (not cfg.subq_api_key or not cfg.gemini_api_key):
        print("Missing SUBQ_API_KEY or GEMINI_API_KEY in environment/.env.", file=sys.stderr)
        return 1

    res = asyncio.run(
        run_phase13_evaluation(
            output_base=args.output_base,
            use_mock=use_mock,
            max_cases=args.max_cases,
            delay_seconds=args.delay_seconds,
            settings=cfg,
        )
    )
    print(f"Run {res['run_id']} ({'mock' if use_mock else 'live'}) -> {res['run_dir']} | errors={len(res['errors'])}")
    for mode_name, st in res["honest_stats"].items():
        print(
            f"  [{mode_name}] Completed={st['completed_cases']}/{st['attempted_cases']} "
            f"HonestR={st['honest_recall']} HonestEscR={st['honest_escalation_recall']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
