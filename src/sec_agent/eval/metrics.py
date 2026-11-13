from __future__ import annotations

from pydantic import BaseModel

# Verified public pricing (Nov 2026):
# SubQ Snap 1.2: $0.04 / 1M input tokens, $0 output
# Gemini 4 Hydrogen: $1.50 / 1M input tokens, $7.50 / 1M output tokens
SUBQ_INPUT_PER_1M = 0.04
GEMINI_INPUT_PER_1M = 1.50
GEMINI_OUTPUT_PER_1M = 7.50


class CaseEvalRecord(BaseModel):
    case_id: str
    split: str = "default"
    mode: str
    execution_type: str  # "mock" or "live"
    expected_category: str
    predicted_category: str
    expected_severity: str
    predicted_severity: str
    expected_malicious: bool
    predicted_malicious: bool
    expected_escalate: bool
    escalated: bool
    is_adversarial: bool = False
    model_confidence: float = 0.0
    models_agreed: bool | None = None
    latency_ms: float
    input_tokens: int
    output_tokens: int
    subq_input_tokens: int = 0
    gemini_input_tokens: int = 0
    gemini_output_tokens: int = 0


class ModeMetrics(BaseModel):
    mode: str
    split: str = "default"
    execution_type: str
    total_cases: int
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    false_positive_rate: float
    false_negative_rate: float
    category_accuracy: float
    severity_agreement: float
    escalation_recall: float
    adversarial_recall: float
    brier_score: float
    avg_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    total_input_tokens: int
    total_output_tokens: int
    estimated_cost_usd: float


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = int(round((pct / 100.0) * (len(sorted_vals) - 1)))
    return round(sorted_vals[min(len(sorted_vals) - 1, max(0, idx))], 2)


def compute_mode_metrics(records: list[CaseEvalRecord]) -> ModeMetrics:
    if not records:
        raise ValueError("Cannot compute metrics on empty record list.")

    mode = records[0].mode
    split = records[0].split
    exec_type = records[0].execution_type
    n = len(records)

    tp = sum(1 for r in records if r.expected_malicious and r.predicted_malicious)
    fp = sum(1 for r in records if not r.expected_malicious and r.predicted_malicious)
    tn = sum(1 for r in records if not r.expected_malicious and not r.predicted_malicious)
    fn = sum(1 for r in records if r.expected_malicious and not r.predicted_malicious)

    precision = round(tp / (tp + fp), 4) if (tp + fp) else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) else 0.0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) else 0.0
    fnr = round(fn / (fn + tp), 4) if (fn + tp) else 0.0

    cat_acc = round(sum(1 for r in records if r.expected_category == r.predicted_category) / n, 4)
    sev_agr = round(sum(1 for r in records if r.expected_severity == r.predicted_severity) / n, 4)

    esc_expected = [r for r in records if r.expected_escalate]
    esc_recall = (
        round(sum(1 for r in esc_expected if r.escalated) / len(esc_expected), 4)
        if esc_expected
        else 1.0
    )

    adv_expected = [r for r in records if r.is_adversarial and r.expected_malicious]
    adv_recall = (
        round(sum(1 for r in adv_expected if r.predicted_malicious) / len(adv_expected), 4)
        if adv_expected
        else 1.0
    )

    # Brier score on category correctness vs reported confidence
    brier = round(
        sum(
            (r.model_confidence - (1.0 if r.expected_category == r.predicted_category else 0.0)) ** 2
            for r in records
        )
        / n,
        4,
    )

    latencies = sorted(r.latency_ms for r in records)
    avg_lat = round(sum(latencies) / n, 2)
    p50_lat = _percentile(latencies, 50.0)
    p95_lat = _percentile(latencies, 95.0)

    tot_in = sum(r.input_tokens for r in records)
    tot_out = sum(r.output_tokens for r in records)

    subq_in = sum(r.subq_input_tokens for r in records)
    gem_in = sum(r.gemini_input_tokens for r in records)
    gem_out = sum(r.gemini_output_tokens for r in records)
    if subq_in == 0 and gem_in == 0 and tot_in > 0:
        if mode == "subq_only":
            subq_in = tot_in
        elif mode == "gemini_only":
            gem_in, gem_out = tot_in, tot_out

    cost = (
        (subq_in / 1_000_000.0) * SUBQ_INPUT_PER_1M
        + (gem_in / 1_000_000.0) * GEMINI_INPUT_PER_1M
        + (gem_out / 1_000_000.0) * GEMINI_OUTPUT_PER_1M
    )

    return ModeMetrics(
        mode=mode,
        split=split,
        execution_type=exec_type,
        total_cases=n,
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        precision=precision,
        recall=recall,
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        category_accuracy=cat_acc,
        severity_agreement=sev_agr,
        escalation_recall=esc_recall,
        adversarial_recall=adv_recall,
        brier_score=brier,
        avg_latency_ms=avg_lat,
        p50_latency_ms=p50_lat,
        p95_latency_ms=p95_lat,
        total_input_tokens=tot_in,
        total_output_tokens=tot_out,
        estimated_cost_usd=round(cost, 6),
    )
