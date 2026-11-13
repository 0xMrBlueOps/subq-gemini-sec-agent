# Phase 9 Research Report: Adversarial Robustness, Calibration & Workload Scaling

> **Disclaimer:** All quantitative metrics below (`execution_type=mock`) were generated offline using deterministic mock adapters (`MockSubQSnapClient`, `MockGeminiHydrogenClient`) because live API keys and outbound network access are disabled in the build sandbox. **Do not claim production readiness or live model accuracy from synthetic mock data.**

## 1. Adversarial Normalization & Uncertainty Policy

- **Multi-Layer Normalizer (`src/sec_agent/security/normalizer.py`):** Performs Unicode NFKC normalization, zero-width character stripping (`\u200b`, `\u200c`, `\u200d`, `\ufeff`), caret/backtick de-obfuscation (`p^o^w^e^r^s^h^e^l^l`), shell/env substitution detection (`${IFS}`, `$()`, `%COMSPEC%`), command-chaining detection (`&&`, `||`, `;`, `| bash`), and bounded UTF-8/UTF-16LE Base64 decoding.
- **Uncertainty & Calibration Policy (`UncertaintyPolicy` in `src/sec_agent/engine/router.py`):** Invokes Gemini whenever SubQ confidence `< 0.85`, top-2 category probability margin `< 0.20`, `escalate_probability` falls in `[0.30, 0.70]`, obfuscation/encoding is detected, prompt-injection indicators appear, or deterministic high-impact rules fire. Clean deterministic scans are never treated as proof of benignity.

## 2. Offline Mock Benchmark Results (Dev 100 / Held-Out 120 / SOC 200)

| Split | Mode | TP | FP | TN | FN | Precision | Recall | Esc Recall | Adv Recall | Brier | p50 / p95 (ms) | Est. Cost (USD) |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `dev` (100) | `subq_only` | 75 | 5 | 20 | 0 | 0.9375 | 1.0000 | 1.0000 | 1.0000 | 0.0682 | 45.0 / 45.0 | $0.000560 |
| `dev` (100) | `gemini_only` | 75 | 0 | 25 | 0 | 1.0000 | 1.0000 | 0.5467 | 1.0000 | 0.0558 | 210.0 / 210.0 | $0.123750 |
| `dev` (100) | `combined` | 75 | 0 | 25 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0558 | 255.0 / 255.0 | $0.124310 |
| `dev` (100) | `routed` | 75 | 0 | 25 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0551 | 255.0 / 255.0 | $0.102260 |
| `held_out` (120) | `subq_only` | 60 | 0 | 60 | 0 | 1.0000 | 1.0000 | 0.8333 | 1.0000 | 0.0324 | 45.0 / 45.0 | $0.000672 |
| `held_out` (120) | `gemini_only` | 60 | 0 | 60 | 0 | 1.0000 | 1.0000 | 0.6667 | 1.0000 | 0.0330 | 210.0 / 210.0 | $0.143100 |
| `held_out` (120) | `combined` | 60 | 0 | 60 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0330 | 255.0 / 255.0 | $0.143772 |
| `held_out` (120) | `routed` | 60 | 0 | 60 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0315 | 255.0 / 255.0 | $0.088647 |
| `soc_workload` (200) | `subq_only` | 40 | 10 | 150 | 0 | 0.8000 | 1.0000 | 1.0000 | 1.0000 | 0.0337 | 45.0 / 45.0 | $0.001120 |
| `soc_workload` (200) | `gemini_only` | 40 | 0 | 160 | 0 | 1.0000 | 1.0000 | 0.6500 | 1.0000 | 0.0185 | 195.0 / 210.0 | $0.227700 |
| `soc_workload` (200) | `combined` | 40 | 0 | 160 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0185 | 240.0 / 255.0 | $0.228820 |
| `soc_workload` (200) | `routed` | 40 | 0 | 160 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0160 | 45.0 / 255.0 | $0.074470 |

## 3. Failure Analysis & Remaining Limitations

- **Unvalidated Live Calibration:** SubQ Snap's real probability calibration (ECE/Brier) and Gemini 4 Hydrogen's real structured-output latency under `429` throttling remain unmeasured until `live_runner.py --confirm-live` is executed with real API keys.
- **Benign-Heavy Efficiency Gains:** On the 80%-benign `soc_workload` split, `routed` cuts median latency from `240.0 ms` to `45.0 ms` (**81.3%**) and estimated cost from `$0.228820` to `$0.074470` (**67.5%**) while keeping `1.0000` Precision and `1.0000` Escalation Recall.
- **Multi-Stage Encoding:** The normalizer decodes single-layer Base64 (`utf-8` / `utf-16-le`); nested or XOR-encoded payloads still depend on model-level reasoning.

## 4. Running Live Validation (Separate from Mock Results)

```bash
# Writes strictly to eval_results/live_phase9_results.jsonl and live_phase9_summary.csv
PYTHONPATH=src python3 -m sec_agent.eval.live_runner --confirm-live
```
