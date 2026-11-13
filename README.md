# Multi-Model Autonomous Cybersecurity Triage Agent (SubQ Snap + Gemini 4 Hydrogen)

An experimental, modular cybersecurity triage and investigation agent combining **SubQ Snap 1.2** (`POST /v1/systemone`) for fast, calibrated classification/routing with **Gemini 4 Hydrogen** (`gemini-4-hydrogen`) for deep reasoning, anomaly investigation, and structured incident reporting.

## Architecture & Phase 8 Intelligent Routing

- **`src/sec_agent/gateway/`**: Provider-isolated interfaces (`DecisionModelClient`, `ReasoningModelClient`) with live `httpx` adapters (`SubQSnapAdapter`, `GeminiHydrogenAdapter`) and deterministic offline mocks.
- **`src/sec_agent/engine/router.py`**: Configurable `RoutingPolicy` where **SubQ Snap** is the initial decision engine and **Gemini Hydrogen** is invoked selectively when:
  - SubQ classifies the event as non-benign (`category != benign`),
  - SubQ confidence falls below `ROUTING_CONFIDENCE_THRESHOLD` (default `0.85`),
  - SubQ severity is `medium` or higher,
  - Prompt-injection indicators are detected (`ROUTING_INJECTION_THRESHOLD`, default `0.35`, or sanitizer warnings),
  - Deterministic high-impact security rules trigger (e.g., encoded PowerShell, `/etc/sudoers` or `/etc/shadow`, exfiltration indicators, mass auth failures), or `escalate_probability >= ROUTING_ESCALATE_THRESHOLD` (default `0.50`).
- **`src/sec_agent/security/`**: Nonce-delimited untrusted log isolation, prompt-injection detection, secret redaction, least-privilege tool boundaries, and `HumanApprovalGate` (preserving human approval for consequential actions and never auto-dismissing high-impact uncertain events).
- **`src/sec_agent/engine/risk_consensus.py`**: Reconciles SubQ + Gemini outputs; model disagreements trigger human investigation rather than automatic averaging.
- **`src/sec_agent/audit/`**: Append-only JSONL audit logger.
- **`src/sec_agent/eval/`**: Reproducible 25-case synthetic benchmark across 4 modes (`subq_only`, `gemini_only`, `combined`, `routed`).

## Offline Mock Benchmark Results (NOT Live API Inference)

> **Important:** The table below was generated using deterministic offline mock clients (`execution_type=mock`). Do **not** claim production readiness or live model accuracy from synthetic mock data.

| Mode | Type | Precision | Recall | FPR | FNR | Category Acc | Severity Agreement | Escalation Recall | Avg Latency (ms) | Input / Output Tokens |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `subq_only` | `mock` | 0.7895 | 1.0000 | 0.4000 | 0.0000 | 0.8400 | 0.8000 | 0.9333 | 45.0 | 3,500 / 0 |
| `gemini_only` | `mock` | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 1.0000 | 0.7333 | 205.2 | 6,840 / 2,715 |
| `combined` | `mock` | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 0.8000 | 1.0000 | 250.2 | 10,340 / 2,715 |
| `routed` | `mock` | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 0.8000 | 1.0000 | 202.2 | 8,740 / 2,105 |

## Remaining Weaknesses & Limitations

- **Synthetic Evaluation Only:** All 25 test cases are synthetic; live API inference (`USE_MOCK_MODELS=false`) is required to measure real-world precision, calibration, and `429` rate-limit behavior.
- **Keyword-Based Deterministic Rules:** `_HIGH_IMPACT_RULES` in `router.py` catches known patterns (e.g., `/etc/sudoers`, `powershell -enc`) but will miss novel obfuscation if SubQ also misclassifies with high confidence.
- **Dataset Skew Sensitivity:** In the balanced 25-case benchmark (only 20% routine benign), `routed` saves 19.2% latency and 22.5% output tokens; real savings depend on the benign-to-threat ratio in production telemetry.
- **Conservative Max-Severity Flagging:** Retaining the higher severity on SubQ/Gemini disagreement preserves `1.0000` Escalation Recall but leaves `Severity Agreement` at `0.8000` on authorized false positives.

## Reproducible Instructions

```bash
# Run all 19 unit & routing regression tests
PYTHONPATH=src python3 -m unittest discover -s tests -p "test_*.py" -v

# Run 4-mode 25-case synthetic benchmark (mock mode)
PYTHONPATH=src python3 -m sec_agent.eval.runner
```

## Phase 10: Live Model Validation & Preflight Instructions

1. **Configure local `.env`** (never commit secrets):
   ```bash
   cp .env.example .env
   # Set SUBQ_API_KEY, GEMINI_API_KEY, and USE_MOCK_MODELS=false
   ```
2. **Run safe connectivity preflight** (masks keys, checks `/v1/models` and Gemini model metadata):
   ```bash
   PYTHONPATH=src python3 -m sec_agent.eval.preflight
   ```
3. **Run the live 4-mode benchmark** (writes strictly to `eval_results/live_phase9_results.jsonl` and `live_phase9_summary.csv`):
   ```bash
   PYTHONPATH=src python3 -m sec_agent.eval.live_runner --confirm-live
   ```
4. **Generate the live Markdown report**:
   ```bash
   PYTHONPATH=src python3 -c "from sec_agent.eval.report_gen import generate_live_markdown_report; generate_live_markdown_report('eval_results/live_phase9_summary.csv', 'LIVE_EVALUATION_REPORT.md')"
   ```
