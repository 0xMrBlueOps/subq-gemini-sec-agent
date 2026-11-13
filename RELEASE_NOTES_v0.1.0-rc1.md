# Release Candidate `v0.1.0-rc1` — Adaptive Multi-Model Security Agent

**Status:** Stable Offline Checkpoint (`31/31` unit & regression tests passing; **mock-only** benchmark report; live API validation pending).

## Included Capabilities
- **Dual-Model Architecture:** Provider-isolated `SubQSnapAdapter` (`POST /v1/systemone`, `subq-snap-1.2`) and `GeminiHydrogenAdapter` (`gemini-4-hydrogen:generateContent`) with bounded retries, timeouts, and `event_id` deduplication.
- **Adversarial Input Layer:** Unicode NFKC normalization, zero-width stripping, caret/backtick de-obfuscation, shell/env substitution detection, bounded Base64 decoding, nonce-delimited log isolation, and secret redaction.
- **Adaptive Routing & Safety:** Configurable `RoutingPolicy` + `UncertaintyPolicy` with deterministic high-impact overrides, `HumanApprovalGate` for consequential actions, and append-only JSONL audit logging.
- **Reproducible Benchmarks (Mock-Only):** 220-case dev/held-out + 200-case 80%-benign SOC workload in `PHASE9_REPORT.md` and `eval_results/phase9_summary.csv` (explicitly labeled `execution_type=mock`, **not** live API inference).

## Verification
- `PYTHONPATH=src python3 -m unittest discover -s tests -p "test_*.py" -v` -> **31/31 OK**
- `PYTHONPATH=src python3 -m sec_agent.eval.preflight` -> safe secret-masking diagnostic ready for local `.env` keys.
