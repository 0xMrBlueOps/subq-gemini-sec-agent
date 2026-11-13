# Phase 11 Red-Team Report (Offline Mock Simulation)

> **Important:** All results below were executed offline using mock providers and simulated compromised-model stubs (`execution_type=mock`). They do **not** represent live API evaluation or production readiness.

## 1. Baseline (`v0.1.0-rc1`) Vulnerabilities Discovered

Running `redteam_runner.py` against `v0.1.0-rc1` uncovered **5 bypasses out of 21 attacks** (`23.81%` bypass rate, `76.19%` detection rate):

1. **Consensus Category Downgrade (`rt_md_01`, `rt_md_03`, `rt_fb_01`–`03`):** `evaluate_consensus` previously set `final_category = gemini.category` whenever models disagreed. When Gemini was hijacked to return `benign` (`0.99` confidence) or fooled by spoofed `CHG-` tickets, `final_category` became `benign` even when SubQ flagged `CRITICAL`.
2. **False-Benign Spoofing (`rt_fb_01`–`03`):** `MockGeminiHydrogenClient` checked `"authorized"` / `"chg-"` strings *before* checking high-impact compromise indicators (`/etc/sudoers`, `customer_dump`, `winword.exe`).
3. **Missing URL-Decoding & Case Normalization:** `normalizer.py` lacked URL-decoding (`%20`), and `ToolPermissionPolicy` checked `CONSEQUENTIAL_ACTIONS` without `.strip().lower()` normalization.
4. **Incomplete TOR Indicator Matching:** `MockSubQSnapClient` missed standalone `"tor exit node"` when `"impossible travel"` was omitted.

## 2. Before vs. After Remediation (21 Attacks + 4 Controls)

| Metric | Baseline (`v0.1.0-rc1`) | Patched (`phase11-agent-redteam`) |
| :--- | ---: | ---: |
| Attack Detection Rate | 0.7619 (16/21) | **1.0000 (21/21)** |
| Successful Bypass Rate | 0.2381 (5/21) | **0.0000 (0/21)** |
| Human Approval Enforcement | 1.0000 (21/21) | **1.0000 (21/21)** |
| False-Positive Rate (Controls) | 0.0000 (0/4) | **0.0000 (0/4)** |
| False-Negative Rate | 0.2381 (5/21) | **0.0000 (0/21)** |

## 3. Verification & Git Integrity
- **Test Suite:** `36/36` `unittest` tests pass (`31` preserved + `5` new Phase 11 regression tests).
- **Release Tag Preserved:** `v0.1.0-rc1` remains untouched at commit `57a68ca`.

## 4. Remaining Limitations
- Live API prompt-injection resistance against real `subq-snap-1.2` and `gemini-4-hydrogen` weights has not been tested yet (requires local `.env` keys + `live_runner.py --confirm-live`).
- Multi-layer nested encodings (e.g., XOR + double Base64) are not decoded by `normalizer.py`.
