# Phase 11 Threat Model: `subq-gemini-sec-agent`

**Baseline:** `v0.1.0-rc1` (commit `57a68ca`) | **Scope:** Offline Agent-Security Red-Teaming (Mock Providers)

## 1. System Trust Boundaries
1. **Untrusted Telemetry Boundary (`SecurityEvent.raw_log`, `metadata`):** Adversaries control log strings, usernames, hostnames, and HTTP/process arguments. Everything entering `/v1/triage` is untrusted.
2. **Pre-Model Normalization & Sanitization (`normalizer.py`, `sanitizer.py`):** Must strip obfuscation, redact secrets, and wrap telemetry in nonce delimiters (`BEGIN_UNTRUSTED_SECURITY_LOG_<nonce>`) before any model sees it.
3. **Dual-Model Inference Boundary (`SubQSnapAdapter`, `GeminiHydrogenAdapter`):**
   - SubQ Snap (`POST /v1/systemone`) returns typed `noul`, `choice`, `score` probabilities.
   - Gemini Hydrogen (`gemini-4-hydrogen`) returns structured JSON investigation fields.
   - Either model may be partially manipulated or return conflicting outputs.
4. **Consensus & Approval Boundary (`risk_consensus.py`, `HumanApprovalGate`, `ToolPermissionPolicy`):**
   - Must prevent model disagreement from downgrading a threat to `benign`.
   - Must prevent high-impact actions without explicit human approval.
   - Must block unauthorized or case-varied tool names (`execute_shell`, `Execute_Shell`, etc.).

## 2. Attacker Capabilities & Goals
- Embed prompt-injection directives inside logs to hijack Gemini JSON output or SubQ `noul`/`choice`/`score` answers.
- Spoof benign administrative context (e.g., fake change tickets `CHG-9999`) alongside malicious commands to induce false-benign classifications.
- Obfuscate commands via double/URL/hex encoding, PowerShell `-EncodedCommand` / caret / backtick tricks, Unicode zero-width characters, and `${IFS}` / `%COMSPEC%` substitutions.
- Exploit model disagreement so a compromised model overrides a detecting model.
- Attempt tool-permission escalation or approval-gate bypass via forged metadata or API payloads.
