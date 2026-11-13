from __future__ import annotations

import re
from dataclasses import dataclass, field

from sec_agent.schemas import SeverityLevel, SubQTriageResult, ThreatCategory

_HIGH_IMPACT_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("encoded_powershell", re.compile(r"(?i)powershell.*(-enc|-encodedcommand)|winword\.exe.*powershell")),
    ("sudoers_or_shadow", re.compile(r"(?i)(/etc/sudoers|/etc/shadow|nopasswd:all|wheel\s+group|privilege\s+escalation)")),
    ("exfiltration_indicator", re.compile(r"(?i)(exfiltration|customer_dump|tor\s+exit\s+node)")),
    ("mass_auth_failure", re.compile(r"(?i)\b([5-9]\d|\d{3,})\s+failed\s+(password|login)")),
    ("novel_lolbin_execution", re.compile(r"(?i)(certutil\s+-urlcache|bitsadmin\s+/transfer|mshta\s+http|nc\s+-e\s+/bin/|curl\s+[^|]+\|\s*(?:ba)?sh)")),
]


def detect_high_impact_rules(normalized_log: str) -> list[str]:
    """Deterministic security rules on normalized telemetry. Clean scan != benign."""
    hits: list[str] = []
    for name, pattern in _HIGH_IMPACT_RULES:
        if pattern.search(normalized_log):
            hits.append(name)
    return hits


@dataclass(frozen=True)
class UncertaintyPolicy:
    confidence_threshold: float = 0.85
    calibration_margin: float = 0.20
    escalate_band_low: float = 0.30
    escalate_band_high: float = 0.70
    require_gemini_on_obfuscation: bool = True
    high_impact_overrides_confidence: bool = True


@dataclass(frozen=True)
class RoutingDecision:
    invoke_gemini: bool
    decision_label: str
    reasons: list[str] = field(default_factory=list)


class RoutingPolicy:
    """Configurable Phase 9 routing & uncertainty policy: SubQ Snap first, Gemini selectively."""

    def __init__(
        self,
        confidence_threshold: float = 0.85,
        escalate_threshold: float = 0.50,
        injection_threshold: float = 0.35,
        uncertainty_policy: UncertaintyPolicy | None = None,
    ) -> None:
        self.uncertainty = uncertainty_policy or UncertaintyPolicy(confidence_threshold=confidence_threshold)
        self.confidence_threshold = self.uncertainty.confidence_threshold
        self.escalate_threshold = escalate_threshold
        self.injection_threshold = injection_threshold

    def _top_two_margin(self, probs: dict[str, float]) -> float | None:
        if len(probs) < 2:
            return None
        vals = sorted(probs.values(), reverse=True)
        return round(vals[0] - vals[1], 4)

    def decide(
        self,
        subq: SubQTriageResult,
        isolated_log: str,
        sanitization_warnings: list[str],
        obfuscation_signals: list[str] | None = None,
    ) -> RoutingDecision:
        reasons: list[str] = []

        if subq.category != ThreatCategory.BENIGN:
            reasons.append(f"non_benign_category:{subq.category.value}")

        if subq.confidence < self.confidence_threshold:
            reasons.append(f"low_confidence:{subq.confidence:.2f}<{self.confidence_threshold:.2f}")

        margin = self._top_two_margin(subq.category_probabilities)
        if margin is not None and margin < self.uncertainty.calibration_margin:
            reasons.append(f"narrow_probability_margin:{margin:.2f}")

        if subq.severity in {SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL}:
            reasons.append(f"elevated_severity:{subq.severity.value}")

        if subq.escalate_probability >= self.escalate_threshold:
            reasons.append(f"escalate_prob:{subq.escalate_probability:.2f}")
        elif self.uncertainty.escalate_band_low <= subq.escalate_probability <= self.uncertainty.escalate_band_high:
            reasons.append(f"uncertain_escalate_band:{subq.escalate_probability:.2f}")

        if subq.prompt_injection_probability >= self.injection_threshold or any(
            w.startswith("suspected_prompt_injection:") for w in sanitization_warnings
        ):
            reasons.append("prompt_injection_indicator")

        obf = obfuscation_signals or [
            w.split("obfuscation:", 1)[1] for w in sanitization_warnings if w.startswith("obfuscation:")
        ]
        if self.uncertainty.require_gemini_on_obfuscation and obf:
            reasons.append(f"obfuscation_detected:{','.join(obf[:3])}")

        rule_hits = detect_high_impact_rules(isolated_log)
        for hit in rule_hits:
            reasons.append(f"deterministic_rule:{hit}")

        if reasons:
            return RoutingDecision(invoke_gemini=True, decision_label="escalated_to_gemini", reasons=reasons)
        return RoutingDecision(invoke_gemini=False, decision_label="subq_fast_path", reasons=["high_confidence_benign"])
