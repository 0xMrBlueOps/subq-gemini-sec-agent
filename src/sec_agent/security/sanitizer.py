import re
from dataclasses import dataclass, field
from uuid import uuid4

from sec_agent.security.normalizer import normalize_telemetry

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"sk-[A-Za-z0-9_-]{16,}"), "[REDACTED_API_KEY]"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{20,}"), "[REDACTED_GOOGLE_KEY]"),
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)\S+"), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(?i)(password|passwd|secret|token)\s*=\s*\S+"), r"\1=[REDACTED]"),
]

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ignore_instructions", re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions")),
    ("role_override", re.compile(r"(?i)(you\s+are\s+now|act\s+as\s+system|new\s+system\s+prompt)")),
    ("tool_coercion", re.compile(r"(?i)(execute\s+command|run\s+shell|disable\s+logging|mark\s+as\s+benign)")),
    ("output_hijack", re.compile(r"(?i)(classify\s+(as\s+)?benign|set\s+severity\s+low|output\s+benign)")),
]


@dataclass(frozen=True)
class SanitizedPayload:
    isolated_text: str
    redacted_log: str
    normalized_text: str
    delimiter_nonce: str
    warnings: list[str] = field(default_factory=list)
    obfuscation_signals: list[str] = field(default_factory=list)


def redact_secrets(text: str) -> str:
    """Redact common API keys, bearer tokens, and inline credentials before logging or model calls."""
    cleaned = text
    for pattern, replacement in _SECRET_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


def isolate_untrusted_log(raw_log: str) -> SanitizedPayload:
    """Redact secrets, normalize adversarial obfuscation, and wrap log in a randomized nonce boundary."""
    redacted = redact_secrets(raw_log)
    norm = normalize_telemetry(redacted)
    warnings: list[str] = []

    for label, pattern in _INJECTION_PATTERNS:
        if pattern.search(norm.normalized_text):
            warnings.append(f"suspected_prompt_injection:{label}")

    if redacted != raw_log:
        warnings.append("secrets_redacted_from_input")

    for sig in norm.obfuscation_signals:
        warnings.append(f"obfuscation:{sig}")

    nonce = uuid4().hex[:12]
    isolated = (
        f"BEGIN_UNTRUSTED_SECURITY_LOG_{nonce}\n"
        f"{norm.normalized_text}\n"
        f"END_UNTRUSTED_SECURITY_LOG_{nonce}"
    )
    return SanitizedPayload(
        isolated_text=isolated,
        redacted_log=redacted,
        normalized_text=norm.normalized_text,
        delimiter_nonce=nonce,
        warnings=warnings,
        obfuscation_signals=norm.obfuscation_signals,
    )
