from __future__ import annotations

import base64
import re
import unicodedata
from urllib.parse import unquote
from dataclasses import dataclass, field

_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff\u00ad]")
_OBFUSCATED_TICKS_RE = re.compile(r"[\^`](?=[A-Za-z0-9])")
_BASE64_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_CHAINING_RE = re.compile(r"(\&\&|\|\||;|\|\s*(?:bash|sh|zsh|powershell|pwsh|python|curl|wget))")
_SUBSTITUTION_RE = re.compile(r"(\$\{IFS\}|\$\([^)]+\)|`[^`]+`|%COMSPEC%|\$env:[A-Za-z_]+)", re.IGNORECASE)
_NOVEL_SUSPICIOUS_RE = re.compile(
    r"(?i)(certutil\s+-urlcache|bitsadmin\s+/transfer|mshta\s+http|rundll32\s+javascript|"
    r"curl\s+[^|]+\|\s*(?:ba)?sh|wget\s+[^|]+\|\s*(?:ba)?sh|nc\s+-e\s+/bin/|tar\s+.*\|\s*base64)"
)


@dataclass(frozen=True)
class NormalizedTelemetry:
    normalized_text: str
    decoded_fragments: list[str] = field(default_factory=list)
    obfuscation_signals: list[str] = field(default_factory=list)


def _try_decode_base64(token: str) -> str | None:
    if len(token) % 4 != 0:
        return None
    for encoding in ("utf-8", "utf-16-le"):
        try:
            raw = base64.b64decode(token, validate=True)
            decoded = raw.decode(encoding, errors="strict")
            printable = sum(1 for ch in decoded if 32 <= ord(ch) <= 126 or ch in "\r\n\t")
            if len(decoded) >= 6 and (printable / len(decoded)) >= 0.85:
                return decoded.strip()
        except Exception:
            continue
    return None


def normalize_telemetry(raw_text: str) -> NormalizedTelemetry:
    """Canonicalize Unicode, strip obfuscation ticks/zero-width chars, and safely decode bounded Base64."""
    signals: list[str] = []

    nfkc = unicodedata.normalize("NFKC", raw_text)
    if nfkc != raw_text:
        signals.append("unicode_nfkc_normalized")

    no_zw = _ZERO_WIDTH_RE.sub("", nfkc)
    if no_zw != nfkc:
        signals.append("zero_width_chars_stripped")

    deobfuscated = _OBFUSCATED_TICKS_RE.sub("", no_zw)
    if deobfuscated != no_zw:
        signals.append("caret_or_backtick_obfuscation")

    unquoted = unquote(deobfuscated)
    if unquoted != deobfuscated:
        signals.append("url_encoding_decoded")
    collapsed = re.sub(r"[ 	]+", " ", unquoted)

    if _CHAINING_RE.search(collapsed):
        signals.append("command_chaining_detected")

    if _SUBSTITUTION_RE.search(collapsed):
        signals.append("shell_or_env_substitution")

    if _NOVEL_SUSPICIOUS_RE.search(collapsed):
        signals.append("novel_lolbin_or_pipe_pattern")

    decoded_fragments: list[str] = []
    for match in _BASE64_TOKEN_RE.finditer(collapsed):
        if len(decoded_fragments) >= 4:
            break
        dec = _try_decode_base64(match.group(0))
        if dec:
            decoded_fragments.append(dec)
            signals.append("base64_payload_decoded")

    combined = collapsed
    if decoded_fragments:
        combined = f"{collapsed}\n[DECODED_FRAGMENTS]: " + " | ".join(decoded_fragments)

    return NormalizedTelemetry(
        normalized_text=combined,
        decoded_fragments=decoded_fragments,
        obfuscation_signals=sorted(set(signals)),
    )
