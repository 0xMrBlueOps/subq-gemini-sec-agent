from pathlib import Path

from sec_agent.schemas import AuditRecord, ConsensusAssessment
from sec_agent.security.sanitizer import redact_secrets


class AuditLogger:
    """Append-only JSONL audit logger with secret redaction."""

    def __init__(self, log_path: str | Path) -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, assessment: ConsensusAssessment) -> AuditRecord:
        entry = AuditRecord(assessment=assessment)
        raw_json = entry.model_dump_json() if hasattr(entry, "model_dump_json") else entry.json()
        serialized = redact_secrets(raw_json)
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(serialized + "\n")
        return entry
