from abc import ABC, abstractmethod

from sec_agent.schemas import GeminiInvestigationResult, SecurityEvent, SubQTriageResult


class DecisionModelClient(ABC):
    """Abstract interface for structured decision models (e.g., SubQ Snap 1.2)."""

    @abstractmethod
    async def triage_event(self, event: SecurityEvent, isolated_log: str) -> SubQTriageResult:
        raise NotImplementedError


class ReasoningModelClient(ABC):
    """Abstract interface for generative investigation models (e.g., Gemini 4 Hydrogen)."""

    @abstractmethod
    async def investigate_event(self, event: SecurityEvent, isolated_log: str) -> GeminiInvestigationResult:
        raise NotImplementedError
