from __future__ import annotations

import argparse
import asyncio
import json
import sys

from sec_agent.config import Settings
from sec_agent.eval.metrics import GEMINI_INPUT_PER_1M, GEMINI_OUTPUT_PER_1M, SUBQ_INPUT_PER_1M
from sec_agent.gateway import (
    DecisionModelClient,
    GeminiHydrogenAdapter,
    MockGeminiHydrogenClient,
    MockSubQSnapClient,
    ReasoningModelClient,
    SubQSnapAdapter,
)
from sec_agent.schemas import SecurityEvent
from sec_agent.security import isolate_untrusted_log


async def run_one_event_smoke(use_mock: bool = True, settings: Settings | None = None) -> dict[str, object]:
    cfg = settings or Settings()
    event = SecurityEvent(
        event_id="smoke_evt_001",
        source="windows-sysmon",
        host="ws-smoke-01",
        user="smoke_analyst",
        raw_log="winword.exe spawned powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ==",
    )
    sanitized = isolate_untrusted_log(event.raw_log)

    if use_mock:
        subq_client: DecisionModelClient = MockSubQSnapClient()
        gemini_client: ReasoningModelClient = MockGeminiHydrogenClient()
    else:
        subq_client = SubQSnapAdapter(
            api_key=cfg.subq_api_key or "",
            base_url=cfg.subq_base_url,
            model_id=cfg.subq_model_id,
        )
        gemini_client = GeminiHydrogenAdapter(
            api_key=cfg.gemini_api_key or "",
            model_id=cfg.gemini_model_id,
            base_url=cfg.gemini_base_url,
            thinking_level=cfg.gemini_thinking_level,
        )

    subq_res = await subq_client.triage_event(event, sanitized.isolated_text)
    gemini_res = await gemini_client.investigate_event(event, sanitized.isolated_text)

    subq_cost = (subq_res.input_tokens / 1_000_000.0) * SUBQ_INPUT_PER_1M
    gem_cost = (
        (gemini_res.input_tokens / 1_000_000.0) * GEMINI_INPUT_PER_1M
        + ((gemini_res.output_tokens + gemini_res.thoughts_tokens) / 1_000_000.0) * GEMINI_OUTPUT_PER_1M
    )

    return {
        "execution_type": "mock" if use_mock else "live",
        "event_id": event.event_id,
        "subq": {
            "model": subq_res.model,
            "category": subq_res.category.value,
            "severity": subq_res.severity.value,
            "confidence": subq_res.confidence,
            "input_tokens": subq_res.input_tokens,
            "latency_ms": subq_res.latency_ms,
        },
        "gemini": {
            "model": gemini_res.model,
            "category": gemini_res.category.value,
            "severity": gemini_res.severity.value,
            "confidence": gemini_res.confidence,
            "input_tokens": gemini_res.input_tokens,
            "output_tokens": gemini_res.output_tokens,
            "thoughts_tokens": gemini_res.thoughts_tokens,
            "latency_ms": gemini_res.latency_ms,
        },
        "estimated_cost_usd": round(subq_cost + gem_cost, 6),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Safe 1-event live smoke test (1 call per provider).")
    parser.add_argument("--confirm-live", action="store_true", help="Confirm 1 live request per provider.")
    parser.add_argument("--mock", action="store_true", help="Run in offline mock mode.")
    args = parser.parse_args(argv)

    if not args.mock and not args.confirm_live:
        print("Aborted: pass --confirm-live for 1 live call per provider, or --mock for offline.", file=sys.stderr)
        return 2

    cfg = Settings()
    if not args.mock and (not cfg.subq_api_key or not cfg.gemini_api_key):
        print("Missing SUBQ_API_KEY or GEMINI_API_KEY in environment/.env.", file=sys.stderr)
        return 1

    out = asyncio.run(run_one_event_smoke(use_mock=args.mock, settings=cfg))
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
