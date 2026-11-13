from __future__ import annotations

import argparse
import asyncio
import sys

from sec_agent.config import Settings
from sec_agent.eval.runner_phase9 import run_phase9_benchmark


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run live SubQ Snap + Gemini 4 Hydrogen benchmark.")
    parser.add_argument("--confirm-live", action="store_true", help="Confirm live API calls and token spend.")
    parser.add_argument("--output-dir", default="eval_results", help="Directory for live_phase9_* outputs.")
    args = parser.parse_args(argv)

    cfg = Settings()
    if not args.confirm_live:
        print("Aborted: pass --confirm-live to execute live API requests.", file=sys.stderr)
        return 2
    if not cfg.subq_api_key or not cfg.gemini_api_key:
        print("Missing SUBQ_API_KEY or GEMINI_API_KEY in environment/.env.", file=sys.stderr)
        return 1

    summaries = asyncio.run(run_phase9_benchmark(output_dir=args.output_dir, use_mock=False, settings=cfg))
    for m in summaries:
        print(f"[{m.split}:{m.mode}] (LIVE) P={m.precision} R={m.recall} Cost=${m.estimated_cost_usd:.6f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
