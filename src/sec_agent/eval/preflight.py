from __future__ import annotations

import asyncio
import importlib
import json
import platform
import sys
from typing import Any

import httpx

from sec_agent.config import Settings


def _mask_secret_status(val: str | None) -> str:
    if not val:
        return "missing"
    return f"configured (len={len(val)})"


async def run_preflight(settings: Settings | None = None, check_network: bool = True) -> dict[str, Any]:
    cfg = settings or Settings()
    deps: dict[str, bool] = {}
    for pkg in ("fastapi", "pydantic", "httpx"):
        try:
            importlib.import_module(pkg)
            deps[pkg] = True
        except ImportError:
            deps[pkg] = False

    report: dict[str, Any] = {
        "python_version": platform.python_version(),
        "dependencies": deps,
        "config": {
            "subq_api_key": _mask_secret_status(cfg.subq_api_key),
            "subq_base_url": cfg.subq_base_url,
            "subq_model_id": cfg.subq_model_id,
            "gemini_api_key": _mask_secret_status(cfg.gemini_api_key),
            "gemini_base_url": cfg.gemini_base_url,
            "gemini_model_id": cfg.gemini_model_id,
            "gemini_thinking_level": cfg.gemini_thinking_level,
            "use_mock_models": cfg.use_mock_models,
        },
        "connectivity": {
            "subq": "skipped (missing SUBQ_API_KEY)" if not cfg.subq_api_key else "pending",
            "gemini": "skipped (missing GEMINI_API_KEY)" if not cfg.gemini_api_key else "pending",
        },
        "ready_for_live_eval": False,
    }

    if check_network and cfg.subq_api_key:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(
                    f"{cfg.subq_base_url.rstrip('/')}/models",
                    headers={"Authorization": f"Bearer {cfg.subq_api_key}"},
                )
            report["connectivity"]["subq"] = f"http_{r.status_code}"
        except Exception as exc:
            report["connectivity"]["subq"] = f"network_error: {type(exc).__name__}"

    if check_network and cfg.gemini_api_key:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(
                    f"{cfg.gemini_base_url.rstrip('/')}/models/{cfg.gemini_model_id}",
                    headers={"x-goog-api-key": cfg.gemini_api_key},
                )
            report["connectivity"]["gemini"] = f"http_{r.status_code}"
        except Exception as exc:
            report["connectivity"]["gemini"] = f"network_error: {type(exc).__name__}"

    report["ready_for_live_eval"] = (
        all(deps.values())
        and report["connectivity"]["subq"] == "http_200"
        and report["connectivity"]["gemini"] == "http_200"
    )
    return report


if __name__ == "__main__":
    res = asyncio.run(run_preflight())
    print(json.dumps(res, indent=2))
    raise SystemExit(0 if res["ready_for_live_eval"] else 1)
