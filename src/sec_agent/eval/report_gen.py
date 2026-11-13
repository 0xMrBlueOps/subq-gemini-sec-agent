from __future__ import annotations

import csv
from pathlib import Path


def generate_live_markdown_report(csv_path: str | Path, out_md: str | Path) -> Path:
    src = Path(csv_path)
    if not src.exists():
        raise FileNotFoundError(f"Live summary CSV not found: {src}")

    rows: list[dict[str, str]] = []
    with src.open("r", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    lines = [
        "# Live Model Evaluation Report (SubQ Snap 1.2 + Gemini 4 Hydrogen)",
        "",
        "| Split | Mode | TP / FP / TN / FN | Precision | Recall | Esc Recall | Avg / p95 (ms) | Cost (USD) |",
        "| :--- | :--- | :--- | ---: | ---: | ---: | :--- | ---: |",
    ]
    for r in rows:
        cm = f"{r['tp']} / {r['fp']} / {r['tn']} / {r['fn']}"
        lat = f"{r['avg_latency_ms']} / {r['p95_latency_ms']}"
        lines.append(
            f"| `{r['split']}` | `{r['mode']}` | {cm} | {r['precision']} | {r['recall']} | {r['escalation_recall']} | {lat} | ${r['estimated_cost_usd']} |"
        )

    dest = Path(out_md)
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return dest
