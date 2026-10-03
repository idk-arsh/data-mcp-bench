from __future__ import annotations

import json
from collections import Counter

from .runner import PROMISES, Result


def summary(results: list[Result], promises: set[str]) -> dict:
    by = {}
    for p in PROMISES:
        rs = [r for r in results if r.promise == p or (p == "read-only" and r.promise == "control")]
        if not rs:
            continue
        c = Counter(r.status.upper() for r in rs)
        by[p] = {"declared": p in promises, "held": c["HELD"], "broken": c["BROKEN"], "error": c["ERROR"]}
    return by


def failed(results: list[Result]) -> bool:
    return any(r.status == "BROKEN" for r in results)


def to_json(results: list[Result], meta: dict, promises: set[str]) -> str:
    return json.dumps({**meta, "summary": summary(results, promises),
                       "results": [r.__dict__ for r in results]}, indent=2)


def _cell(s: str, n: int = 120) -> str:
    s = " ".join(s.split())
    s = s if len(s) <= n else s[: n - 1] + "…"
    return s.replace("|", "\\|")


def to_markdown(results: list[Result], meta: dict, promises: set[str]) -> str:
    lines = [f"# data-mcp-bench report", "",
             f"- Server: `{meta['server']}`",
             f"- Engine: {meta['engine']}, tool `{meta.get('tool')}`",
             f"- Promises checked: {', '.join(sorted(promises)) or 'none'}", ""]
    lines += ["| Promise | Declared | Held | Broken | Errors |", "|---|---|---|---|---|"]
    for p, s in summary(results, promises).items():
        lines.append(f"| {p} | {'yes' if s['declared'] else 'no (informational)'} | {s['held']} | "
                     f"{s['broken']} | {s['error']} |")
    lines += ["", "**Verdicts come from the database, not from the server's reply.** BROKEN means the "
              "database changed, a file was written or read, or rows/PII came back past the promise.", ""]
    lines += ["| Status | Scenario | Promise | Evidence | Server said |", "|---|---|---|---|---|"]
    order = {"BROKEN": 0, "ERROR": 1, "broken": 2, "HELD": 3, "held": 4, "error": 5}
    for r in sorted(results, key=lambda r: order.get(r.status, 9)):
        said = ("refused: " if r.refused else "ok: ") + _cell(r.reply, 80)
        lines.append(f"| {r.status} | `{r.id}` | {r.promise} | {_cell('; '.join(r.evidence)) or '-'} | {said} |")
    lines += ["", "Lower-case status = the server did not claim that promise; shown for information only."]
    return "\n".join(lines) + "\n"
