from __future__ import annotations

import os
import re
import secrets
import tempfile
from dataclasses import dataclass, field
from importlib import resources

import yaml

from .engines import DuckDBEngine, PostgresEngine, SQLiteEngine
from .mcp_client import MCPError, StdioClient

PROMISES = ("read-only", "confined", "bounded", "masked")
EVENT_RE = re.compile(r"evt-\d{7}")
PII_RE = re.compile(r"dmb\.user\d{4}@pii-canary\.invalid|987-65-\d{4}|4000-0000-0000-\d{4}")
TOOL_NAME_RE = re.compile(r"query|sql|select|execute|run|read", re.I)
WRITE_NAME_RE = re.compile(r"write|insert|update|delete|create|drop|alter|modify", re.I)
ARG_NAME_RE = re.compile(r"^(sql|query|statement|sql_query|querystring|q)$", re.I)


@dataclass
class Result:
    id: str
    promise: str
    sql: str
    status: str            # HELD | BROKEN | ERROR | (lower-case when the promise was not declared)
    evidence: list = field(default_factory=list)
    reply: str = ""
    refused: bool = False
    why: str = ""
    source: str = ""


def load_scenarios(engine: str, path: str | None = None) -> list[dict]:
    if path:
        text = open(path, encoding="utf-8").read()
    else:
        text = resources.files("data_mcp_bench").joinpath(f"scenarios/{engine}.yaml").read_text("utf-8")
    return yaml.safe_load(text)


def fill(s: str, values: dict) -> str:
    for k, v in values.items():
        s = s.replace("{" + k + "}", str(v))
    return s


def pick_tool(tools: list[dict], name: str | None, arg: str | None) -> tuple[str, str]:
    def string_args(t):
        props = (t.get("inputSchema") or {}).get("properties") or {}
        return [k for k, v in props.items() if (v or {}).get("type") in ("string", None)]

    if name:
        cands = [t for t in tools if t["name"] == name]
        if not cands:
            raise SystemExit(f"tool {name!r} not found; server offers: {[t['name'] for t in tools]}")
    else:
        cands = [t for t in tools if TOOL_NAME_RE.search(t["name"]) and not WRITE_NAME_RE.search(t["name"])
                 and any(ARG_NAME_RE.match(a) for a in string_args(t))]
        if not cands:
            raise SystemExit("could not find a read/query tool; pass --tool and --arg. "
                             f"Server offers: {[t['name'] for t in tools]}")
        # prefer names that say read/select/query over generic execute/run
        cands.sort(key=lambda t: (not re.search(r"read|select|query", t["name"], re.I), len(t["name"])))
    tool = cands[0]
    if arg:
        return tool["name"], arg
    args = [a for a in string_args(tool) if ARG_NAME_RE.match(a)] or string_args(tool)
    if not args:
        raise SystemExit(f"tool {tool['name']!r} has no string argument; pass --arg")
    return tool["name"], args[0]


def describe_diff(before: dict, after: dict) -> list[str]:
    out = []
    for k in sorted(set(before) | set(after)):
        b, a = before.get(k), after.get(k)
        if b == a or k == "schema":
            continue
        if k == "objects":
            added, removed = sorted(set(a or []) - set(b or [])), sorted(set(b or []) - set(a or []))
            if added:
                out.append("created " + ", ".join(added))
            if removed:
                out.append("dropped " + ", ".join(removed))
        elif k.startswith("rows:"):
            if a is None:
                continue  # covered by "dropped"
            if b is None:
                out.append(f"new table {k[5:]} ({a.split(' #')[0]})")
                continue
            bc, ac = b.split(" #")[0], a.split(" #")[0]
            out.append(f"{k[5:]}: {bc} -> {ac}" if bc != ac else f"{k[5:]}: rows changed ({ac})")
        elif k.startswith("file:"):
            if b is None and a is not None:
                out.append(f"new file {k[5:]} ({a} bytes)")
            elif a is None:
                out.append(f"file removed {k[5:]}")
            else:
                out.append(f"file {k[5:]} changed ({b} -> {a} bytes)")
        elif isinstance(b, list) or isinstance(a, list):
            added = sorted(set(a or []) - set(b or []))
            removed = sorted(set(b or []) - set(a or []))
            out.append(f"{k}: " + ", ".join([f"+{x}" for x in added] + [f"-{x}" for x in removed]))
        else:
            out.append(f"{k}: {b} -> {a}")
    return out


class Runner:
    def __init__(self, engine: str, server_cmd: list[str], promises: set[str], dsn: str | None = None,
                 tool: str | None = None, arg: str | None = None, row_limit: int = 1000,
                 scenarios_file: str | None = None, only: list[str] | None = None,
                 timeout: float = 30.0, log=print):
        self.engine_name = engine
        self.engine = {"sqlite": SQLiteEngine, "duckdb": DuckDBEngine}.get(engine)
        self.engine = self.engine() if self.engine else PostgresEngine(dsn or "")
        if engine == "postgres" and not dsn:
            raise SystemExit("--dsn is required for postgres (a throwaway server you are superuser on)")
        self.server_cmd = server_cmd
        self.promises = promises
        self.tool, self.arg = tool, arg
        self.row_limit = row_limit
        self.timeout = timeout
        self.log = log
        scen = load_scenarios(engine, scenarios_file)
        if only:
            scen = [s for s in scen if s["promise"] == "sanity" or any(o in s["id"] for o in only)]
        self.scenarios = scen

    def run(self) -> list[Result]:
        root = tempfile.mkdtemp(prefix="dmb-")
        nonce = secrets.token_hex(4)
        self.engine.build(root, nonce)
        results = []
        try:
            for i, s in enumerate(self.scenarios):
                r = self._one(root, i, s)
                results.append(r)
                self.log(f"  {r.status:<8} {r.id}" + (f"  ({'; '.join(r.evidence)})" if r.evidence else ""))
                if s["promise"] == "sanity" and r.status != "HELD":
                    raise SystemExit("sanity check failed: the harness could not get rows back from the "
                                     f"server's query tool. Reply was: {r.reply[:300]!r}")
        finally:
            self.engine.close()
        return results

    def _one(self, root: str, i: int, s: dict) -> Result:
        sid = s["id"]
        ctx = self.engine.prepare(os.path.join(root, f"s{i:02d}"), sid)
        sql = fill(s["sql"], ctx.values)
        res = Result(sid, s["promise"], sql, "ERROR", why=s.get("why", ""), source=s.get("source", ""))
        try:
            before = self.engine.snapshot(ctx)
            cmd = [fill(a, ctx.values) for a in self.server_cmd]
            client = StdioClient(cmd, timeout=self.timeout,
                                 stderr_path=os.path.join(root, f"s{i:02d}.stderr.log"))
            try:
                client.initialize()
                if not self.tool or not self.arg:
                    self.tool, self.arg = pick_tool(client.list_tools(), self.tool, self.arg)
                    self.log(f"  using tool {self.tool!r}, argument {self.arg!r}")
                res.refused, res.reply = client.call_tool(self.tool, {self.arg: sql})
            except MCPError as e:
                res.evidence.append(f"server error before the call: {e}")
                return res
            finally:
                client.close()
            after = self.engine.snapshot(ctx)
        except SystemExit:
            raise
        except Exception as e:  # noqa: BLE001 - one bad scenario must not stop the run
            res.evidence.append(f"harness error: {type(e).__name__}: {e}")
            return res
        finally:
            try:
                self.engine.cleanup(ctx)
            except Exception:  # noqa: BLE001
                pass

        diff = describe_diff(before, after)
        broken = False
        p = s["promise"]
        if p == "sanity":
            broken = res.refused or "alpha" not in res.reply
            if broken:
                res.evidence.append("no rows came back")
        elif p in ("read-only", "control"):
            broken = bool(diff)
            res.evidence += diff
        elif p == "confined":
            leaked = ctx.values.get("token", "\0") in res.reply
            broken = bool(diff) or leaked
            res.evidence += diff + (["canary secret file contents returned"] if leaked else [])
        elif p == "bounded":
            n = len(set(EVENT_RE.findall(res.reply)))
            broken = n > self.row_limit
            res.evidence.append(f"{n:,} of 100,000 rows returned (limit {self.row_limit:,})")
            if diff:
                res.evidence += diff
        elif p == "masked":
            n = len(set(PII_RE.findall(res.reply)))
            broken = n > 0
            if n:
                res.evidence.append(f"{n} raw PII values returned")
            if diff:
                res.evidence += diff
        status = "BROKEN" if broken else "HELD"
        promised = p in ("sanity", "control") or p in self.promises or (p == "control" and "read-only" in self.promises)
        res.status = status if promised else status.lower()
        return res
