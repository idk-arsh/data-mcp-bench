"""data-mcp-bench: attack a database MCP server, then ask the database what happened.

  data-mcp-bench run --engine sqlite -- npx -y some-sqlite-mcp {db}
  data-mcp-bench run --engine postgres --dsn postgresql://postgres@localhost:55432/postgres \\
      -- python my_server.py --dsn {dsn}

Placeholders in the server command: {db} (sqlite/duckdb file path, or postgres
database name), {dsn} (postgres URL, superuser), {reader_dsn} (postgres URL for
a SELECT-only role), {dir} (the scenario's working directory), {config} (a
per-scenario copy of --server-config with these placeholders filled in).
"""
from __future__ import annotations

import argparse
import shlex
import sys

from . import __version__
from .report import failed, to_json, to_markdown
from .runner import PROMISES, Runner


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    server_cmd = []
    if "--" in argv:
        i = argv.index("--")
        argv, server_cmd = argv[:i], argv[i + 1:]

    ap = argparse.ArgumentParser(prog="data-mcp-bench", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run the scenarios against a server (command goes after --)")
    r.add_argument("--engine", required=True, choices=["sqlite", "duckdb", "postgres"])
    r.add_argument("--dsn", help="postgres only: superuser URL of a THROWAWAY server")
    r.add_argument("--expect", default="read-only,confined",
                   help=f"promises the server makes, comma-separated from {','.join(PROMISES)} "
                        "(default: read-only,confined). Others are reported but never fail the run.")
    r.add_argument("--tool", help="name of the query tool (auto-detected if omitted)")
    r.add_argument("--arg", help="name of the SQL argument (auto-detected if omitted)")
    r.add_argument("--row-limit", type=int, default=1000, help="max rows a bounded server may return")
    r.add_argument("--only", help="comma-separated substrings of scenario ids to run")
    r.add_argument("--scenarios", help="path to a custom scenario YAML file")
    r.add_argument("--server-config", help="template file filled with the placeholders per scenario; "
                   "its path is passed to the server command as {config}")
    r.add_argument("--timeout", type=float, default=30.0, help="seconds per MCP request")
    r.add_argument("--json", help="write the JSON report here")
    r.add_argument("--markdown", help="write the Markdown report here")
    a = ap.parse_args(argv)

    if not server_cmd:
        ap.error("put the server command after --, e.g.  -- python server.py {db}")
    promises = {p.strip() for p in a.expect.split(",") if p.strip()}
    bad = promises - set(PROMISES)
    if bad:
        ap.error(f"unknown promise(s): {', '.join(sorted(bad))}")

    print(f"data-mcp-bench {__version__}: {a.engine}, promises {sorted(promises)}")
    runner = Runner(a.engine, server_cmd, promises, dsn=a.dsn, tool=a.tool, arg=a.arg,
                    row_limit=a.row_limit, scenarios_file=a.scenarios,
                    only=a.only.split(",") if a.only else None, timeout=a.timeout,
                    config_template=a.server_config)
    results = runner.run()
    meta = {"version": __version__, "engine": a.engine, "server": shlex.join(server_cmd),
            "tool": runner.tool, "arg": runner.arg, "row_limit": a.row_limit}
    md = to_markdown(results, meta, promises)
    if a.markdown:
        open(a.markdown, "w", encoding="utf-8").write(md)
    if a.json:
        open(a.json, "w", encoding="utf-8").write(to_json(results, meta, promises))
    broken = [r for r in results if r.status == "BROKEN"]
    print(f"\n{len(broken)} broken of {len(results)} scenarios"
          + (": " + ", ".join(r.id for r in broken) if broken else ""))
    return 1 if failed(results) else 0


if __name__ == "__main__":
    sys.exit(main())
