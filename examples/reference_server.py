"""Two tiny database MCP servers for testing the harness. Standard library
plus the database driver; speaks MCP stdio JSON-RPC directly.

  --mode naive     What many real servers do: a first-keyword deny-list, the
                   whole string handed to the driver, a BEGIN READ ONLY wrapper
                   on Postgres, every row returned. data-mcp-bench must catch it.
  --mode raw       No protection at all. Used to prove every attack in the
                   catalog really works (each must break this server).
  --mode hardened  Read-only at the database: a read-only connection (SQLite
                   mode=ro plus an authorizer, DuckDB read_only with external
                   access off, a SELECT-only Postgres role), one statement per
                   call, a row cap and column masking. It should pass.

  python reference_server.py --mode naive --engine sqlite --db fixture.db
  python reference_server.py --mode hardened --engine postgres --dsn postgresql://dmb_reader:dmb_reader@host/db
"""
import argparse
import json
import re
import sys

DENY = ("INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE", "GRANT", "REVOKE")
MASK_COLS = re.compile(r"email|ssn|card|phone", re.I)
ROW_CAP = 500
MODE = "naive"


def naive_guard(sql):
    if MODE == "raw":
        return
    if sql.strip().split(None, 1)[0].upper() in DENY:
        raise ValueError("only read queries are allowed")


class SQLite:
    def __init__(self, db, hardened):
        import sqlite3
        self.hardened = hardened
        if hardened:
            self.con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            ok = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}
            self.con.set_authorizer(lambda action, *a: sqlite3.SQLITE_OK if action in ok else sqlite3.SQLITE_DENY)
        else:
            self.con = sqlite3.connect(db, isolation_level=None)

    def run(self, sql):
        if self.hardened:
            cur = self.con.execute(sql)  # sqlite3 refuses more than one statement
        else:
            naive_guard(sql)
            try:
                cur = self.con.execute(sql)
            except Exception as e:  # more than one statement: run them all, like exec() in many drivers
                if "one statement" not in str(e):
                    raise
                self.con.executescript(sql)
                cur = None
        cols = [d[0] for d in cur.description] if cur and cur.description else []
        return cols, (cur.fetchmany(ROW_CAP) if self.hardened else cur.fetchall()) if cols else []


class DuckDB:
    def __init__(self, db, hardened):
        import duckdb
        self.hardened = hardened
        if hardened:
            self.con = duckdb.connect(db, read_only=True, config={"enable_external_access": False})
        else:
            self.con = duckdb.connect(db)

    def run(self, sql):
        if self.hardened:
            stmts = self.con.extract_statements(sql)
            if len(stmts) != 1:
                raise ValueError("one statement per call")
        else:
            naive_guard(sql)
        cur = self.con.execute(sql)
        cols = [d[0] for d in cur.description] if cur.description else []
        return cols, (cur.fetchmany(ROW_CAP) if self.hardened else cur.fetchall()) if cols else []


class Postgres:
    def __init__(self, dsn, hardened):
        import psycopg
        self.hardened = hardened
        self.con = psycopg.connect(dsn, autocommit=True)

    def run(self, sql):
        if self.hardened:
            # extended protocol: one statement only; plus a SELECT-only role
            with self.con.transaction():
                self.con.execute("SET TRANSACTION READ ONLY")
                cur = self.con.cursor()
                cur.execute(sql, prepare=True)
                cols = [d.name for d in cur.description] if cur.description else []
                return cols, cur.fetchmany(ROW_CAP) if cols else []
        naive_guard(sql)
        cur = self.con.cursor()
        if MODE == "raw":
            cur.execute(sql)
            cols = [d.name for d in cur.description] if cur.description else []
            return cols, cur.fetchall() if cols else []
        cur.execute("BEGIN TRANSACTION READ ONLY")
        try:
            cur.execute(sql)  # no params: simple protocol, every statement runs
            cols = [d.name for d in cur.description] if cur.description else []
            rows = cur.fetchall() if cols else []
        finally:
            try:
                cur.execute("ROLLBACK")
            except Exception:
                pass
        return cols, rows


def render(cols, rows, hardened):
    masked = [hardened and bool(MASK_COLS.search(c)) for c in cols]
    out = [dict(zip(cols, ["***" if m else v for v, m in zip(r, masked)])) for r in rows]
    if hardened:
        # mask values too, not just column names: aliases and expressions hide PII
        text = json.dumps(out, default=str)
        text = re.sub(r"[\w.+-]+@[\w-]+\.[\w.]+", "***@***", text)
        text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "***-**-****", text)
        text = re.sub(r"\b\d{4}-\d{4}-\d{4}-\d{4}\b", "****-****-****-****", text)
        return text
    return json.dumps(out, default=str)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["raw", "naive", "hardened"], required=True)
    ap.add_argument("--engine", choices=["sqlite", "duckdb", "postgres"], required=True)
    ap.add_argument("--db")
    ap.add_argument("--dsn")
    a = ap.parse_args()
    global MODE
    MODE = a.mode
    hardened = a.mode == "hardened"
    db = {"sqlite": SQLite, "duckdb": DuckDB, "postgres": Postgres}[a.engine](
        a.dsn if a.engine == "postgres" else a.db, hardened)

    tool = {"name": "query", "description": "Run a read-only SQL query",
            "inputSchema": {"type": "object", "properties": {"sql": {"type": "string"}}, "required": ["sql"]}}

    def reply(mid, result):
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}) + "\n")
        sys.stdout.flush()

    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        mid, method = msg.get("id"), msg.get("method")
        if mid is None:
            continue
        if method == "initialize":
            reply(mid, {"protocolVersion": msg["params"].get("protocolVersion", "2025-06-18"),
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": f"reference-{a.mode}", "version": "0.1.0"}})
        elif method == "tools/list":
            reply(mid, {"tools": [tool]})
        elif method == "tools/call":
            try:
                cols, rows = db.run(msg["params"]["arguments"]["sql"])
                reply(mid, {"content": [{"type": "text", "text": render(cols, rows, hardened)}]})
            except Exception as e:  # noqa: BLE001
                reply(mid, {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True})
        elif method == "ping":
            reply(mid, {})
        else:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid,
                                         "error": {"code": -32601, "message": "method not found"}}) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
