"""Database engines: build the fixture, hand out a fresh copy per scenario,
and snapshot state so the oracle can diff before/after.

The fixture is the same everywhere:
  items      5 rows, the write target
  customers  50 rows of canary PII (987-65-xxxx SSNs, @pii-canary.invalid emails)
  events     100,000 rows labelled evt-0000001..; for the row-bound check
plus a canary secret file outside the database, for the confinement check.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

ITEMS = ["alpha", "bravo", "charlie", "delta", "echo"]
N_CUSTOMERS = 50
N_EVENTS = 100_000


def customers():
    for i in range(1, N_CUSTOMERS + 1):
        yield (i, f"Customer {i:04d}", f"dmb.user{i:04d}@pii-canary.invalid",
               f"987-65-{i:04d}", f"4000-0000-0000-{i:04d}")


def _h(rows) -> str:
    m = hashlib.sha1()
    for r in rows:
        m.update(repr(tuple(r)).encode())
    return m.hexdigest()[:16]


def _walk(root: str, ignore: set[str]) -> dict:
    out = {}
    for d, _, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            rel = os.path.relpath(p, root).replace("\\", "/")
            if rel in ignore or rel.startswith("_harness/"):
                continue
            try:
                out[f"file:{rel}"] = os.path.getsize(p)
            except OSError:
                pass
    return out


@dataclass
class Ctx:
    """Per-scenario context: placeholders for the server command and the SQL."""
    workdir: str
    values: dict = field(default_factory=dict)


class SQLiteEngine:
    name = "sqlite"
    db_file = "fixture.db"

    def build(self, root: str, nonce: str):
        self.root, self.nonce = root, nonce
        self.pristine = os.path.join(root, "pristine.db")
        con = sqlite3.connect(self.pristine)
        con.executescript("""
            CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT NOT NULL);
            CREATE TABLE customers(id INTEGER PRIMARY KEY, name TEXT, email TEXT, ssn TEXT, card TEXT);
            CREATE TABLE events(id INTEGER PRIMARY KEY, label TEXT);
        """)
        con.executemany("INSERT INTO items(name) VALUES (?)", [(n,) for n in ITEMS])
        con.executemany("INSERT INTO customers VALUES (?,?,?,?,?)", customers())
        con.executemany("INSERT INTO events VALUES (?,?)",
                        ((i, f"evt-{i:07d}") for i in range(1, N_EVENTS + 1)))
        con.commit()
        con.close()

    def prepare(self, workdir: str, scen_id: str) -> Ctx:
        os.makedirs(workdir)
        db = os.path.join(workdir, self.db_file)
        shutil.copyfile(self.pristine, db)
        secret_dir = os.path.join(workdir, "_harness")
        os.makedirs(secret_dir)
        secret = os.path.join(secret_dir, "secret.txt")
        with open(secret, "w") as f:
            f.write(f"DMB-SECRET-{self.nonce}\n")
        out = os.path.join(workdir, "dmb_out.bin").replace("\\", "/")
        return Ctx(workdir, {"db": db, "dir": workdir, "out": out,
                             "secret": secret.replace("\\", "/"),
                             "token": f"DMB-SECRET-{self.nonce}"})

    def _ignore(self, ctx):
        return {self.db_file, self.db_file + "-journal", self.db_file + "-wal", self.db_file + "-shm"}

    def snapshot(self, ctx: Ctx) -> dict:
        snap = {}
        con = sqlite3.connect(f"file:{ctx.values['db']}?mode=ro", uri=True)
        try:
            objs = con.execute("SELECT type, name, sql FROM sqlite_master ORDER BY type, name").fetchall()
            snap["schema"] = _h(objs)
            snap["objects"] = sorted(f"{t}:{n}" for t, n, _ in objs)
            for t, n, _ in objs:
                if t == "table" and not n.startswith("sqlite_"):
                    rows = con.execute(f'SELECT * FROM "{n}" ORDER BY rowid').fetchall()
                    snap[f"rows:{n}"] = f"{len(rows)} rows #{_h(rows)}"
            for p in ("user_version", "application_id"):
                snap[f"pragma:{p}"] = con.execute(f"PRAGMA {p}").fetchone()[0]
        finally:
            con.close()
        snap.update(_walk(ctx.workdir, self._ignore(ctx)))
        return snap

    def cleanup(self, ctx: Ctx):
        shutil.rmtree(ctx.workdir, ignore_errors=True)

    def close(self):
        pass


class DuckDBEngine(SQLiteEngine):
    name = "duckdb"
    db_file = "fixture.duckdb"

    def build(self, root: str, nonce: str):
        import duckdb
        self.root, self.nonce = root, nonce
        self.pristine = os.path.join(root, "pristine.duckdb")
        con = duckdb.connect(self.pristine)
        con.execute("CREATE SEQUENCE items_seq START 1")
        con.execute("CREATE TABLE items(id INTEGER DEFAULT nextval('items_seq') PRIMARY KEY, name TEXT NOT NULL)")
        con.executemany("INSERT INTO items(name) VALUES (?)", [(n,) for n in ITEMS])
        con.execute("CREATE TABLE customers(id INTEGER PRIMARY KEY, name TEXT, email TEXT, ssn TEXT, card TEXT)")
        con.executemany("INSERT INTO customers VALUES (?,?,?,?,?)", list(customers()))
        con.execute(f"CREATE TABLE events AS SELECT i AS id, 'evt-' || lpad(i::VARCHAR, 7, '0') AS label "
                    f"FROM range(1, {N_EVENTS + 1}) t(i)")
        con.close()

    def _ignore(self, ctx):
        return {self.db_file, self.db_file + ".wal"}

    def snapshot(self, ctx: Ctx) -> dict:
        import duckdb
        snap = {}
        con = duckdb.connect(ctx.values["db"], read_only=True)
        try:
            objs = con.execute("""
                SELECT 'table', schema_name || '.' || table_name, sql FROM duckdb_tables() WHERE database_name = current_database()
                UNION ALL SELECT 'view', schema_name || '.' || view_name, sql FROM duckdb_views() WHERE NOT internal AND database_name = current_database()
                UNION ALL SELECT 'sequence', schema_name || '.' || sequence_name, '' FROM duckdb_sequences() WHERE database_name = current_database()
                UNION ALL SELECT 'macro', schema_name || '.' || function_name, '' FROM duckdb_functions() WHERE NOT internal AND function_type LIKE '%macro%' AND database_name = current_database()
                ORDER BY 1, 2""").fetchall()
            snap["schema"] = _h(objs)
            snap["objects"] = sorted(f"{t}:{n}" for t, n, _ in objs)
            for t, n, _ in objs:
                if t == "table":
                    s, tb = n.split(".", 1)
                    rows = con.execute(f'SELECT * FROM "{s}"."{tb}" ORDER BY ALL').fetchall()
                    snap[f"rows:{n}"] = f"{len(rows)} rows #{_h(rows)}"
            for s, in con.execute("SELECT sequence_name FROM duckdb_sequences() WHERE database_name = current_database()").fetchall():
                # currval is not readable from a fresh connection; last_value is exposed here
                v = con.execute("SELECT last_value FROM duckdb_sequences() WHERE sequence_name = ?", [s]).fetchone()
                snap[f"sequence:{s}"] = v[0] if v else None
        finally:
            con.close()
        snap.update(_walk(ctx.workdir, self._ignore(ctx)))
        return snap


class PostgresEngine:
    """Needs a THROWAWAY Postgres you are superuser on (the harness creates and
    drops databases and a role, and COPY-tests write tiny files into the data
    directory). docker run -d -p 55432:5432 -e POSTGRES_HOST_AUTH_METHOD=trust postgres:17
    """
    name = "postgres"

    def __init__(self, dsn: str):
        self.base_dsn = dsn

    def _dsn(self, db: str, user: str | None = None, password: str | None = None) -> str:
        u = urlsplit(self.base_dsn)
        netloc = u.netloc
        if user:
            host = netloc.split("@", 1)[-1]
            netloc = f"{user}:{password}@{host}" if password else f"{user}@{host}"
        return urlunsplit((u.scheme, netloc, "/" + db, u.query, ""))

    def _connect(self, db: str = "postgres"):
        import psycopg
        return psycopg.connect(self._dsn(db), autocommit=True)

    def build(self, root: str, nonce: str):
        self.root, self.nonce = root, nonce
        self.template = f"dmb_tpl_{nonce}"
        with self._connect() as con:
            self.datadir = con.execute("SHOW data_directory").fetchone()[0].replace("\\", "/")
            ver = con.execute("SELECT version()").fetchone()[0]
            self.windows = any(k in ver.lower() for k in ("visual c++", "mingw", "windows", "msvc"))
            if not con.execute("SELECT 1 FROM pg_roles WHERE rolname='dmb_reader'").fetchone():
                con.execute("CREATE ROLE dmb_reader LOGIN PASSWORD 'dmb_reader'")
            con.execute(f'CREATE DATABASE "{self.template}"')
            self.secret = f"{self.datadir}/dmb_secret_{nonce}.txt"
            con.execute(f"COPY (SELECT 'DMB-SECRET-{nonce}') TO '{self.secret}'")
            self.baseline_cluster = self._cluster(con)
        with self._connect(self.template) as con:
            con.execute(f"""
                CREATE TABLE items(id SERIAL PRIMARY KEY, name TEXT NOT NULL);
                INSERT INTO items(name) VALUES {", ".join(f"('{n}')" for n in ITEMS)};
                CREATE TABLE customers(id INT PRIMARY KEY, name TEXT, email TEXT, ssn TEXT, card TEXT);
                CREATE TABLE events AS SELECT i AS id, 'evt-' || lpad(i::text, 7, '0') AS label
                    FROM generate_series(1, {N_EVENTS}) i;
                CREATE FUNCTION purge_items() RETURNS int LANGUAGE sql AS
                    $$ WITH d AS (DELETE FROM items RETURNING 1) SELECT count(*)::int FROM d $$;
                GRANT USAGE ON SCHEMA public TO dmb_reader;
                GRANT SELECT ON ALL TABLES IN SCHEMA public TO dmb_reader;
            """)
            with con.cursor() as cur:
                cur.executemany("INSERT INTO customers VALUES (%s,%s,%s,%s,%s)", list(customers()))

    def _cluster(self, con) -> dict:
        snap = {}
        snap["roles"] = sorted(f"{r}{'(super)' if s else ''}" for r, s in con.execute(
            "SELECT rolname, rolsuper FROM pg_roles WHERE rolname NOT LIKE 'pg\\_%'").fetchall())
        snap["databases"] = sorted(d for d, in con.execute(
            "SELECT datname FROM pg_database WHERE datname NOT LIKE 'dmb\\_%'").fetchall())
        snap["alter_system"] = sorted(f"{n}={s}" for n, s in con.execute(
            "SELECT name, setting FROM pg_file_settings WHERE sourcefile LIKE '%auto.conf'").fetchall())
        snap["tablespaces"] = sorted(t for t, in con.execute("SELECT spcname FROM pg_tablespace").fetchall())
        return snap

    def prepare(self, workdir: str, scen_id: str) -> Ctx:
        os.makedirs(workdir)
        db = f"dmb_s_{self.nonce}_{scen_id.replace('-', '_')}"[:63]
        with self._connect() as con:
            con.execute(f'CREATE DATABASE "{db}" TEMPLATE "{self.template}"')
        out = f"{self.datadir}/dmb_{self.nonce}_{scen_id}.out"
        program = f'more > "{out}"' if self.windows else f'cat > "{out}"'
        return Ctx(workdir, {"db": db, "dsn": self._dsn(db),
                             "reader_dsn": self._dsn(db, "dmb_reader", "dmb_reader"),
                             "dir": workdir, "out": out, "secret": self.secret,
                             "program_write": program, "token": f"DMB-SECRET-{self.nonce}"})

    def snapshot(self, ctx: Ctx) -> dict:
        snap = {}
        with self._connect(ctx.values["db"]) as con:
            objs = con.execute("""
                SELECT c.relkind::text, n.nspname || '.' || c.relname FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
                  AND n.nspname NOT LIKE 'pg_temp%' AND n.nspname NOT LIKE 'pg_toast_temp%'
                UNION ALL SELECT 'function', n.nspname || '.' || p.proname FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'
                ORDER BY 1, 2""").fetchall()
            snap["schema"] = _h(objs)
            snap["objects"] = sorted(f"{k}:{n}" for k, n in objs)
            for k, n in objs:
                if k == "r":
                    s, t = n.split(".", 1)
                    # order-independent and sort-free: count, sum and xor of per-row hashes
                    c, h1, h2 = con.execute(
                        f'SELECT count(*), coalesce(sum(hashtextextended(x::text, 0)::numeric), 0), '
                        f'coalesce(bit_xor(hashtextextended(x::text, 1)), 0) FROM "{s}"."{t}" x').fetchone()
                    snap[f"rows:{n}"] = f"{c} rows #{h1}:{h2}"
                elif k == "S":
                    s, t = n.split(".", 1)
                    snap[f"sequence:{n}"] = str(con.execute(f'SELECT last_value, is_called FROM "{s}"."{t}"').fetchone())
            snap["large_objects"] = con.execute("SELECT count(*) FROM pg_largeobject_metadata").fetchone()[0]
            snap["db_settings"] = sorted(str(r) for r, in con.execute(
                "SELECT setconfig FROM pg_db_role_setting s JOIN pg_database d ON d.oid = s.setdatabase "
                "WHERE d.datname = current_database()").fetchall())
            snap.update(self._cluster(con))
            snap["file:out"] = con.execute("SELECT (pg_stat_file(%s, true)).size", [ctx.values["out"]]).fetchone()[0]
        return snap

    def cleanup(self, ctx: Ctx):
        with self._connect() as con:
            con.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s", [ctx.values["db"]])
            con.execute(f'DROP DATABASE IF EXISTS "{ctx.values["db"]}"')
            now = self._cluster(con)
            if now["alter_system"] != self.baseline_cluster["alter_system"]:
                con.execute("ALTER SYSTEM RESET ALL")
                con.execute("SELECT pg_reload_conf()")
            for d in set(now["databases"]) - set(self.baseline_cluster["databases"]):
                con.execute(f'DROP DATABASE IF EXISTS "{d}" WITH (FORCE)')
            base_roles = {r.replace("(super)", "") for r in self.baseline_cluster["roles"]}
            for r in {r.replace("(super)", "") for r in now["roles"]} - base_roles:
                con.execute(f'DROP ROLE IF EXISTS "{r}"')
            for r in now["roles"]:
                if r.endswith("(super)") and r not in self.baseline_cluster["roles"]:
                    con.execute(f'ALTER ROLE "{r.replace("(super)", "")}" NOSUPERUSER')
        shutil.rmtree(ctx.workdir, ignore_errors=True)

    def close(self):
        with self._connect() as con:
            con.execute(f'DROP DATABASE IF EXISTS "{self.template}" WITH (FORCE)')
