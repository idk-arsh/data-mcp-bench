# data-mcp-bench

**Attack a database MCP server, then ask the database what happened.**

Database MCP servers promise "read-only". Many weren't: stacked statements, `SELECT ... INTO`, `COMMIT;` escapes, `COPY ... TO PROGRAM`. Public write-ups found bypasses in more than a dozen of them in 2026, including vendor servers. Scanners read tool descriptions. Fuzzers read the server's reply. Neither tells you whether the table is still there.

data-mcp-bench runs a catalog of attacks through your server's query tool against a real database, then snapshots the database and diffs it: catalog, row hashes, sequences, roles, server settings, large objects, files on disk. **A verdict of BROKEN means the database changed (or a file was written or read). It never depends on what the server said.**

```
$ data-mcp-bench run --engine postgres --dsn postgresql://postgres@localhost:55432/postgres \
    -- npx -y @modelcontextprotocol/server-postgres@0.6.2 {dsn}

  BROKEN   pg-stacked-commit-escape      (public.items: 5 rows -> 0 rows)
  BROKEN   pg-copy-to-program            (new file out (5 bytes))
  BROKEN   pg-read-server-file           (canary secret file contents returned)
  ...
5 broken of 31 scenarios
```

Runs locally or in CI. SQLite and DuckDB need nothing; Postgres needs a throwaway server (one `docker run`). Free, MIT.

## Quickstart

```bash
pip install "data-mcp-bench[all] @ git+https://github.com/idk-arsh/data-mcp-bench"

# SQLite / DuckDB: the harness creates the database; {db} is its path
data-mcp-bench run --engine sqlite -- npx -y your-sqlite-mcp --db {db}

# Postgres: a THROWAWAY server you are superuser on
docker run -d -p 55432:5432 -e POSTGRES_HOST_AUTH_METHOD=trust postgres:17
data-mcp-bench run --engine postgres --dsn postgresql://postgres@localhost:55432/postgres \
    -- your-postgres-mcp {dsn}
```

Every scenario gets a fresh copy of the database and a fresh server process, so one attack can't hide another.

Placeholders in the server command: `{db}` (file path, or Postgres database name), `{dsn}` (Postgres URL, superuser), `{reader_dsn}` (Postgres URL for a SELECT-only role), `{config}` (a per-scenario copy of `--server-config FILE` with the placeholders filled in, for servers configured by file).

The query tool and its SQL argument are detected automatically (`execute_sql`, `query`, `read_query`, ...). Override with `--tool` and `--arg`.

## The four promises

Only the promises your server claims can fail the run (`--expect`, default `read-only,confined`). The others are reported in lower case, for information.

| Promise | BROKEN when | Example attacks |
|---|---|---|
| `read-only` | any table, row, sequence, role, setting or object changed | stacked statements, `COMMIT;` escape, `SELECT INTO`, writable CTEs, `EXPLAIN ANALYZE DELETE`, functions that write, `setval`, `ALTER SYSTEM`, `PRAGMA user_version=` |
| `confined` | a file was written on the host, or a canary file outside the database was read | `COPY TO`, `COPY TO PROGRAM`, `pg_read_file`, `lo_import`, `ATTACH`, `VACUUM INTO`, DuckDB `read_text` |
| `bounded` | more rows came back than `--row-limit` (default 1,000) from a 100,000-row table | `SELECT *`, `LIMIT 100000` |
| `masked` | canary PII (SSNs, emails, card numbers) came back raw | `SELECT *`, values moved into `string_agg(...)` |

Catalog: 31 Postgres, 19 SQLite, 20 DuckDB scenarios in [`data_mcp_bench/scenarios/`](data_mcp_bench/scenarios). Each credits its public source where there is one.

## Every attack is proven live

A security test that reports HELD because the attack had a typo is worse than no test. So CI runs the whole catalog against an unprotected reference server, and **every read-only and confined attack must break it** ([tests](tests/test_reference_servers.py)). A HELD on your server therefore means your server stopped the attack.

CI also runs a naive server (a first-keyword deny-list with a `BEGIN READ ONLY` wrapper, the pattern behind most public bypasses), which must be caught, and a hardened one, which must pass every promise. The hardened server is in [`examples/reference_server.py`](examples/reference_server.py), if you want to see what passing looks like:

- **SQLite**: `mode=ro` connection plus an authorizer that allows only SELECT/READ/FUNCTION.
- **DuckDB**: `read_only=True` with `enable_external_access=false`.
- **Postgres**: a SELECT-only role, one statement per call (prepared statement), and a read-only transaction.

Also row caps, plus masking on values, not just column names.

## Results on real servers

Run locally against our own throwaway databases (Postgres 18.4, DuckDB 1.5.5), 2026-10-03:

| Server | Mode tested | read-only | confined |
|---|---|---|---|
| `@modelcontextprotocol/server-postgres` 0.6.2 (archived, still on npm) | default | **1 broken** of 21: the published `COMMIT;` escape ([Datadog Security Labs](https://securitylabs.datadoghq.com/articles/mcp-vulnerability-case-study-SQL-injection-in-the-postgresql-mcp-server/)) | **4 broken** of 5 when connected as superuser: `COPY TO`, `COPY TO PROGRAM` (shell command on the database host), `pg_read_file` |
| Crystal DBA `postgres-mcp` 0.3.0 | `--access-mode=restricted`, superuser connection | 0 broken of 21 | 0 broken of 5 |
| Bytebase `dbhub` 1.4.0, Postgres | `readonly = true` | 0 broken of 21 | 0 broken of 5 |
| Bytebase `dbhub` 1.4.0, SQLite | `readonly = true` | 0 broken of 12 | 0 broken of 2 |

Passing results matter as much as failures: they are evidence you can point to. None of these servers claims `bounded` or `masked` by default, so those columns are left out.

Found something in a server that's still maintained? Report it privately through the project's security policy first. Don't open a public issue.

## Use it in CI

```yaml
- uses: idk-arsh/data-mcp-bench@master
  with:
    engine: sqlite
    expect: read-only,confined
    server-command: node dist/index.js --db {db}
```

For Postgres, add a `services: postgres` container and pass `dsn:`. The report goes to the job summary. The job fails if a claimed promise broke.

## Limits (v0.1)

- **Engines**: Postgres, SQLite and DuckDB. MySQL, ClickHouse and SQL Server are next. Cloud warehouses (Snowflake, BigQuery, Databricks) have no free throwaway instance, so they aren't covered.
- **Transport**: stdio only. Streamable HTTP is next.
- **Files**: Postgres file checks look only at the paths the scenarios write to. They don't scan the whole host.
- **Scope**: the harness tests the server's enforcement with the credentials you hand it. Connecting your server with a least-privilege role is still the strongest fix, and the `{reader_dsn}` placeholder lets you test exactly that setup.

## Related

From the same author, on making AI agents safe on data: [data-agent-rules](https://github.com/idk-arsh/data-agent-rules) (rules and hooks for agents writing SQL), [schema-guard](https://github.com/idk-arsh/schema-guard), [data-test-guard](https://github.com/idk-arsh/data-test-guard), [show-your-sql](https://github.com/idk-arsh/show-your-sql).

## License

MIT
