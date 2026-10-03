"""End-to-end: the harness against the three reference servers.

raw       every read-only / confined attack must break it (proves each attack is live,
          so a HELD elsewhere means the server stopped it, not that the attack was malformed)
naive     must be caught
hardened  must pass every promise

Postgres tests run when DMB_PG_DSN points at a throwaway server you are superuser on.
"""
import os
import sys
from pathlib import Path

import pytest

from data_mcp_bench.runner import Runner

SERVER = str(Path(__file__).resolve().parent.parent / "examples" / "reference_server.py")
ALL = {"read-only", "confined", "bounded", "masked"}
PG = os.environ.get("DMB_PG_DSN")

ENGINES = ["sqlite", "duckdb"] + (["postgres"] if PG else [])


def run(engine, mode, promises=ALL):
    db_arg = ["--dsn", "{reader_dsn}" if mode == "hardened" else "{dsn}"] if engine == "postgres" else ["--db", "{db}"]
    cmd = [sys.executable, SERVER, "--mode", mode, "--engine", engine, *db_arg]
    return Runner(engine, cmd, promises, dsn=PG, log=lambda *_: None).run()


@pytest.mark.parametrize("engine", ENGINES)
def test_every_attack_is_live(engine):
    results = run(engine, "raw")
    dead = [r.id for r in results if r.promise in ALL and r.status != "BROKEN"]
    assert not dead, f"these attacks did not break an unprotected server: {dead}"
    assert all(r.status == "HELD" for r in results if r.promise in ("sanity", "control"))


@pytest.mark.parametrize("engine", ENGINES)
def test_naive_server_is_caught(engine):
    results = run(engine, "naive", {"read-only", "confined"})
    broken = {r.id for r in results if r.status == "BROKEN"}
    assert len(broken) >= 3, broken


@pytest.mark.parametrize("engine", ENGINES)
def test_hardened_server_passes(engine):
    results = run(engine, "hardened")
    bad = [(r.id, r.status, r.evidence) for r in results if r.status != "HELD"]
    assert not bad, bad
