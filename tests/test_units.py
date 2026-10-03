from data_mcp_bench.runner import describe_diff, fill, load_scenarios, pick_tool


def test_scenarios_load_and_ids_unique():
    for engine in ("sqlite", "duckdb", "postgres"):
        scen = load_scenarios(engine)
        ids = [s["id"] for s in scen]
        assert len(ids) == len(set(ids)), engine
        assert scen[0]["promise"] == "sanity"
        assert all(s["promise"] in {"sanity", "control", "read-only", "confined", "bounded", "masked"} for s in scen)


def test_fill():
    assert fill("COPY t TO '{out}'", {"out": "/x"}) == "COPY t TO '/x'"
    assert fill("DO $$ BEGIN END $$", {"out": "/x"}) == "DO $$ BEGIN END $$"


def tool(name, *args):
    return {"name": name, "inputSchema": {"type": "object", "properties": {a: {"type": "string"} for a in args}}}


def test_pick_tool_prefers_read_over_write():
    tools = [tool("write_query", "query"), tool("read_query", "query"), tool("list_tables")]
    assert pick_tool(tools, None, None) == ("read_query", "query")


def test_pick_tool_generic_execute():
    assert pick_tool([tool("execute_sql", "sql")], None, None) == ("execute_sql", "sql")


def test_pick_tool_override():
    assert pick_tool([tool("run", "statement", "db")], "run", "statement") == ("run", "statement")


def test_describe_diff():
    before = {"objects": ["table:items"], "rows:items": "5 rows #a", "pragma:user_version": 0}
    after = {"objects": ["table:items", "view:v"], "rows:items": "0 rows #b", "pragma:user_version": 42,
             "file:out.db": 8192}
    d = describe_diff(before, after)
    assert "created view:v" in d
    assert "items: 5 rows -> 0 rows" in d
    assert "pragma:user_version: 0 -> 42" in d
    assert "new file out.db (8192 bytes)" in d


def test_pick_tool_skips_explain_tools():
    tools = [tool("explain_query", "sql"), tool("execute_sql", "sql"), tool("list_schemas")]
    assert pick_tool(tools, None, None) == ("execute_sql", "sql")
