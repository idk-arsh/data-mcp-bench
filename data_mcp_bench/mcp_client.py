"""A minimal MCP client over stdio (newline-delimited JSON-RPC).

Written against the protocol, not an SDK, so the harness can drive any
server regardless of which SDK version (or language) the server uses.
"""
from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import threading
import time

PROTOCOL_VERSION = "2025-06-18"


class MCPError(Exception):
    pass


class StdioClient:
    def __init__(self, cmd: list[str], cwd: str | None = None, env: dict | None = None,
                 stderr_path: str | None = None, timeout: float = 30.0):
        exe = shutil.which(cmd[0]) or cmd[0]
        self.timeout = timeout
        self._stderr = open(stderr_path, "wb") if stderr_path else subprocess.DEVNULL
        self.proc = subprocess.Popen(
            [exe, *cmd[1:]], cwd=cwd, env={**os.environ, **(env or {})},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self._stderr,
        )
        self._next_id = 0
        self._lines: queue.Queue = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for raw in self.proc.stdout:
            line = raw.decode("utf-8", "replace").strip()
            if line:
                self._lines.put(line)
        self._lines.put(None)

    def _send(self, msg: dict):
        try:
            self.proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise MCPError(f"server closed its input: {e}") from e

    def request(self, method: str, params: dict | None = None, timeout: float | None = None) -> dict:
        self._next_id += 1
        rid = self._next_id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        deadline = time.monotonic() + (timeout or self.timeout)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise MCPError(f"timed out waiting for {method}")
            try:
                line = self._lines.get(timeout=left)
            except queue.Empty:
                raise MCPError(f"timed out waiting for {method}")
            if line is None:
                raise MCPError(f"server exited during {method}")
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue  # stray log output on stdout
            if "method" in msg and "id" in msg:  # server -> client request
                if msg["method"] == "ping":
                    self._send({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
                elif msg["method"] == "roots/list":
                    self._send({"jsonrpc": "2.0", "id": msg["id"], "result": {"roots": []}})
                else:
                    self._send({"jsonrpc": "2.0", "id": msg["id"],
                                "error": {"code": -32601, "message": "not supported"}})
                continue
            if msg.get("id") != rid:
                continue  # notification or stale response
            if "error" in msg:
                raise MCPError(f"{method} failed: {msg['error'].get('message')}")
            return msg.get("result", {})

    def initialize(self) -> dict:
        res = self.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "data-mcp-bench", "version": "0.1.0"},
        }, timeout=max(self.timeout, 60))
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return res

    def list_tools(self) -> list[dict]:
        tools, cursor = [], None
        while True:
            res = self.request("tools/list", {"cursor": cursor} if cursor else {})
            tools += res.get("tools", [])
            cursor = res.get("nextCursor")
            if not cursor:
                return tools

    def call_tool(self, name: str, arguments: dict) -> tuple[bool, str]:
        """Returns (is_error, text). Protocol errors count as is_error too."""
        try:
            res = self.request("tools/call", {"name": name, "arguments": arguments})
        except MCPError as e:
            return True, str(e)
        parts = []
        for item in res.get("content", []) or []:
            if item.get("type") == "text":
                parts.append(item.get("text", ""))
            else:
                parts.append(json.dumps(item))
        if res.get("structuredContent") is not None:
            parts.append(json.dumps(res["structuredContent"], default=str))
        return bool(res.get("isError")), "\n".join(parts)

    def close(self):
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            if os.name == "nt":  # npx/uvx wrappers leave children holding the db file
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(self.proc.pid)],
                               capture_output=True)
            else:
                self.proc.kill()
            self.proc.wait(timeout=5)
        if self._stderr not in (None, subprocess.DEVNULL):
            self._stderr.close()
