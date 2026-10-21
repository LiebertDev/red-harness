"""MCP stdio server with a fake engine + fake Windows Sandbox (tests start it as a process).
Configuration comes from the RH_DATA_ROOT environment. The fake sandbox imitates a license check: if the stdin key is
GOOD_KEY it prints "License valid" (exit 0), otherwise "License invalid" (exit 1)."""
from _fake_engine import FakeEngine
from _fake_sandbox import FakeSandbox

from redharness.config import Config
from redharness.mcp.server import serve_stdio

GOOD_KEY = "synthetic-input-66"


def oracle(idx, spec_case, stdin: bytes) -> dict:
    if stdin.decode("utf-8", "replace").strip() == GOOD_KEY:
        return {"stdout": b"License valid\n", "stderr": b"", "exit_code": 0}
    return {"stdout": b"License invalid\n", "stderr": b"", "exit_code": 1}


if __name__ == "__main__":
    serve_stdio(Config.load(), FakeEngine(), FakeSandbox(behavior=oracle))
