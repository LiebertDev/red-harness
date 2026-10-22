"""MCP stdio server with a fake engine + fake Windows Sandbox (tests start it as a process).
Configuration comes from the RH_DATA_ROOT environment. The fake sandbox imitates a license check: if the stdin key is
GOOD_KEY it prints "License valid" (exit 0), otherwise "License invalid" (exit 1). The VC++ runtime DLLs that
run_controlled places next to the target come from a fake SystemRoot, so the run never depends on the host's real DLLs
(they do not exist off Windows)."""
import tempfile
from pathlib import Path

from _fake_engine import FakeEngine
from _fake_sandbox import FakeSandbox

from redharness.config import Config
from redharness.mcp import session
from redharness.mcp.server import serve_stdio

GOOD_KEY = "synthetic-input-66"


def oracle(idx, spec_case, stdin: bytes) -> dict:
    if stdin.decode("utf-8", "replace").strip() == GOOD_KEY:
        return {"stdout": b"License valid\n", "stderr": b"", "exit_code": 0}
    return {"stdout": b"License invalid\n", "stderr": b"", "exit_code": 1}


def _use_fake_system_root(root: Path) -> None:
    sub32 = root / "System32"
    sub32.mkdir(parents=True, exist_ok=True)
    for n in ("vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll"):
        (sub32 / n).write_bytes(b"dll-" + n.encode())
    real = session.vc_runtime_files
    session.vc_runtime_files = lambda binary, system_root=None: real(binary, system_root=system_root or str(root))


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="rh-fake-sysroot-") as d:
        _use_fake_system_root(Path(d))
        serve_stdio(Config.load(), FakeEngine(), FakeSandbox(behavior=oracle))
