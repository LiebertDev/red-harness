"""MCP stdio server whose decompile blocks forever the FIRST time (until the marker file exists).
Used by the process-kill test: the test waits for the marker (written with this server's PID right before the hang), kills
the process hard and starts a second server with the same data root; the second one finds the marker and decompiles normally."""
import os
import time
from pathlib import Path

from _fake_engine import FakeEngine

from redharness.config import Config
from redharness.mcp.server import serve_stdio


class HangingEngine(FakeEngine):
    def decompile(self, sha256, function, *, max_chars=200_000):
        marker = os.environ.get("RH_HANG_MARKER")
        if marker and not Path(marker).exists():
            tmp = Path(marker + ".tmp")
            tmp.write_text(str(os.getpid()))
            os.replace(tmp, marker)   # the marker only appears complete
            time.sleep(3600)          # "long analysis": the test kills this process now
        return super().decompile(sha256, function, max_chars=max_chars)


if __name__ == "__main__":
    serve_stdio(Config.load(), HangingEngine(), None)
