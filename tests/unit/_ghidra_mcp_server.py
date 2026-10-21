"""MCP stdio server on the REAL Ghidra engine, with an optional deterministic hang inside decompile (RH_HANG_MARKER, first
call only): lets the kill test cut a call off while a real engine is open. Used by the real-process kill tests."""
import os
import time
from pathlib import Path

from redharness.config import Config
from redharness.engines.ghidra import GhidraEngine
from redharness.mcp.server import serve_stdio


class HangingGhidra(GhidraEngine):
    def decompile(self, sha256, function, **kw):
        marker = os.environ.get("RH_HANG_MARKER")
        if marker and not Path(marker).exists():
            tmp = Path(marker + ".tmp")
            tmp.write_text(str(os.getpid()))
            os.replace(tmp, marker)
            time.sleep(3600)
        return super().decompile(sha256, function, **kw)


if __name__ == "__main__":
    cfg = Config.load()
    serve_stdio(cfg, HangingGhidra(cfg), None)
