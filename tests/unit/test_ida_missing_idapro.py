"""When `idapro` is not installed (the extra/PyPI dependency was removed) the IDA backend and the MCP layer return TOOL_MISSING.
The real `_worker.py` is used; only `import idapro` is turned into an ImportError."""
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.core.result import Status
from redharness.engines.ida import IdaEngine
from redharness.mcp.session import Hub, ToolFailure

from .mcp_helpers import make_manifest

NO_IDAPRO = Path(__file__).with_name("_no_idapro_worker.py")


@pytest.fixture
def parts(tmp_path):
    ida_dir = tmp_path / "fake_ida"
    ida_dir.mkdir()
    (ida_dir / "idalib.dll").write_bytes(b"x")  # the install directory is visible, but there is no idapro module
    target = tmp_path / "t.bin"
    target.write_bytes(b"MZ" + b"\x00" * 64)
    cfg = Config.load(tmp_path / "data")
    return cfg, IdaEngine(cfg, ida_dir=ida_dir, worker=NO_IDAPRO), target, make_manifest(tmp_path / "s.json", target)


def test_backend_reports_tool_missing_when_idapro_absent(parts):
    cfg, eng, target, _ = parts
    info = eng.probe()
    assert not info.available and "unavailable" in info.detail
    r = eng.open_target(target)
    assert r.status is Status.TOOL_MISSING and not r.ok
    assert eng.functions("a" * 64).status is Status.TOOL_MISSING


def test_mcp_target_open_fails_closed_with_tool_missing(parts):
    cfg, eng, target, manifest = parts
    hub = Hub(cfg, eng)
    try:
        with pytest.raises(ToolFailure) as ei:
            hub.call("target_open", {}, lambda: hub.target_open(str(target), str(manifest)))
        assert ei.value.code == "TOOL_MISSING"
        with pytest.raises(ToolFailure) as ei2:  # no session was opened: the following tools are closed too
            hub.call("functions_list", {}, lambda: hub.functions_list())
        assert ei2.value.code == "NO_TARGET"
    finally:
        hub.close()
