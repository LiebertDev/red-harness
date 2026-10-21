"""What a first-time user sees: real `rh --help`, actionable engine errors, an answer to `initialize` when the
requested engine is missing, and a scope manifest written by PowerShell 5.1 (UTF-8 with BOM)."""
import asyncio
import io
import json
import sys

import pytest

from redharness import cli
from redharness.config import Config
from redharness.engines.ghidra import backend as gb
from redharness.engines.ida import IdaEngine
from redharness.mcp import server as server_mod
from redharness.mcp.server import reply_initialize_error
from redharness.scope.manifest import load_manifest

from .mcp_helpers import make_manifest

NO_IDAPRO = __import__("pathlib").Path(__file__).with_name("_no_idapro_worker.py")


def test_help_lists_commands_and_environment(capsys):
    assert cli.main(["--help"]) == 0
    out = capsys.readouterr().out
    for word in ("mcp", "export", "import", "compute-runtime", "eval", "bench", "version", "RH_GHIDRA_DIR", "RH_DATA_ROOT"):
        assert word in out
    assert cli.main(["-h"]) == 0 and cli.main(["help"]) == 0


def test_mcp_help_does_not_start_the_server(monkeypatch, capsys):
    monkeypatch.setattr(server_mod, "serve_stdio", lambda *a, **k: pytest.fail("must not start"))
    assert cli.main(["mcp", "--help"]) == 0
    out = capsys.readouterr().out
    assert "--engine" in out and "ghidra" in out


def test_no_arguments_still_prints_status(capsys):
    assert cli.main([]) == 0
    assert "data_root" in capsys.readouterr().out


def test_missing_idapro_message_is_actionable(tmp_path):
    ida_dir = tmp_path / "fake_ida"
    ida_dir.mkdir()
    (ida_dir / "idalib.dll").write_bytes(b"x")
    eng = IdaEngine(Config.load(tmp_path / "data"), ida_dir=ida_dir, worker=NO_IDAPRO)
    detail = eng.probe().detail
    assert "idapro" in detail and "pip install" in detail and "--engine ghidra" in detail


def test_missing_ida_dir_message_names_the_variable_and_the_alternative(tmp_path, monkeypatch):
    for v in ("RH_IDA_DIR", "IDADIR"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "nothing"))
    detail = IdaEngine(Config.load(tmp_path / "data")).probe().detail
    assert "RH_IDA_DIR" in detail and "--engine ghidra" in detail and detail.count("IDA unavailable") == 1


def test_missing_ghidra_message_says_where_to_get_and_put_it(tmp_path, monkeypatch):
    for v in ("RH_GHIDRA_DIR", "GHIDRA_INSTALL_DIR"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setattr(gb, "discover_ghidra_dir", lambda explicit=None: None)
    detail = gb.GhidraEngine(Config.load(tmp_path / "data")).probe().detail
    assert "RH_GHIDRA_DIR" in detail and "12.1.3" in detail and "JDK 21" in detail


def test_java_from_java_home_when_not_on_path(tmp_path, monkeypatch):
    home = tmp_path / "jdk"
    (home / "bin").mkdir(parents=True)
    (home / "bin" / "java.exe").write_bytes(b"x")
    monkeypatch.setattr(gb.shutil, "which", lambda name: None)
    monkeypatch.setenv("JAVA_HOME", str(home))
    assert gb._java_exe() == str(home / "bin" / "java.exe")
    monkeypatch.delenv("JAVA_HOME")
    assert gb._java_exe() == "java"


def test_reply_initialize_error_answers_the_request_with_a_json_rpc_error():
    request = json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}).encode() + b"\n"
    out = io.BytesIO()
    assert reply_initialize_error("rh mcp: engine 'ghidra' requested but unavailable", io.BytesIO(request), out, wait_s=5)
    msg = json.loads(out.getvalue().decode())
    assert msg["id"] == 0 and msg["error"]["code"] == -32000 and "ghidra" in msg["error"]["message"]


@pytest.mark.parametrize("data", [b"", b"\n", b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n', b"not json\n"])
def test_reply_initialize_error_stays_quiet_without_a_request(data):
    out = io.BytesIO()
    assert reply_initialize_error("x", io.BytesIO(data), out, wait_s=2) is False and out.getvalue() == b""


def test_reply_initialize_error_skips_a_terminal():
    class Tty(io.BytesIO):
        def isatty(self):
            return True
    out = io.BytesIO()
    assert reply_initialize_error("x", Tty(b'{"id":1}\n'), out, wait_s=2) is False and out.getvalue() == b""


def test_real_client_sees_the_reason_instead_of_connection_closed(tmp_path):
    """A real MCP client against `rh mcp --engine ghidra` with no Ghidra: initialize fails with the reason."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.shared.exceptions import McpError

    empty = tmp_path / "empty"
    empty.mkdir()
    env = {"PATH": str(empty), "SystemRoot": __import__("os").environ.get("SystemRoot", ""),
           "RH_DATA_ROOT": str(tmp_path / "data"), "RH_GHIDRA_DIR": str(empty / "nope"),
           "USERPROFILE": str(empty), "HOME": str(empty), "ProgramFiles": str(empty),
           "PYTHONPATH": __import__("os").environ.get("PYTHONPATH", "")}

    async def go():
        params = StdioServerParameters(command=sys.executable, args=["-m", "redharness.cli", "mcp", "--engine", "ghidra"],
                                       env=env)
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as session:
                await session.initialize()

    with pytest.raises((McpError, BaseExceptionGroup)) as ei:
        asyncio.run(asyncio.wait_for(go(), 60))
    def leaves(e):   # the SDK's task group wraps the error of `initialize` (possibly nested)
        if isinstance(e, BaseExceptionGroup):
            for x in e.exceptions:
                yield from leaves(x)
        else:
            yield e
    errs = [e for e in leaves(ei.value) if isinstance(e, McpError)]
    assert errs, repr(ei.value)
    err = errs[0]
    assert "ghidra" in str(err).lower() and "RH_GHIDRA_DIR" in str(err)
    assert "closed" not in str(err).lower()


def test_manifest_with_utf8_bom_is_accepted(tmp_path):
    target = tmp_path / "t.bin"
    target.write_bytes(b"MZ" + b"\0" * 64)
    path = make_manifest(tmp_path / "scope.json", target)
    path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes())
    man, _sha = load_manifest(path, target)
    assert man.allows("static")
