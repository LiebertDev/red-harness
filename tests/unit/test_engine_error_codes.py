"""Stable engine error codes (docs/usage-mcp.md "Engine error codes"): the same closed set from IDA and Ghidra,
lifted by the backends into `EngineResult.code` and surfaced as the MCP tool error code. Fakes only (the real
cross-engine proof is tests/heavy/test_engine_error_codes_real.py)."""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.core.result import Status
from redharness.engines.base import ENGINE_ERROR_CODES, EngineResult, split_error
from redharness.engines.ghidra import GhidraEngine
from redharness.engines.ida import IdaEngine
from redharness.mcp.session import Hub, ToolFailure

from ._fake_engine import BASE, FakeEngine
from ._pe_builder import build_pe
from .mcp_helpers import make_manifest
from .test_ghidra_backend import FAKE as GHIDRA_FAKE
from .test_ghidra_backend import PROBE, gdir, log, sample  # noqa: F401  (fixtures)
from .test_ida_backend import FAKE as IDA_FAKE
from .test_ida_backend import ida_dir  # noqa: F401  (fixture)

WORKER_PATH = Path(__file__).resolve().parents[2] / "src" / "redharness" / "engines" / "ida" / "_worker.py"


def test_closed_set_is_the_documented_one():
    assert ENGINE_ERROR_CODES == {"NO_FUNCTION_AT_ADDRESS", "NAME_NOT_RESOLVED", "OUT_OF_IMAGE", "DECOMPILE_FAILED",
                                  "DECOMPILE_TIMEOUT", "DECOMPILER_UNAVAILABLE"}
    doc = (Path(__file__).resolve().parents[2] / "docs" / "usage-mcp.md").read_text(encoding="utf-8")
    for code in ENGINE_ERROR_CODES:
        assert code in doc, f"{code} is not documented in docs/usage-mcp.md"


@pytest.mark.parametrize("detail,code", [
    ("decompile failed: worker error: LookupError: NO_FUNCTION_AT_ADDRESS: no function at address: 0x10", "NO_FUNCTION_AT_ADDRESS"),
    ("decompile failed: script error: IllegalArgumentException: NAME_NOT_RESOLVED: could not resolve name: x", "NAME_NOT_RESOLVED"),
    ("script error: RuntimeException: DECOMPILE_TIMEOUT: 120 s exceeded", "DECOMPILE_TIMEOUT"),
    ("decompile failed: worker error: RuntimeError: DECOMPILER_UNAVAILABLE: Hex-Rays is unavailable", "DECOMPILER_UNAVAILABLE"),
    ("decompile failed: worker error: RuntimeError: DECOMPILE_FAILED", "DECOMPILE_FAILED"),
    ("decompile failed: worker error: RuntimeError: intentional", ""),
    ("", ""),
    # text from the target can never set the code: only the leading error prefix counts
    ("decompile failed: worker error: RuntimeError: DECOMPILE_FAILED: worker error: X: NO_FUNCTION_AT_ADDRESS: y",
     "DECOMPILE_FAILED"),
    ("decompile failed: worker error: RuntimeError: boom NAME_NOT_RESOLVED: x", ""),
    ("decompile timeout (fake)", ""),
])
def test_split_error(detail, code):
    got, msg = split_error(detail)
    assert got == code
    if not code:
        assert msg == detail


def test_split_error_message_has_no_prefix():
    code, msg = split_error("decompile failed: worker error: LookupError: NO_FUNCTION_AT_ADDRESS: no function at address: 0x10")
    assert (code, msg) == ("NO_FUNCTION_AT_ADDRESS", "no function at address: 0x10")


# ------------------------------------------------------------------ the real IDA worker raises the coded text
def load_worker():
    spec = importlib.util.spec_from_file_location("rh_ida_worker_codes", WORKER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_ida_worker_resolve_function_raises_coded_errors(monkeypatch):
    BAD = 0xFFFFFFFFFFFFFFFF
    funcs = types.ModuleType("ida_funcs")
    funcs.get_func = lambda ea: None
    idaapi = types.ModuleType("ida_idaapi")
    idaapi.BADADDR = BAD
    name = types.ModuleType("ida_name")
    name.get_name_ea = lambda base, n: BAD
    for m in (funcs, idaapi, name):
        monkeypatch.setitem(sys.modules, m.__name__, m)
    w = load_worker()
    with pytest.raises(LookupError) as e:
        w.resolve_function(0x401000)
    assert split_error("worker error: LookupError: " + str(e.value))[0] == "NO_FUNCTION_AT_ADDRESS"
    with pytest.raises(LookupError) as e:
        w.resolve_function("nosuch")
    assert split_error("worker error: LookupError: " + str(e.value))[0] == "NAME_NOT_RESOLVED"


def test_worker_and_script_sources_carry_no_legacy_lookup_wording():
    root = Path(__file__).resolve().parents[2] / "src" / "redharness" / "engines"
    java = (root / "ghidra" / "scripts" / "RHQuery.java").read_text(encoding="utf-8")
    py = WORKER_PATH.read_text(encoding="utf-8")
    assert "LOOKUP:" not in java and 'LookupError("no function' not in py and 'LookupError("name could' not in py
    assert java.count("NO_FUNCTION_AT_ADDRESS") >= 3 and py.count("NO_FUNCTION_AT_ADDRESS") >= 3


# ------------------------------------------------------------------ both backends lift the same code
@pytest.mark.parametrize("mode,code", [("nofunc", "NO_FUNCTION_AT_ADDRESS"), ("noname", "NAME_NOT_RESOLVED"),
                                       ("decomp_failed", "DECOMPILE_FAILED")])
def test_both_backends_report_the_same_code(tmp_path, gdir, log, ida_dir, sample, monkeypatch, mode, code):  # noqa: F811
    ida = IdaEngine(Config.load(tmp_path / "ida"), ida_dir=ida_dir, worker=IDA_FAKE)
    ghi = GhidraEngine(Config.load(tmp_path / "ghi"), ghidra_dir=gdir, launcher=[sys.executable, "-I", str(GHIDRA_FAKE)],
                       probe_argv=[sys.executable, "-I", str(PROBE)])
    got = {}
    for name, eng in (("ida", ida), ("ghidra", ghi)):
        sha = eng.open_target(sample).data.sha256
        monkeypatch.setenv("FAKE_MODE", mode)
        r = eng.decompile(sha, "nosuch" if mode == "noname" else 0x401000)
        monkeypatch.setenv("FAKE_MODE", "ok")
        assert r.status is Status.ERROR and not r.ok and r.data is None
        got[name] = r.code
    assert got == {"ida": code, "ghidra": code}


def test_decompile_timeout_has_its_own_code(tmp_path, gdir, log, sample, monkeypatch):  # noqa: F811
    ghi = GhidraEngine(Config.load(tmp_path / "ghi"), ghidra_dir=gdir, launcher=[sys.executable, "-I", str(GHIDRA_FAKE)],
                       probe_argv=[sys.executable, "-I", str(PROBE)])
    sha = ghi.open_target(sample).data.sha256
    monkeypatch.setenv("FAKE_MODE", "decomp_timeout")
    r = ghi.decompile(sha, 0x401000)
    assert r.status is Status.TIMEOUT and r.code == "DECOMPILE_TIMEOUT"


# ------------------------------------------------------------------ MCP surface
class CodedEngine(FakeEngine):
    """Behaves like a real engine: errors carry the stable code the backends lift."""

    def decompile(self, sha256, function, *, max_chars=200_000):
        if function == "nosuch":
            return EngineResult(Status.ERROR, None, "decompile failed: worker error: LookupError: NAME_NOT_RESOLVED: "
                                "name could not be resolved: nosuch", code="NAME_NOT_RESOLVED")
        if function == BASE + 0x1500:
            return EngineResult(Status.TIMEOUT, None, "decompile failed: worker error: RuntimeError: DECOMPILE_TIMEOUT: "
                                "MERR_TIMEOUT after 5 ms", code="DECOMPILE_TIMEOUT")
        if function == BASE + 0x1600:
            return EngineResult(Status.ERROR, None, "decompile failed: worker error: RuntimeError: DECOMPILE_FAILED: "
                                "empty result", code="DECOMPILE_FAILED")
        if isinstance(function, int) and not BASE + 0x1250 <= function < BASE + 0x1370:
            return EngineResult(Status.ERROR, None, "decompile failed: script error: IllegalArgumentException: "
                                f"NO_FUNCTION_AT_ADDRESS: no function at address: 0x{function:x}",
                                code="NO_FUNCTION_AT_ADDRESS")
        return super().decompile(sha256, function, max_chars=max_chars)

    def disassemble(self, sha256, address, *, count=200, whole_function=False):
        if whole_function and not BASE + 0x1250 <= address < BASE + 0x1370:
            return EngineResult(Status.ERROR, None, "disassemble failed: worker error: LookupError: "
                                f"NO_FUNCTION_AT_ADDRESS: no function at address: 0x{address:x}",
                                code="NO_FUNCTION_AT_ADDRESS")
        return super().disassemble(sha256, address, count=count, whole_function=whole_function)


def open_hub(tmp_path, pe: bool):
    target = tmp_path / "t.exe"
    target.write_bytes(build_pe(is64=True) if pe else b"MZ" + bytes(range(256)) * 8)
    manifest = make_manifest(tmp_path / "scope.json", target, allowed_operations=["static"])
    hub = Hub(Config.load(tmp_path / "data"), CodedEngine())
    hub.target_open(str(target), str(manifest))
    return hub


@pytest.fixture
def hub(tmp_path):
    h = open_hub(tmp_path, pe=False)
    yield h
    h.close()


def code_of(fn, *a, **kw):
    with pytest.raises(ToolFailure) as e:
        fn(*a, **kw)
    return e.value.code, e.value.message


def test_decompile_no_function_is_the_stable_code(hub):
    code, msg = code_of(hub.decompile, "0x140009000")
    assert code == "NO_FUNCTION_AT_ADDRESS" and "0x140009000" in msg and "worker error" not in msg
    assert "disassemble" in msg   # tells the model what to try next


def test_decompile_unknown_name_timeout_and_failed_codes(hub):
    assert code_of(hub.decompile, "nosuch")[0] == "NAME_NOT_RESOLVED"
    assert code_of(hub.decompile, f"0x{BASE + 0x1500:x}")[0] == "DECOMPILE_TIMEOUT"
    assert code_of(hub.decompile, f"0x{BASE + 0x1600:x}")[0] == "DECOMPILE_FAILED"


def test_address_outside_the_image_is_out_of_image(tmp_path):
    h = open_hub(tmp_path, pe=True)
    try:
        code, msg = code_of(h.decompile, "0x10")                 # below the image base
        assert code == "OUT_OF_IMAGE" and "outside the image" in msg
        assert code_of(h.decompile, f"0x{BASE + 0x2000000:x}")[0] == "OUT_OF_IMAGE"   # beyond SizeOfImage
        # an address inside the image that no function covers stays NO_FUNCTION_AT_ADDRESS
        assert code_of(h.decompile, "0x140003000")[0] == "NO_FUNCTION_AT_ADDRESS"
        # the failures are journaled with their codes and OUT_OF_IMAGE is not a coverage gap
        # dataflow_slice (whole-function disassembly) reports the same codes
        assert code_of(h.dataflow_slice, "0x140003000")[0] == "NO_FUNCTION_AT_ADDRESS"
        assert code_of(h.dataflow_slice, "0x10")[0] == "OUT_OF_IMAGE"
        for addr in ("0x140003000", "0x10"):   # through the journaled call path (as the MCP wire does)
            with pytest.raises(ToolFailure):
                h.call("decompile", {"function": addr}, lambda a=addr: h.decompile(a))
        cov = h.coverage()
        codes = {c["code"] for c in cov["failed_calls"]}
        assert "NO_FUNCTION_AT_ADDRESS" in codes and "OUT_OF_IMAGE" not in codes
    finally:
        h.close()


def test_uncoded_engine_error_keeps_the_plain_status(tmp_path):
    class Plain(FakeEngine):
        def decompile(self, sha256, function, *, max_chars=200_000):
            return EngineResult(Status.ERROR, None, "decompile failed: worker error: RuntimeError: intentional")

    target = tmp_path / "t.exe"
    target.write_bytes(b"MZ" + bytes(range(256)) * 8)
    manifest = make_manifest(tmp_path / "scope.json", target, allowed_operations=["static"])
    h = Hub(Config.load(tmp_path / "data"), Plain())
    h.target_open(str(target), str(manifest))
    try:
        code, msg = code_of(h.decompile, "0x140001250")
        assert code == "ERROR" and "intentional" in msg
    finally:
        h.close()


def test_failed_calls_leave_no_evidence_so_no_step_version_bump_is_needed(hub):
    code_of(hub.decompile, "0x140009000")
    assert not [e for e in hub._s.ledger.state["evidence"].values() if e["operation"] == "decompile"]
