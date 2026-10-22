"""Kernel-mode targets (core safety logic): detection and the no-user-mode-run denial. The driver facts in the
target_open summary are premium and tested in test_driver_facts.py.

Fake engine and fake sandbox (no real engine, no Windows Sandbox, nothing is ever run)."""
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from redharness.analysis.pe_image import kernel_mode_reasons, parse_pe
from redharness.config import Config
from redharness.core.result import Status
from redharness.mcp import kernel_tool
from redharness.mcp.effects import TOOL_EFFECTS
from redharness.mcp.server import MAX_TOOLS, TOOL_NAMES
from redharness.mcp.session import Hub, ToolFailure
from redharness.sandbox import Code, RunCase, run_controlled
from redharness.scope.manifest import ScopeManifest

from ._fake_engine import BASE, FakeEngine
from ._fake_sandbox import FakeSandbox
from ._pe_builder import build_pe
from .mcp_helpers import make_manifest

CODE = "KERNEL_TARGET_NO_USERMODE_RUN"
ALL_OPS = ["static", "run_controlled", "compute", "dynamic_observe", "dynamic_memory"]


def make_hub(tmp_path, name="drv.sys", ops=tuple(ALL_OPS), pe=None, sandbox=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    target = tmp_path / name
    target.write_bytes(pe if pe is not None else build_pe(False, subsystem=1))
    manifest = make_manifest(tmp_path / "scope.json", target, allowed_operations=list(ops))
    hub = Hub(Config.load(tmp_path / "data"), FakeEngine(), sandbox if sandbox is not None else FakeSandbox())
    return hub, target, manifest


@pytest.fixture
def kernel_hub(tmp_path):
    hub, target, manifest = make_hub(tmp_path)
    reply = hub.target_open(str(target), str(manifest))
    yield hub, reply
    hub.close()


# ---------------------------------------------------------------- detection
def _img(**kw):
    data = build_pe(False, **kw)
    return parse_pe(lambda o, n: data[o:o + n], len(data))


def test_native_subsystem_is_kernel_mode():
    why = kernel_mode_reasons(_img(subsystem=1))
    assert why and "NATIVE" in why[0]


def test_wdm_driver_flag_is_kernel_mode():
    assert any("WDM_DRIVER" in w for w in kernel_mode_reasons(_img(subsystem=2, dll_characteristics=0x2000)))


def test_sys_extension_is_kernel_mode_even_with_gui_subsystem():
    img = _img(subsystem=2)
    assert any(".sys" in w for w in kernel_mode_reasons(img, "Some.SYS"))
    assert kernel_mode_reasons(img, "some.exe") == ()


def test_usermode_exe_is_not_kernel_mode():
    assert kernel_mode_reasons(_img(subsystem=3, dll_characteristics=0x8160), "tool.exe") == ()


def test_target_open_marks_native_image_even_without_sys_name(tmp_path):
    hub, target, manifest = make_hub(tmp_path, name="renamed.bin")
    try:
        r = hub.target_open(str(target), str(manifest))
        assert r["target"]["kernel_mode"] is True and "NATIVE" in r["target"]["kernel_reasons"][0]
    finally:
        hub.close()


def test_usermode_target_has_no_kernel_fields(tmp_path):
    hub, target, manifest = make_hub(tmp_path, name="app.exe", pe=build_pe(False, subsystem=3))
    try:
        r = hub.target_open(str(target), str(manifest))
        assert "kernel_mode" not in r["target"] and "driver" not in r["target"]
    finally:
        hub.close()


# ---------------------------------------------------------------- denial
def test_run_controlled_denied_with_code_even_if_scope_allows(kernel_hub):
    hub, _ = kernel_hub
    with pytest.raises(ToolFailure) as e:
        hub.call("run_controlled", {"cases": [{"stdin": "x"}]}, lambda: hub.run_controlled([{"stdin": "x"}]))
    assert e.value.code == CODE
    assert hub.sandbox_backend.started == []   # the sandbox was never touched


def test_observe_denied_with_code(kernel_hub):
    hub, _ = kernel_hub
    args = {"cases": [{"stdin": "x"}], "observe": {"channels": ["api_trace", "memory"]}}
    with pytest.raises(ToolFailure) as e:
        hub.call("run_controlled", args, lambda: hub.run_controlled(args["cases"], 5, args["observe"]))
    assert e.value.code == CODE
    assert hub.sandbox_backend.started == []


def test_denial_wins_over_a_manifest_without_run_permission(tmp_path):
    """Whatever the manifest says: with only `static` the kernel code is still explicit (not a bare SCOPE_DENIED)."""
    hub, target, manifest = make_hub(tmp_path, ops=("static",))
    try:
        hub.target_open(str(target), str(manifest))
        with pytest.raises(ToolFailure) as e:
            hub.call("run_controlled", {"cases": [{"stdin": "x"}]}, lambda: hub.run_controlled([{"stdin": "x"}]))
        assert e.value.code == CODE
    finally:
        hub.close()


def test_direct_hub_method_is_guarded_too(kernel_hub):
    hub, _ = kernel_hub
    with pytest.raises(ToolFailure) as e:
        hub.run_controlled([{"stdin": "x"}])
    assert e.value.code == CODE


def test_compute_on_execution_bytes_denied_static_inputs_allowed():
    kernel = SimpleNamespace(kernel=("PE subsystem is NATIVE (1)",))
    with pytest.raises(ToolFailure) as e:
        kernel_tool.deny_compute_inputs(kernel, [{"name": "a", "kind": "range"}, {"name": "m", "kind": "memrange"}])
    assert e.value.code == CODE
    kernel_tool.deny_compute_inputs(kernel, [{"name": "a", "kind": "range"}, {"name": "c", "kind": "const"}])
    kernel_tool.deny_compute_inputs(SimpleNamespace(kernel=()), [{"name": "m", "kind": "memrange"}])


def test_static_tools_still_work_on_a_kernel_job(kernel_hub):
    hub, _ = kernel_hub
    assert hub.functions_list()["status"] == "OK"
    assert hub.disassemble(hex(BASE + 0x1250), count=3)["status"] == "OK"
    assert hub.strings()["status"] == "OK"


def test_sandbox_layer_refuses_a_kernel_image_without_touching_the_sandbox(tmp_path):
    data = build_pe(False, subsystem=1)
    sha = hashlib.sha256(data).hexdigest()
    p = tmp_path / "x.exe"
    p.write_bytes(data)
    sb = FakeSandbox()
    scope = ScopeManifest(sha, "test", "owner", "test", ("static", "run_controlled"), None, "")
    run = run_controlled(sha, scope, [RunCase(stdin="x")], 5, cfg=Config.load(tmp_path / "data"), backend=sb,
                         target_path=p, poll_interval_s=0.01, proc_check_interval_s=0.05)
    assert run.code == Code.KERNEL_TARGET_NO_USERMODE_RUN and run.status is Status.ERROR
    assert "NATIVE" in run.detail and sb.started == []


def test_no_new_tool_for_driver_facts():
    assert len(TOOL_NAMES) <= MAX_TOOLS
    assert "driver_scan" not in TOOL_NAMES and "driver_scan" not in TOOL_EFFECTS
