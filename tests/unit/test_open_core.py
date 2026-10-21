"""Open core: the premium modules are absent from the public build, and everything that reaches one degrades with a
"premium feature" message instead of failing at import time. Runs in BOTH builds: here the premium modules are made
unimportable (a `None` entry in sys.modules makes the import raise ModuleNotFoundError), so the full build behaves like
the core build."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from redharness import cli
from redharness.config import Config
from redharness.mcp.server import MAX_TOOLS, TOOL_NAMES
from redharness.mcp.session import Hub, ToolFailure

from ._fake_engine import FakeEngine
from ._fake_sandbox import FakeSandbox
from ._pe_builder import build_pe
from .mcp_helpers import make_manifest
from .test_kernel_target import make_hub

PREMIUM_NOTE = "premium feature not included in this build"

# module names (and the package attribute that would shortcut a `from pkg import module`) that only the build with
# optional modules has
PREMIUM_MODULES = (
    "redharness.dynamic.rhtrace", "redharness.dynamic.region_view", "redharness.mcp.region_tool",
    "redharness.jobs.bundle", "redharness.mcp.driver_facts",
    "redharness.analysis.driver", "redharness.analysis.ctl", "redharness.analysis.driver_profile",
    "redharness.analysis.bundle", "redharness.analysis.workspace", "redharness.analysis.service_audit",
    "redharness.evals", "redharness.evals.runner", "redharness.evals.bench",
    "redharness.kernel", "redharness.models", "redharness.studio",
)


@pytest.fixture
def no_premium(monkeypatch):
    for name in PREMIUM_MODULES:
        parent, _, leaf = name.rpartition(".")
        pkg = sys.modules.get(parent)
        if pkg is not None:
            monkeypatch.delattr(pkg, leaf, raising=False)   # `from . import leaf` would find the attribute first
        monkeypatch.setitem(sys.modules, name, None)        # a None entry raises ModuleNotFoundError on import
        for loaded in [m for m in sys.modules if m.startswith(name + ".")]:   # already imported by an earlier test
            monkeypatch.setitem(sys.modules, loaded, None)   # (else `from .pkg.mod import x` finds the cached module)


def test_observe_without_the_tracer_module_says_premium(tmp_path, no_premium):
    target = tmp_path / "t64.exe"
    target.write_bytes(build_pe(True))
    manifest = make_manifest(tmp_path / "scope.json", target,
                             allowed_operations=["static", "run_controlled", "dynamic_observe"])
    sb = FakeSandbox()
    hub = Hub(Config.load(tmp_path / "data"), FakeEngine(), sb)
    try:
        hub.target_open(str(target), str(manifest))
        observe = {"channels": ["api_trace"]}
        with pytest.raises(ToolFailure) as e:
            hub.call("run_controlled", {"cases": [{}], "observe": observe},
                     lambda: hub.run_controlled([{}], 10, observe))
        assert e.value.code == "DYNAMIC_BACKEND_UNAVAILABLE"
        assert "dynamic observation (observe) is a premium feature not included in this build" in e.value.message
        assert sb.started == []
    finally:
        hub.close()


def test_captured_region_without_the_premium_modules_says_premium(tmp_path, no_premium):
    target = tmp_path / "t64.exe"
    target.write_bytes(build_pe(True))
    manifest = make_manifest(tmp_path / "scope.json", target, allowed_operations=[
        "static", "run_controlled", "dynamic_observe", "dynamic_memory"])
    hub = Hub(Config.load(tmp_path / "data"), FakeEngine(), FakeSandbox())
    try:
        hub.target_open(str(target), str(manifest))
        args = {"evidence_id": "ev_" + "0" * 64, "event": 0}
        with pytest.raises(ToolFailure) as e:
            hub.call("captured_region", args, lambda: hub.captured_region(**args))
        assert e.value.code == "DYNAMIC_BACKEND_UNAVAILABLE" and PREMIUM_NOTE in e.value.message
    finally:
        hub.close()


def test_injected_dynamic_backend_still_works_without_the_tracer_module(tmp_path, no_premium):
    from redharness.dynamic.fake import FakeDynamicBackend
    hub = Hub(Config.load(tmp_path / "data"), FakeEngine(), FakeSandbox(), dynamic_backend=FakeDynamicBackend("n"))
    try:
        assert hub._dyn_backend() is hub.dynamic_backend
    finally:
        hub.close()


@pytest.mark.parametrize("cmd,args", [("export", ["job_x", "out.zip"]), ("import", ["in.zip"]),
                                      ("eval", ["--help"]), ("bench", ["verify"]),
                                      ("studio", []), ("studio", ["--engine", "ghidra"])])
def test_premium_cli_commands_print_a_notice_and_exit_2(cmd, args, no_premium, capsys):
    assert cli.main([cmd, *args]) == 2
    captured = capsys.readouterr()
    assert captured.err.strip() == f"{cmd}: {PREMIUM_NOTE}" and captured.out == ""


def test_premium_commands_stay_in_the_help(capsys):
    assert cli.main(["--help"]) == 0
    out = capsys.readouterr().out
    assert all(f"\n  {c}" in out for c in ("export", "import", "eval", "bench", "studio"))


def test_target_open_of_a_driver_reports_driver_facts_unavailable(tmp_path, no_premium):
    hub, target, manifest = make_hub(tmp_path)
    try:
        r = hub.target_open(str(target), str(manifest))
        assert r["target"]["kernel_mode"] is True    # detection and the run denial are core
        assert r["target"]["driver"] == {"available": False, "note": PREMIUM_NOTE}
    finally:
        hub.close()


def test_the_tool_surface_is_the_same_in_every_build():
    assert len(TOOL_NAMES) == 18 and len(TOOL_NAMES) <= MAX_TOOLS


_IMPORT_ALL = r'''
import importlib, json, pkgutil, sys
sys.path[:0] = json.loads(sys.argv[1])
blocked = tuple(json.loads(sys.argv[2]))

class Block:
    def find_spec(self, name, path=None, target=None):
        if any(name == b or name.startswith(b + ".") for b in blocked):
            raise ModuleNotFoundError(f"premium module {name} is not part of this build", name=name)

sys.meta_path.insert(0, Block())
import redharness
failed = []
for m in pkgutil.walk_packages(redharness.__path__, "redharness."):
    if any(m.name == b or m.name.startswith(b + ".") for b in blocked):
        continue
    if m.name.endswith((".__main__", ".rh_boot")):   # scripts that run on import (module entry point, guest bootstrap)
        continue
    try:
        importlib.import_module(m.name)
    except Exception as e:
        failed.append(f"{m.name}: {type(e).__name__}: {e}")
print(json.dumps(failed))
'''


def test_every_core_module_imports_with_the_premium_modules_blocked():
    """The seam test for the whole package: no non-premium module may import a premium one at import time."""
    proc = subprocess.run([sys.executable, "-c", _IMPORT_ALL, json.dumps([p for p in sys.path if p]),
                           json.dumps(list(PREMIUM_MODULES))], capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert json.loads(proc.stdout.strip().splitlines()[-1]) == []


def test_studio_is_premium_and_the_core_cli_never_imports_it_at_import_time(no_premium, capsys):
    """Studio (and the model gateway it needs) are premium-only: the public `rh studio` prints the notice and exits 2,
    and nothing else in the core tree imports the package."""
    assert cli.main(["studio", "--help"]) == 2
    err = capsys.readouterr().err
    assert err.strip() == f"studio: {PREMIUM_NOTE}"
    src = Path(cli.__file__).parent
    offenders = [str(p.relative_to(src)) for p in src.rglob("*.py")
                 if "studio" not in p.parts and "from .studio" in p.read_text(encoding="utf-8")
                 and p.name != "cli.py"]
    assert offenders == []
    top = [ln for ln in Path(cli.__file__).read_text(encoding="utf-8").splitlines()
           if ln.startswith(("import ", "from ")) and "studio" in ln]
    assert top == []    # only the lazy import inside main()
