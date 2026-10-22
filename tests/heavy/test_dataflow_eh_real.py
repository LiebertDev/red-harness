"""REAL-binary proof for the unmodelled-exception-handler rule of `dataflow_slice` (slicer revision 8): MSVC-built
ground-truth fixtures (`tests/fixtures/eh/`, see ground-truth.md) whose joined local is known per path.

At the post-join `cmp edx, ecx` of each function the slice must never report a definite value that differs from a path:
- C++ try/catch (x64 FH4, x86 frame handler) and x86 SEH: `unknown:` with the "exception handler not modelled" reason;
- x64 `__try/__except` and nested `__try/__except`: the scope table's rows run out-of-line filter funclets, so the
  function is not modelled either (revision 8) even though its `__except` block is a CFG edge;
- x64 `__try/__finally`: the row's JumpTarget is 0 and its funclet writes the joined local during unwind, so it is not
  modelled;
- the no-EH control stays definite (1).
Engine: `RH_DF_ENGINE=ida` (default) or `ghidra`; run one engine at a time.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.mcp.session import Hub

from tests.unit.mcp_helpers import make_manifest

pytestmark = pytest.mark.heavy

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "eh"
if not (FIX / "ground-truth.json").is_file():
    pytest.skip("EH ground-truth fixtures (tests/fixtures/eh) are not present in this tree", allow_module_level=True)
TRUTH = json.loads((FIX / "ground-truth.json").read_text(encoding="utf-8"))
WHY = "exception handler not modelled"


def _cases():
    out = []
    for b in TRUTH["binaries"]:
        for f in b["functions"]:
            out.append(pytest.param(b["path"], b["arch"], f, id=f"{b['arch']}-{f['name']}"))
    return out


def _engine(root: Path):
    which = os.environ.get("RH_DF_ENGINE", "ida").lower()
    cfg = Config.load(root)
    if which == "ghidra":
        from redharness.engines.ghidra import GhidraEngine
        eng = GhidraEngine(cfg)
    else:
        from redharness.engines.ida import IdaEngine
        eng = IdaEngine(cfg)
    info = eng.probe()
    if not info.available:
        pytest.skip(f"{which} unavailable: {info.detail}")
    return which, eng


@pytest.fixture(scope="module")
def hubs(heavy_data_root, tmp_path_factory):
    made: dict[str, Hub] = {}
    which, eng = _engine(heavy_data_root)

    def get(path: str) -> tuple[str, Hub]:
        if path not in made:
            src = FIX / path
            if not src.is_file():
                pytest.skip(f"{src} not built")
            d = tmp_path_factory.mktemp("eh")
            target = d / src.name
            shutil.copyfile(src, target)
            hub = Hub(Config.load(d / "data"), eng)
            hub.target_open(str(target), str(make_manifest(d / "scope.json", target)))
            made[path] = hub
        return which, made[path]

    yield get
    for h in made.values():
        h.close()


def _slice(hub, **kw):
    return hub.call("dataflow_slice", kw, lambda: hub.dataflow_slice(**kw))


@pytest.mark.parametrize("path,arch,fn", _cases())
def test_join_value_is_never_wrongly_definite(path, arch, fn, hubs):
    which, hub = hubs(path)
    cmp_va = fn["compare"]["va"]
    r = _slice(hub, address=cmp_va, operand=0, detail="full")
    text = r["content"]
    name = fn["name"]
    print(f"\n[{which}] {arch} {name} compare {cmp_va} status={r['status']}\n"
          + "\n".join(ln for ln in text.splitlines() if ln.startswith(("flow:", "read ", "  value", "unknown:", "coverage"))))
    dis = hub.engine.disassemble(hub._s.sha, int(fn["va"], 16), count=20_000, whole_function=True)
    if dis.ok:
        print(f"[{which}] {name}: " + " ; ".join(f"{i.address:x} {i.text}" for i in dis.data.items[:16]))
    paths = [p["joined_v"] for p in fn["paths"] if p.get("compare_result") is not None]
    definite = [ln for ln in text.splitlines() if ln.strip().startswith("value=") and " definite" in ln]
    assert paths, "ground truth must carry at least one joined value for a reachable path"
    # operand 1 of the compare is the expected value (an immediate) stored by an immediate right before the compare
    exp = _slice(hub, address=cmp_va, operand=1, detail="full")["content"]
    exp_definite = any(ln.strip().startswith("value=0x") and " definite" in ln for ln in exp.splitlines())
    if name == "eh_no_eh_control":
        # v escapes to the noinline callee, so operand 0 is unknown for that (old) reason; nothing about EH changes
        assert not definite and WHY not in text and r["status"] == "OK" and exp_definite and WHY not in exp
        return
    # every other fixture has an exception handler the slicer does not model: x86 frame-based SEH, x64 C++ EH, and the
    # x64 C-specific scope tables, whose rows all run a filter or __finally funclet (no row has the constant filter 1)
    assert not definite, f"definite value reported where a handler can change it: {definite}"
    assert f"unknown: {WHY} (" in text and "coverage: partial" in text
    assert not exp_definite and f"unknown: {WHY} (" in exp      # even the immediate-fed local is not definite
    if arch == "x64":
        # the reason names the funclet from the PE's scope table; the __except block stays a CFG edge of the function
        if name == "eh_seh_try_except":
            assert "exception_edges=0 " not in text
            assert "C-specific filter funclet at 0x140001f67 not modelled" in text
        elif name == "eh_nested_handler":
            assert "exception_edges=0 " not in text
            assert "C-specific filter funclet at 0x140001f3b not modelled" in text
        elif name == "eh_seh_try_finally":
            assert "__finally funclet at 0x140001f7d not modelled" in text
