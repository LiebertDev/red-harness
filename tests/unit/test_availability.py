"""Availability report (`tools` in target_open / coverage) and routing hint (`next` on tool replies).

The report is the same decision a call makes (mcp/availability.py `blocker`, run by `Hub.call` before every tool). The
central test below proves it call by call: for every tool, over a matrix of scope manifests and installations (Pro
modules present or absent, optional package installed or not, sandbox available or not, Windows host or not, engine with
or without a decompiler, user-mode or kernel-mode image, compute runtime installed or not), the report's verdict equals
the outcome of the real call. The hint is guidance only: tool names from the registry, never target text, never evidence.
"""
import json
import re
import sys
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.mcp import availability
from redharness.mcp.registry import SPECS, TOOL_NAMES
from redharness.mcp.session import Hub, ToolFailure

from ._fake_engine import FakeEngine
from ._fake_sandbox import FakeSandbox
from ._pe_builder import build_pe
from .mcp_helpers import make_manifest
from .test_compute import fake_runtime_zip, python_guest
from .test_emulate import B64, SUM5_X64, _in_process, with_code
from .test_run_controlled_mcp import fake_system_root

AVAILABILITY_CODES = {"SCOPE_DENIED", "TOOL_NOT_IN_EFFECT_TABLE", "KERNEL_TARGET_NO_USERMODE_RUN",
                      "DYNAMIC_BACKEND_UNAVAILABLE", "EMULATE_PLATFORM_UNSUPPORTED", "EMULATOR_MISSING", "TOOL_MISSING",
                      "COMPUTE_RUNTIME_MISSING", "SANDBOX_UNAVAILABLE"}
PRO_MODULES = ("redharness.mcp.region_tool", "redharness.dynamic.region_view", "redharness.dynamic.rhtrace")

OPS = {
    "static": ["static"],
    "emulate": ["static", "emulate"],
    "run": ["static", "run_controlled"],
    "run+compute": ["static", "run_controlled", "compute"],
    "observe": ["static", "run_controlled", "dynamic_observe"],
    "all": ["static", "run_controlled", "compute", "emulate", "dynamic_observe", "dynamic_memory"],
}
# installation / host variants: each key is a fact that changes what is usable
ENVS = {
    "full": {},
    "core": {"pro": False},
    "no_sandbox": {"sandbox": False},
    "no_runtime": {"runtime": False},
    "no_unicorn": {"unicorn": False},
    "linux": {"platform": "linux"},
    "no_decompiler": {"decompiler": False},
    "kernel": {"kernel": True},
    "bare": {"pro": False, "sandbox": False, "runtime": False, "unicorn": False, "platform": "linux",
             "decompiler": False},
}

CALLS = {   # one real call per tool: valid where that is cheap, so the call reaches its own checks
    "target_open": None,
    "functions_list": dict(offset=0, limit=3, detail="summary"),
    "decompile": dict(function="validate_license", detail="summary"),
    "disassemble": dict(address=hex(B64 + 0x1000), count=4, detail="summary"),
    "dataflow_slice": dict(address=hex(B64 + 0x1000), detail="summary"),
    "xrefs": dict(address=hex(B64 + 0x1250)),
    "strings": dict(limit=3, detail="summary"),
    "read_bytes": dict(address=hex(B64 + 0x1000), length=8),
    "file_strings": dict(max_hits=5, detail="summary"),
    "imports": dict(limit=3),
    "run_controlled": dict(cases=[{"stdin": "x\n"}], timeout_s=5),
    "compute": dict(code="print(1)", timeout_s=10),
    "emulate": dict(function=hex(B64 + 0x1000), args=[1, 2, 3, 4, 5]),
    "captured_region": dict(),
    "claim_add": dict(text="x", kind="observation"),
    "unknown_record": dict(question="q", reason="r"),
    "coverage": dict(),
    "report_build": dict(),
}


def _hub(tmp_path, ops, env, monkeypatch):
    tmp_path.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "t.exe"
    target.write_bytes(with_code(build_pe(True), SUM5_X64))
    manifest = make_manifest(tmp_path / "scope.json", target, allowed_operations=list(ops))
    cfg = Config.load(tmp_path / "data")
    hub = Hub(cfg, FakeEngine(), FakeSandbox(behavior=python_guest, available=env.get("sandbox", True)),
              system_root=fake_system_root(tmp_path / "win"))
    zp, spec = fake_runtime_zip(tmp_path)
    hub.compute_runtime_spec = spec
    if env.get("runtime", True):
        from redharness.compute.runtime import install_runtime
        install_runtime(cfg, zp, spec)
    hub.emulate_runner = _in_process
    hub.target_open(str(target), str(manifest))
    if not env.get("pro", True):                      # the Core edition: the Pro modules are not in the build
        for m in PRO_MODULES:
            monkeypatch.setitem(sys.modules, m, None)
    if not env.get("unicorn", True):
        real = availability.module_present
        monkeypatch.setattr(availability, "module_present", lambda n: False if n == "unicorn" else real(n))
    monkeypatch.setattr(availability, "host_platform", lambda: env.get("platform", "win32"))   # default: a Windows host, so the matrix is the same on every host
    hub._s.decompiler = env.get("decompiler", True)
    if env.get("kernel"):
        hub._s.kernel = ("test: subsystem NATIVE",)
    return hub


def _outcome(hub, tool):
    """None when the call was not refused for an availability reason; else the refusal's code."""
    kw = CALLS[tool]
    if tool == "target_open":
        return None   # its own gate is checked below; reopening here would reset the monkeypatched session facts
    try:
        hub.call(tool, kw, lambda: getattr(hub, tool)(**kw))
    except ToolFailure as e:
        return e.code if e.code in AVAILABILITY_CODES else None
    return None


@pytest.mark.parametrize("env_name", list(ENVS))
@pytest.mark.parametrize("ops_name", list(OPS))
def test_the_report_equals_what_a_call_does(tmp_path, monkeypatch, ops_name, env_name):
    hub = _hub(tmp_path, OPS[ops_name], ENVS[env_name], monkeypatch)
    try:
        rep = hub.call("coverage", {}, hub.coverage)["tools"]
        assert list(CALLS) == list(TOOL_NAMES)
        for tool in TOOL_NAMES:
            code = _outcome(hub, tool)
            if tool in rep["unavailable"]:
                assert code == rep["unavailable"][tool]["code"], (tool, rep["unavailable"][tool], code)
            else:
                assert tool in rep["usable"] and code is None, (tool, code)
        assert sorted(rep["usable"] + [t for t in rep["unavailable"] if t in TOOL_NAMES]) == sorted(TOOL_NAMES)
        assert rep["usable"] == [t for t in TOOL_NAMES if t not in rep["unavailable"]]   # registry order
        # argument-dependent rows (observe): a refused row is refused by the call too
        for label, probe in availability.OBSERVE_PROBES:
            if label in rep["unavailable"]:
                kw = dict(cases=[{"stdin": "x\n"}], timeout_s=5, **probe)
                with pytest.raises(ToolFailure) as e:
                    hub.call("run_controlled", kw, lambda: hub.run_controlled(**kw))
                assert e.value.code == rep["unavailable"][label]["code"], (label, e.value.message)
    finally:
        hub.close()


def test_every_reason_kind_appears_somewhere_in_the_matrix(tmp_path, monkeypatch):
    seen = set()
    for i, (ops, env) in enumerate([("all", "bare"), ("all", "no_unicorn"), ("static", "full"), ("all", "kernel"), ("run+compute", "no_runtime")]):
        with monkeypatch.context() as mp:
            hub = _hub(tmp_path / str(i), OPS[ops], ENVS[env], mp)
            try:
                rep = hub.coverage()["tools"]
                seen |= {v["kind"] for v in rep["unavailable"].values()}
            finally:
                hub.close()
    assert seen == {"scope", "edition", "platform", "extra", "engine", "runtime", "sandbox", "target"}


def _documented_blocker_codes() -> set[tuple[str, str]]:
    """(kind, code) rows of the table in docs/usage-mcp.md (section 'availability')."""
    text = (Path(__file__).resolve().parents[2] / "docs" / "usage-mcp.md").read_text(encoding="utf-8")
    return set(re.findall(r"^\s*\| `(\w+)` \| [^|]+ \| `([A-Z_]+)` \|\s*$", text, re.M))


def test_every_blocker_condition_has_the_code_the_docs_table_lists(tmp_path, monkeypatch):
    """One condition, one code: whatever the availability layer refuses with is exactly what docs/usage-mcp.md says,
    for every reason kind, on any host (the platform is set explicitly)."""
    documented = _documented_blocker_codes()
    assert len(documented) >= 10, documented
    seen: set[tuple[str, str]] = set()
    combos = [("all", "bare"), ("all", "no_unicorn"), ("static", "full"), ("all", "kernel"), ("run+compute", "no_runtime"),
              ("all", "no_decompiler"), ("all", "linux"), ("all", "no_sandbox"), ("observe", "core")]
    for i, (ops, env) in enumerate(combos):
        with monkeypatch.context() as mp:
            hub = _hub(tmp_path / str(i), OPS[ops], ENVS[env], mp)
            try:
                probes = [(t, CALLS[t]) for t in TOOL_NAMES] + [("run_controlled", p) for _, p in availability.OBSERVE_PROBES]
                probes += [("functions_list", {"compare": "fixed"}), ("no_such_tool", None)]
                for tool, args in probes:
                    b = availability.blocker(hub, tool, args)
                    if b is not None:
                        seen.add((b.kind, b.code))
            finally:
                hub.close()
    assert seen == documented, (sorted(seen - documented), sorted(documented - seen))


def test_the_off_windows_refusal_is_one_code_and_says_nothing_ran(tmp_path, monkeypatch):
    from redharness.emulate import host
    hub = _hub(tmp_path, OPS["all"], ENVS["linux"], monkeypatch)
    try:
        b = availability.blocker(hub, "emulate", CALLS["emulate"])
        assert (b.kind, b.code) == ("platform", "EMULATE_PLATFORM_UNSUPPORTED") and "No code was run" in b.message
        monkeypatch.setattr(host.sys, "platform", "linux")
        with pytest.raises(host.WorkerError) as e:   # the layer below refuses with the same code
            host.run_in_worker("x", "0" * 64, {"timeout_ms": 10})
        assert e.value.code == b.code
        kw = CALLS["emulate"]
        with pytest.raises(ToolFailure) as f:
            hub.call("emulate", kw, lambda: hub.emulate(**kw))
        assert f.value.code == b.code
    finally:
        hub.close()


def test_target_open_carries_the_report_and_a_hint(tmp_path):
    target = tmp_path / "t.exe"
    target.write_bytes(with_code(build_pe(True), SUM5_X64))
    manifest = make_manifest(tmp_path / "scope.json", target)
    hub = Hub(Config.load(tmp_path / "data"), FakeEngine())
    try:
        r = hub.call("target_open", {}, lambda: hub.target_open(str(target), str(manifest)))
        assert set(r["tools"]) == {"usable", "unavailable", "note"}
        assert set(r["tools"]["unavailable"]) == {"run_controlled", "compute", "emulate", "captured_region"}
        assert r["tools"]["unavailable"]["run_controlled"] == {
            "kind": "scope", "code": "SCOPE_DENIED", "reason": "allowed_operations lacks 'run_controlled'"}
        assert r["tools"]["unavailable"]["captured_region"]["reason"] == "allowed_operations lacks 'dynamic_memory'"
        assert r["tools"]["unavailable"]["emulate"]["reason"] == "allowed_operations lacks 'emulate'"
        assert "run_controlled" not in r["next"] and "emulate" not in r["next"]   # a denied tool is not suggested
        assert r["next"].startswith(availability.HINT_LABEL)
        assert len(json.dumps(r["tools"])) < 1200 and len(r["next"]) < 260        # terse
        print("\n" + json.dumps({"tools": r["tools"], "next": r["next"]}, indent=1))
    finally:
        hub.close()


def test_a_denied_tool_is_never_suggested_a_granted_one_is(tmp_path, monkeypatch):
    for ops_name, expect in (("static", False), ("all", availability.module_present("unicorn"))):   # the extra may be absent
        hub = _hub(tmp_path / ops_name, OPS[ops_name], {}, monkeypatch)
        try:
            dec = hub.call("decompile", CALLS["decompile"], lambda: hub.decompile(**CALLS["decompile"]))
            assert ("emulate" in dec["next"]) is expect, dec["next"]
            assert "dataflow_slice" in dec["next"] and "xrefs" in dec["next"]
            # the hint never names a tool the open scope refuses, whichever tool it follows
            for s in SPECS:
                h = availability.hint(hub, s.name)
                for t, _ in s.follow_ups:
                    assert (h is not None and t + " (" in h) == (availability.blocker(hub, t) is None), (s.name, t)
        finally:
            hub.close()


def test_the_hint_is_only_registry_words_and_costs_little():
    for s in SPECS:
        assert len(s.follow_ups) <= 4
        text = availability.HINT_LABEL + ": " + "; ".join(f"{t} ({w})" for t, w in s.follow_ups)
        assert len(text) <= 260, s.name
        assert text.isascii()


def test_a_hint_is_not_evidence_and_cannot_back_a_claim(tmp_path):
    target = tmp_path / "t.exe"
    target.write_bytes(with_code(build_pe(True), SUM5_X64))
    manifest = make_manifest(tmp_path / "scope.json", target)
    hub = Hub(Config.load(tmp_path / "data"), FakeEngine())
    try:
        hub.call("target_open", {}, lambda: hub.target_open(str(target), str(manifest)))
        fl = hub.call("functions_list", dict(detail="summary"), lambda: hub.functions_list(detail="summary"))
        ev, hint = fl["evidence_id"], fl["next"]
        assert hint.startswith(availability.HINT_LABEL)
        stored = json.dumps(hub._s.ledger.state["evidence"], default=str)
        assert "hint, not evidence" not in stored and hint not in stored          # not part of any evidence
        assert "hint, not evidence" not in hub._s.journal.path.read_text(encoding="utf-8")   # nor of the journal
        kw = dict(text="The harness suggests reading a candidate.", evidence_ids=[ev], kind="observation",
                  atoms=[{"type": "quote", "evidence_id": ev, "text": "read a candidate"}])
        r = hub.call("claim_add", kw, lambda: hub.claim_add(**kw))
        assert r["status"] == "REJECTED" and "QUOTE_NOT_IN_RAW" in [i["code"] for i in r["issues"]]
        kw["atoms"] = [{"type": "quote", "evidence_id": ev, "text": hint[:60]}]
        r = hub.call("claim_add", kw, lambda: hub.claim_add(**kw))
        assert r["status"] == "REJECTED"
        # an error reply carries no hint; neither do the record-keeping tools
        with pytest.raises(ToolFailure):
            hub.call("decompile", dict(function="0x1"), lambda: hub.decompile("0x1"))
        assert "next" not in hub.call("coverage", {}, hub.coverage)
    finally:
        hub.close()


def test_registry_validation_of_follow_ups_and_pro_modules():
    from redharness.mcp.toolspec import ToolEffects, ToolSpec, validate_specs
    base = dict(effects=ToolEffects(), read_only=True, exposure="always", real_tests=("tests/heavy/test_x.py::test_y",))
    a = ToolSpec("a", follow_ups=(("b", "next"),), **base)
    b = ToolSpec("b", **base)
    validate_specs((a, b))
    for bad in (ToolSpec("a", follow_ups=(("nope", "x"),), **base), ToolSpec("a", follow_ups=(("a", "x"),), **base),
                ToolSpec("a", follow_ups=(("b", ""),), **base), ToolSpec("a", follow_ups=(("b", "x" * 80),), **base),
                ToolSpec("a", follow_ups=(("b", "é"),), **base)):
        with pytest.raises(ValueError):
            validate_specs((bad, b))
    with pytest.raises(ValueError):   # a pro tool must name the modules the availability check looks for
        validate_specs((ToolSpec("p", tier="pro", premium_module="src/x.py", **base),))


def test_both_eval_prompts_explain_the_guidance_fields():
    try:
        from pathlib import Path
        from redharness.evals import blind, phase1d_eval
    except ImportError:
        pytest.skip("the eval package is not part of this tree")
    ops = ("static",)
    texts = [blind.build_task("t.exe", "scope.json", operations=ops, provider="claude"),
             phase1d_eval.build_task(Path("t.exe"), Path("scope.json"), next(iter(phase1d_eval.KINDS)), ops, "claude")]
    for text in texts:
        assert "`next` hint" in text and "not evidence about the target" in text
        assert "@" not in text and blind.tool_name("target_open", "claude") in text
