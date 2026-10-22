"""Tool wiring conformance. Every tool is declared once in the registry (`mcp/registry.py`, one `ToolSpec` each);
`TOOL_NAMES`, the effect table, the MCP annotations, the Studio sets and the eval exposure are DERIVED from it. This file
checks what cannot be derived, so an unwired tool fails CI by construction. For each tool:

1. a FastMCP handler of the same name, registered with annotations that agree with its spec, and a `run("<name>")` call
   inside that handler with the same name (so the journal / effect-check name cannot drift);
2. an effect-table entry (derived; checked, so a hand-added row cannot hide);
3. a row in `docs/usage-mcp.md` (the reference table of tool signatures);
4. an explicit eval exposure (`exposure` has no default and the eval package derives its sets from it, so nothing is
   exposed by omission) -- checked where the eval package is present (vault);
5. real (heavy) tests named by node id in the spec, which must exist and reach a call of the tool (AST, through the
   helpers and fixtures the test uses), or a written reason (`no_real_test`) -- checked in the vault, where the proof
   files live (the public tree ships only some of them);
6. a premium tool names an implementation path that the public export denies (vault).
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from redharness.mcp.effects import TOOL_EFFECTS
from redharness.mcp.registry import SPECS, TOOL_NAMES, spec
from redharness.mcp.toolspec import ToolEffects, ToolSpec, validate_specs

ROOT = Path(__file__).resolve().parents[2]
VAULT = (ROOT / "tools" / "export_public.py").is_file()


def test_the_registry_is_the_single_source_of_the_tool_list():
    from redharness.mcp import server
    assert server.TOOL_NAMES is TOOL_NAMES and TOOL_NAMES == tuple(s.name for s in SPECS)
    assert list(TOOL_EFFECTS) == list(TOOL_NAMES) and all(TOOL_EFFECTS[s.name] is s.effects for s in SPECS)
    assert len(TOOL_NAMES) <= server.MAX_TOOLS


def _server():
    from redharness.config import Config
    from redharness.mcp import server
    from ._fake_engine import FakeEngine
    return server, Config.load(ROOT / "x"), FakeEngine()


def test_every_tool_has_a_registered_handler_with_spec_annotations():
    import asyncio
    server, config, engine = _server()
    mcp, hub = server.build_server(config, engine)
    try:
        by = {t.name: t for t in asyncio.run(mcp.list_tools())}
    finally:
        hub.close()
    assert list(by) == list(TOOL_NAMES)
    for name, t in by.items():
        s, a = spec(name), t.annotations
        assert (a.readOnlyHint, a.idempotentHint, a.openWorldHint) == (s.read_only, s.effects.idempotent,
                                                                       s.effects.network)


def test_a_handler_without_a_spec_cannot_be_registered(monkeypatch):
    server, config, engine = _server()

    def no_spec(name):
        raise KeyError(name)
    monkeypatch.setattr(server, "spec", no_spec)
    with pytest.raises(KeyError):
        server.build_server(config, engine)


def test_each_handler_journals_under_its_own_name():
    tree = ast.parse((ROOT / "src" / "redharness" / "mcp" / "server.py").read_text(encoding="utf-8"))
    handlers: dict[str, set] = {}
    for fn in ast.walk(tree):
        if isinstance(fn, ast.AsyncFunctionDef) and any(isinstance(d, ast.Name) and d.id == "tool"
                                                        for d in fn.decorator_list):
            handlers[fn.name] = {c.args[0].value for c in ast.walk(fn)
                                 if isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == "run"
                                 and c.args and isinstance(c.args[0], ast.Constant)}
    assert list(handlers) == list(TOOL_NAMES)
    assert {n: v for n, v in handlers.items() if v != {n}} == {}


def test_every_tool_has_an_effect_entry():
    assert [t for t in TOOL_NAMES if t not in TOOL_EFFECTS] == []
    assert sorted(TOOL_EFFECTS) == sorted(TOOL_NAMES)          # and no effect row without a tool


def test_every_tool_has_a_usage_row():
    text = (ROOT / "docs" / "usage-mcp.md").read_text(encoding="utf-8")
    assert [t for t in TOOL_NAMES if not re.search(rf"^\| `{t}[(`]", text, re.M)] == []


def test_eval_exposure_is_explicit_per_tool():
    ok = dict(name="t", effects=ToolEffects(), read_only=True, real_tests=("tests/heavy/test_x.py::test_y",))
    with pytest.raises(TypeError):                              # no default: omitting it is a construction error
        ToolSpec(**ok)
    with pytest.raises(ValueError):
        validate_specs((ToolSpec(**ok, exposure="maybe"),))
    with pytest.raises(ValueError):                             # "operation" exposure names the operation
        validate_specs((ToolSpec(**ok, exposure="operation"),))
    validate_specs((ToolSpec(**ok, exposure="always"),))
    assert all(s.exposure in ("always", "operation") for s in SPECS)
    assert {s.name for s in SPECS if s.exposure == "operation"} == {"run_controlled", "compute", "emulate",
                                                                    "captured_region"}


def test_the_eval_prompt_exposes_exactly_what_the_specs_declare():
    try:
        from redharness.evals import blind
    except ImportError:
        pytest.skip("the eval package is not part of this tree")
    assert set(blind.BASE_TOOLS) == {s.name for s in SPECS if s.exposure == "always"}
    assert blind.TOOL_OPERATION == {s.name: s.operation for s in SPECS if s.exposure == "operation"}
    assert not set(blind.BASE_TOOLS) & set(blind.TOOL_OPERATION)
    assert sorted(blind.BASE_TOOLS + blind.OPERATION_TOOLS) == sorted(TOOL_NAMES)
    assert blind.exposed_tools(["static"]) == [s.name for s in SPECS if s.exposure == "always"]
    assert blind.TOOL_NOTES == {s.name: s.eval_note for s in SPECS if s.eval_note}


def test_studio_sets_are_derived_from_the_specs():
    try:
        from redharness.studio import bridge
    except ImportError:
        pytest.skip("Studio is not part of this tree")
    assert bridge.USER_ONLY_TOOLS == {"target_open"}
    assert bridge.EXECUTION_TOOLS == {"run_controlled", "compute", "emulate"}
    assert set(bridge.EXECUTION_SUMMARY) == bridge.EXECUTION_TOOLS and all(bridge.EXECUTION_SUMMARY.values())


def _manifest(ops):
    from redharness.scope.manifest import parse_manifest
    return parse_manifest({"schema": "rh.scope/1", "target_sha256": "ab" * 32,
                           "authorization": {"declared_by": "test", "basis": "owner", "statement": "test binary"},
                           "allowed_operations": list(ops)})


def test_captured_region_needs_dynamic_memory():
    from redharness.mcp.effects import BASE_OPERATION, EFFECT_REQUIRES, EffectDenied, check_permission
    assert TOOL_EFFECTS["captured_region"].captures_memory and EFFECT_REQUIRES["captures_memory"] == ("dynamic_memory",)
    assert BASE_OPERATION == "static"
    for ops in (["static"], ["static", "run_controlled", "dynamic_observe", "compute"]):
        with pytest.raises(EffectDenied):
            check_permission("captured_region", _manifest(ops), TOOL_EFFECTS)
    check_permission("captured_region", _manifest(["static", "run_controlled", "dynamic_observe", "dynamic_memory"]),
                     TOOL_EFFECTS)


# How the real tests invoke a tool by name: `hub.call("t", ...)`, `call(session, "t", ...)`, `_call(hub, "t", ...)`,
# `session.tool("t", ...)` (the name is one of the first two positional arguments), or directly as a method, `hub.t(...)`.
DISPATCHERS = frozenset({"call", "_call", "tool", "call_tool"})


def _dispatches(call: ast.Call, tool: str) -> bool:
    """A Call node that invokes `tool`: the callee is named `tool`, or a known dispatcher gets the name as a literal.
    A bare string, a bare attribute or a string in an assert message is not a call and does not count."""
    f = call.func
    callee = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else None
    if callee == tool:
        return True
    return callee in DISPATCHERS and any(isinstance(a, ast.Constant) and a.value == tool for a in call.args[:2])


def _reaches_tool(tree: ast.Module, test: str, tool: str) -> bool | None:
    """None: the test function is not in the module. True: the test, or a module-level function / fixture it names
    (call, argument, name reference, transitively), contains the tool's name as a string or a `.tool(` call."""
    funcs = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    if test not in funcs:
        return None
    seen, todo = set(), [test]
    while todo:
        f = funcs[todo.pop()]
        if f.name in seen:
            continue
        seen.add(f.name)
        for n in ast.walk(f):
            if isinstance(n, ast.Call) and _dispatches(n, tool):
                return True
            ref = n.id if isinstance(n, ast.Name) else n.arg if isinstance(n, ast.arg) else None
            if ref in funcs and ref not in seen:
                todo.append(ref)
    return False


def test_every_tool_has_real_tests_that_call_it_or_a_reason():
    if not VAULT:
        pytest.skip("the real-test files are vault-only in part; the check runs in the vault")
    bad = []
    for s in SPECS:
        if s.no_real_test:
            continue                                            # validate_specs requires a non-blank reason
        for node in s.real_tests:
            path, _, test = node.partition("::")
            f = ROOT / path
            if not f.is_file():
                bad.append(f"{s.name}: {path} does not exist")
                continue
            r = _reaches_tool(ast.parse(f.read_text(encoding="utf-8")), test, s.name)
            if r is None:
                bad.append(f"{s.name}: {node} is not a test function of that file")
            elif not r:
                bad.append(f"{s.name}: {node} never calls the tool")
    assert bad == [], "real tests missing or not calling their tool (fix the registry entry): " + "; ".join(bad)


def test_the_real_test_check_rejects_a_test_that_does_not_call_the_tool():
    tree = ast.parse("import pytest\n"
                     "def _c(h):\n    return h.call('xrefs', {})\n"
                     "def test_a(hub):\n    _c(hub)\n"
                     "def test_b(hub):\n    pass\n"
                     "@pytest.fixture\ndef run():\n    return lambda h: h.coverage()\n"
                     "def test_c(run):\n    pass\n")
    assert _reaches_tool(tree, "test_a", "xrefs") is True      # through a helper
    assert _reaches_tool(tree, "test_b", "xrefs") is False
    assert _reaches_tool(tree, "test_c", "coverage") is True   # through a fixture argument
    assert _reaches_tool(tree, "test_zzz", "xrefs") is None


def test_the_real_test_check_rejects_false_pass_shapes():
    shapes = {
        "bare string": "x = 'xrefs'",
        "bare attribute": "hub.xrefs",
        "string in an assert message": "assert ok, 'xrefs failed'",
        "string to a non-dispatcher": "print('xrefs')",
        "string as a later argument": "hub.call(1, 2, 'xrefs')",
        "string in a dict": "send({'name': 'xrefs'})",
        "other tool dispatched": "hub.call('strings', {})",
    }
    for label, body in shapes.items():
        tree = ast.parse(f"def test_t(hub):\n    {body}\n")
        assert _reaches_tool(tree, "test_t", "xrefs") is False, label
    calls = ["hub.call('xrefs', {})", "call(s, 'xrefs')", "_call(hub, 'xrefs')", "s.tool('xrefs')", "hub.xrefs(1)",
             "hub.call('xrefs', {}, lambda: 1)"]
    for body in calls:
        assert _reaches_tool(ast.parse(f"def test_t(hub):\n    {body}\n"), "test_t", "xrefs") is True, body
    with pytest.raises(ValueError):                             # a spec needs real tests or a reason, not neither
        validate_specs((ToolSpec("t", ToolEffects(), read_only=True, exposure="always"),))


def test_a_premium_tool_names_a_denied_implementation():
    assert [s.name for s in SPECS if s.tier == "pro"] == ["captured_region"]
    if not VAULT:
        pytest.skip("the export deny list is vault-only")
    import importlib.util
    sp = importlib.util.spec_from_file_location("export_public_wiring", ROOT / "tools" / "export_public.py")
    ex = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(ex)
    for s in SPECS:
        if s.tier == "pro":
            assert (ROOT / s.premium_module).is_file() and ex.is_denied(s.premium_module), s.name
