"""Which tools are usable for THIS target, under THIS scope manifest, in THIS build and on THIS host, and why not.

One function, `blocker(hub, tool, args)`, decides. `Hub.call` runs it before every tool (a refusal is the Blocker as a
ToolFailure) and the same function builds the availability report (`report`, in the `target_open` and `coverage`
replies) and the routing hint (`hint`, after a successful call). The report therefore cannot disagree with what a call
would do: both are the same decision (tests/unit/test_availability.py checks it call by call over a matrix of manifests
and editions).

Reasons (`kind`), in the order they are checked:
  registry  the tool is not in the effect table (fail-closed)
  target    kernel-mode image: run_controlled is refused whatever the scope says; compare="fixed" without a fixed build
  scope     the manifest's allowed_operations lack the permission the tool's effects need
  edition   the Pro implementation is not part of this build (open-core)
  platform  the host operating system cannot run it (emulate: Windows hosts only)
  extra     an optional Python package is not installed (emulate: unicorn)
  engine    the analysis engine cannot do it for this target (decompile: no decompiler)
  runtime   the pinned Python interpreter for compute is not installed
  sandbox   Windows Sandbox is not available (run_controlled, compute)

The hint (`next`) is guidance from the harness: tool names and a few fixed words from the registry, never target data,
never recorded as evidence, and only tools that are usable right now (a tool the scope does not allow is not suggested).
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping

from ..core.premium import NOT_INCLUDED
from . import kernel_tool
from .effects import BASE_OPERATION, VIRTUAL_EFFECTS, EffectDenied, check_permission, virtual_entry
from .toolspec import EFFECT_REQUIRES
from .registry import SPEC_BY_NAME

if TYPE_CHECKING:
    from .session import Hub

OBSERVE_MODULES = ("redharness.dynamic.rhtrace",)   # Pro: run_controlled(observe=...)
EMULATOR_PACKAGE = "unicorn"                        # optional extra `emulate`
EMULATE_PLATFORM = "win32"                          # the emulation worker is hardened with Windows job objects
OBSERVE_PROBES = (("run_controlled(observe)", {"observe": {"channels": ["api_trace"]}}),
                  ("run_controlled(observe memory)", {"observe": {"channels": ["api_trace", "memory"]}}))

REPORT_NOTE = ("Harness guidance, not evidence about the target (do not cite it). A call applies the same checks; "
               "tools/list does not change.")
HINT_LABEL = "hint, not evidence (never cite it)"


@dataclass(frozen=True)
class Blocker:
    code: str        # the ToolFailure code a call would raise
    kind: str        # see the module docstring
    reason: str      # short, for the report
    message: str     # full, what the refused call says


def module_present(name: str) -> bool:
    """True when the dotted module can be found (it is not imported). A module that is absent, or whose parent package
    is absent (a stripped build), is not present."""
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def host_platform() -> str:
    return sys.platform


def _runtime_problem(hub: "Hub") -> str | None:
    """None when the pinned compute interpreter is installed and intact. The files are re-hashed whenever their
    size/mtime signature changes (compute itself always re-hashes before it runs)."""
    from ..compute.runtime import PINNED, RuntimeMissing, load_runtime, runtime_dir
    spec = getattr(hub, "compute_runtime_spec", PINNED)
    root = runtime_dir(hub.config, spec)
    try:
        sig = tuple((n, (root / n).stat().st_size, (root / n).stat().st_mtime_ns) for n in spec.files)
    except OSError:
        sig = None
    memo = getattr(hub, "_runtime_memo", None)
    if sig is not None and memo == (str(root), sig):
        return None
    try:
        load_runtime(hub.config, spec)
    except RuntimeMissing as e:
        return str(e)
    if sig is not None:
        hub._runtime_memo = (str(root), sig)
    return None


def _missing_operations(manifest: Any, effects: Any) -> tuple[str, ...]:
    """The operations that would unlock a tool whose scope check failed: the unmet requirement with the fewest
    alternatives (static-only run_controlled fails writes_files first, but 'run_controlled' is the one to add)."""
    if not manifest.allows(BASE_OPERATION):
        return (BASE_OPERATION,)
    unmet = [EFFECT_REQUIRES[f] for f in effects.active() if not any(manifest.allows(op) for op in EFFECT_REQUIRES[f])]
    return min(unmet, key=len) if unmet else ()


def blocker(hub: "Hub", tool: str, args: Mapping[str, Any] | None = None) -> Blocker | None:
    """None when a call of `tool` is not refused for an availability reason (it may still fail on its arguments)."""
    if tool not in hub.effects:
        return Blocker("TOOL_NOT_IN_EFFECT_TABLE", "registry", "not in the effect table",
                       f"tool {tool!r} has no entry in the effect table; refused")
    s = hub._s
    if s is None:
        return None   # no target yet: only table membership is checked (the tool then answers NO_TARGET)
    if tool == "run_controlled":
        msg = kernel_tool.refusal(s, "run_controlled (with or without observe)")   # before the manifest: no scope can allow it
        if msg is not None:
            return Blocker(kernel_tool.KERNEL_CODE, "target", "kernel-mode image: never run here", msg)
    observing = virtual_entry(tool, args)
    row, table = tool, hub.effects
    try:
        check_permission(tool, s.manifest, hub.effects)
        if observing is not None:
            row, table = observing, {**hub.effects, **VIRTUAL_EFFECTS}
            check_permission(observing, s.manifest, table)
    except EffectDenied as e:
        needs = _missing_operations(s.manifest, table[row]) or e.needs
        reason = ("allowed_operations lacks " + " or ".join(repr(o) for o in needs)) if needs             else "no scope manifest can allow it"
        suffix = " Plain run_controlled (without observe) still works." if observing is not None else ""
        return Blocker(e.code, "scope", reason, e.message + suffix)
    spec = SPEC_BY_NAME.get(tool)
    if spec is not None and spec.impl_modules and not all(module_present(m) for m in spec.impl_modules):
        return Blocker("DYNAMIC_BACKEND_UNAVAILABLE", "edition", f"Pro feature, {NOT_INCLUDED}",
                       f"{tool} is a {NOT_INCLUDED}.")
    if observing is not None and hub.dynamic_backend is None and not all(module_present(m) for m in OBSERVE_MODULES):
        return Blocker("DYNAMIC_BACKEND_UNAVAILABLE", "edition", f"observe is a Pro feature, {NOT_INCLUDED}",
                       f"dynamic observation (observe) is a {NOT_INCLUDED}. Run without observe.")
    if tool == "emulate":
        if host_platform() != EMULATE_PLATFORM:
            return Blocker("PLATFORM_UNSUPPORTED", "platform", f"runs on Windows hosts only (this host: {host_platform()})",
                           f"emulate runs on Windows hosts only (this host: {host_platform()}); no code was run. "
                           "Continue without emulate.")
        if not module_present(EMULATOR_PACKAGE):
            return Blocker("EMULATOR_MISSING", "extra", "Python package 'unicorn' is not installed",
                           "The CPU emulator (Python package 'unicorn') is not installed for the harness. No code "
                           "was run. Ask the operator to install it (see docs/design/emulation.md); continue "
                           "without emulate meanwhile.")
    if tool == "functions_list" and (args or {}).get("compare") == "fixed" and not (s.fixed_sha and s.fixed_path):
        return Blocker("FIXED_BUILD_NOT_OPEN", "target", "no fixed build is open (compare='fixed')",
                       "no fixed build is open: the scope manifest needs fixed_target_sha256 and target_open needs "
                       "fixed_target_path (the file with that SHA-256)")
    if tool == "decompile" and not getattr(s, "decompiler", True):
        return Blocker("TOOL_MISSING", "engine", "the engine has no decompiler for this target",
                       "The analysis engine has no decompiler for this target (e.g. no Hex-Rays licence). Use "
                       "disassemble and dataflow_slice instead.")
    if tool == "compute":
        problem = _runtime_problem(hub)
        if problem is not None:
            return Blocker("COMPUTE_RUNTIME_MISSING", "runtime", "the pinned Python interpreter is not installed",
                           f"The pinned Python runtime is not installed or was modified ({problem}). No code was run. "
                           "Ask the user to install it; continue without compute meanwhile.")
    if tool in ("run_controlled", "compute"):
        from ..sandbox.backend import WindowsSandboxBackend
        ok, why = (hub.sandbox_backend or WindowsSandboxBackend()).available()
        if not ok:
            return Blocker("SANDBOX_UNAVAILABLE", "sandbox", "Windows Sandbox is not available on this host",
                           f"Windows Sandbox is unavailable on this host ({why}). Dynamic runs are not possible; "
                           "continue with static tools.")
    return None


def report(hub: "Hub") -> dict:
    """`tools` block of the target_open / coverage reply. `unavailable` is empty when everything is usable."""
    usable: list[str] = []
    unavailable: dict[str, dict] = {}
    for name in hub.effects:
        b = blocker(hub, name)
        if b is None:
            usable.append(name)
        else:
            unavailable[name] = {"kind": b.kind, "code": b.code, "reason": b.reason}
    if "run_controlled" in usable:   # observe is an argument-dependent permission; list what is not granted
        for label, probe in OBSERVE_PROBES:
            b = blocker(hub, "run_controlled", probe)
            if b is not None:
                unavailable[label] = {"kind": b.kind, "code": b.code, "reason": b.reason}
    return {"usable": usable, "unavailable": unavailable, "note": REPORT_NOTE}


def hint(hub: "Hub", tool: str) -> str | None:
    """Suggested next tools after a successful `tool` call (None when there is nothing usable to suggest)."""
    spec = SPEC_BY_NAME.get(tool)
    if spec is None:
        return None
    ups = [f"{t} ({why})" for t, why in spec.follow_ups if blocker(hub, t) is None]
    return f"{HINT_LABEL}: " + "; ".join(ups) if ups else None
