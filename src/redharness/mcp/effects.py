"""Tool effect table: the possible effects of each MCP tool and how they map to scope manifest permissions.

Effect flags are defined explicitly for every tool and the permission decision is derived from this table. Field names
and permission bindings are specific to this project.

Rules (fail-closed):
- A tool that is not in the table is refused (`TOOL_NOT_IN_EFFECT_TABLE`).
- Every tool needs at least the `static` permission (the manifest already requires it; it is checked here too).
- If a flag is set, `EFFECT_REQUIRES` says which manifest operations make that effect allowed (any one
  is enough). Empty set = no manifest can allow this effect (e.g. network): the tool is always refused.
- Running the operator-configured analysis engine (IDA/Ghidra) does not count as an effect; running the target does.
"""

from __future__ import annotations

from dataclasses import fields, replace
from typing import Any, Mapping

from ..scope.manifest import ScopeManifest
from .registry import SPECS
from .toolspec import EFFECT_REQUIRES, ToolEffects


BASE_OPERATION = "static"

TOOL_EFFECTS: Mapping[str, ToolEffects] = {s.name: s.effects for s in SPECS}   # the registry (mcp/registry.py) is the source


# Effect rows that are not tools: run_controlled with `observe` (the effect depends on the argument). Hub.call checks the
# matching row IN ADDITION to the tool's own row. Not registered tools (the tool count does not change).
VIRTUAL_EFFECTS: Mapping[str, ToolEffects] = {
    "run_controlled#observe": replace(TOOL_EFFECTS["run_controlled"], instruments_process=True),
    "run_controlled#observe+memory": replace(TOOL_EFFECTS["run_controlled"], instruments_process=True,
                                             captures_memory=True),
}


def virtual_entry(tool: str, args: Mapping[str, Any] | None) -> str | None:
    """Virtual effect row for this call, or None. `observe` present and not None/False -> an observe row; a malformed
    `observe` (not an object, channels not a list) is checked against the strictest row (fail-closed)."""
    if tool != "run_controlled" or not isinstance(args, Mapping):
        return None
    obs = args.get("observe")
    if obs is None or obs is False:
        return None
    chans = obs.get("channels") if isinstance(obs, Mapping) else None
    if not isinstance(chans, (list, tuple)) or "memory" in chans:
        return "run_controlled#observe+memory"
    return "run_controlled#observe"


class EffectDenied(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


def check_permission(tool: str, manifest: ScopeManifest,
                     table: Mapping[str, ToolEffects] = TOOL_EFFECTS) -> None:
    """Raises `EffectDenied` if any of the tool's effects is not allowed in the manifest."""
    eff = table.get(tool)
    if eff is None:
        raise EffectDenied("TOOL_NOT_IN_EFFECT_TABLE", f"tool {tool!r} has no entry in the effect table; refused")
    if not manifest.allows(BASE_OPERATION):
        raise EffectDenied("SCOPE_DENIED", f"scope manifest does not allow {BASE_OPERATION!r}")
    for flag in eff.active():
        need = EFFECT_REQUIRES[flag]
        if not need:
            raise EffectDenied("SCOPE_DENIED", f"tool {tool!r} has effect '{flag}', which no scope manifest can allow")
        if not any(manifest.allows(op) for op in need):
            raise EffectDenied(
                "SCOPE_DENIED",
                f"Scope manifest does not allow {tool}: it has effect '{flag}', which needs "
                f"{' or '.join(repr(o) for o in need)} in allowed_operations. Static tools still work; "
                f"ask the user to add it to the manifest.")


def effects_markdown(table: Mapping[str, ToolEffects] | None = None) -> str:
    """Generates the table in docs/usage-mcp.md (a test checks that it matches the document). Default: the tools plus
    the virtual `run_controlled#observe` rows."""
    if table is None:
        table = {**TOOL_EFFECTS, **VIRTUAL_EFFECTS}
    cols = [f.name for f in fields(ToolEffects)]
    out = ["| Tool | " + " | ".join(cols) + " | required permission |", "|---|" + "---|" * (len(cols) + 1)]
    for name, e in table.items():
        groups = sorted({"/".join(EFFECT_REQUIRES[fl]) or "NEVER" for fl in e.active()})
        need = " + ".join([BASE_OPERATION] + groups)  # "a/b": any one is enough; "+": all are required
        out.append(f"| `{name}` | " + " | ".join("yes" if getattr(e, c) else "-" for c in cols)
                   + f" | {need} |")
    return "\n".join(out)
