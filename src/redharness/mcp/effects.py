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

from dataclasses import dataclass, fields, replace
from typing import Any, Mapping

from ..scope.manifest import ScopeManifest


@dataclass(frozen=True)
class ToolEffects:
    reads_files: bool = False          # reads the target file / engine output
    writes_files: bool = False         # writes files OUTSIDE the job store (journal, CAS, report) (e.g. the sandbox work folder)
    launches_process: bool = False     # starts a process other than the operator's engine
    executes_foreign_code: bool = False  # runs the target / foreign code (run_controlled)
    executes_model_code: bool = False  # runs code written by the model (isolated) (compute); needs a separate permission
    emulates_target_code: bool = False  # interprets the target's code in a CPU emulator (emulate); never runs it natively
    instruments_process: bool = False  # a debugger/hook attaches to the target process inside the guest (observe)
    captures_memory: bool = False      # target process memory is read and digested (observe memory channel)
    network: bool = False              # network access
    mutates_target: bool = False       # modifies the target binary (patch)
    mutates_session: bool = False      # adds evidence/claim/unknown records (append-only writes to the job store)
    idempotent: bool = True            # the same arguments give the same result/record again

    def active(self) -> list[str]:
        """Active effects that may need permission (excluding the idempotent and pure record/read flags)."""
        return [f.name for f in fields(self) if f.name in EFFECT_REQUIRES and getattr(self, f.name)]


# Effect -> any one of the manifest operations that allow this effect. Empty tuple: never allowed.
EFFECT_REQUIRES: Mapping[str, tuple[str, ...]] = {
    "executes_foreign_code": ("run_controlled",),
    "executes_model_code": ("compute",),   # default DENY: the manifest must explicitly say "compute" (run_controlled is not enough)
    "emulates_target_code": ("emulate",),   # default DENY: run_controlled / compute do not imply it
    "launches_process": ("run_controlled", "compute", "emulate"),
    "writes_files": ("run_controlled", "patch_poc", "compute"),
    "mutates_target": ("patch_poc",),
    "instruments_process": ("dynamic_observe",),   # default DENY
    "captures_memory": ("dynamic_memory",),
    "network": (),
}
BASE_OPERATION = "static"

_READ = ToolEffects(reads_files=True, mutates_session=True)

TOOL_EFFECTS: Mapping[str, ToolEffects] = {
    "target_open": ToolEffects(reads_files=True, mutates_session=True),
    "functions_list": _READ,
    "decompile": _READ,
    "disassemble": _READ,
    "dataflow_slice": _READ,   # harness slice over the engine's disassembly + the CAS copy: same effects as disassemble
    "xrefs": _READ,
    "strings": _READ,
    "read_bytes": _READ,   # reads the target PE file (CAS copy), does not call the engine: no new permission needed
    "imports": _READ,      # PE import/delay-import tables parsed from the CAS copy (engine-free): no new permission needed
    "file_strings": _READ,  # raw ASCII/UTF-16LE file scan (CAS copy, engine-free, bounded): no new permission needed
    "run_controlled": ToolEffects(reads_files=True, writes_files=True, launches_process=True,
                                  executes_foreign_code=True, mutates_session=True, idempotent=False),
    "compute": ToolEffects(reads_files=True, writes_files=True, launches_process=True, executes_model_code=True,
                           mutates_session=True),  # deterministic: same code+input = same ev_
    "emulate": ToolEffects(reads_files=True, launches_process=True, emulates_target_code=True,
                           mutates_session=True),  # bounded worker process on the host; same request = same ev_
    # views of bytes a stored dynamic observation captured: reads the stored document only (CAS), runs nothing; it shows
    # target memory, so it needs the memory permission the capture needed (dynamic_memory), not run_controlled again
    "captured_region": ToolEffects(reads_files=True, captures_memory=True, mutates_session=True),
    "claim_add": ToolEffects(mutates_session=True),
    "unknown_record": ToolEffects(mutates_session=True),
    "coverage": ToolEffects(),
    "report_build": ToolEffects(mutates_session=True),
}


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
