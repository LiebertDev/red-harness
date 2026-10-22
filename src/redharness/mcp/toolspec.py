"""Types of the tool registry: the effect flags, how they map to scope permissions, and `ToolSpec` (one declarative
record per MCP tool). The records themselves live in `registry.py`; `effects.py`, `server.py`, the Studio bridge and the
eval prompt derive their tool facts from them.

This module imports nothing from the rest of the package, so every consumer can import it without cycles, and it never
imports a premium module (a spec only NAMES the path of a premium implementation).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from typing import Mapping


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

EXPOSURES = ("always", "operation")


@dataclass(frozen=True)
class ToolSpec:
    """Everything the harness knows about one MCP tool, declared once.

    Derived from it: the tool list (`TOOL_NAMES`), the effect table (`TOOL_EFFECTS`), the MCP annotations, the Studio
    user-only / execution sets and approval summaries, the eval prompt's exposure rule and usage note.
    Checked against it (tests/unit/test_tool_wiring.py): the registered FastMCP tools, the rows of docs/usage-mcp.md, the
    real-run test, and for a premium tool the public export's deny list."""

    name: str
    effects: ToolEffects
    read_only: bool                  # MCP readOnlyHint (a read-only tool changes no target, process or file)
    exposure: str                    # eval prompt: "always" (offered with every scope) or "operation" (offered only
                                     # when the scope grants `operation`). REQUIRED, no default: a new tool is never
                                     # exposed to an eval by omission.
    operation: str = ""              # exposure "operation": the scope operation that unlocks the tool
    tier: str = "core"               # "core" (public) or "pro" (implementation stays out of the public export)
    premium_module: str = ""         # tier "pro": repo path of the implementation (a name only; never imported here)
    user_only: bool = False          # Studio: the user performs this step, the model never calls it
    execution_summary: str = ""      # Studio: non-empty = the tool executes something; text of the approval card
    eval_note: str = ""              # eval prompt: one-line usage note shown next to the tool name
    real_tests: tuple[str, ...] = () # real (heavy) tests that drive the tool: "tests/heavy/<file>.py::<test function>"
    no_real_test: str = ""           # OR the reason there is none (exactly one of real_tests / no_real_test)

    @property
    def executes(self) -> bool:
        return bool(self.execution_summary)


def validate_specs(specs: tuple[ToolSpec, ...]) -> None:
    """Import-time check of the registry itself (a violation raises, so a broken entry never reaches a run)."""
    seen: set[str] = set()
    allowed_ops = {op for ops in EFFECT_REQUIRES.values() for op in ops}
    for s in specs:
        if not s.name or s.name in seen:
            raise ValueError(f"tool registry: empty or duplicate tool name {s.name!r}")
        seen.add(s.name)
        if s.tier not in ("core", "pro"):
            raise ValueError(f"tool registry: {s.name}: tier must be 'core' or 'pro'")
        if (s.tier == "pro") != bool(s.premium_module):
            raise ValueError(f"tool registry: {s.name}: a pro tool names its premium module, a core tool does not")
        if s.exposure not in EXPOSURES:
            raise ValueError(f"tool registry: {s.name}: exposure must be one of {EXPOSURES}, got {s.exposure!r}")
        if (s.exposure == "operation") != bool(s.operation):
            raise ValueError(f"tool registry: {s.name}: exposure 'operation' needs an operation, 'always' has none")
        if bool(s.real_tests) == bool(s.no_real_test.strip()):
            raise ValueError(f"tool registry: {s.name}: give real_tests or a no_real_test reason (exactly one)")
        for node in s.real_tests:
            if not re.fullmatch(r"tests/heavy/test_\w+\.py::test_\w+", node):
                raise ValueError(f"tool registry: {s.name}: real test {node!r} is not 'tests/heavy/<file>.py::<test>'")
        if s.operation and s.operation not in allowed_ops:
            raise ValueError(f"tool registry: {s.name}: operation {s.operation!r} is not a scope operation of any effect")
        if s.operation and not any(op == s.operation for fl in s.effects.active() for op in EFFECT_REQUIRES[fl]):
            raise ValueError(f"tool registry: {s.name}: operation {s.operation!r} is not required by its own effects")
        if s.execution_summary and not s.operation:
            raise ValueError(f"tool registry: {s.name}: an executing tool needs its scope operation")
        if s.user_only and (s.operation or s.execution_summary):
            raise ValueError(f"tool registry: {s.name}: a user-only tool is neither gated nor executing")
