"""Kernel-mode targets in the MCP layer (a separate file to keep session.py small).

Two jobs, both static and engine-based only (the driver is never loaded or run):
1. Detection: `target_open` marks the job `kernel_mode` when the PE says it is a driver / native image
   (`analysis.pe_image.kernel_mode_reasons`). For such a job `run_controlled` (plain or with observe) and `compute`
   inputs taken from a dynamic observation are refused with `KERNEL_TARGET_NO_USERMODE_RUN`, whatever the scope
   manifest allows, until a VM path exists (Phase 2). Static tools stay allowed.
2. Driver facts (premium, `mcp/driver_facts.py`): `target_open` of a kernel job also returns the static driver scan
   (DriverEntry, dispatch writes, IOCTL codes, device creation). The detection and the denial above are core safety
   logic; a build without the premium module answers `{"available": false, ...}` in the `driver` block.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..analysis.pe_image import PeError, kernel_mode_reasons, parse_pe

if TYPE_CHECKING:
    from ..core.cas import Cas
    from .session import _Session

KERNEL_CODE = "KERNEL_TARGET_NO_USERMODE_RUN"
KERNEL_MESSAGE = ("This target is a kernel-mode image ({why}). It is never run in the Win32 sandbox and no scope "
                  "manifest can allow it until a VM path exists (Phase 2). {what} Static tools still work: "
                  "functions_list, decompile, disassemble, xrefs, strings, read_bytes (and compute on static "
                  "evidence); the target_open summary has a `driver` block (the static driver facts, when available).")


def detect(cas: "Cas", sha: str, file_name: str | None) -> tuple[str, ...]:
    """Reasons this CAS copy is a kernel-mode image; empty when none or when the headers cannot be parsed
    (the engine already opened the file, so a PE that this reader cannot parse is not a kernel finding)."""
    try:
        img = parse_pe(lambda off, n: cas.read_at(sha, off, n), cas.size(sha))
    except (PeError, OSError):
        return ()
    return kernel_mode_reasons(img, file_name)


def deny(s: "_Session", what: str):
    """Raises ToolFailure(KERNEL_TARGET_NO_USERMODE_RUN) when the job is kernel_mode. `what` names the refused action."""
    if not s.kernel:
        return
    from .session import ToolFailure
    raise ToolFailure(KERNEL_CODE, KERNEL_MESSAGE.format(why="; ".join(s.kernel), what=f"{what} is refused."))


def deny_compute_inputs(s: "_Session", bindings: list[dict]) -> None:
    """compute on a kernel job may use static evidence only: a binding to a dynamic observation is refused."""
    if s.kernel and any(b.get("kind") == "memrange" for b in bindings):
        deny(s, "compute on bytes of a target execution")
