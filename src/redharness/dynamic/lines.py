"""Quotable trace lines of an observation.

Every event of an `rh.dynamic` document has one deterministic text line with a stable index (`[seq]`). The line is a pure
function of the sealed document, so the verifier recomputes it and accepts a `quote` atom that is a substring of the
rendered trace as well as of the raw JSON (verifier.py, version 13). `run_controlled(observe=...)` prints the same lines
(`observation.trace`), so a model copies a line instead of guessing at JSON field names.

    [3] api_call kernel32.dll!VirtualProtect caller=image
    [5] resolve kernel32.dll!lstrlenA -> 0x7ffa1f2fadf0 caller=dynamic
    [7] memory exec_transition base=0x1d0000 size=4096 sha256=<64 hex> prot=RX req_base=0x1d0000 req_size=125 req_sha256=<64 hex> captured=4096

The observed execution's own output (`output`) renders like a plain `run_controlled` evidence blob: stdout, then
`--- stderr ---`, then stderr (decoded as UTF-8 with replacement); a quote atom may also be a substring of that text.
"""

from __future__ import annotations

import re
from typing import Iterable

from .model import ApiCallEvent, MemoryEvent, Observation, ResolveEvent

STDERR_MARK = "\n--- stderr ---\n"   # same separator as the run_controlled evidence blob (sandbox/evidence.py)

Event = ApiCallEvent | ResolveEvent | MemoryEvent
_WORD = re.compile(r"[A-Za-z0-9_]{3,}")


def event_line(e: Event) -> str:
    if isinstance(e, ApiCallEvent):
        return (f"[{e.seq}] api_call {e.module}!{e.api}" + (f" caller={e.caller}" if e.caller else "")
                + ("" if e.from_target else " from_target=false"))
    if isinstance(e, ResolveEvent):
        return (f"[{e.seq}] resolve {e.module}!{e.api} -> {'NULL' if e.address is None else hex(e.address)} "
                f"caller={e.caller}")
    line = f"[{e.seq}] memory {e.kind} base={hex(e.base)} size={e.size} sha256={e.sha256} prot={e.protection}"
    if e.req_size is not None:
        line += f" req_base={hex(e.req_base)} req_size={e.req_size} req_sha256={e.req_sha256}"
    if e.data is not None:
        line += f" captured={len(e.data)}"
    return line


def trace_lines(obs: Observation) -> list[str]:
    return [event_line(e) for e in obs.events]


def trace_text(obs: Observation) -> str:
    return "\n".join(trace_lines(obs))


def output_text(obs: Observation) -> str | None:
    """The observed execution's captured stdout + STDERR_MARK + stderr, or None when the document carries no output."""
    if obs.output is None:
        return None
    return (obs.output.stdout.decode("utf-8", "replace") + STDERR_MARK
            + obs.output.stderr.decode("utf-8", "replace"))


def lines_for(events: Iterable[Event]) -> list[str]:
    return [event_line(e) for e in events]


def nonzero_extent(data: bytes) -> int:
    """Length up to and including the last non-zero byte (a page holding a short payload ends in zeros)."""
    return len(data.rstrip(b"\0"))


def suggest_lines(obs: Observation, quote: str, k: int = 3) -> list[str]:
    """Trace lines that share words with a failed quote (best first); the first lines if none does."""
    lines = trace_lines(obs)
    words = {w.lower() for w in _WORD.findall(quote)}
    scored = sorted(((sum(w in ln.lower() for w in words), -i, ln) for i, ln in enumerate(lines)), reverse=True)
    best = [ln for score, _, ln in scored[:k] if score > 0]
    return best or lines[:k]
