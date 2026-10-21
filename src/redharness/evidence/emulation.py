"""`emulate` evidence (authority=`cpu-emulation`, confidence=`derived`): record checks for the verifier.

An emulation record is an observation of CPU EMULATION of the target's own code (docs/design/emulation.md): it backs a
value only in an `observation` + `present` claim (SUPPORTED at most, `support: emulation`), never a behavior claim or
PROVEN. The generic checks (id recomputed, raw blob re-hashed, subject SHA) run first; this module checks that the
record is what the `emulate` tool writes: a deterministic return (version 20: or, for a code range with `end` in its
request, a deterministic arrival at `end`), no native execution, the request recorded.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from .model import EMULATION_AUTHORITY

REQUIRED_PARAMS = ("function", "arch", "convention", "args", "outputs", "max_instructions", "timeout_ms",
                   "stack_size", "layout_version", "emulator")


def is_emulation(rec: Mapping[str, Any] | None) -> bool:
    return bool(rec) and rec.get("authority") == EMULATION_AUTHORITY


def validate_record(rec: Mapping[str, Any], cas: Any = None) -> list[tuple[str, str]]:
    """Problems that make the record unusable (code, detail); empty list = consistent."""
    bad: list[tuple[str, str]] = []
    p = rec.get("parameters") or {}
    res = rec.get("result") if isinstance(rec.get("result"), Mapping) else {}
    if rec.get("result_blob_sha256") and cas is not None:
        try:
            res = json.loads(cas.get(rec["result_blob_sha256"]).decode("utf-8"))
        except Exception:  # noqa: BLE001 - an unreadable result is an invalid record, never a pass
            res = {}
    env = rec.get("environment") or {}
    cap = rec.get("capture") or {}
    if rec.get("operation") != "emulate" or (rec.get("source") or {}).get("tool") != "emulate":
        bad.append(("EMULATION_RECORD_INVALID", "not an emulate record"))
    if rec.get("confidence") != "derived" or env.get("native_execution") is not False:
        bad.append(("EMULATION_RECORD_INVALID", "an emulation record is derived and never native execution"))
    missing = [k for k in REQUIRED_PARAMS if k not in p]
    if missing:
        bad.append(("EMULATION_RECORD_INVALID", f"request not recorded (missing {', '.join(missing)})"))
    if cap.get("status") != "OK" or cap.get("truncated") or cap.get("timed_out"):
        bad.append(("EMULATION_RECORD_INVALID", "not a complete emulation"))
    # version 20: a code range (parameters.end) ends with stop=range_end; a function call ends with stop=return. The
    # stop must match the request: a range record without `end`, or a call record that did not return, is invalid.
    want = "range_end" if "end" in p else "return"
    if not isinstance(res, Mapping) or res.get("stop") != want or res.get("deterministic") is not True:
        bad.append(("EMULATION_RECORD_INVALID", "only a deterministic return to the caller (or, for a code range, "
                                                "a deterministic arrival at its end address) is a result"))
    return bad
