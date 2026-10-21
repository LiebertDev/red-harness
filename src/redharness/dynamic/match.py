"""Compares the observed trace with known expected values (pure function; does not run the target).

`check_api_sequence`: is the expected API name list equal to the observed one, in EXACT order and preserving repeats? The
verdict is three-valued: `match` | `mismatch` | `unknown`. If coverage is incomplete (api_trace channel not complete, events were
dropped, or timeout) the result is `unknown`; an incomplete observation never counts as `match` or "clean".

`caller` (rh.dynamic/2 only): keep only calls made from that origin (`image` = main image, `dynamic` = unpacked or
generated code in private/mapped memory).

`check_api_subsequence`: do the expected names appear in the observed trace IN ORDER (other calls may be interleaved, repeats count)?
Observed events are real; if coverage is incomplete ONLY a found subsequence is valid (`match`), a missing one is `unknown`
(missing events do not count as absence); when coverage is complete a missing one is `mismatch`.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Sequence

from .model import MemoryEvent, Observation


@dataclass(frozen=True)
class SequenceCheck:
    verdict: str                          # match | mismatch | unknown
    reason: str
    observed: tuple[str, ...]
    first_divergence: int | None = None   # first differing position (mismatch only)
    missing: tuple[str, ...] = ()
    extra: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.verdict == "match"


def check_api_sequence(obs: Observation, expected: Sequence[str], *, module: str | None = None,
                       only_target: bool = True, caller: str | None = None) -> SequenceCheck:
    observed = tuple(e.api for e in obs.api_calls(module=module, only_target=only_target, caller=caller))
    if "api_trace" not in obs.channels_requested:
        return SequenceCheck("unknown", "api_trace channel was not requested", observed)
    if obs.timed_out or obs.dropped_events or obs.coverage.get("api_trace") != "complete":
        return SequenceCheck("unknown", f"api_trace coverage is not complete ({obs.coverage.get('api_trace')}, "
                             f"dropped events {obs.dropped_events}, timed out {obs.timed_out})", observed)
    want = tuple(expected)
    if observed == want:
        return SequenceCheck("match", "exact match", observed)
    div = next((i for i, (a, b) in enumerate(zip(observed, want)) if a != b), min(len(observed), len(want)))
    co, cw = Counter(observed), Counter(want)
    return SequenceCheck("mismatch", "order/count differs", observed, div, tuple(sorted((cw - co).elements())),
                         tuple(sorted((co - cw).elements())))


def check_api_subsequence(obs: Observation, expected: Sequence[str], *, module: str | None = None,
                          only_target: bool = True, caller: str | None = None) -> SequenceCheck:
    observed = tuple(e.api for e in obs.api_calls(module=module, only_target=only_target, caller=caller))
    if "api_trace" not in obs.channels_requested:
        return SequenceCheck("unknown", "api_trace channel was not requested", observed)
    want = tuple(expected)
    it = iter(observed)
    found = bool(want) and all(any(a == w for a in it) for w in want)  # `it` is shared, so order is preserved
    if found:
        return SequenceCheck("match", "expected names found in order (as a subsequence)", observed)
    if obs.timed_out or obs.dropped_events or obs.coverage.get("api_trace") != "complete":
        return SequenceCheck("unknown", f"subsequence not found and api_trace coverage is not complete "
                             f"({obs.coverage.get('api_trace')}, dropped events {obs.dropped_events}, "
                             f"timed out {obs.timed_out}): missing events do not count as absence", observed)
    return SequenceCheck("mismatch", "expected names not found in order", observed)


def find_dumps(obs: Observation, sha256: str, *, size: int | None = None) -> list[MemoryEvent]:
    """Memory dumps with the given digest (for unpacking measurement). Incomplete coverage does not decide here; the caller
    checks `obs.coverage['memory']`."""
    return [e for e in obs.memory_events() if e.sha256 == sha256 and (size is None or e.size == size)]
