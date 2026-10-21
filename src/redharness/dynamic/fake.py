"""Deterministic fake backend (tests only): builds an observation document from a script and seals it with the nonce.

Stands in for a real guest wrapper: it is the only party that knows the nonce. It has settings for forgery/tampering scenarios
(unsealed, wrong nonce, dropped events, timeout). Does NOT run the target.
"""

from __future__ import annotations

import hashlib
from typing import Sequence

from .backend import ObservationRequest
from .model import CHANNELS, ApiCallEvent, MemoryEvent, Observation, active_channels
from .seal import document_bytes, seal_body


class FakeDynamicBackend:
    name = "fake"
    version = "1"

    def __init__(self, nonce: str, *, api_calls: Sequence[str | tuple[str, bool]] = (), module: str = "kernel32.dll",
                 dumps: Sequence[tuple] = (), exit_code: int | None = 0,
                 timed_out: bool = False, dropped_events: int = 0, coverage: dict[str, str] | None = None,
                 identity_override=None, seal: bool = True):
        """api_calls: name or (name, from_target). dumps: (base, content, kind, protection[, (req_offset, req_size)]);
        `content` is the whole region (page), the optional pair the range the target asked for. The region head is
        returned as bytes when the request asks for `memory_capture_bytes` (like the real tracer)."""
        self.nonce, self.api_calls, self.module, self.dumps = nonce, tuple(api_calls), module, tuple(dumps)
        self.exit_code, self.timed_out, self.dropped = exit_code, timed_out, dropped_events
        self.coverage_override, self.identity_override, self.seal = coverage, identity_override, seal
        self.requests: list[ObservationRequest] = []

    def observation(self, request: ObservationRequest) -> Observation:
        events: list[ApiCallEvent | MemoryEvent] = []
        for item in self.api_calls:
            name, mine = (item, True) if isinstance(item, str) else item
            events.append(ApiCallEvent(len(events), 1, self.module, name, mine))
        for base, content, kind, prot, *rest in self.dumps:
            req = (None, None, None)
            if rest:
                off, n = rest[0]
                req = (base + off, n, hashlib.sha256(content[off:off + n]).hexdigest())
            cap = request.memory_capture_bytes if "memory" in request.channels else 0
            data = content[:cap] if cap else None
            events.append(MemoryEvent(len(events), 1, kind, base, len(content),
                                      hashlib.sha256(content).hexdigest(), prot, *req, data))
        full = self.dropped == 0 and not self.timed_out
        cov = {c: ("unknown" if c not in request.channels else ("complete" if full else "partial"))
               for c in CHANNELS}
        cov.update(self.coverage_override or {})
        return Observation(self.identity_override or request.identity, self.name, self.version, request.argv,
                           request.stdin_sha256, self.exit_code, self.timed_out, active_channels(request.channels),
                           cov, self.dropped, tuple(events))

    def observe(self, request: ObservationRequest) -> bytes:
        self.requests.append(request)
        body = self.observation(request).to_body()
        if not self.seal:
            return document_bytes(body)
        return document_bytes(seal_body(body, self.nonce or request.seal_nonce))
