"""Dynamic observation backend interface (backend-independent). The first real backend is `rhtrace.py`(own
Win32 Debug API tracer); `fake.py` is the test double.

Contract (kept small):
- `observe(request)`: runs the target in an isolated environment with the REQUESTED case (argv/stdin) and returns the observed events.
- What it returns is the raw bytes of a SEALED observation document (like a file the guest writes to its output folder). The host
  treats it as untrusted input and verifies it with `ingest.ingest_observation` (seal + identity); the backend's own
  claims are not trusted.
- The backend must report everything it did not see or could not capture as `partial`/`unknown` in `coverage`; if it dropped
  events it must write `dropped_events` > 0. "No events" vs "no observation" is distinguished by the coverage field.
- Real backends run only inside Windows Sandbox, in the same isolation as the target (user-mode dynamic observation); this module
  NEVER runs the target on the host.
- A backend with `in_session = True` (rhtrace) is driven by run_controlled: it gives an `ObservePlan` (`plan()`), the
  observed execution runs in the SAME sandbox session as the plain one, and `observe()` gets the verified captured
  output in `request.capture`. Other backends (the fake) ignore `capture`.
- `seal_nonce` is the session's one-time dynamic seal key (host only); a backend that has no nonce of its own seals with it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .model import CHANNELS, RunIdentity

ARCHS = ("x64", "x86")


@dataclass(frozen=True)
class ObservationRequest:
    identity: RunIdentity
    target_path: str                       # target path inside the guest (not a host path)
    argv: tuple[str, ...] = ()
    stdin_sha256: str = ""                 # SHA-256 of the stdin bytes given to the target (same definition as run_controlled)
    channels: tuple[str, ...] = CHANNELS
    timeout_s: float = 30.0
    max_events: int = 100_000
    memory_dump_bytes: int = 0             # 0 = digest the whole region (capped); N = digest of the first N bytes
    memory_capture_bytes: int = 0          # bytes of each created/changed executable region returned (0 = digests only)
    arch: str = "x64"                      # target architecture (x64 | x86): the in-session backend picks its tool by it
    seal_nonce: str = field(default="", repr=False, compare=False)
    capture: Any = field(default=None, repr=False, compare=False)   # in-session backends: verified CaseResult

    def __post_init__(self):
        object.__setattr__(self, "argv", tuple(self.argv))
        if not self.channels or any(c not in CHANNELS for c in self.channels):
            raise ValueError("channels must be a subset of CHANNELS")
        if (isinstance(self.memory_dump_bytes, bool) or not isinstance(self.memory_dump_bytes, int)
                or not 0 <= self.memory_dump_bytes <= 1 << 20):
            raise ValueError("memory_dump_bytes must be 0..1048576")
        if (isinstance(self.memory_capture_bytes, bool) or not isinstance(self.memory_capture_bytes, int)
                or not 0 <= self.memory_capture_bytes <= 1 << 18):
            raise ValueError("memory_capture_bytes must be 0..262144")
        if self.arch not in ARCHS:
            raise ValueError(f"arch must be one of {ARCHS}")


class BackendUnavailable(RuntimeError):
    """The backend cannot run (tracer binary missing or not matching its pin, or not part of this build): nothing runs
    (`DYNAMIC_BACKEND_UNAVAILABLE`)."""


@runtime_checkable
class DynamicBackend(Protocol):
    name: str
    version: str

    def observe(self, request: ObservationRequest) -> bytes:
        """Bytes of the sealed observation document. Raises on failure; never returns a silent empty document."""
        ...
