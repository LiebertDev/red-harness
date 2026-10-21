"""User-mode dynamic observation document (`rh.dynamic/1`): identity, events, coverage and strict parsing.

An observation is bound to ONE sandbox run (run_id), ONE target (SHA-256) and ONE scope manifest (its digest);
this triple (`RunIdentity`) is carried inside the document and the seal (seal.py) covers it too. So an observation cannot be
moved to another target or run and replayed.

Coverage rule: missing/uncertain coverage is `unknown`, never "clean". `complete` may be reported only for a requested channel
and only if no events were dropped (dropped_events == 0); otherwise it is a contradiction in the document and the document is rejected.
The document contains no floats (canonical JSON and evidence id rule); addresses are `0x...` hex strings.

Schema versions: `rh.dynamic/1` (fake backend) and `rh.dynamic/2` (real backend `rhtrace`).
Memory events may also carry (optional, rh.dynamic/2): `req_base`/`req_size`/`req_sha256` = the exact range the target
asked for in the call that made the region executable (before page rounding) and its SHA-256, and `bytes_hex` = the
captured head of the region (bytes). A document that carries bytes must agree with its own digests (checked at parse).
Version 2 adds the call ORIGIN to every `api_call` event (`caller`: image = the target's main image, dynamic = private/
mapped executable memory, i.e. unpacked or generated code; `from_target` must equal caller in {image, dynamic}) and a
`resolve` event (a GetProcAddress call from target code: requested name, module, returned address or null). Version 1
documents parse exactly as before.
Optional `output` (rh.dynamic/2): the observed execution's own stdout/stderr as the tracer captured them (hex of the
first bytes, plus the total byte counts), so accept/reject under the tracer can be read and quoted. Documents without it
parse exactly as before.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from ..core.journal import canonical, sha256_hex

SCHEMA = "rh.dynamic/1"
SCHEMA_V2 = "rh.dynamic/2"
SCHEMAS = (SCHEMA, SCHEMA_V2)
CHANNELS = ("api_trace", "memory")
CALLERS = ("image", "dynamic", "system", "unknown")
TARGET_CALLERS = ("image", "dynamic")
COVERAGE = ("complete", "partial", "unknown")
MEMORY_KINDS = ("dump", "exec_transition")
MAX_DOC_BYTES = 8 << 20
MAX_CAPTURE_REGION = 1 << 18      # bytes captured per memory event (host limit; the tracer takes the cap as an argument)
MAX_EVENTS = 100_000
MAX_OUTPUT_BYTES = 1 << 16        # captured target output per stream in a document (the tracer keeps 32 KiB)
_SHA = re.compile(r"[0-9a-f]{64}")
_RUN_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_HEXADDR = re.compile(r"0x[0-9a-f]{1,16}")
_PROT = re.compile(r"[A-Z-]{1,8}")
_MEM_KEYS = frozenset({"seq", "type", "tid", "kind", "base", "size", "sha256", "protection"})
_MEM_REQ = frozenset({"req_base", "req_size", "req_sha256"})
_BODY_KEYS = frozenset({"schema", "identity", "backend", "input", "outcome", "channels_requested", "coverage",
                        "dropped_events", "events"})


class ObservationError(ValueError):
    """The observation document does not match the schema or contradicts itself. `code` is a stable reason code."""

    def __init__(self, message: str, code: str = "DYNAMIC_OBSERVATION_INVALID"):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- identity

def scope_digest(scope: Any) -> str:
    """Identity of the scope manifest: SHA-256 of the canonical JSON of `ScopeManifest.to_summary()` (path excluded)."""
    return sha256_hex(canonical(scope.to_summary()))


@dataclass(frozen=True)
class RunIdentity:
    run_id: str
    target_sha256: str
    scope_sha256: str

    def __post_init__(self):
        if not isinstance(self.run_id, str) or not _RUN_ID.fullmatch(self.run_id):
            raise ValueError("run_id invalid")
        for f in ("target_sha256", "scope_sha256"):
            v = getattr(self, f)
            if not isinstance(v, str) or not _SHA.fullmatch(v):
                raise ValueError(f"{f} must be 64 lowercase hex characters")

    @classmethod
    def from_scope(cls, run_id: str, target_sha256: str, scope: Any) -> "RunIdentity":
        """The scope must belong to the target and grant `run_controlled` (dynamic observation is an execution)."""
        if scope.target_sha256 != target_sha256:
            raise ValueError("scope manifest belongs to another target")
        if not scope.allows("run_controlled"):
            raise ValueError("scope manifest does not allow run_controlled")
        return cls(run_id, target_sha256, scope_digest(scope))

    def to_dict(self) -> dict:
        return {"run_id": self.run_id, "target_sha256": self.target_sha256, "scope_sha256": self.scope_sha256}


# ---------------------------------------------------------------- events

@dataclass(frozen=True)
class ApiCallEvent:
    seq: int
    tid: int
    module: str          # e.g. kernel32.dll
    api: str             # e.g. CreateFileW
    from_target: bool    # whether the call comes from the target's own code (not loader/system internal calls)
    caller: str | None = None   # rh.dynamic/2 only: image | dynamic | system | unknown (origin of the call)

    def to_dict(self) -> dict:
        d = {"seq": self.seq, "type": "api_call", "tid": self.tid, "module": self.module, "api": self.api,
             "from_target": self.from_target}
        if self.caller is not None:
            d["caller"] = self.caller
        return d


@dataclass(frozen=True)
class ResolveEvent:
    """rh.dynamic/2: a GetProcAddress call made by target code and what it returned (None = NULL / not resolved)."""
    seq: int
    tid: int
    module: str          # module the target asked for (by handle), e.g. kernel32.dll
    api: str             # requested name, or "#<ordinal>"
    address: int | None
    caller: str          # image | dynamic

    def to_dict(self) -> dict:
        return {"seq": self.seq, "type": "resolve", "tid": self.tid, "module": self.module, "api": self.api,
                "address": None if self.address is None else hex(self.address), "caller": self.caller}


@dataclass(frozen=True)
class MemoryEvent:
    seq: int
    tid: int
    kind: str            # dump | exec_transition (region became executable: unpacking candidate)
    base: int
    size: int
    sha256: str          # SHA-256 of the `size` bytes taken from the region (page granular, or `memory_dump_bytes`)
    protection: str      # e.g. RX, RW
    req_base: int | None = None     # range the target asked for (NtProtect/NtAllocate arguments, not page rounded)
    req_size: int | None = None
    req_sha256: str | None = None   # SHA-256 of exactly [req_base, req_base + req_size)
    data: bytes | None = None       # captured head of the region, starting at `base` (None = not captured)

    def to_dict(self) -> dict:
        d = {"seq": self.seq, "type": "memory", "tid": self.tid, "kind": self.kind, "base": hex(self.base),
             "size": self.size, "sha256": self.sha256, "protection": self.protection}
        if self.req_size is not None:
            d.update(req_base=hex(self.req_base), req_size=self.req_size, req_sha256=self.req_sha256)
        if self.data is not None:
            d["bytes_hex"] = self.data.hex()
        return d

    def slice(self, offset: int, length: int) -> bytes | None:
        """`length` captured bytes at `offset` from the region base, or None if they were not all captured."""
        if self.data is None or offset < 0 or length < 1 or offset + length > len(self.data):
            return None
        return self.data[offset:offset + length]


@dataclass(frozen=True)
class TargetOutput:
    """The observed execution's stdout/stderr: the first captured bytes and the total counts (untrusted target data)."""
    stdout: bytes
    stderr: bytes
    stdout_bytes: int          # total bytes the target wrote (>= len(stdout))
    stderr_bytes: int
    drained: bool = True       # False: a stream was still open when the tracer stopped reading (counts may lag)

    @property
    def truncated(self) -> bool:
        return len(self.stdout) < self.stdout_bytes or len(self.stderr) < self.stderr_bytes or not self.drained

    def to_dict(self) -> dict:
        return {"stdout_hex": self.stdout.hex(), "stderr_hex": self.stderr.hex(), "stdout_bytes": self.stdout_bytes,
                "stderr_bytes": self.stderr_bytes, "drained": self.drained}


@dataclass(frozen=True)
class Observation:
    identity: RunIdentity
    backend_name: str
    backend_version: str
    argv: tuple[str, ...]
    stdin_sha256: str
    exit_code: int | None
    timed_out: bool
    channels_requested: tuple[str, ...]
    coverage: Mapping[str, str]          # complete|partial|unknown per channel (unrequested channel: unknown)
    dropped_events: int
    events: tuple[ApiCallEvent | MemoryEvent | ResolveEvent, ...]
    schema: str = SCHEMA
    output: TargetOutput | None = None   # rh.dynamic/2 only, optional

    def api_calls(self, *, module: str | None = None, only_target: bool = True,
                  caller: str | None = None) -> list[ApiCallEvent]:
        out = [e for e in self.events if isinstance(e, ApiCallEvent)]
        if only_target:
            out = [e for e in out if e.from_target]
        if module is not None:
            out = [e for e in out if e.module.lower() == module.lower()]
        if caller is not None:
            out = [e for e in out if e.caller == caller]
        return out

    def resolves(self) -> list[ResolveEvent]:
        return [e for e in self.events if isinstance(e, ResolveEvent)]

    def memory_events(self) -> list[MemoryEvent]:
        return [e for e in self.events if isinstance(e, MemoryEvent)]

    @property
    def fully_covered(self) -> bool:
        """EVERY requested channel is complete, no events dropped and no timeout. Otherwise the observation is incomplete (unknown)."""
        return (not self.timed_out and self.dropped_events == 0
                and all(self.coverage.get(c) == "complete" for c in self.channels_requested))

    def to_body(self) -> dict:
        body = {"schema": self.schema, "identity": self.identity.to_dict(),
                "backend": {"name": self.backend_name, "version": self.backend_version},
                "input": {"argv": list(self.argv), "stdin_sha256": self.stdin_sha256},
                "outcome": {"exit_code": self.exit_code, "timed_out": self.timed_out},
                "channels_requested": list(self.channels_requested),
                "coverage": {c: self.coverage.get(c, "unknown") for c in CHANNELS},
                "dropped_events": self.dropped_events, "events": [e.to_dict() for e in self.events]}
        if self.output is not None:
            body["output"] = self.output.to_dict()
        return body


def body_digest(body: Mapping[str, Any]) -> str:
    """Canonical JSON SHA-256 of the observation body (EXCLUDING the integrity block)."""
    return sha256_hex(canonical(body))


# ---------------------------------------------------------------- strict parsing

def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise ObservationError(msg)


def _int(v: Any, lo: int = 0) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= lo


def _str(v: Any, maxlen: int = 260) -> bool:
    return isinstance(v, str) and 0 < len(v) <= maxlen


def _memory_event(i: int, e: dict) -> MemoryEvent:
    """Optional request range and captured bytes of a memory event; the digests must agree with the bytes."""
    base, size = int(e["base"], 16), e["size"]
    req = (None, None, None)
    if "req_size" in e:
        _need(isinstance(e["req_base"], str) and _HEXADDR.fullmatch(e["req_base"]) and _int(e["req_size"], 1)
              and isinstance(e["req_sha256"], str) and _SHA.fullmatch(e["req_sha256"]), f"events[{i}] req malformed")
        req = (int(e["req_base"], 16), e["req_size"], e["req_sha256"])
    data = None
    if "bytes_hex" in e:
        h = e["bytes_hex"]
        _need(isinstance(h, str) and h and len(h) % 2 == 0 and len(h) // 2 <= MAX_CAPTURE_REGION
              and re.fullmatch(r"[0-9a-f]+", h), f"events[{i}] bytes malformed")
        data = bytes.fromhex(h)
        _need(len(data) <= size, f"events[{i}]: {len(data)} captured bytes exceed the declared size {size}")
        if len(data) >= size:
            _need(hashlib.sha256(data[:size]).hexdigest() == e["sha256"], f"events[{i}]: bytes do not match the digest")
        if req[1] is not None and req[0] >= base and req[0] - base + req[1] <= len(data):
            _need(hashlib.sha256(data[req[0] - base:req[0] - base + req[1]]).hexdigest() == req[2],
                  f"events[{i}]: bytes do not match the requested-range digest")
    return MemoryEvent(i, e["tid"], e["kind"], base, size, e["sha256"], e["protection"], req[0], req[1], req[2], data)


def _output(o: Any) -> TargetOutput:
    _need(isinstance(o, dict) and set(o) == {"stdout_hex", "stderr_hex", "stdout_bytes", "stderr_bytes", "drained"}
          and isinstance(o["drained"], bool), "output malformed")
    data = []
    for k in ("stdout", "stderr"):
        h, n = o[k + "_hex"], o[k + "_bytes"]
        _need(isinstance(h, str) and len(h) % 2 == 0 and len(h) // 2 <= MAX_OUTPUT_BYTES
              and (not h or re.fullmatch(r"[0-9a-f]+", h)) and _int(n) and len(h) // 2 <= n,
              f"output.{k} malformed or longer than its byte count")
        data.append(bytes.fromhex(h))
    return TargetOutput(data[0], data[1], o["stdout_bytes"], o["stderr_bytes"], o["drained"])


def parse_body(body: Any) -> Observation:
    """Strictly parses the body (integrity block removed); every contradiction raises ObservationError."""
    _need(isinstance(body, dict), "observation must be an object")
    _need(set(body) in (_BODY_KEYS, _BODY_KEYS | {"output"}), "observation fields do not match the schema exactly")
    _need(body["schema"] in SCHEMAS, f"schema must be one of {', '.join(SCHEMAS)}")
    v2 = body["schema"] == SCHEMA_V2
    _need(v2 or "output" not in body, "output needs schema rh.dynamic/2")
    output = _output(body["output"]) if "output" in body else None
    ident = body["identity"]
    _need(isinstance(ident, dict) and set(ident) == {"run_id", "target_sha256", "scope_sha256"}, "identity malformed")
    try:
        identity = RunIdentity(ident["run_id"], ident["target_sha256"], ident["scope_sha256"])
    except ValueError as e:
        raise ObservationError(f"identity: {e}") from e
    be = body["backend"]
    _need(isinstance(be, dict) and set(be) == {"name", "version"} and _str(be["name"], 64)
          and isinstance(be["version"], str) and len(be["version"]) <= 64, "backend malformed")
    inp = body["input"]
    _need(isinstance(inp, dict) and set(inp) == {"argv", "stdin_sha256"}, "input malformed")
    _need(isinstance(inp["argv"], list) and len(inp["argv"]) <= 64 and all(isinstance(a, str) for a in inp["argv"]),
          "input.argv malformed")
    _need(isinstance(inp["stdin_sha256"], str) and _SHA.fullmatch(inp["stdin_sha256"]), "input.stdin_sha256 malformed")
    out = body["outcome"]
    _need(isinstance(out, dict) and set(out) == {"exit_code", "timed_out"}, "outcome malformed")
    ec = out["exit_code"]
    _need(ec is None or (isinstance(ec, int) and not isinstance(ec, bool)), "outcome.exit_code must be an integer/null")
    _need(isinstance(out["timed_out"], bool), "outcome.timed_out must be bool")
    req = body["channels_requested"]
    _need(isinstance(req, list) and req and all(c in CHANNELS for c in req) and len(set(req)) == len(req),
          "channels_requested must be a subset of CHANNELS")
    cov = body["coverage"]
    _need(isinstance(cov, dict) and set(cov) == set(CHANNELS) and all(v in COVERAGE for v in cov.values()),
          "coverage must give complete|partial|unknown for every channel")
    dropped = body["dropped_events"]
    _need(_int(dropped), "dropped_events must be an integer")
    for c in CHANNELS:
        if c not in req:
            _need(cov[c] == "unknown", f"coverage must be unknown for unrequested channel ({c})")
        if cov[c] == "complete":
            _need(dropped == 0, "coverage cannot be complete if events were dropped")
            _need(not out["timed_out"], "coverage cannot be complete on timeout")
    raw_events = body["events"]
    _need(isinstance(raw_events, list) and len(raw_events) <= MAX_EVENTS, "events malformed or too long")
    events: list[ApiCallEvent | MemoryEvent | ResolveEvent] = []
    api_keys = {"seq", "type", "tid", "module", "api", "from_target"} | ({"caller"} if v2 else set())
    for i, e in enumerate(raw_events):
        _need(isinstance(e, dict) and e.get("seq") == i and _int(e.get("tid")), f"events[{i}]: seq is not consecutive")
        t = e.get("type")
        if t == "api_call":
            _need(set(e) == api_keys and _str(e["module"])
                  and _str(e["api"], 256) and isinstance(e["from_target"], bool), f"events[{i}] malformed")
            caller = e.get("caller")
            if v2:
                _need(caller in CALLERS and e["from_target"] == (caller in TARGET_CALLERS),
                      f"events[{i}]: caller must be one of {CALLERS} and agree with from_target")
            events.append(ApiCallEvent(i, e["tid"], e["module"], e["api"], e["from_target"], caller))
        elif t == "resolve" and v2:
            _need(set(e) == {"seq", "type", "tid", "module", "api", "address", "caller"} and _str(e["module"])
                  and _str(e["api"], 256) and e["caller"] in TARGET_CALLERS
                  and (e["address"] is None or (isinstance(e["address"], str) and _HEXADDR.fullmatch(e["address"]))),
                  f"events[{i}] malformed")
            events.append(ResolveEvent(i, e["tid"], e["module"], e["api"],
                                       None if e["address"] is None else int(e["address"], 16), e["caller"]))
        elif t == "memory":
            opt = set(e) - _MEM_KEYS
            _need(_MEM_KEYS <= set(e) and opt in (set(), _MEM_REQ, {"bytes_hex"}, _MEM_REQ | {"bytes_hex"})
                  and e["kind"] in MEMORY_KINDS and isinstance(e["base"], str) and _HEXADDR.fullmatch(e["base"])
                  and _int(e["size"], 1) and isinstance(e["sha256"], str) and _SHA.fullmatch(e["sha256"])
                  and isinstance(e["protection"], str) and _PROT.fullmatch(e["protection"]),
                  f"events[{i}] malformed")
            events.append(_memory_event(i, e))
        else:
            raise ObservationError(f"events[{i}]: unknown type")
    return Observation(identity, be["name"], be["version"], tuple(inp["argv"]), inp["stdin_sha256"], ec,
                       out["timed_out"], tuple(req), dict(cov), dropped, tuple(events), body["schema"], output)


def split_document(doc_bytes: bytes) -> tuple[dict, dict]:
    """(body, integrity block) from the raw document bytes. ObservationError if not JSON / too large / block missing."""
    if not isinstance(doc_bytes, (bytes, bytearray)) or len(doc_bytes) > MAX_DOC_BYTES:
        raise ObservationError("observation document bytes missing or too large")
    try:
        doc = json.loads(bytes(doc_bytes).decode("utf-8"), parse_float=_no_float)
    except (ValueError, UnicodeDecodeError) as e:
        raise ObservationError(f"observation document is not JSON: {e}") from e
    if not isinstance(doc, dict) or not isinstance(doc.get("integrity"), dict):
        raise ObservationError("observation document has no integrity block (unsealed)", "DYNAMIC_INTEGRITY")
    body = {k: v for k, v in doc.items() if k != "integrity"}
    return body, doc["integrity"]


def _no_float(s: str) -> Any:
    raise ValueError("no floats")


def load_observation(doc_bytes: bytes) -> Observation:
    """Parses WITHOUT verifying the seal (for reading/matching only; use ingest for trust)."""
    return parse_body(split_document(doc_bytes)[0])


def active_channels(req: Iterable[str]) -> tuple[str, ...]:
    return tuple(c for c in CHANNELS if c in set(req))
