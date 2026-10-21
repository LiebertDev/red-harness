"""`compute` evidence (authority=`sandboxed-computation`, confidence=`derived`): input binding and verifier checks.

Meaning (docs/design/compute-tool.md §5, evidence-schema.md §4.8): compute evidence is the fact that "THIS code, with THESE inputs,
on THIS interpreter produced this output"; it says nothing about what the target does. Therefore:
- Inputs come only from evidence in this job's ledger. Explicit forms: the whole raw output (`raw: true`), a quote appearing
  VERBATIM in the raw output (`quote`, >= 4 characters), a constant numerically EQUAL to one in the raw output (`const`), or (version
  11, the easy path) a byte range of a `read_bytes` evidence (`{evidence_id, select?}`, kind `range`: the tool resolves the bytes
  from the ledger). The record holds each input's evidence id, kind and SHA-256; the verifier re-derives the input from the
  evidence and compares the digest.
- Auto-binding (version 11): a pasted literal (`{hex}`) whose bytes EXACTLY equal a contiguous region of a `read_bytes`
  evidence of this job is recorded as an `auto` `range` binding to that evidence id and address. The verifier treats it exactly
  like an explicit `range` (it only re-derives the bytes and compares SHA-256). A literal that matches nothing stays an unbound
  `literal` (no evidence id): the claim stays UNVERIFIED (`VALUE_COMPUTE_NOT_BOUND`). No fuzzy / partial / cross-segment
  matching; only static (`shipped-artifact`) `read_bytes` evidence of the same target counts.
- Value support exists only in an `observation` + `present` claim and only with a BOUND compute evidence: deterministic (two runs
  byte-for-byte identical), complete (untruncated, no timeout, exit 0), isolated, and with ALL inputs from `shipped-artifact`
  (static target) evidence cited in the claim. A supported value carries `"support":"computation"`; the claim becomes at most
  SUPPORTED (same ceiling as the derivation atom, §4.7.2). It supports nothing for a behavior claim or for PROVEN.
- Dynamic memory bytes (version 13): `{evidence_id, select:{event, offset|address, length}}` on a `dynamic-observation`
  evidence hands the code bytes the tracer captured from an executable region (`kind=memrange`; the record keeps the
  event, offset and SHA-256, the verifier re-derives them from the sealed document). Such an input is bound like a static
  one if that dynamic evidence is cited in the claim, but the ceiling does not move: only an observation + present
  claim, at most SUPPORTED, never behavior, never PROVEN (§4.6 and §4.8 are unchanged: a computation, and a single
  uncovered run, never proves what the program does).
- compute evidence cannot be a derivation leaf (a leaf is only `shipped-artifact`), nor the input of another compute.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping

from ..core.cas import Cas, CasError
from ..dynamic.model import MemoryEvent, ObservationError, load_observation
from .model import COMPUTE_AUTHORITY, DYNAMIC_AUTHORITY, derive_strength, evidence_id_ok

STATIC_AUTHORITY = "shipped-artifact"
MIN_QUOTE_LEN = 4
QUOTE_MAX = 4096
NAME_MAX = 32
INPUT_KINDS = ("raw", "quote", "const")             # explicit selectors of a spec (version 7)
MEMRANGE = "memrange"                               # bytes captured from an executable region of a dynamic observation
RECORD_KINDS = INPUT_KINDS + ("range", "literal", MEMRANGE)   # kinds a recorded binding can have (range/literal: 11, memrange: 13)
DYNAMIC_OPERATION = "dynamic_observe"
SPEC_KEYS = frozenset({"name", "evidence_id", "select", "hex", *INPUT_KINDS})
MIN_LITERAL_LEN = 4                                 # a pasted literal shorter than this is never auto-bound
BYTES_MAX = 1 << 20
DUMP_OPERATION = "read_bytes"

# read_bytes evidence text: `segment N FILE 0xS..0xE len=L ...`, rows `  0xADDR: aabbccdd_eeff...`, then `  -- view --` blocks
_SEG_FILE = re.compile(r"^segment \d+ FILE 0x([0-9a-f]+)\.\.0x([0-9a-f]+) len=(\d+) ")
_SEG_ANY = re.compile(r"^segment \d+ ")
_VIEW = re.compile(r"^\s+-- \w+ --$")
_ROW = re.compile(r"^\s+0x([0-9a-f]+): ([0-9a-f_]+)$")


class ComputeInputError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


def _valid_name(name: Any) -> bool:
    return (isinstance(name, str) and 0 < len(name) <= NAME_MAX and (name[0].isalpha() or name[0] == "_")
            and all(c.isascii() and (c.isalnum() or c == "_") for c in name))


def _const(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        from .values import numeric
        return numeric(value.strip())
    return None


def input_value_sha256(value: bytes | int) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else str(value).encode("ascii")).hexdigest()


def dump_regions(rec: Mapping[str, Any], raw: bytes) -> list[tuple[int, bytes]]:
    """Contiguous FILE byte regions `(start_va, bytes)` of a `read_bytes` evidence, decoded from its hex dump. Fail-closed: a
    segment whose rows are not exactly contiguous, or whose length does not match its header, is not a region."""
    if rec.get("operation") != DUMP_OPERATION:
        return []
    regions: list[tuple[int, bytes]] = []
    cur: list[Any] | None = None   # [start, end, length, chunks]
    live = False

    def close() -> None:
        if cur is not None and live:
            data = b"".join(cur[3])
            if len(data) == cur[2] == cur[1] - cur[0]:
                regions.append((cur[0], data))

    for ln in raw.decode("utf-8", "replace").split("\n"):
        m = _SEG_FILE.match(ln)
        if m:
            close()
            cur, live = [int(m.group(1), 16), int(m.group(2), 16), int(m.group(3)), []], True
            continue
        if _SEG_ANY.match(ln):
            close()
            cur, live = None, False
            continue
        if cur is None or not live:
            continue
        if _VIEW.match(ln):
            close()
            live = False
            continue
        m = _ROW.match(ln)
        groups = m.group(2).replace("_", "") if m else ""
        if not m or len(groups) % 2 or int(m.group(1), 16) != cur[0] + sum(len(c) for c in cur[3]):
            live = False   # unrecognized / non-contiguous row: this segment is not trusted
            continue
        cur[3].append(bytes.fromhex(groups))
    close()
    return regions


def _slice(regions: list[tuple[int, bytes]], va: int, length: int) -> bytes | None:
    for start, data in regions:
        if start <= va and va + length <= start + len(data):
            return data[va - start:va - start + length]
    return None


def _parse_select(select: Any, regions: list[tuple[int, bytes]], name: str) -> tuple[int, int]:
    """select -> (start VA, length). None / 'all': the whole region (only if the evidence has exactly one)."""
    if select is None or select == "all":
        if len(regions) != 1:
            raise ComputeInputError("BAD_ARGUMENT", f"input {name!r}: the evidence has {len(regions)} file segments; give "
                                    "select={'offset':N,'length':M} or {'address':'0x..','length':M}")
        return regions[0][0], len(regions[0][1])
    if (not isinstance(select, Mapping) or set(select) - {"offset", "address", "length"}
            or ("offset" in select) == ("address" in select)):
        raise ComputeInputError("BAD_ARGUMENT", f"input {name!r}: select = {{offset|address, length}} (a byte range)")
    n = select.get("length")
    if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= BYTES_MAX:
        raise ComputeInputError("BAD_ARGUMENT", f"input {name!r}: select.length must be an integer >= 1")
    if "address" in select:
        va = _const(select["address"])
        if va is None:
            raise ComputeInputError("BAD_ARGUMENT", f"input {name!r}: select.address must be 0x.. or a non-negative integer")
        return va, n
    off = select["offset"]
    if isinstance(off, bool) or not isinstance(off, int) or off < 0:
        raise ComputeInputError("BAD_ARGUMENT", f"input {name!r}: select.offset must be an integer >= 0 (into the file "
                                "bytes of the dump)")
    for start, data in regions:
        if off < len(data):
            return start + off, n
        off -= len(data)
    raise ComputeInputError("COMPUTE_INPUT_NOT_IN_RAW", f"input {name!r}: select.offset is past the end of the dump bytes")


def _memory_select(select: Any, rec: Mapping[str, Any], raw: bytes, name: str) -> tuple[MemoryEvent, int, bytes]:
    """select {event, offset|address, length} -> (event, offset from the region base, bytes) of a dynamic observation."""
    form = "select = {event: <seq of a memory event>, offset: N | address: '0x..', length: M} (offset from the region base)"
    try:
        events = [e for e in load_observation(raw).memory_events() if e.data]
    except ObservationError as e:
        raise ComputeInputError("COMPUTE_INPUT_MISMATCH", f"input {name!r}: the observation does not parse ({e})") from e
    have = ", ".join(f"event {e.seq}: base 0x{e.base:x}, {len(e.data)} bytes captured" for e in events[:8]) or "none"
    if not isinstance(select, Mapping) or set(select) - {"event", "offset", "address", "length"}             or ("offset" in select and "address" in select):
        raise ComputeInputError("BAD_ARGUMENT", f"input {name!r}: {form}")
    seq = select.get("event")
    if seq is None:
        if len(events) != 1:
            raise ComputeInputError("BAD_ARGUMENT", f"input {name!r}: give select.event; events with captured bytes: {have}")
        ev = events[0]
    else:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise ComputeInputError("BAD_ARGUMENT", f"input {name!r}: select.event must be the integer seq of a memory event")
        ev = next((e for e in events if e.seq == seq), None)
        if ev is None:
            raise ComputeInputError("COMPUTE_INPUT_NOT_IN_RAW", f"input {name!r}: event {seq} is not a memory event with "
                                    f"captured bytes in {rec.get('evidence_id')} (events with bytes: {have})")
    off = select.get("offset", 0)
    if "address" in select:
        va = _const(select["address"])
        if va is None or va < ev.base:
            raise ComputeInputError("BAD_ARGUMENT", f"input {name!r}: select.address must be 0x.. inside the region "
                                    f"(base 0x{ev.base:x})")
        off = va - ev.base
    if isinstance(off, bool) or not isinstance(off, int) or off < 0:
        raise ComputeInputError("BAD_ARGUMENT", f"input {name!r}: select.offset must be an integer >= 0")
    n = select.get("length", len(ev.data) - off)
    if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= BYTES_MAX:
        raise ComputeInputError("BAD_ARGUMENT", f"input {name!r}: select.length must be an integer >= 1")
    got = ev.slice(off, n)
    if got is None:
        raise ComputeInputError("COMPUTE_INPUT_NOT_IN_RAW", f"input {name!r}: bytes {off}..{off + n} of event {ev.seq} "
                                f"were not captured (captured {len(ev.data)} of the region's bytes; the page may be "
                                "larger: observe with a bigger memory_bytes)")
    return ev, off, got


def _parse_hex(h: Any, name: str) -> bytes:
    t = re.sub(r"[\s_]", "", h) if isinstance(h, str) else ""
    if not t or len(t) % 2 or len(t) // 2 > BYTES_MAX or not re.fullmatch(r"[0-9a-fA-F]+", t):
        raise ComputeInputError("BAD_ARGUMENT", f"input {name!r}: hex must be an even number of hex digits (spaces and _ "
                                "allowed, no 0x prefix)")
    return bytes.fromhex(t)


def _usable(eid: str, rec: Mapping[str, Any], invalidated: Mapping[str, Any] | None, job_sha: str | None) -> bool:
    return (not (invalidated and eid in invalidated) and evidence_id_ok(rec) and rec.get("authority") == STATIC_AUTHORITY
            and derive_strength(rec.get("capture") or {}) != "failed"
            and (job_sha is None or (rec.get("subject") or {}).get("sha256") == job_sha))


def find_literal(value: bytes, evidence: Mapping[str, Mapping[str, Any]], cas: Cas,
                 invalidated: Mapping[str, Any] | None = None, job_sha: str | None = None) -> tuple[str, int] | None:
    """EXACT byte equality of `value` with a contiguous region of a `read_bytes` evidence of this job (lowest evidence id
    first, first occurrence in it): `(evidence_id, start_va)` or None."""
    if len(value) < MIN_LITERAL_LEN:
        return None
    for eid in sorted(evidence):
        rec = evidence[eid]
        if rec.get("operation") != DUMP_OPERATION or not _usable(eid, rec, invalidated, job_sha):
            continue
        try:
            regions = dump_regions(rec, cas.get(rec["raw"]["blob_sha256"]))
        except (CasError, KeyError, TypeError):
            continue
        for start, data in regions:
            i = data.find(value)
            if i >= 0:
                return eid, start + i
    return None


def resolve_input(spec: Mapping[str, Any], evidence: Mapping[str, Mapping[str, Any]], cas: Cas,
                  invalidated: Mapping[str, Any] | None = None, *, job_sha: str | None = None,
                  index: int = 0) -> tuple[dict, bytes | int]:
    """Model input -> (binding record to write into the evidence, value to give the code). Error: ComputeInputError.

    Forms: `{evidence_id, select?}` (byte range of a read_bytes evidence; for other evidence = raw), `{evidence_id, raw:true |
    quote:'..' | const:0x..}`, `{hex:'..'}` (pasted literal; auto-bound if it exactly equals a read_bytes region). `name` is
    optional (default `in<index>`)."""
    if not isinstance(spec, Mapping):
        raise ComputeInputError("BAD_ARGUMENT", "each input must be an object")
    kinds = [k for k in INPUT_KINDS if k in spec]
    forms = ("input = {evidence_id, select?} (byte range of a read_bytes evidence) | {evidence_id, raw:true | quote:'text' "
             "| const:0x..} | {hex:'..'} (pasted bytes; bound only if they equal a read_bytes region); name is optional")
    if set(spec) - SPEC_KEYS or len(kinds) > 1 or ("select" in spec and kinds) or (
            "hex" in spec and (kinds or "select" in spec or "evidence_id" in spec)):
        raise ComputeInputError("BAD_ARGUMENT", forms)
    name, eid = spec.get("name", f"in{index}"), spec.get("evidence_id")
    if not _valid_name(name):
        raise ComputeInputError("BAD_ARGUMENT", f"input name must be an identifier of 1-{NAME_MAX} ASCII characters")
    if "hex" in spec:
        value = _parse_hex(spec["hex"], name)
        hit = find_literal(value, evidence, cas, invalidated, job_sha)
        if hit is None:
            bind: dict[str, Any] = {"name": name, "evidence_id": None, "kind": "literal", "authority": None}
        else:
            bind = {"name": name, "evidence_id": hit[0], "kind": "range", "authority": evidence[hit[0]].get("authority"),
                    "va": hit[1], "auto": True}
        bind["sha256"], bind["bytes"] = input_value_sha256(value), len(value)
        return bind, value
    rec = evidence.get(eid) if isinstance(eid, str) else None
    if rec is None:
        raise ComputeInputError("COMPUTE_INPUT_UNKNOWN_EVIDENCE",
                                f"input {name!r}: evidence_id is not an ev_ of this job")
    if invalidated and eid in invalidated:
        raise ComputeInputError("COMPUTE_INPUT_UNKNOWN_EVIDENCE", f"input {name!r}: evidence {eid} was invalidated")
    if not evidence_id_ok(rec):
        raise ComputeInputError("COMPUTE_INPUT_MISMATCH", f"input {name!r}: evidence record does not hash to its id")
    if job_sha is not None and (rec.get("subject") or {}).get("sha256") != job_sha:
        raise ComputeInputError("COMPUTE_INPUT_UNKNOWN_EVIDENCE", f"input {name!r}: evidence {eid} is about another target")
    if rec.get("authority") == COMPUTE_AUTHORITY:
        raise ComputeInputError("COMPUTE_INPUT_NOT_ALLOWED", f"input {name!r}: compute output cannot be a compute "
                                "input; cite the original evidence instead")
    if derive_strength(rec.get("capture") or {}) == "failed":
        raise ComputeInputError("COMPUTE_INPUT_NOT_ALLOWED", f"input {name!r}: evidence {eid} failed")
    try:
        raw = cas.get(rec["raw"]["blob_sha256"])
    except (CasError, KeyError, TypeError) as e:
        raise ComputeInputError("COMPUTE_INPUT_MISMATCH", f"input {name!r}: raw output unavailable") from e
    dyn = rec.get("authority") == DYNAMIC_AUTHORITY and rec.get("operation") == DYNAMIC_OPERATION
    kind = kinds[0] if kinds else (MEMRANGE if dyn and "select" in spec else
                                   "range" if rec.get("operation") == DUMP_OPERATION or "select" in spec else "raw")
    bind = {"name": name, "evidence_id": eid, "kind": kind, "authority": rec.get("authority")}
    value: bytes | int
    if kind == MEMRANGE:
        ev, off, value = _memory_select(spec.get("select"), rec, raw, name)
        bind["event"], bind["offset"], bind["va"] = ev.seq, off, ev.base + off
    elif kind == "range":
        regions = dump_regions(rec, raw)
        if not regions:
            raise ComputeInputError("COMPUTE_INPUT_NOT_BYTES", f"input {name!r}: {eid} has no file bytes to select (select "
                                    "works on read_bytes evidence; use raw:true, quote or const for other evidence)")
        va, n = _parse_select(spec.get("select"), regions, name)
        got = _slice(regions, va, n)
        if got is None:
            raise ComputeInputError("COMPUTE_INPUT_NOT_IN_RAW", f"input {name!r}: bytes 0x{va:x}+{n} are not inside one file "
                                    f"segment of {eid}")
        value = got
        bind["va"], bind["auto"] = va, False
    elif kind == "raw":
        if spec.get("raw", True) is not True:
            raise ComputeInputError("BAD_ARGUMENT", f"input {name!r}: raw must be true")
        value = raw
    elif kind == "quote":
        q = spec["quote"]
        if not isinstance(q, str) or not MIN_QUOTE_LEN <= len(q) <= QUOTE_MAX:
            raise ComputeInputError("BAD_ARGUMENT", f"input {name!r}: quote must be {MIN_QUOTE_LEN}-{QUOTE_MAX} chars")
        value = q.encode("utf-8")
        if value not in raw:
            raise ComputeInputError("COMPUTE_INPUT_NOT_IN_RAW",
                                    f"input {name!r}: quote is not verbatim in {eid} output")
        bind["quote"] = q
    else:
        n = _const(spec["const"])
        if n is None:
            raise ComputeInputError("BAD_ARGUMENT", f"input {name!r}: const must be a non-negative integer or 0x../decimal string")
        from .verifier import numbers_of  # imported late to avoid a circular import
        hexes, decs = numbers_of(raw, rec)
        if n not in hexes and n not in decs:
            raise ComputeInputError("COMPUTE_INPUT_NOT_IN_RAW", f"input {name!r}: constant {hex(n)} is not in {eid} output")
        value = n
        bind["const"] = n
    bind["sha256"] = input_value_sha256(value)
    bind["bytes"] = len(value) if isinstance(value, bytes) else 0
    return bind, value


def input_links(inputs: Any) -> list[str]:
    """Evidence ids an input list is bound to (unbound literals have none)."""
    return sorted({b["evidence_id"] for b in inputs if isinstance(b, Mapping) and b.get("evidence_id") is not None})


def validate_record(rec: Mapping[str, Any], raw: bytes, evidence: Mapping[str, Mapping[str, Any]], cas: Cas,
                    allowed_isolations: frozenset[str]) -> list[tuple[str, str]]:
    """Internal consistency of the cited compute evidence. Empty list = valid; otherwise the claim is REJECTED."""
    bad: list[tuple[str, str]] = []
    res = rec.get("result") or {}
    params = rec.get("parameters") or {}
    if (rec.get("environment") or {}).get("isolation") not in allowed_isolations:
        bad.append(("COMPUTE_NOT_ISOLATED", "computation did not run in an isolated environment"))
    if res.get("deterministic") is not True or not isinstance(res.get("runs"), int) or res["runs"] < 2:
        bad.append(("COMPUTE_NONDETERMINISTIC", "computation is not recorded as deterministic over >= 2 runs"))
    if res.get("output_sha256") != hashlib.sha256(raw).hexdigest() or (rec.get("capture") or {}).get("exit_code") != 0:
        bad.append(("COMPUTE_RECORD_INVALID", "output hash/exit code does not match the record"))
    try:
        code = cas.get(params.get("code_sha256") or "")
        if len(code) != params.get("code_bytes"):
            bad.append(("COMPUTE_RECORD_INVALID", "code blob size does not match"))
    except (CasError, TypeError, ValueError):
        bad.append(("COMPUTE_RECORD_INVALID", "code blob missing or corrupt (cannot be re-run)"))
    inputs = params.get("inputs")
    if not isinstance(inputs, list):
        bad.append(("COMPUTE_RECORD_INVALID", "inputs missing"))
        return bad
    for b in inputs:
        if not isinstance(b, Mapping) or b.get("kind") not in RECORD_KINDS:
            bad.append(("COMPUTE_RECORD_INVALID", "malformed input binding"))
            continue
        if b["kind"] == "literal":   # pasted bytes that matched no evidence: nothing to re-derive, and it binds nothing
            if b.get("evidence_id") is not None:
                bad.append(("COMPUTE_RECORD_INVALID", "an unbound literal must not name evidence"))
            continue
        spec: dict[str, Any] = {"name": b.get("name"), "evidence_id": b.get("evidence_id")}
        if b["kind"] == MEMRANGE:
            spec["select"] = {"event": b.get("event"), "offset": b.get("offset"), "length": b.get("bytes")}
        elif b["kind"] == "range":   # auto-bound and explicit ranges are re-derived the same way
            spec["select"] = {"address": b.get("va"), "length": b.get("bytes")}
        else:
            spec[b["kind"]] = True if b["kind"] == "raw" else b.get(b["kind"])
        try:
            again, _ = resolve_input(spec, evidence, cas)
        except ComputeInputError as e:
            bad.append(("COMPUTE_INPUT_MISMATCH", f"input {b.get('name')!r}: {e.message}"))
            continue
        if again["sha256"] != b.get("sha256") or again["authority"] != b.get("authority"):
            bad.append(("COMPUTE_INPUT_MISMATCH", f"input {b.get('name')!r}: re-derived bytes differ from the record"))
    if rec.get("evidence_links") != input_links(inputs):
        bad.append(("COMPUTE_RECORD_INVALID", "evidence_links do not list the input evidence"))
    return bad


def is_bound(rec: Mapping[str, Any], cited: Mapping[str, Mapping[str, Any]]) -> bool:
    """Can it support a value: at least one input, ALL inputs from static target evidence cited in the claim (a
    `memrange` input may instead come from cited dynamic-observation evidence). An unbound literal has no evidence id and
    therefore never qualifies."""
    inputs = (rec.get("parameters") or {}).get("inputs") or []
    return bool(inputs) and all(
        isinstance(b, Mapping) and b.get("evidence_id") in cited
        and (cited[b["evidence_id"]].get("authority") == STATIC_AUTHORITY
             or (b.get("kind") == MEMRANGE and cited[b["evidence_id"]].get("authority") == DYNAMIC_AUTHORITY))
        for b in inputs)
