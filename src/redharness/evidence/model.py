"""Schemas for evidence (rh.evidence/1), claim (rh.claim/1) and unknown (rh.unknown/1).

Only server code produces evidence (`build_evidence`). The id derives from the canonical content; the timestamp,
duration (capture.elapsed_ms) and local paths do not enter the id, so the same id comes out after resume.
The id projection has no floats (only int/string/bool/None/list/dict).
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Iterable, Mapping

from ..core.cas import Cas
from ..core.journal import canonical, sha256_hex
from ..core.result import Status
from .kinds import CLAIM_KINDS  # noqa: F401  (re-export; see kinds.py)

EVIDENCE_SCHEMA = "rh.evidence/1"
CLAIM_SCHEMA = "rh.claim/1"
UNKNOWN_SCHEMA = "rh.unknown/1"

EXCERPT_MAX = 2048
RESULT_MAX = 8192

CONFIDENCE = ("observed", "derived", "inferred")
DYNAMIC_AUTHORITY = "dynamic-observation"  # user-mode dynamic observation (dynamic/); never grants PROVEN alone
# compute (docs/design/compute-tool.md): isolated computation of model-written code; not about the target, but the fact
# "this code gave this with these inputs". Supports a value only in an observation claim, if bound (SUPPORTED at most).
COMPUTE_AUTHORITY = "sandboxed-computation"
# emulate (docs/design/emulation.md): CPU emulation of the target's own code from the file image. An observation of
# emulation, never of a program run: backs a value only in an observation claim (SUPPORTED at most).
EMULATION_AUTHORITY = "cpu-emulation"
# captured_region (evidence/region_view.py): a bounded, read-only VIEW (hex / strings / disassembly) of bytes that the
# tracer captured from an executable region of a dynamic observation. Always confidence=derived and linked to that
# observation; backs a statement only in an observation + present claim that also cites the observation (SUPPORTED at most).
REGION_VIEW_AUTHORITY = "dynamic-region-view"
AUTHORITY = ("shipped-artifact", "controlled-replay", "historical-reference",
             "external-service", "analyst-inference", DYNAMIC_AUTHORITY, COMPUTE_AUTHORITY, EMULATION_AUTHORITY,
             REGION_VIEW_AUTHORITY)
ISOLATION = ("none", "process", "container", "virtual-machine", "windows-sandbox")
ISOLATED = frozenset({"container", "virtual-machine", "windows-sandbox"})
COVERAGE = ("complete", "partial", "unknown")
LOCATION_KINDS = ("address", "address-range", "file-offset", "file-offset-range", "artifact-path")
SPACES = ("file_offset", "rva", "va")


class ClaimStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    SUPPORTED = "SUPPORTED"
    PROVEN = "PROVEN"
    REJECTED = "REJECTED"


POLARITIES = ("present", "absent")


# ---------- address ----------

class AddressError(ValueError):
    pass


_HEX = re.compile(r"0[xX][0-9a-fA-F]+")
_DEC = re.compile(r"[0-9]+")


def normalize_address(value: Any, space: str = "file_offset", *, strict: bool = True) -> int:
    """Converts an address to a number. Only strict=True is supported: AddressError if the form is malformed.

    Accepted: int (not bool, >=0), '0x..' hex or plain decimal string. Whitespace, sign, suffix, a bare
    '0x' and an unknown space are rejected. Comparison is always numeric, never a string substring.
    """
    if not strict:
        raise AddressError("strict=False is not supported (risk of invented addresses)")
    if space not in SPACES:
        raise AddressError(f"unknown address space: {space!r}")
    if isinstance(value, bool):
        raise AddressError("a bool is not an address")
    if isinstance(value, int):
        n = value
    elif isinstance(value, str):
        if _HEX.fullmatch(value):
            n = int(value, 16)
        elif _DEC.fullmatch(value):
            n = int(value, 10)
        else:
            raise AddressError(f"unparseable address: {value!r}")
    else:
        raise AddressError(f"invalid address type: {type(value).__name__}")
    if n < 0:
        raise AddressError("negative address")
    return n


_LOOSE_HEX = re.compile(r"(?<![0-9A-Za-z_])0[xX][0-9A-Za-z_]*")
# C/Hex-Rays integer suffixes (verifier version 6): u, l, ll, ul, ull, lu, llu, i64, ui64 (they do not change the value)
C_INT_SUFFIX = r"(?:[uU](?:ll|LL|l|L|i64|I64)?|(?:ll|LL|l|L)[uU]?|i64|I64)?"
_HEX_SUFFIXED = re.compile(r"0[xX]([0-9a-fA-F]+)" + C_INT_SUFFIX)


MAX_NUMBER_HEX_DIGITS = 16   # verifier version 21: a longer 0x token is a byte string, not a number (values.py)


def hex_literals(text: str) -> tuple[list[int], list[str]]:
    """0x literals in the text: (well-formed numeric values, malformed strings).
    A decompiler suffix (`0x..LL`, `0xCu`) is accepted and the value is read in full with the suffix dropped; any other suffix is malformed.
    Version 21: a literal of more than 16 hex digits is not a number (it is neither listed here nor malformed; see
    `long_hex_literals`)."""
    good: list[int] = []
    bad: list[str] = []
    for m in _LOOSE_HEX.finditer(text):
        tok = m.group(0)
        sm = _HEX_SUFFIXED.fullmatch(tok)
        if sm:
            if len(sm.group(1)) <= MAX_NUMBER_HEX_DIGITS:
                good.append(int(sm.group(1), 16))
        else:
            bad.append(tok)
    return good, bad


def long_hex_literals(text: str) -> list[str]:
    """Version 21: the 0x literals of more than 16 hex digits (byte strings / digests) as canonical strings (digits,
    lower case, leading zeros kept, no 0x), in text order. A suffixed long literal is a canonical string too."""
    out: list[str] = []
    for m in _LOOSE_HEX.finditer(text):
        sm = _HEX_SUFFIXED.fullmatch(m.group(0))
        if sm and len(sm.group(1)) > MAX_NUMBER_HEX_DIGITS:
            out.append(sm.group(1).lower())
    return out


def location_contains(loc: Mapping[str, Any], space: str, value: int) -> bool:
    """Does the location contain the number in the given space? Ranges are half-open [start, end)."""
    kind = loc.get("kind")
    if kind in ("file-offset", "file-offset-range"):
        if space != "file_offset":
            return False
    elif kind in ("address", "address-range"):
        if loc.get("space") != space:
            return False
    else:
        return False
    if kind in ("file-offset", "address"):
        return loc.get("start") == value
    return loc["start"] <= value < loc["end"]


def location_contains_any_space(loc: Mapping[str, Any], value: int) -> bool:
    return any(location_contains(loc, s, value) for s in SPACES)


def _validate_location(loc: Mapping[str, Any]) -> dict:
    kind = loc.get("kind")
    if kind not in LOCATION_KINDS:
        raise ValueError(f"invalid location kind: {kind!r}")
    out: dict[str, Any] = {"kind": kind}
    if kind == "artifact-path":
        if not isinstance(loc.get("path"), str):
            raise ValueError("artifact-path requires path")
        out["path"] = loc["path"]
        return out
    if kind in ("address", "address-range"):
        if loc.get("space") not in ("rva", "va"):
            raise ValueError("an address location needs space rva|va")
        out["space"] = loc["space"]
    out["start"] = normalize_address(loc.get("start"))
    if kind.endswith("range"):
        out["end"] = normalize_address(loc.get("end"))
        if out["end"] <= out["start"]:
            raise ValueError("empty/reversed range")
    return out


# ---------- evidence ----------

def derive_strength(capture: Mapping[str, Any]) -> str:
    """full | partial | failed; derived only from core Status and flags, not from text."""
    status = capture.get("status")
    if status in (Status.TIMEOUT.value, Status.MEMORY_LIMIT.value, Status.ERROR.value):
        return "failed"
    if status == Status.OK.value and not capture.get("truncated") and not capture.get("timed_out"):
        return "full"
    if status in (Status.OK.value, Status.PARTIAL.value, Status.LIMIT_REACHED.value):
        return "partial"
    return "failed"  # unknown/TOOL_MISSING: fail-closed


def _assert_no_float(obj: Any, path: str = "$") -> None:
    if isinstance(obj, float):
        raise ValueError(f"no float allowed in the id projection: {path}")
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            _assert_no_float(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _assert_no_float(v, f"{path}[{i}]")


def evidence_projection(record: Mapping[str, Any]) -> dict:
    """The semantic projection that enters the id: everything except evidence_id and capture.elapsed_ms."""
    proj = {k: v for k, v in record.items() if k != "evidence_id"}
    cap = dict(proj.get("capture") or {})
    cap.pop("elapsed_ms", None)
    proj["capture"] = cap
    return proj


def compute_evidence_id(record: Mapping[str, Any]) -> str:
    proj = evidence_projection(record)
    _assert_no_float(proj)
    return "ev_" + sha256_hex(canonical(proj))


def evidence_id_ok(record: Mapping[str, Any]) -> bool:
    try:
        return record.get("evidence_id") == compute_evidence_id(record)
    except (ValueError, TypeError):
        return False


def build_evidence(cas: Cas, *, subject_sha256: str, tool: str, operation: str, raw: bytes,
                   status: Status, confidence: str, authority: str,
                   parameters: Mapping[str, Any] | None = None, tool_version: str = "",
                   engine: str = "native", engine_version: str = "",
                   truncated: bool = False, exit_code: int | None = None, elapsed_ms: int = 0,
                   result: Any = None, locations: Iterable[Mapping[str, Any]] = (),
                   environment: Mapping[str, Any] | None = None,
                   coverage: Mapping[str, Any] | None = None,
                   limitations: Iterable[str] = (), evidence_links: Iterable[str] = (),
                   subject_format: str = "pe", architecture: str | None = None,
                   derived_from_sha256: str | None = None) -> dict:
    """Server-side evidence production. The raw output is written to the CAS first, then the record is returned."""
    if status is Status.TOOL_MISSING:
        raise ValueError("TOOL_MISSING produces no evidence (step event only)")
    if confidence not in CONFIDENCE or authority not in AUTHORITY:
        raise ValueError("invalid confidence/authority")
    if authority in ("controlled-replay", DYNAMIC_AUTHORITY):
        if not environment or environment.get("isolation") not in ISOLATION:
            raise ValueError("controlled-replay evidence requires environment.isolation")
    if environment is not None and environment.get("isolation") not in ISOLATION:
        raise ValueError("invalid environment.isolation")
    if authority == DYNAMIC_AUTHORITY and environment["isolation"] not in ISOLATED:
        raise ValueError("dynamic-observation evidence requires an isolated environment")
    if authority == COMPUTE_AUTHORITY and (not environment or environment.get("isolation") not in ISOLATED
                                           or confidence != "derived"):
        raise ValueError("sandboxed-computation evidence requires an isolated environment and confidence=derived")
    if authority == EMULATION_AUTHORITY and (confidence != "derived" or not environment
                                             or environment.get("native_execution") is not False):
        raise ValueError("cpu-emulation evidence requires confidence=derived and environment.native_execution=false")
    cov = dict(coverage or {"scope": "unspecified", "relationship": "unknown"})
    if cov.get("relationship") not in COVERAGE:
        raise ValueError("invalid coverage.relationship")
    blob = cas.put(raw)
    res_inline, res_blob = result, None
    if result is not None and len(canonical(result)) > RESULT_MAX:
        res_blob, res_inline = cas.put(canonical(result)), None
    capture = {"status": status.value, "truncated": bool(truncated),
               "timed_out": status is Status.TIMEOUT, "exit_code": exit_code,
               "elapsed_ms": int(elapsed_ms)}
    capture["strength"] = derive_strength(capture)
    rec = {
        "schema": EVIDENCE_SCHEMA, "untrusted_content": True,
        "subject": {"sha256": subject_sha256, "format": subject_format,
                    "architecture": architecture, "derived_from_sha256": derived_from_sha256},
        "source": {"tool": tool, "tool_version": tool_version, "engine": engine,
                   "engine_version": engine_version},
        "operation": operation, "parameters": dict(parameters or {}),
        "capture": capture,
        "raw": {"blob_sha256": blob, "bytes": len(raw),
                "excerpt": raw[:EXCERPT_MAX].decode("utf-8", "replace")},
        "result": res_inline, "result_blob_sha256": res_blob,
        "locations": [_validate_location(loc) for loc in locations],
        "confidence": confidence, "authority": authority,
        "environment": dict(environment) if environment else None,
        "coverage": cov, "limitations": list(limitations), "evidence_links": list(evidence_links),
    }
    rec["evidence_id"] = compute_evidence_id(rec)
    return rec


def wrap_untrusted(evidence_id: str, text: str) -> str:
    """Presents target text inside a marked block; a closing-tag sequence is escaped."""
    safe = text.replace("</untrusted_target_content", "<\\/untrusted_target_content")
    return f'<untrusted_target_content evidence_id="{evidence_id}">{safe}</untrusted_target_content>'


# ---------- claim ----------

_WS = re.compile(r"\s+")


def normalize_text(s: str) -> str:
    return _WS.sub(" ", s).strip()


def make_claim_id(text: str, kind: str, polarity: str, target_sha256: str) -> str:
    return "cl_" + sha256_hex(canonical({"text": normalize_text(text), "kind": kind,
                                         "polarity": polarity, "target_sha256": target_sha256}))


def is_hypothesis(claim: Mapping[str, Any]) -> bool:
    """There is no separate HYPOTHESIS status; an UNVERIFIED claim with no evidence references is a hypothesis."""
    return claim.get("status") == ClaimStatus.UNVERIFIED.value and not claim.get("evidence_ids")


# ---------- unknown ----------

UNKNOWN_STATUSES = ("open", "investigating", "blocked", "resolved", "withdrawn")
SEVERITIES = ("low", "medium", "high", "critical")


def make_unknown_id(domain: str, question: str, target_sha256: str, scope: str = "") -> str:
    return "unk_" + sha256_hex(canonical({"domain": domain, "question": normalize_text(question),
                                          "target_sha256": target_sha256, "scope": scope}))


def build_unknown(domain: str, question: str, target_sha256: str, *, scope: str = "",
                  severity: str = "medium", required_authority: str | None = None,
                  recommended_probes: Iterable[str] = (),
                  supporting_evidence_ids: Iterable[str] = (), reason: str = "",
                  address: int | None = None) -> dict:
    """`reason` (why it could not be answered) and `address` (the related VA) are optional; if not given they are absent from the record
    (rh.unknown/1 is backward compatible; they do not enter the id, but an address given via `scope` does)."""
    if severity not in SEVERITIES:
        raise ValueError("invalid severity")
    if required_authority is not None and required_authority not in AUTHORITY:
        raise ValueError("invalid required_authority")
    q = normalize_text(question)
    if not q:
        raise ValueError("empty question")
    return {"schema": UNKNOWN_SCHEMA, "unknown_id": make_unknown_id(domain, q, target_sha256, scope),
            "domain": domain, "question": q, "target_sha256": target_sha256, "scope": scope,
            "status": "open", "severity": severity, "required_authority": required_authority,
            "recommended_probes": list(recommended_probes),
            "supporting_evidence_ids": list(supporting_evidence_ids),
            "contradicting_evidence_ids": [], "resolution": None, "revision": 1,
            **({"reason": normalize_text(reason)} if reason and normalize_text(reason) else {}),
            **({"address": address} if address is not None else {})}
