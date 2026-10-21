"""`derivation` atom: the verifier itself deterministically recomputes a computed value from values in the cited STATIC
evidence (verifier version 6; docs/design/evidence-schema.md section 4.7).

Atom: {"type": "derivation", "value": <string|integer>, "expr": <node>}
Node:
- leaf `{"quote": "<text>", "evidence_id": ev}`: text found VERBATIM in the evidence's raw output (>= 4 characters);
  its value is its UTF-8 bytes.
- leaf `{"const": "0x37" | 55, "evidence_id": ev}`: a number found numerically (token-bounded, exact equality) in the
  evidence's raw output; its value is an integer.
- operation `{"op": ..., "args": [...], <parameter>}`; closed set:
  `xor` (int^int; bytes^int(0..255) on every byte; bytes^bytes of equal length), `add`/`sub` (int; optional modular
  `bits` 8|16|32|64), `concat` (2..8 byte strings), `slice` (`start`, `end`: 0 <= start < end <= length),
  `le_bytes`/`be_bytes` (int -> `width` 1|2|4|8 bytes; must fit).
Limits: depth <= 6, nodes <= 32, leaves <= 8, intermediate byte string <= 4096, integer 0..2^64-1.

This module only evaluates the expression; whether a leaf is in the evidence and which evidence it may come from
(only the cited `shipped-artifact` evidence; execution input/output NEVER) is decided by the verifier (`leaf`).
"""

from __future__ import annotations

from typing import Any, Callable

OPS = ("xor", "add", "sub", "concat", "slice", "le_bytes", "be_bytes")
MAX_DEPTH = 6
MAX_NODES = 32
MAX_LEAVES = 8
MAX_BYTES = 4096
MAX_INT = (1 << 64) - 1
WIDTHS = (1, 2, 4, 8)
BITS = (8, 16, 32, 64)
_PARAMS = {"xor": set(), "add": {"bits"}, "sub": {"bits"}, "concat": set(), "slice": {"start", "end"},
           "le_bytes": {"width"}, "be_bytes": {"width"}}
_ARITY = {"xor": (2, 2), "add": (2, 2), "sub": (2, 2), "concat": (2, 8), "slice": (1, 1),
          "le_bytes": (1, 1), "be_bytes": (1, 1)}

Value = "int | bytes"
Leaf = Callable[[str, dict], Any]  # (kind, node) -> int|bytes; raises DerivationError if not in the evidence


class DerivationError(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


def _bad(detail: str) -> DerivationError:
    return DerivationError("DERIVATION_MALFORMED", detail)


def _is_int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _int(x: Any, op: str) -> int:
    if not _is_int(x):
        raise _bad(f"{op}: integer expected")
    return x


def _bytes(x: Any, op: str) -> bytes:
    if not isinstance(x, bytes):
        raise _bad(f"{op}: byte string expected")
    return x


def _range(n: int, op: str) -> int:
    if not 0 <= n <= MAX_INT:
        raise DerivationError("DERIVATION_RANGE", f"{op}: result outside 0..2^64-1 (give a modular computation with bits)")
    return n


def evaluate(expr: Any, leaf: Leaf) -> int | bytes:
    """Evaluates the expression. Format/type/limit error: DerivationError (code DERIVATION_*)."""
    count = {"nodes": 0, "leaves": 0}

    def ev(node: Any, depth: int) -> int | bytes:
        if depth > MAX_DEPTH:
            raise _bad(f"depth > {MAX_DEPTH}")
        count["nodes"] += 1
        if count["nodes"] > MAX_NODES:
            raise _bad(f"nodes > {MAX_NODES}")
        if not isinstance(node, dict):
            raise _bad("node must be an object")
        if "op" not in node:
            keys = set(node)
            if keys not in ({"quote", "evidence_id"}, {"const", "evidence_id"}):
                raise _bad("leaf must be {quote, evidence_id} or {const, evidence_id}")
            count["leaves"] += 1
            if count["leaves"] > MAX_LEAVES:
                raise _bad(f"leaves > {MAX_LEAVES}")
            val = leaf("quote" if "quote" in keys else "const", node)
            if isinstance(val, bytes) and len(val) > MAX_BYTES:
                raise _bad(f"byte string > {MAX_BYTES}")
            return val
        op = node["op"]
        if op not in OPS:
            raise _bad(f"unknown operation (allowed: {', '.join(OPS)})")
        if set(node) - {"op", "args"} - _PARAMS[op]:
            raise _bad(f"{op}: unknown field")
        args = node.get("args")
        lo, hi = _ARITY[op]
        if not isinstance(args, list) or not lo <= len(args) <= hi:
            raise _bad(f"{op}: {lo}..{hi} arguments")
        vals = [ev(a, depth + 1) for a in args]
        out = _apply(op, node, vals)
        if isinstance(out, bytes) and len(out) > MAX_BYTES:
            raise _bad(f"byte string > {MAX_BYTES}")
        return out

    return ev(expr, 1)


def _apply(op: str, node: dict, vals: list) -> int | bytes:
    if op == "xor":
        a, b = vals
        if _is_int(a) and _is_int(b):
            return a ^ b
        if isinstance(a, bytes) and _is_int(b):
            if not 0 <= b <= 0xFF:
                raise _bad("xor: a byte string combines only with an integer 0..255")
            return bytes(x ^ b for x in a)
        if isinstance(a, bytes) and isinstance(b, bytes):
            if len(a) != len(b):
                raise _bad("xor: byte strings must have equal length")
            return bytes(x ^ y for x, y in zip(a, b))
        raise _bad("xor: (int,int) | (bytes,int) | (bytes,bytes)")
    if op in ("add", "sub"):
        a, b = _int(vals[0], op), _int(vals[1], op)
        r = a + b if op == "add" else a - b
        if "bits" in node:
            bits = node["bits"]
            if not _is_int(bits) or bits not in BITS:
                raise _bad(f"{op}: bits must be one of {BITS}")
            return r & ((1 << bits) - 1)
        return _range(r, op)
    if op == "concat":
        return b"".join(_bytes(v, op) for v in vals)
    if op == "slice":
        s = _bytes(vals[0], op)
        start, end = node.get("start"), node.get("end")
        if not (_is_int(start) and _is_int(end) and 0 <= start < end <= len(s)):
            raise _bad("slice: 0 <= start < end <= length")
        return s[start:end]
    # le_bytes / be_bytes
    n, width = _int(vals[0], op), node.get("width")
    if not _is_int(width) or width not in WIDTHS:
        raise _bad(f"{op}: width must be one of {WIDTHS}")
    if not 0 <= n < (1 << (8 * width)):
        raise _bad(f"{op}: value does not fit in {width} bytes")
    return n.to_bytes(width, "little" if op == "le_bytes" else "big")


def result_matches(result: int | bytes, claimed: Any) -> bool:
    """Exact equality: a bytes result = the UTF-8 bytes of the claimed string; an integer result = the claimed integer or its
    exact hex/decimal string. No approximate or format-independent matching. Version 21: the string must be a NUMBER
    under values.value_class (a 0x string of > 16 digits or a zero-padded decimal is a byte string, never equal to an
    integer result)."""
    from .values import claim_number  # no circular import; kept local

    if isinstance(result, bytes):
        return isinstance(claimed, str) and claimed.encode("utf-8") == result
    if _is_int(claimed):
        return claimed == result
    return isinstance(claimed, str) and claim_number(claimed) == result
