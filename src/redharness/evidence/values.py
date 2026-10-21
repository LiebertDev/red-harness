"""Result values: the concrete values a claim asserts (password/key string, numeric constant, address,
computed result).

If the verifier checks quote/address/SHA but not the RESULT the claim reaches, a model can slip a value it computed in
its head into the report (e.g. a decoded password that never appears in the evidence). This module collects values from two sources:
- model: `claim_add(values=[...])` ("declared");
- server: automatic extraction from the claim text (quoted/backticked strings, decimal numbers). Even if the model leaves
  the field empty the value does not escape. 0x hex literals are checked separately and numerically via `model.hex_literals`.
Rule (verifier.py): every value must appear in the cited evidence's raw output verbatim (number: numeric equality, not
substring; string: verbatim substring) or be backed by execution evidence (`controlled-replay`).

Value classes (verifier version 21, `value_class`; docs/design/evidence-schema.md section 4.14). A claimed token is
classified BEFORE it is compared, so a byte string is never collapsed into a number:
- number: `0x` + 1..16 hex digits (leading zeros allowed: any padding up to the 64-bit width, `0x0000005A`,
  `0x00000000deadbeef`, is the same number), or a bare decimal of 1..20 digits without a leading zero (`0` itself is
  fine). Compared by exact numeric equality (as before).
- hex string (byte string / digest): `0x` + more than 16 hex digits; a bare hex run of more than 16 characters; a bare
  decimal-form token with a leading zero (`00`, `0090`, 64 zeros) or with more than 20 digits. Canonical form: the
  digits without `0x`, lower case, leading zeros KEPT. Compared as that exact string against WHOLE hex tokens of the
  cited evidence (a token may carry `0x`; it is bounded by non-word characters, so a part of a longer token never
  matches; read_bytes/emulate dump rows and disassembly instruction bytes are not tokens, as for numbers).
- fraction: a decimal fraction (`1.5`). Compared as the exact token (`2.5` is not `2.50`, `3.14` is not in `13.145`).
- string: everything else, as before (verbatim substring).
"""

from __future__ import annotations

import re
from typing import Any, Iterable

MAX_VALUES = 64
MAX_VALUE_LEN = 4096
MAX_NUMBER_HEX_DIGITS = 16   # a number is at most 64 bits; a longer hex token is a byte string
MAX_NUMBER_DEC_DIGITS = 20   # 2**64-1 has 20 decimal digits
_HEX_FULL = re.compile(r"0[xX][0-9a-fA-F]+")
_DEC_FULL = re.compile(r"[0-9]+")
_BARE_HEX_FULL = re.compile(r"[0-9a-fA-F]+")
_FRACTION_FULL = re.compile(r"[0-9]+\.[0-9]+")
# hex strings in the claim text: a long 0x literal, or a bare hex run of > 16 characters with at least one letter
# (a digits-only run is a decimal token and is classified by value_class)
_LONG_HEX_LIT = re.compile(r"(?<![0-9A-Za-z_])0[xX][0-9a-fA-F]{%d,}(?![0-9A-Za-z_])" % (MAX_NUMBER_HEX_DIGITS + 1))
_BARE_HEX_RUN = re.compile(r"(?<![0-9A-Za-z_])(?=[0-9]*[a-fA-F])[0-9a-fA-F]{%d,}(?![0-9A-Za-z_])"
                           % (MAX_NUMBER_HEX_DIGITS + 1))

# Quoted spans: backtick, double quote (straight/curly), single quote (bounded so it is not confused with an apostrophe)
_QUOTED = (
    re.compile(r"`([^`\n]{1,%d})`" % MAX_VALUE_LEN),
    re.compile(r'"([^"\n]{1,%d})"' % MAX_VALUE_LEN),
    re.compile("“([^”\n]{1,%d})”" % MAX_VALUE_LEN),
    re.compile("(?<![0-9A-Za-z])'([^'\n]{1,%d})'(?![0-9A-Za-z])" % MAX_VALUE_LEN),
    re.compile("(?<![0-9A-Za-z])‘([^’\n]{1,%d})’(?![0-9A-Za-z])" % MAX_VALUE_LEN),
)
# Decimal number: token-bounded; numbers glued to letters such as `SHA-256`/`x86` and unit-suffixed such as `16-bit` are not values
_DECIMAL = re.compile(
    r"(?<![0-9A-Za-z_.])(?<![A-Za-z]-)[0-9]+(?:\.[0-9]+)?(?![0-9A-Za-z_])(?!\.[0-9])"
    r"(?!\s?-?(?:bit|bits|byte|bytes)\b)", re.I)


def _as_text(v: Any) -> str:
    if isinstance(v, bool) or not isinstance(v, (str, int)):
        raise ValueError("result value must be a string or an integer")
    s = str(v).strip() if isinstance(v, str) else str(v)
    if not s:
        raise ValueError("empty result value")
    if len(s) > MAX_VALUE_LEN:
        raise ValueError("result value too long")
    return s


def normalize_declared(values: Iterable[Any] | None) -> list[dict]:
    """Values declared by the model: string/integer or {"value": .., "derived": bool}. ValueError if malformed."""
    out: list[dict] = []
    if values is None:
        return out
    if not isinstance(values, (list, tuple)):
        raise ValueError("values must be a list")
    for v in values:
        derived = False
        if isinstance(v, dict):
            if set(v) - {"value", "derived"} or "value" not in v:
                raise ValueError("values item must be {value, derived?}")
            if "derived" in v and not isinstance(v["derived"], bool):
                raise ValueError("derived must be a bool")
            derived = bool(v.get("derived", False))
            v = v["value"]
        item = {"value": _as_text(v), "derived": derived}
        if item not in out:
            out.append(item)
    if len(out) > MAX_VALUES:
        raise ValueError("too many result values")
    return out


def extract_from_text(text: str) -> list[dict]:
    """Values from the claim text: quoted/backticked strings, decimal numbers and (version 21) hex strings (a 0x
    literal of more than 16 digits, a bare hex run of more than 16 characters with a letter). EXCLUDING 0x numbers of
    <= 16 digits (those are checked by `model.hex_literals`). Deterministic; order is the order in the text."""
    found: list[tuple[int, dict]] = []
    rest = text
    for rx in _QUOTED:
        def blank(m: re.Match[str]) -> str:
            s = m.group(1).strip()
            if s and (not _HEX_FULL.fullmatch(s) or value_class(s)[0] == "hexstr"):
                found.append((m.start(), {"value": s, "derived": False, "source": "quoted"}))
            return " " * (m.end() - m.start())
        rest = rx.sub(blank, rest)  # the extracted span is blanked: numbers inside it must not become separate values

    def hexstr(m: re.Match[str]) -> str:   # version 21: a long 0x literal / bare hex run is a byte-string value
        found.append((m.start(), {"value": m.group(0), "derived": False, "source": "hex_string"}))
        return " " * (m.end() - m.start())
    rest = _BARE_HEX_RUN.sub(hexstr, _LONG_HEX_LIT.sub(hexstr, rest))
    for m in _DECIMAL.finditer(rest):
        found.append((m.start(), {"value": m.group(0), "derived": False, "source": "decimal"}))
    out: list[dict] = []
    for _, item in sorted(found, key=lambda t: t[0]):
        if not any(o["value"] == item["value"] for o in out):
            out.append(item)
    return out[:MAX_VALUES]


def effective_values(text: str, declared: Iterable[dict]) -> list[dict]:
    """Union of declared + automatic extraction (same value once; the declared `derived` flag is kept)."""
    out = [{**d, "source": "declared"} for d in declared]
    for item in extract_from_text(text):
        if not any(o["value"] == item["value"] for o in out):
            out.append(item)
    return out


def numeric(value: str) -> int | None:
    """The number if it is an exact hex or a plain decimal integer, else None (string/fractional). A PARSER (compute
    input constants use it); what a claimed token may be compared as is decided by `value_class`."""
    if _HEX_FULL.fullmatch(value):
        return int(value, 16)
    if _DEC_FULL.fullmatch(value):
        return int(value, 10)
    return None


def value_class(value: str) -> tuple[str, Any]:
    """Classifies a claimed token (version 21, module docstring): ("number", int) | ("hexstr", canonical digits) |
    ("fraction", text) | ("string", text). Deterministic; the caller strips whitespace."""
    if _HEX_FULL.fullmatch(value):
        digits = value[2:]
        if len(digits) <= MAX_NUMBER_HEX_DIGITS:
            return "number", int(digits, 16)
        return "hexstr", digits.lower()
    if _DEC_FULL.fullmatch(value):
        if len(value) <= MAX_NUMBER_DEC_DIGITS and (value == "0" or value[0] != "0"):
            return "number", int(value, 10)
        return "hexstr", value
    if len(value) > MAX_NUMBER_HEX_DIGITS and _BARE_HEX_FULL.fullmatch(value):
        return "hexstr", value.lower()
    if _FRACTION_FULL.fullmatch(value):
        return "fraction", value
    return "string", value


def claim_number(value: str) -> int | None:
    """The number a claimed token denotes, or None when it is not a number under version 21 (a byte string, a
    fraction or a string are never compared numerically)."""
    cls, key = value_class(value)
    return key if cls == "number" else None
