"""Engine-free raw file string scan (R5): ASCII and UTF-16LE, including overlay and section gaps.

`strings` in the engine works on the parsed image; packed files, installers and dumps often carry the useful
text in the overlay or in bytes that are not mapped by a section. This module scans the raw file instead and
reports the file offset, the mapped RVA when the offset belongs to a section or the headers, the section name,
and the encoding. It is static and read-only: no execution, no driver load, no network.

The scan is a stream in file-offset order and is bounded: it stops at `max_strings` hits, at a hard cap on
strings examined, and at a wall-clock budget. A stopped scan is reported as truncated/partial, never as
"no matches". Each string is clipped to `max_string_chars` before the user pattern runs on it, the pattern
length is capped and only a linear-time-safe regex subset is accepted (see `validate_pattern`).
"""

from __future__ import annotations

import heapq
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .pe_image import PeImage, parse_pe
from .string_enc import enc_label

MIN_LENGTH = 4
MAX_STRINGS = 10_000            # upper bound for max_strings (hits kept)
MAX_EXAMINED = 200_000          # hard cap on candidate strings examined (before the pattern filter)
MAX_STRING_CHARS = 4096         # per-string cap: only this prefix is matched and returned (clipped flag set)
MAX_PATTERN_CHARS = 256
MAX_REPEAT_BOUND = 256          # largest bound accepted in a {m,n} quantifier
MAX_UNBOUNDED_REPEATS = 2       # more unbounded quantifiers than this = polynomial blow-up risk
TIME_BUDGET_S = 10.0            # wall-clock budget for one scan (checked between strings)
ENCODINGS = ("ascii", "utf-16le")

# Truncation reasons (FileStrings.reasons)
R_MAX_HITS = "max_hits"
R_EXAMINED = "strings_examined_cap"
R_TIME = "time_budget"


@dataclass(frozen=True)
class FileString:
    value: str                   # at most MAX_STRING_CHARS characters
    file_offset: int
    byte_length: int             # real length of the run in the file (not clipped)
    encoding: str
    rva: int | None
    section: str | None          # None = headers or overlay
    clipped: bool = False        # value is a prefix of a longer string


@dataclass(frozen=True)
class FileStrings:
    entries: tuple[FileString, ...]
    total: int                   # hits found; a lower bound when `truncated` (the scan stops early)
    truncated: bool
    notes: tuple[str, ...]
    reasons: tuple[str, ...] = ()
    examined: int = 0            # candidate strings examined
    complete: bool = True        # False = partial scan: absence of a hit means nothing


def _ascii_re(min_length: int) -> re.Pattern[bytes]:
    return re.compile(rb"[\x20-\x7e]{%d,}" % min_length)


def _utf16_re(min_length: int) -> re.Pattern[bytes]:
    # Printable ASCII code units only: a low byte 0x20..0x7e followed by a zero high byte. Runs are
    # self-synchronising (a printable byte is never 0x00), so one unaligned scan finds each run once.
    return re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)


def _locate(img: PeImage | None, offset: int, length: int) -> tuple[int | None, str | None]:
    if img is None:
        return None, None
    if offset < min(img.size_of_headers, img.file_size):
        return offset, None
    for s in img.sections:
        if s.raw_ptr <= offset < s.raw_ptr + s.raw_size:
            return s.rva + (offset - s.raw_ptr), s.name
    return None, None


_PATTERN_HELP = (
    "allowed: literals, character classes ([...], \\d \\w \\s and their negations), '.', anchors ^ $ \\b \\B, "
    "alternation (|) at top level or inside a group that is not quantified, capturing/non-capturing groups that "
    "are not quantified, and quantifiers (* + ? {m,n} with n <= 256) on a single literal, class or '.'"
)


def _reject_pattern(what: str) -> None:
    raise ValueError(f"unsupported regex construct ({what}): {_PATTERN_HELP}")


def validate_pattern(pattern: str) -> None:
    """Accepts only a linear-time-safe regex subset; raises ValueError for everything else.

    The subset is parsed with Python's own parser and checked as a whitelist (not a blacklist), so
    overlapping alternations such as `(a|aa)+`, quantified groups and back-references are refused
    before the pattern ever runs. Patterns are still capped at MAX_PATTERN_CHARS.
    """
    if not isinstance(pattern, str):
        raise ValueError("pattern must be a string")
    if len(pattern) > MAX_PATTERN_CHARS:
        raise ValueError(f"pattern too long ({len(pattern)} > {MAX_PATTERN_CHARS} chars)")
    try:                                   # Python >= 3.11
        from re import _constants as c, _parser as p
    except ImportError:                    # pragma: no cover - older/alternate Python builds
        try:
            import sre_constants as c     # type: ignore[no-redef]
            import sre_parse as p         # type: ignore[no-redef]
        except ImportError as exc:
            raise ValueError("pattern safety validation is unavailable in this Python") from exc
    try:
        tree = p.parse(pattern, re.I)
        compiled = re.compile(pattern, re.I)
    except (re.error, RecursionError, OverflowError, ValueError) as exc:
        raise ValueError(f"invalid pattern: {exc}") from exc
    if compiled.flags & ~(re.I | re.U):
        _reject_pattern("inline flags (only the implicit case-insensitive flag is used)")

    single_atoms = {c.LITERAL, c.NOT_LITERAL, c.IN, c.ANY}
    if hasattr(c, "ANY_ALL"):
        single_atoms.add(c.ANY_ALL)
    anchors = {c.AT_BEGINNING, c.AT_END, c.AT_BOUNDARY, c.AT_NON_BOUNDARY}
    categories = set()
    for suffix in ("DIGIT", "NOT_DIGIT", "SPACE", "NOT_SPACE", "WORD", "NOT_WORD"):
        for prefix in ("CATEGORY_", "CATEGORY_UNI_", "CATEGORY_LOC_"):
            op = getattr(c, prefix + suffix, None)
            if op is not None:
                categories.add(op)
    repeats = {getattr(c, n) for n in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT") if hasattr(c, n)}
    possessive = getattr(c, "POSSESSIVE_REPEAT", None)
    unbounded = 0

    def check_class(items) -> None:
        for op, av in items:
            if op in (c.NEGATE, c.LITERAL, c.RANGE):
                continue
            if op is c.CATEGORY and av in categories:
                continue
            _reject_pattern(f"character class item '{getattr(op, 'name', op)}'")

    def check(items) -> None:
        nonlocal unbounded
        for op, av in items:
            if op in (c.LITERAL, c.NOT_LITERAL):
                continue
            if op is c.IN:
                check_class(av)
                continue
            if op is c.ANY or (hasattr(c, "ANY_ALL") and op is c.ANY_ALL):
                continue
            if op is c.AT and av in anchors:
                continue
            if op is c.BRANCH:
                for branch in av[1]:
                    check(branch)
                continue
            if op is c.SUBPATTERN:
                _group, add_flags, del_flags, sub = av
                if add_flags or del_flags:
                    _reject_pattern("inline group flags")
                check(sub)
                continue
            if op in repeats:
                if op is possessive:
                    _reject_pattern("possessive quantifier")
                _lo, hi, sub = av
                if len(sub) != 1 or sub[0][0] not in single_atoms:
                    _reject_pattern("quantifier on a group or sequence (only a single literal, class or '.')")
                if hi == c.MAXREPEAT:
                    unbounded += 1
                elif hi > MAX_REPEAT_BOUND:
                    _reject_pattern(f"repetition count {hi} > {MAX_REPEAT_BOUND}")
                continue
            _reject_pattern(getattr(op, "name", str(op)))

    check(tree)
    if unbounded > MAX_UNBOUNDED_REPEATS:
        raise ValueError(f"pattern has {unbounded} unbounded quantifiers (max {MAX_UNBOUNDED_REPEATS}): "
                         f"{_PATTERN_HELP}")


def _runs(data: bytes, rx: re.Pattern[bytes], enc: str) -> Iterator[tuple[int, int, str]]:
    for m in rx.finditer(data):
        yield m.start(), m.end() - m.start(), enc


def scan_file_strings(data: bytes, *, min_length: int = MIN_LENGTH, encodings: tuple[str, ...] = ENCODINGS,
                      pattern: str | None = None, max_strings: int = MAX_STRINGS,
                      max_examined: int = MAX_EXAMINED, max_string_chars: int = MAX_STRING_CHARS,
                      time_budget_s: float | None = TIME_BUDGET_S) -> FileStrings:
    """Streaming scan of raw bytes in file-offset order. `pattern` is a case-insensitive regular expression over
    the decoded value (first `max_string_chars` characters). The scan stops as soon as `max_strings` hits were
    found, `max_examined` candidate strings were looked at, or `time_budget_s` seconds passed; then
    `truncated` is True with the reason, and absence of a hit proves nothing (`complete` False)."""
    if min_length < 1:
        raise ValueError("min_length must be >= 1")
    if max_strings < 1:
        raise ValueError("max_strings must be >= 1")
    wanted = tuple(dict.fromkeys(e.lower() for e in encodings))
    bad = [e for e in wanted if e not in ENCODINGS]
    if bad:
        raise ValueError(f"unknown encoding(s): {', '.join(bad)}; supported: {', '.join(ENCODINGS)}")
    rx = None
    if pattern:
        validate_pattern(pattern)
        rx = re.compile(pattern, re.I)
    try:
        img = parse_pe(lambda o, n: data[o:o + n], len(data))
    except Exception:          # a malformed PE must not block the raw scan: sections become unknown
        img = None

    streams = []
    if "ascii" in wanted:
        streams.append(_runs(data, _ascii_re(min_length), "ascii"))
    if "utf-16le" in wanted:
        streams.append(_runs(data, _utf16_re(min_length), "utf-16le"))

    hits: list[FileString] = []
    examined = 0
    reasons: list[str] = []
    deadline = None if time_budget_s is None else time.monotonic() + time_budget_s
    for off, length, enc in heapq.merge(*streams, key=lambda t: (t[0], t[2])):
        if deadline is not None and time.monotonic() >= deadline:
            reasons.append(R_TIME)
            break
        if examined >= max_examined:
            reasons.append(R_EXAMINED)
            break
        examined += 1
        unit = 1 if enc == "ascii" else 2
        clipped = length // unit > max_string_chars
        raw = data[off:off + (max_string_chars * unit if clipped else length)]   # never materialise a huge run
        value = raw.decode("latin-1") if enc == "ascii" else raw.decode("utf-16-le")
        if rx is not None:
            if deadline is not None and time.monotonic() >= deadline:   # cheap: do not start a long search
                reasons.append(R_TIME)
                break
            if not rx.search(value):
                continue
        rva, section = _locate(img, off, length)
        hits.append(FileString(value, off, length, enc, rva, section, clipped))
        if len(hits) >= max_strings:
            reasons.append(R_MAX_HITS)
            break
    notes = [
        "raw file scan: sections, headers, overlay and non-mapped gaps are all included",
        "UTF-16LE detection covers printable ASCII code units; non-ASCII UTF-16 is not decoded",
        f"values longer than {max_string_chars} characters are clipped (clipped); byte_length is the real length",
    ]
    if img is None:
        notes.append("not a parseable PE: offsets are file offsets and rva is unavailable")
    if reasons:
        notes.append("PARTIAL scan (" + ", ".join(reasons) + "): strings after the stopping point were not "
                     "examined; 'no match' cannot be concluded from a truncated result")
    return FileStrings(tuple(hits), len(hits), bool(reasons), tuple(notes), tuple(reasons), examined,
                       not reasons)


def scan_file_strings_file(path: str | Path, **kw) -> FileStrings:
    return scan_file_strings(Path(path).read_bytes(), **kw)


def _line(s: FileString) -> str:
    rva = f"0x{s.rva:x}" if s.rva is not None else "-"
    sec = s.section or ("header" if s.rva is not None else "overlay/gap")
    clip = " clipped" if s.clipped else ""
    return f"0x{s.file_offset:x} rva={rva} section={sec} {enc_label(s.encoding)} len={s.byte_length}{clip} {s.value!r}"


def fit_entries(r: FileStrings, budget: int) -> int:
    """How many leading entries fit in `budget` characters (at least 1 when there is any entry)."""
    used = 0
    for i, s in enumerate(r.entries):
        used += len(_line(s)) + 1
        if used > budget and i > 0:
            return i
    return len(r.entries)


def render_file_strings(r: FileStrings, *, budget: int | None = None) -> str:
    """Text form. With `budget` (characters) entries that do not fit are left out (see `fit_entries`)."""
    n = len(r.entries) if budget is None else fit_entries(r, budget)
    more = "+" if r.truncated else ""
    head = f"strings shown={n} found={r.total}{more} examined={r.examined} truncated={r.truncated or n < len(r.entries)}"
    if r.reasons:
        head += " reasons=" + ",".join(r.reasons)
    if n < len(r.entries):
        head += " reply_budget"
    lines = [head, *(_line(s) for s in r.entries[:n]), *(f"note: {note}" for note in r.notes)]
    return "\n".join(lines) + "\n"
