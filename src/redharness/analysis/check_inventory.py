"""Check inventory: protection / licensing check CANDIDATES listed with evidence. Static, engine-free.

Given the bytes of a PE, list where it shows a signal of one of the eight categories of `check_taxonomy.CATEGORIES`
(C1 licence/key validation .. C8 network activation): an imported API, a string, or an instruction pattern. Nothing is
run, unpacked or decoded, and no engine is needed; where the code lives is found by byte patterns (RIP-relative / absolute
operands that point at the string or the import slot, and the x64 `.pdata` function table for the enclosing function).

What a candidate is NOT: proof that a check exists, runs, or decides anything. It is an observation that a signal is
present at a place. The verifier can support a claim about it as a static observation (SUPPORTED at most); whether the
program really validates a key is for `decompile` / `disassemble` / `run_controlled` to settle.

Rules (fail-closed):
- Absence is never "no checks". Unreadable imports, a file that is not a parseable PE, no named imports, an unscannable
  code section or a packed image make the state `UNKNOWN`; with none of that and no signal the state is
  `NO_KNOWN_CANDIDATES`, which only says the known signals were not found.
- Known false positives are handled by a stated rule, never silently: imports the statically linked C runtime's startup
  pulls in together (IsDebuggerPresent, GetSystemTimeAsFileTime, GetModuleHandle...) are SUPPRESSED when the whole
  startup cluster is present and are listed under `suppressed`; every other candidate carries its false-positive note.
- A string is one candidate per distinct string, with the strongest matching signal; the import-name strings of the
  import table itself are not strings of the program.
- The scan lists what it covers (`coverage`) and never claims more.
- A capped scan is a coverage gap, never "no known candidates": when a string needle has more than
  `MAX_MATCHES_PER_NEEDLE` matches the later ones are not examined, so an empty result is `UNKNOWN` (the cap is the
  reason) and a result with candidates states that its coverage is partial.
"""

from __future__ import annotations

import hashlib
import re
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Any

from .antianalysis import API_TECHNIQUES, MARKER_TECHNIQUES, _dll_key, _function_keys
from .check_taxonomy import (BENIGN_URL_HOSTS, CATEGORIES, CONTEXT_ONLY, FROM_CATALOGUE, HASH_PARTNERS, IMPORT_SIGNALS,
                             PATTERN_SIGNALS, STRENGTH_ORDER, STRING_SIGNALS, URL_SIGNAL, Signal)
from .pe_dirs import ImportProfile, PeDirectoryError, scan_imports_image
from .pe_image import PeError, PeImage, parse_pe

MAX_FILE_BYTES = 32 * 1024 * 1024    # larger files are reported UNKNOWN, not scanned
MAX_CANDIDATES = 200                 # candidates kept in the evidence (after sorting); the rest is counted
MAX_RUNS_PER_SIGNAL = 4              # distinct strings listed per string signal
MAX_PATTERN_HITS = 4                 # hits listed per pattern signal
MAX_REFS = 4                         # code references listed per candidate
MAX_TEXT = 80                        # characters of a string shown in a candidate
MAX_MATCHES_PER_NEEDLE = 64          # raw matches examined per needle and encoding
MAX_SUPPRESSED = 300                 # suppressed entries kept in the evidence (the total is stated)

STATES = ("CANDIDATES_FOUND", "NO_KNOWN_CANDIDATES", "UNKNOWN")
EXEC_FLAGS = 0x20000000 | 0x20       # IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE

# --------------------------------------------------------------------------------------- CRT startup rule
# The statically linked MSVC C runtime (also in /MD executables: the startup objects are linked in) imports these
# together. When most of the sentinel set is present, the SUPPRESSIBLE imports below are indistinguishable from the
# runtime's own use, so they are not listed as candidates (they are listed under `suppressed` with this rule).
CRT_SENTINELS = frozenset({
    "kernel32!setunhandledexceptionfilter", "kernel32!unhandledexceptionfilter", "kernel32!isprocessorfeaturepresent",
    "kernel32!getsystemtimeasfiletime", "kernel32!queryperformancecounter", "kernel32!getcurrentprocessid",
    "kernel32!getcurrentthreadid", "kernel32!terminateprocess", "kernel32!getcurrentprocess",
    "kernel32!initializeslisthead"})
CRT_MIN_SENTINELS = 5
CRT_SUPPRESSIBLE = frozenset({
    "kernel32!isdebuggerpresent", "kernel32!getsystemtimeasfiletime", "kernel32!getmodulehandlew",
    "kernel32!getmodulehandleexw", "kernel32!getmodulehandlea", "kernel32!getmodulefilenamew",
    "kernel32!getmodulefilenamea"})
CRT_RULE = ("crt-startup-cluster: at least %d of the %d imports the statically linked C runtime startup pulls in "
            "together are present, so IsDebuggerPresent / GetSystemTimeAsFileTime / GetModuleHandle* / "
            "GetModuleFileName* are the runtime's own use until code outside the runtime is shown to call them "
            "(xrefs on the import)" % (CRT_MIN_SENTINELS, len(CRT_SENTINELS)))


# ----------------------------------------------------------------------------------------- signal tables
def _weaker(a: str, b: str) -> str:
    return a if STRENGTH_ORDER[a] >= STRENGTH_ORDER[b] else b


def _catalogue_signals() -> tuple[tuple[Signal, ...], tuple[Signal, ...]]:
    """Import and string signals taken from the anti-analysis catalogue through `FROM_CATALOGUE` (rows reused, not
    copied). A technique named in the map but absent from the catalogue is a table error and fails loudly."""
    known = {t.technique for t in API_TECHNIQUES} | {m.technique for m in MARKER_TECHNIQUES}
    missing = sorted(set(FROM_CATALOGUE) - known)
    if missing:
        raise RuntimeError(f"check_taxonomy.FROM_CATALOGUE names techniques the catalogue does not have: {missing}")
    imports: list[Signal] = []
    strings: list[Signal] = []
    for t in API_TECHNIQUES:
        if t.technique in FROM_CATALOGUE:
            code, cap, fp = FROM_CATALOGUE[t.technique]
            imports.append(Signal(code, "import", t.technique, _weaker(t.strength, cap), t.apis, t.why, fp))
    for m in MARKER_TECHNIQUES:
        if m.technique in FROM_CATALOGUE:
            code, cap, fp = FROM_CATALOGUE[m.technique]
            strings.append(Signal(code, "string", m.technique, _weaker(m.strength, cap), (m.needle,), m.why, fp))
    return tuple(imports), tuple(strings)


_CAT_IMPORTS, _CAT_STRINGS = _catalogue_signals()
ALL_IMPORT_SIGNALS = _CAT_IMPORTS + IMPORT_SIGNALS
ALL_STRING_SIGNALS = _CAT_STRINGS + STRING_SIGNALS
ALL_SIGNALS = ALL_IMPORT_SIGNALS + ALL_STRING_SIGNALS + (URL_SIGNAL,) + PATTERN_SIGNALS

_IMPORT_INDEX: dict[str, list[Signal]] = {}
for _s in ALL_IMPORT_SIGNALS:
    for _api in _s.match:
        _IMPORT_INDEX.setdefault(_api, []).append(_s)


def _import_signals_for(dll: str, function: str) -> list[Signal]:
    out: list[Signal] = []
    seen: set[int] = set()
    d = _dll_key(dll)
    for k in _function_keys(function):
        for s in _IMPORT_INDEX.get(f"{d}!{k}", ()):
            if id(s) not in seen:
                seen.add(id(s))
                out.append(s)
    return out


# ------------------------------------------------------------------------------------- byte patterns
_DOT = re.DOTALL
_RM_ABS = b"[\\x05\\x0d\\x15\\x1d\\x25\\x2d\\x35\\x3d]"
_PEB_READ = rb"(?:\x0f\xb6[\x40-\x7f]\x02|\x8a[\x40-\x7f]\x02|\x80[\x78-\x7f]\x02\x00)"
# (pattern id) -> (compiled regex, scope: "exec" | "file")
PATTERNS: dict[str, tuple[re.Pattern[bytes], str]] = {
    "peb-beingdebugged": (re.compile(
        rb"(?:\x65[\x48\x4c]\x8b[\x04\x0c\x14\x1c\x24\x2c\x34\x3c]\x25\x60\x00\x00\x00"
        rb"|\x64\xa1\x30\x00\x00\x00"
        rb"|\x64\x8b" + _RM_ABS + rb"\x30\x00\x00\x00).{0,16}?" + _PEB_READ, _DOT), "exec"),
    "rdtsc-pair": (re.compile(rb"\x0f\x31.{0,64}?\x0f\x31", _DOT), "exec"),
    "cpuid-hypervisor": (re.compile(
        rb"(?:\xb8\x00\x00\x00\x40\x0f\xa2"
        rb"|\xb8\x01\x00\x00\x00\x0f\xa2.{0,32}?(?:\x0f\xba[\xe0-\xe7]\x1f|\xf7[\xc0-\xc7]\x00\x00\x00\x80"
        rb"|\x81[\xe0-\xe7]\x00\x00\x00\x80|\xa9\x00\x00\x00\x80))", _DOT), "exec"),
    "fnv-1a-prime": (re.compile(rb"(?:\x69[\xc0-\xff]|[\xb8-\xbf])\x93\x01\x00\x01", _DOT), "exec"),
    "crc32-table": (re.compile(rb"\x00\x00\x00\x00\x96\x30\x07\x77\x2c\x61\x0e\xee\xba\x51\x09\x99", _DOT), "file"),
}
_LEA_RIP = re.compile(rb"(?P<rex>[\x48\x4c])?(?P<op>[\x8b\x8d])(?P<rm>[\x05\x0d\x15\x1d\x25\x2d\x35\x3d])", _DOT)
_CALL_RIP = re.compile(rb"\xff[\x15\x25]", _DOT)


# --------------------------------------------------------------------------------------------- model
@dataclass
class Scan:
    """Mutable working state of one inventory run."""
    data: bytes
    img: PeImage | None
    candidates: list[dict] = field(default_factory=list)
    suppressed: list[dict] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)       # coverage gaps from a cap / truncation (not an unreadable input)
    notes: list[str] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)


def _hx(v: int | None) -> str:
    return "none" if v is None else f"0x{v:x}"


def _safe(s: str) -> str:
    """Target-controlled text on one raw line: printable ASCII only, quotes and backslashes escaped."""
    return "".join(c if 32 <= ord(c) < 127 and c not in '"\\' else f"\\x{ord(c) & 0xff:02x}" for c in s)


def _rva_of_offset(img: PeImage | None, off: int) -> tuple[int | None, str | None]:
    if img is None:
        return None, None
    if off < min(img.size_of_headers, img.file_size):
        return off, "(headers)"
    for s in img.sections:
        if s.raw_ptr <= off < s.raw_ptr + s.raw_size:
            return s.rva + (off - s.raw_ptr), s.name
    return None, None


def _exec_sections(img: PeImage, data: bytes) -> list[tuple[int, bytes, str]]:
    out = []
    for s in img.sections:
        if not s.flags & EXEC_FLAGS or not s.raw_size:
            continue
        ptr = s.raw_ptr & ~0x1FF
        n = max(0, min(s.raw_size, s.extent, len(data) - ptr))
        if n:
            out.append((s.rva, data[ptr:ptr + n], s.name.strip("\0 ")))
    return out


def _functions(img: PeImage | None, data: bytes) -> tuple[list[int], list[tuple[int, int, int]], str]:
    """x64 `.pdata` function starts (sorted) and rows; (`[]`, `[]`, reason) when unavailable."""
    if img is None:
        return [], [], "no parseable PE"
    if img.machine != 0x8664:
        return [], [], "no function table (not x64)"
    try:
        from .dataflow.eh import UnwindData
        u = UnwindData(img, lambda off, n: data[off:off + n])
    except Exception as e:  # noqa: BLE001 - a missing function table only removes the `function` field
        return [], [], f"function table unreadable ({type(e).__name__})"
    if u.error:
        return [], [], f"function table unreadable ({u.error})"
    return list(u.begins), list(u.rows), ("function table truncated" if u.truncated else "")


def _function_of(starts: list[int], rows: list[tuple[int, int, int]], rva: int | None) -> int | None:
    if rva is None or not starts:
        return None
    k = bisect_right(starts, rva) - 1
    if k < 0 or rows[k][1] <= rva:
        return None
    return rows[k][0]


# --------------------------------------------------------------------------------------------- strings
def _ident(b: int) -> bool:
    return 48 <= b <= 57 or 65 <= b <= 90 or 97 <= b <= 122 or b == 95


def _word_needle(needle: str) -> bool:
    """A needle that starts and ends with an identifier character must match a whole word."""
    return _ident(ord(needle[0])) and _ident(ord(needle[-1]))


def _bounded(low: bytes, idx: int, enc: str, length: int) -> bool:
    if enc == "ascii":
        before = low[idx - 1] if idx > 0 else 0
        after = low[idx + length] if idx + length < len(low) else 0
        return not _ident(before) and not _ident(after)

    def unit(pos: int) -> int:
        if pos < 0 or pos + 1 >= len(low):
            return 0
        return low[pos] | (low[pos + 1] << 8)
    return not _ident(unit(idx - 2)) and not _ident(unit(idx + length))


def _run_bounds(data: bytes, idx: int, enc: str, length: int) -> tuple[int, int]:
    """[start, end) of the printable run that contains the match (ASCII bytes, or UTF-16LE code units)."""
    if enc == "ascii":
        a = idx
        while a > 0 and 32 <= data[a - 1] <= 126:
            a -= 1
        b = idx + length
        while b < len(data) and 32 <= data[b] <= 126:
            b += 1
        return a, b
    a = idx
    while a >= 2 and 32 <= data[a - 2] <= 126 and data[a - 1] == 0:
        a -= 2
    b = idx + length
    while b + 1 < len(data) and 32 <= data[b] <= 126 and data[b + 1] == 0:
        b += 2
    return a, b


def _decode(data: bytes, a: int, b: int, enc: str) -> str:
    raw = data[a:b]
    return raw.decode("latin-1") if enc == "ascii" else raw.decode("utf-16-le", "replace")


def _window(text: str, k: int, n: int, from_match: bool = False) -> str:
    """At most MAX_TEXT characters of `text` around the match at char index k (length n); from the match on for a URL."""
    if len(text) <= MAX_TEXT:
        return text
    start = max(0, min(k if from_match else k - 24, len(text) - MAX_TEXT))
    return text[start:start + MAX_TEXT]


def _import_name_spans(table: ImportProfile | None) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    if table is not None:
        for fact in table.all_tables:
            for fn in fact.functions:
                if fn.name is not None and fn.file_offset is not None:
                    spans.append((fn.file_offset, fn.file_offset + len(fn.name) + 1))
    spans.sort()
    return spans


def _in_spans(spans: list[tuple[int, int]], off: int) -> bool:
    k = bisect_right(spans, (off, 1 << 62)) - 1
    return k >= 0 and spans[k][0] <= off < spans[k][1]


def _scan_strings(sc: Scan, spans: list[tuple[int, int]]) -> None:
    data = sc.data
    low = data.lower()
    # (enc, run key) -> list of (signal, needle, match idx, char index of match in run)
    groups: dict[tuple[str, int], dict[str, Any]] = {}
    urls_seen: dict[tuple[str, int], dict[str, Any]] = {}
    total_needles = 0
    capped: list[str] = []
    for sig in ALL_STRING_SIGNALS + (URL_SIGNAL,):
        for needle in sig.match:
            total_needles += 1
            word = _word_needle(needle)
            for enc, pat in (("ascii", needle.lower().encode("ascii")),
                             ("utf-16le", needle.lower().encode("utf-16-le"))):
                start = 0
                seen = 0
                while True:
                    if seen >= MAX_MATCHES_PER_NEEDLE:
                        if low.find(pat, start) >= 0:
                            capped.append(needle)
                        break
                    idx = low.find(pat, start)
                    if idx < 0:
                        break
                    start = idx + max(1, len(pat))
                    if word and not _bounded(low, idx, enc, len(pat)):
                        continue
                    if enc == "ascii" and _in_spans(spans, idx):
                        continue                              # the import table's own name string
                    seen += 1
                    a, b = _run_bounds(data, idx, enc, len(pat))
                    key = (enc, a if (b - a) <= 4 * MAX_TEXT * (1 if enc == "ascii" else 2) else idx)
                    g = (urls_seen if sig is URL_SIGNAL else groups).setdefault(
                        key, {"enc": enc, "a": a, "b": b, "hits": []})
                    g["hits"].append((sig, needle, idx, len(pat)))
    sc.coverage["strings"] = {"scanned": True, "bytes": len(data), "needles": total_needles,
                              "encodings": ["ascii", "utf-16le"],
                              "note": "UTF-16LE covers printable ASCII code units; other encodings and "
                                      "obfuscated / stack-built strings are not seen"}
    # one candidate per distinct string run, the strongest signal first
    per_signal: dict[tuple[str, str], int] = {}
    runs: list[tuple[int, dict[str, Any]]] = []
    for key, g in groups.items():
        runs.append((min(h[2] for h in g["hits"]), g))
    for url_key, g in urls_seen.items():
        if url_key not in groups:
            runs.append((min(h[2] for h in g["hits"]), g))
        else:
            groups[url_key]["hits"].extend(g["hits"])
    runs.sort(key=lambda t: t[0])
    for _, g in runs:
        hits = sorted(g["hits"], key=lambda h: (STRENGTH_ORDER[h[0].strength], h[0] is not URL_SIGNAL, -len(h[1]), h[0].code,
                                                  h[0].name))
        sig, needle, idx, plen = hits[0]
        enc = g["enc"]
        text_full = _decode(data, g["a"], g["b"], enc)
        k = (idx - g["a"]) // (1 if enc == "ascii" else 2)
        shown = _window(text_full, k, len(needle), from_match=sig is URL_SIGNAL)
        if sig is URL_SIGNAL:
            host = re.match(r"https?://([^/:?#\s\\\"'<>]*)", text_full[k:], re.I)
            host_s = (host.group(1).lower() if host else "")
            if not host_s or any(host_s == h or host_s.endswith("." + h) for h in BENIGN_URL_HOSTS):
                sc.suppressed.append({"rule": "benign-url-host", "signal": sig.name, "code": sig.code,
                                      "text": _safe(shown), "file_offset": idx,
                                      "why": f"URL host {_safe(host_s) or '(empty)'} is a namespace, schema or "
                                             "certificate endpoint, not an activation endpoint"})
                continue
        n = per_signal.get((sig.code, sig.name), 0)
        if n >= MAX_RUNS_PER_SIGNAL:
            per_signal[(sig.code, sig.name)] = n + 1
            continue
        per_signal[(sig.code, sig.name)] = n + 1
        rva, section = _rva_of_offset(sc.img, idx)
        others = sorted({h[0].code for h in hits if h[0].code != sig.code})
        sc.candidates.append({
            "code": sig.code, "kind": "string", "signal": sig.name, "strength": sig.strength,
            "string": _safe(shown), "encoding": enc, "needle": needle, "rva": rva, "section": section,
            "file_offset": idx, "also": others, "why": sig.why, "fp": sig.fp})
    if capped:
        names = sorted(set(capped))
        sc.notes.append(f"{len(names)} string needle(s) had more than {MAX_MATCHES_PER_NEEDLE} matches; the "
                        "later ones were not examined: " + ", ".join(names[:6]))
        sc.coverage["strings"]["capped_needles"] = len(names)
        sc.gaps.append(f"string scan capped: {len(names)} needle(s) had more than {MAX_MATCHES_PER_NEEDLE} matches "
                       "and the later match(es) were not examined, so string coverage is partial and a candidate "
                       "behind the cap may be unseen")
    dropped = sum(max(0, n - MAX_RUNS_PER_SIGNAL) for n in per_signal.values())
    if dropped:
        sc.notes.append(f"{dropped} further string(s) of signals already listed {MAX_RUNS_PER_SIGNAL} times were "
                        "not listed")


# ------------------------------------------------------------------------------------------- patterns
def _scan_patterns(sc: Scan) -> list[tuple[int, bytes, str]]:
    img = sc.img
    if img is None:
        sc.unknowns.append("instruction patterns not scanned: the file is not a parseable PE (no executable "
                           "sections known)")
        sc.coverage["patterns"] = {"scanned": False}
        return []
    secs = _exec_sections(img, sc.data)
    sc.coverage["patterns"] = {"scanned": bool(secs), "sections": [s[2] for s in secs],
                               "bytes": sum(len(s[1]) for s in secs), "ids": sorted(PATTERNS)}
    if not secs:
        sc.unknowns.append("instruction patterns not scanned: no executable section with file bytes")
        return []
    by_id = {s.name: s for s in PATTERN_SIGNALS}
    for pid, (rx, scope) in PATTERNS.items():
        sig = by_id[pid]
        found = 0
        total = 0
        spaces: list[tuple[int, bytes, str]] = secs if scope == "exec" else [(0, sc.data, "(file)")]
        for base, blob, name in spaces:
            for m in rx.finditer(blob):
                total += 1
                if found >= MAX_PATTERN_HITS:
                    continue
                found += 1
                if scope == "exec":
                    rva, off, section = base + m.start(), None, name
                    off = _file_offset_of_rva(img, rva)
                else:
                    off = m.start()
                    rva, section = _rva_of_offset(img, off)
                sc.candidates.append({
                    "code": sig.code, "kind": "pattern", "signal": sig.name, "strength": sig.strength,
                    "rva": rva, "section": section, "file_offset": off,
                    "bytes": m.group(0)[:16].hex(), "why": sig.why, "fp": sig.fp})
        if total > found:
            sc.notes.append(f"pattern {pid}: {total - found} further match(es) were not listed")
    return secs


def _file_offset_of_rva(img: PeImage, rva: int) -> int | None:
    for s in img.sections:
        if s.rva <= rva < s.rva + s.extent:
            rel = rva - s.rva
            if rel < s.raw_size:
                return (s.raw_ptr & ~0x1FF) + rel
    return None


# --------------------------------------------------------------------------------------------- imports
def _scan_imports(sc: Scan, table: ImportProfile | None) -> None:
    if table is None:
        sc.coverage["imports"] = {"scanned": False}
        return
    names: list[tuple[str, Any]] = []
    for fact in table.all_tables:
        for fn in fact.functions:
            if fn.name is not None:
                names.append((fact.dll, fn))
    keyset = {f"{_dll_key(d)}!{k}" for d, fn in names for k in _function_keys(fn.name)}
    sentinels = sorted(keyset & CRT_SENTINELS)
    cluster = len(sentinels) >= CRT_MIN_SENTINELS
    sc.coverage["imports"] = {"scanned": True, "complete": table.complete, "dlls": len(table.all_tables),
                              "named_functions": len(names), "delay_imports": len(table.delay_imports),
                              "crt_startup_cluster": cluster, "crt_sentinels_present": len(sentinels)}
    if not table.complete:
        sc.unknowns.append("imports incomplete: " + "; ".join(table.unknowns or ("an import table was cut short",)))
    elif not names:
        sc.unknowns.append("no named imports were read: import-based signals have no input here (packed, stubbed, "
                           "ordinal-only or statically linked?)")
    if {"kernel32!getprocaddress", "ntdll!ldrgetprocedureaddress"} & keyset:
        sc.notes.append("GetProcAddress / LdrGetProcedureAddress is imported: APIs can be resolved at run time and "
                        "stay invisible to the import table (string signals may still show their names)")
    if any(_dll_key(f.dll).startswith(("api-ms-win-", "ext-ms-win-")) for f in table.all_tables):
        sc.notes.append("API-set forwarder DLLs are imported: some APIs may be forwarded and missed by name")
    grouped: dict[int, dict[str, Any]] = {}
    for dll, fn in names:
        for sig in _import_signals_for(dll, fn.name):
            canon = f"{_dll_key(dll)}!{fn.name.lower()}"
            if cluster and canon in CRT_SUPPRESSIBLE:
                sc.suppressed.append({"rule": "crt-startup-cluster", "signal": sig.name, "code": sig.code,
                                      "dll": _safe(dll), "function": _safe(fn.name), "iat_rva": fn.thunk_rva,
                                      "why": CRT_RULE})
                continue
            g = grouped.setdefault(id(sig), {"sig": sig, "fns": []})
            g["fns"].append((dll, fn))
    for g in grouped.values():
        sig: Signal = g["sig"]
        fns = sorted(g["fns"], key=lambda t: (t[0].lower(), t[1].name))
        dll, first = fns[0]
        rva, section = first.thunk_rva, "import"
        sc.candidates.append({
            "code": sig.code, "kind": "import", "signal": sig.name, "strength": sig.strength,
            "dll": _safe(dll), "function": _safe(first.name), "apis": [_safe(f.name) for _, f in fns][:8],
            "iat_rva": first.thunk_rva, "iat_rvas": [f.thunk_rva for _, f in fns][:8],
            "rva": None, "section": section, "file_offset": first.file_offset, "why": sig.why, "fp": sig.fp})
    # suppressed imports are one line each; dedupe stable
    sc.suppressed.sort(key=lambda s: (s["rule"], s.get("function") or s.get("text") or ""))


# ----------------------------------------------------------------------------------------------- refs
def _scan_refs(sc: Scan, secs: list[tuple[int, bytes, str]], starts: list[int],
               rows: list[tuple[int, int, int]]) -> None:
    """Code locations that point at a listed string (data RVA) or call a listed import (IAT slot)."""
    img = sc.img
    if img is None or not secs:
        return
    targets: dict[int, list[dict]] = {}
    for c in sc.candidates:
        if c["kind"] == "string" and c.get("rva") is not None:
            targets.setdefault(c["rva"], []).append(c)
        elif c["kind"] == "import":
            for r in c.get("iat_rvas", ()):
                targets.setdefault(r, []).append(c)
    if not targets:
        return
    refs: dict[int, dict[int, None]] = {}          # id(candidate) -> ordered set of code RVAs
    if img.is64:
        for base, blob, _ in secs:
            for m in _LEA_RIP.finditer(blob):
                pos = m.end()
                if pos + 4 > len(blob):
                    continue
                disp = int.from_bytes(blob[pos:pos + 4], "little", signed=True)
                tgt = base + pos + 4 + disp
                for c in targets.get(tgt, ()):
                    refs.setdefault(id(c), {})[base + m.start()] = None
            for m in _CALL_RIP.finditer(blob):
                pos = m.end()
                if pos + 4 > len(blob):
                    continue
                disp = int.from_bytes(blob[pos:pos + 4], "little", signed=True)
                for c in targets.get(base + pos + 4 + disp, ()):
                    refs.setdefault(id(c), {})[base + m.start()] = None
        how = "x64 RIP-relative operands (lea/mov/call/jmp) that resolve to the target"
    else:
        ib = img.image_base
        for rva, cands in targets.items():
            pat = (ib + rva).to_bytes(4, "little")
            for base, blob, _ in secs:
                start = 0
                n = 0
                while n < 16:
                    i = blob.find(pat, start)
                    if i < 0:
                        break
                    start = i + 1
                    n += 1
                    prev = blob[i - 1] if i >= 1 else -1
                    prev2 = blob[i - 2] if i >= 2 else -1
                    ok = (prev in (0x68, 0xa1, 0xa3) or 0xb8 <= prev <= 0xbf
                          or (prev & 0xC7 == 0x05 and prev2 in (0x8b, 0x8d, 0x89, 0xff, 0x3b, 0x39, 0x03, 0x2b,
                                                                 0x33, 0x31, 0x0b, 0x23, 0x85, 0x83, 0x81, 0xc7)))
                    if ok:
                        at = base + i - (2 if prev & 0xC7 == 0x05 and prev not in (0x68, 0xa1, 0xa3) else 1)
                        for c in cands:
                            refs.setdefault(id(c), {})[at] = None
        how = "x86 absolute operands (push/mov/call [imm32]) equal to the target address"
    for c in sc.candidates:
        r = sorted(refs.get(id(c), {}))
        if r:
            c["refs"] = [{"rva": a, "function": _function_of(starts, rows, a)} for a in r[:MAX_REFS]]
            c["ref_count"] = len(r)
    sc.coverage["refs"] = {"scanned": True, "method": how,
                           "note": "byte-pattern match, heuristic: confirm in xrefs / disassemble"}


# -------------------------------------------------------------------------------------------- driver
def inventory(data: bytes | None, *, protection: str | None = None) -> dict:
    """The full inventory of one PE as a plain dict (see `render_lines`). Never raises on target content.

    `data=None` means the file is over the size limit. `protection`: the `static_coverage` value of the protection
    diagnosis (`likely_partial` / `possibly_partial` mean the visible code may be a stub)."""
    if data is None:
        return _finish(Scan(b"", None), None, protection,
                       "file is larger than the %d MiB check-inventory limit" % (MAX_FILE_BYTES // (1024 * 1024)))
    sc = Scan(data, None)
    try:
        sc.img = parse_pe(lambda off, n: data[off:off + n], len(data))
    except (PeError, ValueError, IndexError, OSError) as e:
        sc.unknowns.append(f"not a readable PE: {_safe(str(e))[:160]}; imports and instruction patterns not scanned "
                           "(raw string scan only)")
    table: ImportProfile | None = None
    if sc.img is not None:
        try:
            table = scan_imports_image(sc.img, lambda off, n: data[off:off + n])
        except (PeError, PeDirectoryError) as e:
            sc.unknowns.append(f"imports unreadable: {_safe(str(e))[:160]}")
    _scan_imports(sc, table)
    spans = _import_name_spans(table)
    _scan_strings(sc, spans)
    secs = _scan_patterns(sc)
    starts, rows, ftab = _functions(sc.img, data)
    if ftab:
        sc.notes.append(ftab)
    sc.coverage["functions"] = {"source": ".pdata (x64)" if starts else "none", "count": len(starts)}
    _scan_refs(sc, secs, starts, rows)
    for c in sc.candidates:
        if c["kind"] == "pattern":
            c["function"] = _function_of(starts, rows, c.get("rva"))
    _apply_context_rule(sc)
    return _finish(sc, hashlib.sha256(data).hexdigest(), protection, None)


def _apply_context_rule(sc: Scan) -> None:
    """A CONTEXT_ONLY signal stays a candidate only next to a hash / checksum partner; else it is suppressed."""
    partner = sorted({c["signal"] for c in sc.candidates if c["signal"] in HASH_PARTNERS})
    keep: list[dict] = []
    for c in sc.candidates:
        if c["signal"] not in CONTEXT_ONLY:
            keep.append(c)
        elif partner:
            c["with"] = partner
            keep.append(c)
        else:
            sc.suppressed.append({
                "rule": "needs-hash-partner", "signal": c["signal"], "code": c["code"],
                "dll": c.get("dll"), "function": c.get("function"), "iat_rva": c.get("iat_rva"),
                "why": "needs-hash-partner: reading ones own module path, memory map or memory is ordinary program "
                       "behaviour; it is listed as a self-integrity candidate only when a hash / checksum signal "
                       "(" + ", ".join(sorted(HASH_PARTNERS)) + ") is present in the same file"})
    sc.candidates[:] = keep


def _finish(sc: Scan, sha: str | None, protection: str | None, too_big: str | None) -> dict:
    cands = sc.candidates
    cands.sort(key=lambda c: (STRENGTH_ORDER[c["strength"]], c["code"], c["signal"],
                              c["rva"] if c.get("rva") is not None else (c.get("iat_rva") or 0),
                              c.get("file_offset") or 0))
    total = len(cands)
    # per-code counts cover EVERY candidate, not only the ones kept in the evidence (which is capped below)
    by_code = {code: sum(1 for c in cands if c["code"] == code) for code in CATEGORIES}
    shown = cands[:MAX_CANDIDATES]
    if total > len(shown):
        sc.notes.append(f"{total - len(shown)} candidate(s) beyond the first {MAX_CANDIDATES} were not listed in the "
                        "evidence (candidate_count and by_code count all of them)")
    cands = shown
    for i, c in enumerate(cands, 1):
        c["id"] = f"K{i}"
        c["category"] = CATEGORIES[c["code"]]
    packed = protection in ("likely_partial", "possibly_partial")
    reason = too_big
    unknowns = list(sc.unknowns) + list(sc.gaps)
    if too_big:
        unknowns.append(too_big)
    if packed:
        unknowns.append("protection diagnosis says static coverage is " + protection.replace("_", " ") + ": the "
                        "visible imports, strings and code may belong to a stub, so the real checks may be unseen")
    if cands:
        state = "CANDIDATES_FOUND"
    elif unknowns:
        state = "UNKNOWN"
        reason = reason or unknowns[0]
    else:
        state = "NO_KNOWN_CANDIDATES"
    suppressed = sc.suppressed[:MAX_SUPPRESSED]
    if len(sc.suppressed) > MAX_SUPPRESSED:
        sc.notes.append(f"{len(sc.suppressed) - MAX_SUPPRESSED} further suppressed entries were not listed")
    if state == "CANDIDATES_FOUND":
        listed = ", ".join(f"{k} {CATEGORIES[k]} x{v}" for k, v in by_code.items() if v)
        statement = (f"{total} check candidate(s): {listed}. A candidate is a static observation that a known "
                     "signal is present at a place; it does not show that the code is a check, that it runs, or "
                     "what it decides. Read the code (decompile / disassemble) before concluding anything.")
        if unknowns:
            statement += " Coverage gaps: " + "; ".join(unknowns) + "."
    elif state == "NO_KNOWN_CANDIDATES":
        statement = ("No known check signal found among the scanned imports, strings and instruction patterns. This "
                     "does not mean the binary has no checks: custom checks, obfuscated or stack-built strings, "
                     "run-time resolved APIs and packed or virtualized code are not detected.")
    else:
        statement = (f"Check inventory could not be fully assessed ({reason}). No signal was found by what did run, "
                     "but missing coverage is unknown, not 'no checks'.")
    return {"state": state, "statement": statement, "candidates": cands, "candidate_count": total,
            "suppressed": suppressed, "suppressed_total": len(sc.suppressed), "by_code": by_code, "coverage": sc.coverage, "unknowns": unknowns,
            "notes": sc.notes, "reason": reason, "sha256": sha, "file_size": len(sc.data)}


# ------------------------------------------------------------------------------------------- evidence text
def candidate_line(c: dict) -> str:
    """The quotable evidence line of one candidate; a reply's `quote` is its prefix `check K<n> C<m> signal=<name>`."""
    bits = [f"check {c['id']} {c['code']} signal={c['signal']}", f"kind={c['kind']}", f"strength={c['strength']}"]
    if c["kind"] == "import":
        bits += [f"dll={c['dll']}", f"function={c['function']}"]
        if len(c.get("apis", ())) > 1:
            bits.append("apis=" + ",".join(c["apis"]))
        bits.append(f"iat_rva={_hx(c['iat_rva'])}")
    elif c["kind"] == "string":
        bits.append(f'string="{c["string"]}"')
        bits.append(f"enc={c['encoding']}")
        if c.get("rva") is not None:
            bits.append(f"rva={_hx(c['rva'])}")
    else:
        bits.append(f"rva={_hx(c['rva'])}")
        if c.get("function") is not None:
            bits.append(f"function={_hx(c['function'])}")
        bits.append(f"bytes={c['bytes']}")
    if c.get("section") and c["kind"] != "import":
        bits.append(f"section={_safe(c['section'])}")
    if c.get("file_offset") is not None:
        bits.append(f"file_offset={_hx(c['file_offset'])}")
    if c.get("refs"):
        parts = []
        for r in c["refs"]:
            parts.append(_hx(r["rva"]) + (f"@fn{_hx(r['function'])}" if r.get("function") is not None else ""))
        label = "calls" if c["kind"] == "import" else "refs"
        bits.append(f"{label}=" + ",".join(parts) + (f"+{c['ref_count'] - len(c['refs'])}more"
                                                      if c["ref_count"] > len(c["refs"]) else ""))
    if c.get("also"):
        bits.append("also=" + ",".join(c["also"]))
    if c.get("with"):
        bits.append("with=" + ",".join(c["with"]))
    return " ".join(bits) + f" | {c['category']}; {c['why']}; false positives: {c['fp']}"


def render_lines(r: dict) -> list[str]:
    """Raw evidence text, one fact per line (header, coverage, candidates, suppressed, unknowns, notes, statement)."""
    lines = [f"check_inventory state={r['state']} candidates={r['candidate_count']} "
             f"suppressed={r['suppressed_total']}" + (f" sha256={r['sha256']} file_size={r['file_size']}"
                                                     if r["sha256"] else "")]
    cov = r["coverage"]
    imp = cov.get("imports") or {}
    if imp.get("scanned"):
        lines.append(f"coverage imports=scanned complete={str(imp['complete']).lower()} dlls={imp['dlls']} "
                     f"named_functions={imp['named_functions']} crt_startup_cluster="
                     f"{str(imp['crt_startup_cluster']).lower()}")
    else:
        lines.append("coverage imports=UNKNOWN not scanned")
    st = cov.get("strings") or {}
    lines.append(f"coverage strings={'scanned' if st.get('scanned') else 'UNKNOWN'} bytes={st.get('bytes', 0)} "
                 f"needles={st.get('needles', 0)} encodings=ascii,utf-16le")
    pt = cov.get("patterns") or {}
    lines.append(f"coverage patterns={'scanned' if pt.get('scanned') else 'UNKNOWN'} sections="
                 f"{','.join(_safe(s) for s in pt.get('sections', ())) or 'none'} bytes={pt.get('bytes', 0)}")
    fn = cov.get("functions") or {}
    lines.append(f"coverage functions source={fn.get('source', 'none')} count={fn.get('count', 0)}")
    if cov.get("refs"):
        lines.append("coverage refs=scanned (heuristic)")
    for c in r["candidates"]:
        lines.append(candidate_line(c))
    for s in r["suppressed"]:
        if s["rule"] in ("crt-startup-cluster", "needs-hash-partner"):
            lines.append(f"suppressed rule={s['rule']} signal={s['signal']} code={s['code']} dll={s['dll']} "
                         f"function={s['function']} iat_rva={_hx(s['iat_rva'])} | {s['why']}")
        else:
            lines.append(f"suppressed rule={s['rule']} signal={s['signal']} code={s['code']} "
                         f'string="{s["text"]}" file_offset={_hx(s["file_offset"])} | {s["why"]}')
    lines += [f"unknown {u}" for u in r["unknowns"]]
    lines += [f"note {n}" for n in r["notes"]]
    lines.append("statement " + r["statement"])
    return lines
