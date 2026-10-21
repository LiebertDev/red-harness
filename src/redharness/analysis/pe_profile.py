"""Static PE profile for `target_open`: every field is computed from the file bytes; nothing is run or loaded.

Engine independent. A field that cannot be read is reported `unavailable(<reason>)`, never guessed or omitted.
The profile states neutral facts (sizes, entropy, flags, placement). It never names a packer or protector; the
separate protection diagnosis (analysis/protection.py) owns that and uses the SAME entry-point, overlay and
section rules, so the two cannot disagree on a shared fact (tests assert this).

Untrusted strings (section names, PDB name) are escaped to printable ASCII and length-capped; every list is capped.
Output is deterministic (header order, fixed formats).
"""

from __future__ import annotations

import datetime as _dt
import struct
from dataclasses import dataclass
from typing import Callable

from .pe_dirs import _directory, _read_mapped, read_data_directories, scan_imports_image, scan_tls_image
from .pe_image import PeError, PeImage, Section, parse_pe
from .protection import HIGH_ENTROPY_MIN_RAW, HIGH_ENTROPY_THRESHOLD, RAW_POINTER_ALIGN, compute_entropy

Reader = Callable[[int, int], bytes]

MAX_NAME_LEN = 24
MAX_TLS_SHOWN = 8
MAX_DEBUG_ENTRIES = 8
MAX_PDB_NAME = 128
COUNT_CAP = 1_000_000
MINIMAL_IMPORT_MAX = 10
EXPORT_DIR, SECURITY_DIR, DEBUG_DIR = 0, 4, 6

SCN_CODE, SCN_INIT, SCN_UNINIT = 0x20, 0x40, 0x80
SCN_DISCARDABLE, SCN_SHARED = 0x02000000, 0x10000000
SCN_X, SCN_R, SCN_W = 0x20000000, 0x40000000, 0x80000000

SUBSYSTEMS = {0: "unknown", 1: "native", 2: "windows_gui", 3: "windows_cui", 5: "os2_cui", 7: "posix_cui",
              9: "windows_ce_gui", 10: "efi_application", 11: "efi_boot_service_driver", 12: "efi_runtime_driver",
              13: "efi_rom", 14: "xbox", 16: "windows_boot_application"}
DEBUG_TYPES = {0: "unknown", 1: "coff", 2: "codeview", 3: "fpo", 4: "misc", 5: "exception", 6: "fixup",
               9: "borland", 10: "reserved10", 11: "clsid", 12: "vc_feature", 13: "pogo", 14: "iltcg", 16: "repro",
               20: "ex_dllcharacteristics"}
LOADER_FUNCS = frozenset(n.lower() for n in (
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress", "GetModuleHandleA",
    "GetModuleHandleW", "GetModuleHandleExA", "GetModuleHandleExW", "VirtualAlloc", "VirtualProtect",
    "VirtualFree", "VirtualQuery", "ExitProcess", "FreeLibrary"))


def esc(s: str, cap: int = MAX_NAME_LEN) -> str:
    """Untrusted text on one line: printable ASCII only, quotes/backslash escaped, length-capped."""
    out = []
    for c in s:
        o = ord(c)
        if c in '\\"':
            out.append("\\" + c)
        elif 32 <= o < 127:
            out.append(c)
        else:
            out.append(f"\\x{o & 0xff:02x}")
    t = "".join(out)
    return t if len(t) <= cap else t[:cap] + "..."


def _hx(v: int | None) -> str:
    return "unavailable" if v is None else f"0x{v:x}"


def _na(reason: str) -> str:
    return f"unavailable({esc(reason, 120)})"


@dataclass(frozen=True)
class SectionProfile:
    index: int
    name: str
    rva: int
    vsize: int
    raw_offset: int
    raw_size: int
    characteristics: int
    perms: str
    flags: tuple[str, ...]
    entropy: str | None          # "x.xx"; None = not measured (no raw bytes in the file)
    notes: tuple[str, ...]


@dataclass(frozen=True)
class PeProfile:
    pe_format: str
    machine: int
    arch: str
    subsystem: int
    timestamp: int
    linker: str
    image_base: int
    size_of_image: int
    file_size: int
    file_characteristics: int
    dll_characteristics: int
    dll_flags: dict
    sections: tuple[SectionProfile, ...]
    entry_rva: int
    entry_section: str | None
    entry_in_exec: bool | None
    overlay_offset: int
    overlay_size: int
    sig_offset: int | None       # security directory (a FILE offset); None when the directory is empty
    sig_size: int
    sig_in_overlay: bool | None
    tls: dict
    imports: dict
    exports: dict
    debug: dict


def _timestamp_text(ts: int) -> str:
    if ts == 0:
        return "0x0 (not set)"
    try:
        iso = _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        iso = "out-of-range"
    return f"0x{ts:x} ({iso}; header value, can be forged)"


def _section(i: int, s: Section, read: Reader, file_size: int) -> SectionProfile:
    f = s.flags
    perms = ("R" if f & SCN_R else "-") + ("W" if f & SCN_W else "-") + ("X" if f & SCN_X else "-")
    flags = [n for bit, n in ((SCN_CODE, "CODE"), (SCN_INIT, "INITDATA"), (SCN_UNINIT, "UNINITDATA"),
                              (SCN_SHARED, "SHARED"), (SCN_DISCARDABLE, "DISCARDABLE")) if f & bit]
    notes: list[str] = []
    off = s.raw_ptr & ~(RAW_POINTER_ALIGN - 1)
    entropy: str | None = None
    if s.raw_size == 0:
        notes.append("no raw data (entropy not measured)")
    else:
        avail = max(0, min(s.raw_size, file_size - off))
        if avail < s.raw_size:
            notes.append(f"raw data runs past end of file ({avail} of {s.raw_size} bytes present)")
        if avail:
            entropy = f"{compute_entropy(read(off, avail)):.2f}"
            if float(entropy) >= HIGH_ENTROPY_THRESHOLD and avail >= HIGH_ENTROPY_MIN_RAW:
                notes.append("high entropy (compressed or encrypted bytes are possible)")
        else:
            notes.append("no raw bytes present in file (entropy not measured)")
    if f & SCN_X and f & SCN_W:
        notes.append("writable+executable")
    if s.raw_size and s.vsize > 4 * s.raw_size and s.vsize - s.raw_size >= 0x1000:
        notes.append("virtual size >> raw size")
    elif s.raw_size == 0 and s.vsize > 0 and not f & SCN_UNINIT:
        notes.append("virtual size > 0 with no raw data")
    return SectionProfile(i, esc(s.name), s.rva, s.vsize, off, s.raw_size, f, perms, tuple(flags), entropy,
                          tuple(notes))


def _dll_flags(dc: int, fc: int) -> dict:
    return {"aslr": bool(dc & 0x40), "dep": bool(dc & 0x100), "cfg": bool(dc & 0x4000),
            "high_entropy_va": bool(dc & 0x20), "relocs_stripped": bool(fc & 0x1)}


def _imports(img: PeImage, read: Reader) -> dict:
    try:
        p = scan_imports_image(img, read)
    except PeError as e:
        return {"status": "unreadable", "reason": str(e)}
    total = p.function_count
    names = [f.name for t in p.all_tables for f in t.functions]
    out = {"status": "ok" if p.complete else "partial", "functions": min(total, COUNT_CAP),
           "dlls": len(p.imports), "delay_functions": sum(len(t.functions) for t in p.delay_imports),
           "delay_dlls": len(p.delay_imports), "complete": p.complete, "minimal": total <= MINIMAL_IMPORT_MAX,
           "loader_only": bool(total) and all(n is not None and n.lower() in LOADER_FUNCS for n in names)}
    if not p.complete:
        out["reason"] = "; ".join(p.unknowns)[:200]
    return out


def _exports(img: PeImage, read: Reader, dirs: tuple) -> dict:
    d = _directory(dirs, EXPORT_DIR)
    if not d.rva:
        return {"status": "absent"}
    raw = _read_mapped(img, read, d.rva, 40) if d.rva < img.size_of_image else None
    if raw is None:
        return {"status": "unreadable", "reason": f"export directory unreadable (rva 0x{d.rva:x})"}
    nfun, nname = struct.unpack_from("<II", raw, 20)
    return {"status": "ok", "functions": min(nfun, COUNT_CAP), "named": min(nname, COUNT_CAP)}


def _debug(img: PeImage, read: Reader, dirs: tuple, file_size: int) -> dict:
    d = _directory(dirs, DEBUG_DIR)
    if not d.rva:
        return {"status": "absent"}
    n = min(d.size // 28, MAX_DEBUG_ENTRIES)    # entries are 28 bytes
    raw = _read_mapped(img, read, d.rva, n * 28) if n and d.rva < img.size_of_image else None
    if raw is None:
        return {"status": "unreadable", "reason": f"debug directory unreadable (rva 0x{d.rva:x}, size 0x{d.size:x})"}
    types: list[str] = []
    pdb: str | None = None
    for i in range(n):
        _c, _ts, _ma, _mi, typ, size, _addr, ptr = struct.unpack_from("<IIHHIIII", raw, 28 * i)
        types.append(DEBUG_TYPES.get(typ, f"type_{typ}"))
        if typ == 2 and pdb is None and size >= 24 and ptr and ptr + 24 <= file_size:
            blob = read(ptr, min(size, 24 + 520, file_size - ptr))
            if blob[:4] == b"RSDS" and len(blob) > 24:
                path = blob[24:].split(b"\0")[0].decode("latin-1")
                pdb = esc(path.replace("\\", "/").rsplit("/", 1)[-1], MAX_PDB_NAME)   # file name only
    return {"status": "ok", "types": types, "total": d.size // 28, "pdb_name": pdb}


def build_profile(img: PeImage, read: Reader) -> PeProfile:
    e = struct.unpack_from("<I", read(0, 0x40), 0x3C)[0]
    blk = read(e, 44)
    ts = struct.unpack_from("<I", blk, 8)[0]
    chars = struct.unpack_from("<H", blk, 22)[0]
    linker = f"{blk[26]}.{blk[27]}"
    entry = struct.unpack_from("<I", blk, 40)[0]
    file_size = img.file_size
    secs = tuple(_section(i, s, read, file_size) for i, s in enumerate(img.sections))
    ep_sec: str | None = None
    ep_exec: bool | None
    if entry >= img.size_of_image:
        ep_exec = None
    else:
        ep_exec = False
        for s in img.sections:
            if s.rva <= entry < s.rva + s.extent:
                if ep_sec is None:
                    ep_sec = esc(s.name)
                if s.flags & SCN_X:
                    ep_exec = True
    ends = [img.size_of_headers] + [(s.raw_ptr & ~(RAW_POINTER_ALIGN - 1)) + s.raw_size
                                    for s in img.sections if s.raw_size > 0]
    ov_off = max(ends)
    ov_size = max(0, file_size - ov_off)
    dir_err: str | None = None
    try:
        dirs = read_data_directories(img, read)
    except PeError as exc:
        dirs, dir_err = (), str(exc)
    sec = _directory(dirs, SECURITY_DIR)
    sig_off, sig_size, sig_in = (sec.rva, sec.size, None) if sec.rva else (None, 0, None)
    if sig_off is not None:
        sig_in = sig_off >= ov_off and sig_off + sig_size <= file_size
    tls = scan_tls_image(img, read)
    tls_d = {"status": tls.status, "directory_rva": tls.directory_rva, "array_rva": tls.array_rva,
             "callbacks": [c.va for c in tls.callbacks], "reason": "; ".join(tls.unknowns)[:200]}
    if dir_err:
        bad = {"status": "unreadable", "reason": dir_err}
        imports, exports, debug = dict(bad), dict(bad), dict(bad)
    else:
        imports, exports, debug = _imports(img, read), _exports(img, read, dirs), _debug(img, read, dirs, file_size)
    return PeProfile("PE32+" if img.is64 else "PE32", img.machine, img.arch, img.subsystem, ts, linker,
                     img.image_base, img.size_of_image, file_size, chars, img.dll_characteristics,
                     _dll_flags(img.dll_characteristics, chars), secs, entry, ep_sec, ep_exec,
                     ov_off, ov_size, sig_off, sig_size, sig_in, tls_d, imports, exports, debug)


def profile_bytes(data: bytes) -> PeProfile:
    """Profile of PE file bytes. `PeError` if the headers cannot be parsed."""
    def read(off: int, n: int) -> bytes:
        return data[off:off + n]
    return build_profile(parse_pe(read, len(data)), read)


def _yn(b: bool) -> str:
    return "yes" if b else "no"


def profile_lines(p: PeProfile) -> list[str]:
    """Quotable evidence lines (one fact group per line, `pe_profile ` prefix)."""
    L = ["pe_profile format=%s machine=%s(0x%04x) subsystem=%s(%d) linker=%s image_base=0x%x size_of_image=0x%x "
         "file_size=%d" % (p.pe_format, p.arch, p.machine, SUBSYSTEMS.get(p.subsystem, "other"), p.subsystem,
                           p.linker, p.image_base, p.size_of_image, p.file_size),
         "pe_profile timestamp=" + _timestamp_text(p.timestamp)]
    f = p.dll_flags
    L.append("pe_profile dll_characteristics=0x%04x aslr=%s dep=%s cfg=%s high_entropy_va=%s relocs_stripped=%s "
             "(header flags only, not verified)"
             % (p.dll_characteristics, _yn(f["aslr"]), _yn(f["dep"]), _yn(f["cfg"]), _yn(f["high_entropy_va"]),
                _yn(f["relocs_stripped"])))
    for s in p.sections:
        ent = "not-measured" if s.entropy is None else s.entropy
        L.append('pe_profile section[%d] name="%s" rva=0x%x vsize=0x%x raw_offset=0x%x raw_size=0x%x perms=%s '
                 "characteristics=0x%08x flags=%s entropy=%s%s"
                 % (s.index, s.name, s.rva, s.vsize, s.raw_offset, s.raw_size, s.perms, s.characteristics,
                    ",".join(s.flags) or "none", ent, ("  notes: " + "; ".join(s.notes)) if s.notes else ""))
    L.append("pe_profile entry_point rva=0x%x section=%s executable=%s"
             % (p.entry_rva, ('"%s"' % p.entry_section) if p.entry_section else "outside any section",
                {True: "yes", False: "no", None: "unknown (outside the image)"}[p.entry_in_exec])
             + (" (AddressOfEntryPoint is 0: the image declares no entry point)" if p.entry_rva == 0 else ""))
    ov = "pe_profile overlay offset=0x%x size=%d" % (p.overlay_offset, p.overlay_size)
    if p.sig_offset is None:
        ov += " signature=none (security directory empty)"
    else:
        ov += (" signature_offset=0x%x signature_size=0x%x signature_in_overlay=%s (location only, signature NOT "
               "validated)" % (p.sig_offset, p.sig_size, _yn(bool(p.sig_in_overlay))))
        if p.sig_offset + p.sig_size > p.file_size:
            ov += " signature_extends_past_end_of_file=yes"
    L.append(ov)
    t = p.tls
    if t["status"] == "absent":
        L.append("pe_profile tls present=no")
    elif t["status"] == "ok":
        cbs = t["callbacks"]
        L.append("pe_profile tls present=yes directory_rva=0x%x callback_array_rva=%s callbacks=%d%s va=[%s]"
                 % (t["directory_rva"], _hx(t["array_rva"]), len(cbs),
                    " (list truncated)" if len(cbs) > MAX_TLS_SHOWN else "",
                    ",".join("0x%x" % v for v in cbs[:MAX_TLS_SHOWN])))
    else:
        L.append("pe_profile tls present=yes directory_rva=%s callbacks=unreadable reason=%s"
                 % (_hx(t["directory_rva"]), esc(t["reason"], 120)))
    i = p.imports
    if i["status"] == "unreadable":
        L.append("pe_profile imports " + _na(i["reason"]))
    else:
        L.append("pe_profile imports functions=%d dlls=%d delay_functions=%d delay_dlls=%d%s minimal_table=%s%s"
                 % (i["functions"], i["dlls"], i["delay_functions"], i["delay_dlls"],
                    "" if i["complete"] else " PARTIAL(" + esc(i.get("reason", ""), 120) + ")",
                    ("no_imports" if i["functions"] == 0 else _yn(i["minimal"])),
                    " only_loader_functions=yes" if i["loader_only"] else "")
                 + " (neutral observation, not a verdict)")
    x = p.exports
    if x["status"] == "ok":
        L.append("pe_profile exports functions=%d named=%d" % (x["functions"], x["named"]))
    elif x["status"] == "absent":
        L.append("pe_profile exports functions=0 (no export directory)")
    else:
        L.append("pe_profile exports " + _na(x["reason"]))
    d = p.debug
    if d["status"] == "ok":
        L.append("pe_profile debug entries=%d types=[%s] codeview_pdb=%s"
                 % (d["total"], ",".join(d["types"]), ('"%s"' % d["pdb_name"]) if d["pdb_name"] else "none"))
    elif d["status"] == "absent":
        L.append("pe_profile debug entries=0 (no debug directory)")
    else:
        L.append("pe_profile debug " + _na(d["reason"]))
    return L


def profile_dict(p: PeProfile) -> dict:
    """JSON-safe form for evidence results (no floats: entropy is a string)."""
    return {"format": p.pe_format, "arch": p.arch, "machine": p.machine, "subsystem": p.subsystem,
            "subsystem_name": SUBSYSTEMS.get(p.subsystem, "other"), "timestamp": p.timestamp, "linker": p.linker,
            "dll_characteristics": p.dll_characteristics, "dll_flags": p.dll_flags,
            "sections": [{"index": s.index, "name": s.name, "rva": s.rva, "vsize": s.vsize,
                          "raw_offset": s.raw_offset, "raw_size": s.raw_size, "perms": s.perms,
                          "characteristics": s.characteristics, "flags": list(s.flags), "entropy": s.entropy,
                          "notes": list(s.notes)} for s in p.sections],
            "entry_point": {"rva": p.entry_rva, "section": p.entry_section, "executable": p.entry_in_exec},
            "overlay": {"offset": p.overlay_offset, "size": p.overlay_size, "signature_offset": p.sig_offset,
                        "signature_size": p.sig_size, "signature_in_overlay": p.sig_in_overlay},
            "tls": p.tls, "imports": p.imports, "exports": p.exports, "debug": p.debug}
