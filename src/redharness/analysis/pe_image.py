"""Static PE image reader: virtual address (VA/RVA) or section+offset -> file bytes on disk.

Engine-independent (no IDA/Ghidra): parses only the PE headers and section table, reads the requested range
from the file. `read_bytes` is the core of the MCP tool.

Rules (fail-closed, zero invented bytes):
- Bytes present in the file (`file`): the section's raw data (the smaller of SizeOfRawData and VirtualSize, clipped
  to the file size) and the headers (RVA < SizeOfHeaders). Only these are shown as bytes.
- Uninitialized (`uninitialized`): the part inside the section's virtual size with no counterpart in the file
  (like .bss). The loader zero-fills it; these zeros are NOT FILE CONTENT, so they are NEVER given as bytes, they
  are marked "not in file; runtime-only".
- Unmapped (`unmapped`): a gap not covered by any section/header, or anything past the end of the image.
- The values read are bytes on disk: relocations are not applied, import tables are not bound;
  they can differ at run time.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Callable

READ_MAX = 1024          # max bytes per call
MAX_SECTIONS = 96
VIEWS = ("u8", "u16", "u32", "u64", "ptr", "ascii", "utf16")
DEFAULT_VIEWS = ("ptr",)
ARCH = {0x14C: "x86", 0x8664: "x64", 0x1C0: "arm", 0xAA64: "arm64"}

Reader = Callable[[int, int], bytes]   # (file offset, length) -> bytes


class PeError(ValueError):
    """The file is not a PE this reader understands / the headers are inconsistent."""


@dataclass(frozen=True)
class Section:
    name: str
    rva: int
    vsize: int
    raw_ptr: int
    raw_size: int
    flags: int

    @property
    def extent(self) -> int:
        """Size in memory: VirtualSize, or the raw size if 0."""
        return self.vsize or self.raw_size


@dataclass(frozen=True)
class Chunk:
    kind: str                 # file | uninitialized | unmapped
    rva: int
    length: int
    section: str | None
    file_offset: int | None   # only when kind == file


@dataclass(frozen=True)
class PeImage:
    file_size: int
    is64: bool
    machine: int
    image_base: int
    size_of_image: int
    size_of_headers: int
    sections: tuple[Section, ...]
    characteristics: int = 0        # COFF file header Characteristics
    subsystem: int = 0              # optional header Subsystem (1 = NATIVE, 2 = GUI, 3 = CUI)
    dll_characteristics: int = 0    # optional header DllCharacteristics (0x2000 = WDM driver)

    @property
    def arch(self) -> str:
        return ARCH.get(self.machine, f"machine_0x{self.machine:x}")

    @property
    def pointer_size(self) -> int:
        return 8 if self.is64 else 4

    def find_section(self, name: str) -> Section:
        hits = [s for s in self.sections if s.name.lower() == name.lower()]
        if not hits:
            raise PeError("section %r not found; sections: %s" % (name, ", ".join(s.name for s in self.sections)))
        if len(hits) > 1:
            raise PeError("section name %r is ambiguous (%d sections); use address or rva" % (name, len(hits)))
        return hits[0]

    def section_at(self, rva: int) -> Section | None:
        for s in self.sections:
            if s.rva <= rva < s.rva + s.extent:
                return s
        return None

    def _file_len(self, s: Section) -> int:
        """Bytes of the section present in the file: min(raw size, memory size), clipped to the end of the file."""
        raw_ptr = s.raw_ptr & ~0x1FF   # the loader rounds the raw pointer down to 512
        return max(0, min(s.raw_size, s.extent, self.file_size - raw_ptr))

    def plan(self, rva: int, length: int) -> list[Chunk]:
        """Splits the [rva, rva+length) range into file-backed / uninitialized / unmapped parts."""
        out: list[Chunk] = []
        end = rva + length
        cur = rva
        hdr_file = min(self.size_of_headers, self.file_size)
        while cur < end:
            if cur >= self.size_of_image:
                out.append(Chunk("unmapped", cur, end - cur, None, None))
                break
            if cur < self.size_of_headers:
                stop = min(end, self.size_of_headers)
                if cur < hdr_file:
                    stop = min(stop, hdr_file)
                    out.append(Chunk("file", cur, stop - cur, "(headers)", cur))
                else:
                    out.append(Chunk("uninitialized", cur, stop - cur, "(headers)", None))
                cur = stop
                continue
            s = self.section_at(cur)
            if s is None:
                nxt = min([x.rva for x in self.sections if x.rva > cur] + [self.size_of_image])
                stop = min(end, nxt)
                out.append(Chunk("unmapped", cur, stop - cur, None, None))
                cur = stop
                continue
            rel, flen = cur - s.rva, self._file_len(s)
            if rel < flen:
                stop = min(end, s.rva + flen)
                out.append(Chunk("file", cur, stop - cur, s.name, (s.raw_ptr & ~0x1FF) + rel))
            else:
                stop = min(end, s.rva + s.extent)
                out.append(Chunk("uninitialized", cur, stop - cur, s.name, None))
            cur = stop
        return out


def parse_pe(read: Reader, file_size: int) -> PeImage:
    """Reads the PE32/PE32+ headers and the section table. `read(offset, n)` returns bytes from the file."""
    if file_size < 64:
        raise PeError("file too small to be a PE")
    head = read(0, min(file_size, 4096))
    if head[:2] != b"MZ":
        raise PeError("not a PE: missing MZ header")
    e = struct.unpack_from("<I", head, 0x3C)[0]
    if e < 64 or e + 24 > file_size:
        raise PeError("not a PE: bad e_lfanew")
    if e + 24 + 0x200 > len(head):
        head = read(0, min(file_size, e + 24 + 0x200))
    if head[e:e + 4] != b"PE\0\0":
        raise PeError("not a PE: missing PE signature")
    machine, nsec = struct.unpack_from("<HH", head, e + 4)
    sizeopt = struct.unpack_from("<H", head, e + 20)[0]
    characteristics = struct.unpack_from("<H", head, e + 22)[0]
    opt = e + 24
    if sizeopt < 64 or nsec == 0 or nsec > MAX_SECTIONS:
        raise PeError("unsupported or corrupt PE headers (optional header size / section count)")
    need = opt + sizeopt + 40 * nsec
    if need > file_size:
        raise PeError("section table lies beyond the end of the file")
    if need > len(head):
        head = read(0, need)
    magic = struct.unpack_from("<H", head, opt)[0]
    if magic == 0x10B:
        is64, base = False, struct.unpack_from("<I", head, opt + 28)[0]
    elif magic == 0x20B:
        is64, base = True, struct.unpack_from("<Q", head, opt + 24)[0]
    else:
        raise PeError("unsupported optional header magic 0x%x" % magic)
    size_of_image, size_of_headers = struct.unpack_from("<II", head, opt + 56)
    subsystem, dll_chars = struct.unpack_from("<HH", head, opt + 68) if sizeopt >= 72 else (0, 0)
    secs = []
    for i in range(nsec):
        nm, vs, va, rs, rp = struct.unpack_from("<8sIIII", head, opt + sizeopt + 40 * i)
        fl = struct.unpack_from("<I", head, opt + sizeopt + 40 * i + 36)[0]
        secs.append(Section(nm.split(b"\0")[0].decode("latin-1"), va, vs, rp, rs, fl))
    if size_of_image == 0:
        raise PeError("corrupt PE: SizeOfImage is 0")
    return PeImage(file_size, is64, machine, base, size_of_image, size_of_headers, tuple(secs),
                   characteristics, subsystem, dll_chars)


# ---------------------------------------------------------------------------------------------- kernel-mode images

SUBSYSTEM_NATIVE = 1
DLLCHAR_WDM_DRIVER = 0x2000


def kernel_mode_reasons(img: PeImage, file_name: str | None = None) -> tuple[str, ...]:
    """Why this image is treated as kernel-mode (a driver / native image that cannot run in the Win32 sandbox).
    Empty tuple = nothing points at a kernel image. Static header facts only; the file is never loaded.
    Any one reason is enough (fail-closed: a user-mode run of a driver is never useful and never safe to attempt)."""
    why: list[str] = []
    if img.subsystem == SUBSYSTEM_NATIVE:
        why.append("PE subsystem is NATIVE (1)")
    if img.dll_characteristics & DLLCHAR_WDM_DRIVER:
        why.append("DllCharacteristics has IMAGE_DLLCHARACTERISTICS_WDM_DRIVER (0x2000)")
    if file_name and file_name.lower().endswith(".sys"):
        why.append("file name extension is .sys")
    return tuple(why)


# ---------------------------------------------------------------------------------------------- output

@dataclass
class ReadOutput:
    status: str                  # OK | PARTIAL
    raw: str                     # raw evidence output (this is also what the model is given)
    result: dict
    locations: list[dict]
    limitations: list[str]
    complete: bool
    scope: str


def normalize_views(view: object) -> tuple[str, ...]:
    """None -> default; 'all' -> all; string (comma-separated) or list -> canonical order. ValueError if malformed."""
    if view is None or view == "" or view == []:
        return DEFAULT_VIEWS
    items = [view] if isinstance(view, str) else list(view) if isinstance(view, (list, tuple)) else None
    if items is None:
        raise ValueError("view must be a string or a list of strings")
    names: set[str] = set()
    for it in items:
        if not isinstance(it, str):
            raise ValueError("view entries must be strings")
        for part in it.replace(" ", "").lower().split(","):
            if part in ("", "hex"):
                continue            # the hex dump is always present
            if part == "all":
                names.update(VIEWS)
            elif part in VIEWS:
                names.add(part)
            else:
                raise ValueError("unknown view %r; use hex plus any of %s, or 'all'" % (part, ", ".join(VIEWS)))
    return tuple(v for v in VIEWS if v in names)


_PRINT = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]{2,}")


def _esc(s: str) -> str:
    return (s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
            .replace("\t", "\\t"))


def _hex_lines(va: int, data: bytes) -> list[str]:
    out = []
    for i in range(0, len(data), 16):
        row = data[i:i + 16]
        groups = "_".join(row[j:j + 4].hex() for j in range(0, len(row), 4))
        out.append("0x%x: %s" % (va + i, groups))
    return out


def _view_lines(name: str, va: int, data: bytes, img: PeImage) -> list[str]:
    out: list[str] = []
    if name == "u8":
        for i in range(0, len(data), 16):
            out.append("0x%x: %s" % (va + i, " ".join(str(b) for b in data[i:i + 16])))
    elif name == "u16":
        n = len(data) // 2
        vals = struct.unpack_from("<%dH" % n, data) if n else ()
        for i in range(0, n, 8):
            out.append("0x%x: %s" % (va + 2 * i, " ".join("0x%04x=%d" % (v, v) for v in vals[i:i + 8])))
    elif name == "u32":
        n = len(data) // 4
        for i, v in enumerate(struct.unpack_from("<%dI" % n, data) if n else ()):
            out.append("0x%x: 0x%08x %d" % (va + 4 * i, v, v))
    elif name == "u64":
        n = len(data) // 8
        for i, v in enumerate(struct.unpack_from("<%dQ" % n, data) if n else ()):
            out.append("0x%x: 0x%016x %d" % (va + 8 * i, v, v))
    elif name == "ptr":
        w = img.pointer_size
        n = len(data) // w
        fmt = "<%d%s" % (n, "Q" if w == 8 else "I")
        for i, v in enumerate(struct.unpack_from(fmt, data) if n else ()):
            note = ""
            if v == 0:
                note = " null"
            elif img.image_base <= v < img.image_base + img.size_of_image:
                s = img.section_at(v - img.image_base)
                note = " -> %s" % (s.name if s else ("(headers)" if v - img.image_base < img.size_of_headers
                                                      else "(unmapped)"))
            out.append("0x%x: 0x%0*x%s" % (va + w * i, w * 2, v, note))
    elif name == "ascii":
        for m in _PRINT.finditer(data):
            out.append('0x%x: "%s"' % (va + m.start(), _esc(m.group(0).decode("ascii"))))
    elif name == "utf16":
        i, n = 0, len(data)
        if va % 2:
            i = 1
        while i + 1 < n:
            j = i
            chars = []
            while j + 1 < n:
                cu = data[j] | (data[j + 1] << 8)
                ch = chr(cu)
                if (0xD800 <= cu <= 0xDFFF) or not (ch in "\t\n\r" or (ch.isprintable() and cu >= 0x20)):
                    break
                chars.append(ch)
                j += 2
            if len(chars) >= 2:
                out.append('0x%x: "%s"' % (va + i, _esc("".join(chars))))
                i = j
            else:
                i += 2
    if not out:
        out.append("(nothing to show in this segment)")
    return out


def read_range(img: PeImage, read: Reader, rva: int, length: int, views: tuple[str, ...],
               requested: int | None = None) -> ReadOutput:
    """Reads the [rva, rva+length) range and produces the evidence text. `length` must already be <= READ_MAX;
    `requested` is the size the user asked for (larger than length if the cap was applied)."""
    if not 0 <= rva < img.size_of_image:
        raise PeError("rva 0x%x is outside the image (SizeOfImage 0x%x)" % (rva, img.size_of_image))
    requested = length if requested is None else requested
    va0 = img.image_base + rva
    chunks = img.plan(rva, length)
    f = sum(c.length for c in chunks if c.kind == "file")
    u = sum(c.length for c in chunks if c.kind == "uninitialized")
    m = sum(c.length for c in chunks if c.kind == "unmapped")
    capped = requested > length
    lines = ["read_bytes va=0x%x rva=0x%x length=%d arch=%s image_base=0x%x" % (va0, rva, length, img.arch,
                                                                                  img.image_base),
             "hex = file bytes in file order, 4-byte groups joined by '_'; typed views are little-endian "
             "on-disk values (no relocations applied)"]
    locations: list[dict] = []
    segs: list[dict] = []
    limitations = ["values are the bytes stored in the file: relocations are not applied and imports are not "
                   "resolved, so they can differ at run time"]
    for k, c in enumerate(chunks, 1):
        s_va, e_va = img.image_base + c.rva, img.image_base + c.rva + c.length
        seg = {"kind": c.kind, "start": s_va, "end": e_va, "length": c.length, "section": c.section,
               "file_offset": c.file_offset}
        segs.append(seg)
        if c.kind == "file":
            data = read(c.file_offset, c.length)
            if len(data) != c.length:
                raise PeError("file shorter than its section table claims (read %d of %d bytes)"
                              % (len(data), c.length))
            lines.append("segment %d FILE 0x%x..0x%x len=%d section=%s file_offset=0x%x"
                         % (k, s_va, e_va, c.length, c.section, c.file_offset))
            lines += ["  " + ln for ln in _hex_lines(s_va, data)]
            for v in views:
                lines.append("  -- %s --" % v)
                lines += ["  " + ln for ln in _view_lines(v, s_va, data, img)]
            locations += [{"kind": "address-range", "space": "va", "start": s_va, "end": e_va},
                          {"kind": "address-range", "space": "rva", "start": c.rva, "end": c.rva + c.length}]
        elif c.kind == "uninitialized":
            lines.append("segment %d UNINITIALIZED 0x%x..0x%x len=%d section=%s -- not in file; runtime-only "
                         "(the loader zero-fills it; no bytes are shown because there is no file content)"
                         % (k, s_va, e_va, c.length, c.section))
            limitations.append("%d bytes at 0x%x..0x%x (section %s) are uninitialized: not in the file, "
                               "runtime-only; their value must be learned from code or a controlled run"
                               % (c.length, s_va, e_va, c.section))
        else:
            lines.append("segment %d UNMAPPED 0x%x..0x%x len=%d -- no section or header covers this range"
                         % (k, s_va, e_va, c.length))
            limitations.append("%d bytes at 0x%x..0x%x are not mapped by any section" % (c.length, s_va, e_va))
    nxt = va0 + length if capped else None
    if capped:
        limitations.append("length capped at %d bytes (asked %d); continue from next_address" % (length, requested))
        lines.append("length capped at %d (asked %d): continue at 0x%x" % (length, requested, nxt))
    first_file = next((c for c in chunks if c.kind == "file"), None)
    complete = f == length and not capped
    result = {"va": va0, "rva": rva, "length": length, "requested_length": requested,
              "file_bytes": f, "uninitialized_bytes": u, "unmapped_bytes": m,
              "section": chunks[0].section if chunks else None,
              "file_offset": first_file.file_offset if first_file else None,
              "next_address": nxt, "views": list(views), "segments": segs, "arch": img.arch,
              "image_base": img.image_base}
    return ReadOutput("OK" if f == length else "PARTIAL", "\n".join(lines) + "\n", result, locations, limitations,
                      complete, "bytes:0x%x-0x%x" % (va0, va0 + length))
