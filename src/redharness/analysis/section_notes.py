"""Section notes for evidence text: which PE section holds an address that a tool output shows.

Gap (found in a live model run): a claim about "the blob in .rdata" could be
backed only by a `read_bytes` evidence (its segment line names the section); `disassemble`, `decompile` and `emulate`
outputs show addresses (`lea rcx, unk_140002040`, `byte_140002040[i]`, an image pointer argument) but not the section
they lie in, so a correct ".rdata" stayed UNVERIFIED unless the model also read the bytes.

Rule (session TOOL_VERSION 5, emulate TOOL_VERSION 2): a note names the section and its R/W/X characteristics, taken
from the PE section headers only, for
- the addresses the tool itself reports (the instructions shown, the decompiled function, the emulated function/end and
  the image pointers/pre-writes of the request), and
- engine auto-names that encode an address (IDA `sub_/loc_/unk_/byte_/word_/dword_/qword_/off_/stru_/asc_/...`,
  Ghidra `DAT_/PTR_/LAB_/FUN_` followed by the hex address) appearing in the output.
A plain number in the output is never annotated (it may be a constant, not an address). An address outside every
section (headers, outside the image) gets no note. Nothing is inferred about the bytes' meaning.
"""

from __future__ import annotations

import re
from typing import Iterable

from .pe_image import PeImage

SCN_EXECUTE = 0x20000000
SCN_READ = 0x40000000
SCN_WRITE = 0x80000000
MAX_NAME_NOTES = 32

_AUTONAME = re.compile(
    r"(?<![0-9A-Za-z_$@?])((?:sub|loc|locret|off|unk|byte|word|dword|qword|xmmword|ymmword|zmmword|oword|tbyte|stru|"
    r"asc|flt|dbl|algn|DAT|PTR|LAB|FUN)_([0-9A-Fa-f]{4,16}))(?![0-9A-Za-z_$@?])")


def flags(section_flags: int) -> str:
    """`R-X` style characteristics (the protection_scan notation)."""
    return (("R" if section_flags & SCN_READ else "-") + ("W" if section_flags & SCN_WRITE else "-")
            + ("X" if section_flags & SCN_EXECUTE else "-"))


def where(img: PeImage, va: int) -> str | None:
    """`.rdata R--` for an address inside a section of the image, else None."""
    rva = va - img.image_base
    if rva < 0 or rva >= img.size_of_image:
        return None
    sec = img.section_at(rva)
    if sec is None:
        return None
    return f"{sec.name} {flags(sec.flags)}"


def range_notes(img: PeImage, addresses: Iterable[int], what: str) -> list[str]:
    """One note per run of consecutive addresses in the same section: `section .text R-X: 0x..-0x.. (<what>)`."""
    out: list[str] = []
    cur: tuple[str, int, int] | None = None
    for a in addresses:
        w = where(img, a)
        if w is None:
            continue
        if cur and cur[0] == w:
            cur = (w, cur[1], a)
        else:
            if cur:
                out.append(_range_line(cur, what))
            cur = (w, a, a)
    if cur:
        out.append(_range_line(cur, what))
    return out


def _range_line(cur: tuple[str, int, int], what: str) -> str:
    w, a, b = cur
    span = f"0x{a:x}" if a == b else f"0x{a:x}..0x{b:x}"
    return f"section {w}: {span} ({what})"


def name_notes(img: PeImage, text: str, limit: int = MAX_NAME_NOTES) -> list[str]:
    """`ref unk_140002040 = 0x140002040 in section .rdata R--` for each distinct auto-name in the text whose address
    lies in a section (text order, at most `limit`; a cut is stated)."""
    out: list[str] = []
    seen: set[str] = set()
    more = 0
    for m in _AUTONAME.finditer(text):
        name = m.group(1)
        if name in seen:
            continue
        seen.add(name)
        va = int(m.group(2), 16)
        w = where(img, va)
        if w is None:
            continue
        if len(out) >= limit:
            more += 1
            continue
        out.append(f"ref {name} = 0x{va:x} in section {w}")
    if more:
        out.append(f"({more} more auto-named references not annotated)")
    return out
