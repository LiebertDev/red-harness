"""Static protection profiling: a protection profile from PE section names, entropy and packer signatures.

Engine-independent (no IDA/Ghidra): it only parses the PE headers with `pe_image` and reads the file
bytes; it executes nothing, uses no network and adds no dependency. The output is a single
`ProtectionProfile`: which sections exist, which have high entropy, which packer markers
appear, and whether the entry point lies in an executable section.

Kurallar (fail-closed):
- An unparsable or truncated PE (section raw data past the end of the file) -> `ProtectionError`
  (pe_image's error message is PRESERVED when wrapping). A partial profile is never returned as "clean".
- Sections are in header order; markers/anomalies are sorted by (file_offset, id) -- the same bytes ALWAYS
  give the same profile (deterministic).
- For a section without raw data (like .bss) the entropy is `None` = "not measured"; it is NOT counted as 0.
- Matched signatures are review hints, not PROOF of protection: a match can be coincidental (carried
  in the notes). Unpacking is not this module's job.
"""

from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass
from pathlib import Path

from .pe_image import PeError, PeImage, parse_pe

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
HIGH_ENTROPY_THRESHOLD = 7.2      # bits/byte; below this threshold it does not count as "high entropy"
HIGH_ENTROPY_MIN_RAW = 4096       # so that random padding of small sections does not raise false alarms
MAX_SIGNATURE_RECORDS = 16        # records kept per byte signature; the true count is reported in `total_matches`
RAW_POINTER_ALIGN = 0x200         # same as pe_image `_file_len`: the loader rounds the raw pointer down to 512


@dataclass(frozen=True)
class MarkerRule:
    """A protection marker rule. `id` is the stable identifier that enters the report, `kind` the rule type
    ("section-name" | "byte-signature"), `needle` the match text (lower case for section-name)."""
    id: str
    kind: str
    needle: str


# Marker table: id + match rule. section-name: the section name is compared stripped/lower-cased;
# byte-signature: searched as a byte string in the WHOLE file (headers and overlay included).
MARKERS: tuple[MarkerRule, ...] = tuple(
    [MarkerRule("name:" + n, "section-name", n) for n in
     ("upx0", "upx1", "upx2", ".aspack", ".adata", ".nsp0", ".nsp1", ".nsp2", "petite", ".petite",
      ".themida", ".winlice", ".tmd", ".vmp0", ".vmp1", ".enigma1", ".enigma2", ".packed",
      ".mpress1", ".mpress2")] +
    [MarkerRule("sig:" + s, "byte-signature", s) for s in
     ("UPX!", "MPRESS1", "MPRESS2", "Themida", "VMProtect", "ASPack", "Enigma", "PECompact", "petite")]
)


class ProtectionError(ValueError):
    """The file could not be profiled: not a PE, corrupt or truncated. No partial profile is returned (fail-closed)."""


@dataclass(frozen=True)
class SectionFact:
    """Static facts of one PE section. `entropy` None means "not measured" (no raw data in the file,
    like .bss) -- it MUST NOT BE CONFUSED WITH 0. `raw_offset` is the effective file offset (the loader
    rounds the raw pointer down to 512; pe_image uses the same rule). `va` is the section's RVA."""
    name: str
    va: int
    vsize: int
    raw_offset: int
    raw_size: int
    entropy: float | None
    is_executable: bool
    is_writable: bool


@dataclass(frozen=True)
class ProtectionMarker:
    """A protection hint record. `file_offset` is set ONLY if the byte string really is there: the
    matched offset of a byte signature. A section NAME is header information; its data is elsewhere, so
    file_offset stays None there (the location is in the detail text). For a byte signature only the first
    `MAX_SIGNATURE_RECORDS` matches become records (memory stays bounded on a file full of repeats);
    `total_matches` is the true number of non-overlapping matches in the file, the same on each of those records."""
    id: str
    kind: str
    detail: str
    file_offset: int | None
    total_matches: int = 1


@dataclass(frozen=True)
class ProtectionAnomaly:
    """A static anomaly with an id. `file_offset`/`rva` are set only where the location is really known."""
    id: str
    detail: str
    file_offset: int | None
    rva: int | None


@dataclass(frozen=True)
class ProtectionProfile:
    """The deterministic static protection profile of a single file."""
    sha256: str
    file_size: int
    sections: tuple[SectionFact, ...]
    entry_point_rva: int
    entry_point_section: str | None
    entry_point_in_exec: bool | None
    markers: tuple[ProtectionMarker, ...]
    anomalies: tuple[ProtectionAnomaly, ...]
    notes: tuple[str, ...]


def compute_entropy(data: bytes) -> float:
    """Shannon entropy (bits/byte, 0..8). Returns 0.0 for empty data (the mathematical limit value);
    this is NOT "not measured" -- unmeasured is expressed by `SectionFact.entropy is None`."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = float(len(data))
    total = 0.0
    for c in counts:
        if c:
            p = c / n
            total -= p * math.log2(p)
    return total


def _parse(data: bytes) -> PeImage:
    """Parses with pe_image; converts PeError to ProtectionError PRESERVING its message."""
    try:
        return parse_pe(lambda off, n: data[off:off + n], len(data))
    except PeError as exc:
        raise ProtectionError(str(exc)) from exc


def _entry_point_rva(data: bytes) -> int:
    """AddressOfEntryPoint (RVA). pe_image's `PeImage` does not expose the entry point; the optional header
    field at +0x10 is the same for PE32/PE32+. This is reached only AFTER a successful parse_pe (parse
    guarantees e+24+sizeopt+40*nsec <= file size and sizeopt >= 64), so the read is in bounds."""
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    return struct.unpack_from("<I", data, e_lfanew + 24 + 16)[0]


def _scan_markers(data: bytes, sections: tuple[SectionFact, ...]) -> list[ProtectionMarker]:
    """Applies the MARKERS rules. Section names match stripped/lower-cased; byte signatures are searched in
    the whole file; the first MAX_SIGNATURE_RECORDS matches are separate records (location = matched offset) and
    the true count is carried in `total_matches`."""
    out: list[ProtectionMarker] = []
    for fact in sections:
        name = fact.name.strip().lower()
        for rule in MARKERS:
            if rule.kind != "section-name" or name != rule.needle:
                continue
            extra = (f", raw data @0x{fact.raw_offset:x} ({fact.raw_size} bytes)" if fact.raw_size
                     else ", no raw data")
            out.append(ProtectionMarker(rule.id, rule.kind,
                                        f"section name points to a protection family: {fact.name!r} "
                                        f"(RVA 0x{fact.va:x}{extra})", None))
    for rule in MARKERS:
        if rule.kind != "byte-signature":
            continue
        needle = rule.needle.encode("ascii")
        total = data.count(needle)       # C speed, non-overlapping: same matches as the find loop below
        start = 0
        for _ in range(min(total, MAX_SIGNATURE_RECORDS)):
            idx = data.find(needle, start)
            out.append(ProtectionMarker(rule.id, rule.kind,
                                        f"signature {rule.needle!r} found in the file", idx, total))
            start = idx + len(needle)
    return out


def _scan_anomalies(img: PeImage, sections: tuple[SectionFact, ...], ep_rva: int,
                    ep_section: str | None, ep_in_exec: bool | None) -> list[ProtectionAnomaly]:
    """Produces the anomalies with ids: EP outside code, X+W section, high-entropy section, overlay."""
    out: list[ProtectionAnomaly] = []
    if ep_in_exec is not True:
        if ep_rva >= img.size_of_image:
            detail = (f"EP RVA 0x{ep_rva:x} outside the image (SizeOfImage 0x{img.size_of_image:x}); "
                      f"could not be matched to a code section")
        else:
            where = f"section {ep_section!r}" if ep_section else "no section"
            detail = f"EP RVA 0x{ep_rva:x} is not inside any executable (X) section ({where})"
        out.append(ProtectionAnomaly("entry_point_outside_code", detail, None, ep_rva))
    for fact in sections:
        if fact.is_executable and fact.is_writable:
            out.append(ProtectionAnomaly("wx_section",
                                         f"section {fact.name!r} is both executable and writable (X+W), "
                                         f"RVA 0x{fact.va:x}", None, fact.va))
        if (fact.entropy is not None and fact.entropy >= HIGH_ENTROPY_THRESHOLD
                and fact.raw_size >= HIGH_ENTROPY_MIN_RAW):
            out.append(ProtectionAnomaly("high_entropy_section",
                                         f"section {fact.name!r} entropy {fact.entropy:.2f} "
                                         f"(raw {fact.raw_size} bytes), RVA 0x{fact.va:x}",
                                         fact.raw_offset, fact.va))
    ends = [img.size_of_headers] + [f.raw_offset + f.raw_size for f in sections if f.raw_size > 0]
    overlay_start = max(ends)
    if img.file_size > overlay_start:
        size = img.file_size - overlay_start
        out.append(ProtectionAnomaly("overlay_present",
                                     f"{size} bytes of overlay at the end of the file (offset 0x{overlay_start:x}; "
                                     f"file size {img.file_size})", overlay_start, None))
    return out


def _sort_key(item: ProtectionMarker | ProtectionAnomaly) -> tuple[int, str, str]:
    """Deterministic order: (file_offset, id); without an offset it comes first (None -> -1). For the same
    offset/id pair the detail breaks the tie -- two scans of the same input give the same order."""
    return (item.file_offset if item.file_offset is not None else -1, item.id, item.detail)


def scan_protection(data: bytes) -> ProtectionProfile:
    """Extracts the static protection profile of a PE file. It ONLY reads static bytes; it executes
    nothing. An unparsable/truncated file -> `ProtectionError` (no partial profile is returned)."""
    img = _parse(data)
    sections: list[SectionFact] = []
    notes: list[str] = []
    for s in img.sections:
        raw_off = s.raw_ptr & ~(RAW_POINTER_ALIGN - 1)
        if s.raw_size > 0:
            end = raw_off + s.raw_size
            if end > img.file_size:
                raise ProtectionError(
                    f"file truncated: the raw data of section {s.name!r} runs past the end of the file "
                    f"(0x{raw_off:x}+0x{s.raw_size:x} > 0x{img.file_size:x})")
            entropy: float | None = compute_entropy(data[raw_off:end])
        else:
            entropy = None       # not measured: nothing in the file, NOT counted as 0
            notes.append(f"section {s.name!r}: no raw data (vsize 0x{s.vsize:x}); entropy not measured "
                         f"(NOT counted as 0)")
        sections.append(SectionFact(s.name, s.rva, s.vsize, raw_off, s.raw_size, entropy,
                                    bool(s.flags & IMAGE_SCN_MEM_EXECUTE),
                                    bool(s.flags & IMAGE_SCN_MEM_WRITE)))
    facts = tuple(sections)

    ep_rva = _entry_point_rva(data)
    ep_section: str | None = None
    ep_in_exec: bool | None
    if ep_rva >= img.size_of_image:
        ep_in_exec = None        # outside the image: cannot be judged with the section table (fail-closed: anomaly)
    else:
        ep_in_exec = False
        for s in img.sections:
            if s.rva <= ep_rva < s.rva + s.extent:
                if ep_section is None:
                    ep_section = s.name
                if s.flags & IMAGE_SCN_MEM_EXECUTE:
                    ep_in_exec = True

    markers = sorted(_scan_markers(data, facts), key=_sort_key)
    anomalies = sorted(_scan_anomalies(img, facts, ep_rva, ep_section, ep_in_exec), key=_sort_key)
    if any(m.kind == "byte-signature" for m in markers):
        notes.append("byte signatures are searched in the whole file (headers and overlay included); a match "
                     "can be coincidental and is NOT PROOF of a packer")
    return ProtectionProfile(hashlib.sha256(data).hexdigest(), img.file_size, facts, ep_rva, ep_section,
                             ep_in_exec, tuple(markers), tuple(anomalies), tuple(notes))


def scan_protection_file(path: str | Path) -> ProtectionProfile:
    """Convenience: reads the file from disk and calls `scan_protection`. A read error is also a
    `ProtectionError` (fail-closed: no partial/imaginary profile is returned)."""
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise ProtectionError(f"file could not be read: {p}") from exc
    return scan_protection(data)
