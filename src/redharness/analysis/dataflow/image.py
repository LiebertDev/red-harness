"""Image reads for the slicer: bytes of a PE image range from the SHA-verified file copy, with section name and R/W/X."""

from __future__ import annotations

from dataclasses import dataclass

from ..pe_image import PeImage, Reader
from ..section_notes import SCN_WRITE, flags


@dataclass(frozen=True)
class ImageLoad:
    va: int
    size: int
    data: bytes | None   # None: not file-backed (uninitialised / unmapped part)
    section: str
    flags: str           # `R--` style
    writable: bool
    reason: str = ""


class PeImageView:
    def __init__(self, img: PeImage, read: Reader, loader_slots: dict[int, str] | None = None):
        """`loader_slots`: import address slot VA -> `dll!name`. The loader overwrites these at run time, so their file
        bytes are never reported as a value."""
        self.img, self.read = img, read
        self.slots = sorted((loader_slots or {}).items())

    @property
    def image_base(self) -> int:
        return self.img.image_base

    def load(self, va: int, size: int) -> ImageLoad | None:
        """None if [va, va+size) is not entirely inside the image."""
        rva = va - self.img.image_base
        if rva < 0 or size <= 0 or rva + size > self.img.size_of_image:
            return None
        chunks = self.img.plan(rva, size)
        sec = self.img.section_at(rva)
        name = sec.name if sec else (chunks[0].section or "(headers)")
        fl = flags(sec.flags) if sec else "R--"
        writable = bool(sec and sec.flags & SCN_WRITE)
        ptr = self.img.pointer_size
        for slot, sym in self.slots:
            if slot < va + size and va < slot + ptr:
                return ImageLoad(va, size, None, name, fl, writable,
                                 f"import address slot 0x{slot:x} ({sym}): filled by the loader at run time")
        if any(c.kind != "file" for c in chunks):
            return ImageLoad(va, size, None, name, fl, writable, "not file-backed (uninitialised or unmapped)")
        if len({c.section for c in chunks}) > 1:
            return ImageLoad(va, size, None, name, fl, writable, "range crosses a section boundary")
        data = b"".join(self.read(c.file_offset, c.length) for c in chunks)
        if len(data) != size:
            return ImageLoad(va, size, None, name, fl, writable, "short read")
        return ImageLoad(va, size, data, name, fl, writable)
