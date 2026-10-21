"""Small synthetic PE builder (read_bytes tests): no real binary needed, the known section layout is the answer.

Layout (FileAlignment 0x200, SectionAlignment 0x1000, headers 0x400 bytes):
  .text   rva 0x1000 vsize 0x100  ham 0x200 @ 0x400   (0xCC padding)
  .rdata  rva 0x2000 vsize 0x80   ham 0x200 @ 0x600   (first 0x40 bytes: pointer table, then 'hello' + UTF-16 'Wide')
  .data   rva 0x3000 vsize 0x300  ham 0x200 @ 0x800   (0x200 bytes in file; last 0x100 bytes uninitialized)
  .bss    rva 0x4000 vsize 0x100  ham 0     @ 0       (fully uninitialized)
  image SizeOfImage 0x5000; 0x3300..0x4000 is in no section (gap).
"""
import struct

IMAGE_SIZE = 0x5000
FILE_ALIGN = 0x200


def build_pe(is64: bool = True, base: int | None = None, data_marker: bytes = b"", subsystem: int = 0,
             dll_characteristics: int = 0) -> bytes:
    base = base if base is not None else (0x140000000 if is64 else 0x400000)
    psize = 8 if is64 else 4
    sizeopt = 0xF0 if is64 else 0xE0
    e = 0x80
    secs = [(b".text", 0x1000, 0x100, 0x400, 0x200, 0x60000020),
            (b".rdata", 0x2000, 0x80, 0x600, 0x200, 0x40000040),
            (b".data", 0x3000, 0x300, 0x800, 0x200, 0xC0000040),
            (b".bss", 0x4000, 0x100, 0, 0, 0xC0000080)]
    hdr = bytearray(0x400)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, e)
    hdr[e:e + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", hdr, e + 4, 0x8664 if is64 else 0x14C, len(secs), 0, 0, 0, sizeopt, 0x22)
    opt = e + 24
    struct.pack_into("<H", hdr, opt, 0x20B if is64 else 0x10B)
    if is64:
        struct.pack_into("<Q", hdr, opt + 24, base)
    else:
        struct.pack_into("<I", hdr, opt + 28, base)
    struct.pack_into("<II", hdr, opt + 32, 0x1000, FILE_ALIGN)           # SectionAlignment, FileAlignment
    struct.pack_into("<II", hdr, opt + 56, IMAGE_SIZE, 0x400)           # SizeOfImage, SizeOfHeaders
    struct.pack_into("<HH", hdr, opt + 68, subsystem, dll_characteristics)   # Subsystem (1 = NATIVE), DllCharacteristics
    for i, (nm, va, vs, rp, rs, fl) in enumerate(secs):
        struct.pack_into("<8sIIIIIIHHI", hdr, opt + sizeopt + 40 * i, nm, vs, va, rs, rp, 0, 0, 0, 0, fl)
    text = bytes([0xCC]) * 0x200
    rdata = bytearray(0x200)
    # pointer table: 4 pointers (3 in .text, 1 in .data)
    targets = [base + 0x1010, base + 0x1020, base + 0x1030, base + 0x3008]
    for i, t in enumerate(targets):
        struct.pack_into("<Q" if is64 else "<I", rdata, psize * i, t)
    rdata[0x40:0x40 + 6] = b"hello\0"
    rdata[0x48:0x48 + 10] = "Wide".encode("utf-16-le") + b"\0\0"
    data = bytearray(0x200)
    for i, v in enumerate([100, 18, 1, 1, 0xDEADBEEF, 0xFFFFFFFF]):
        struct.pack_into("<I", data, 4 * i, v)
    data[0x30:0x30 + len(data_marker)] = data_marker
    return bytes(hdr) + text + bytes(rdata) + bytes(data)
