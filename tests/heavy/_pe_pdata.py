"""Independent third source: PE x64 exception directory (.pdata) RUNTIME_FUNCTION records.

Used to classify the IDA/Ghidra function count difference (not dependent on engine output).
Each record is (BeginAddress, EndAddress, UnwindData). If the UNWIND_INFO flags have CHAININFO (0x4), the record is
a PART (chunk) of another function, not an independent function start.
"""
import struct
from pathlib import Path


def parse_pdata(path):
    data = Path(path).read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe:pe + 4] == b"PE\0\0"
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    assert struct.unpack_from("<H", data, opt)[0] == 0x20B, "PE32+ only"
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    exc_rva, exc_size = struct.unpack_from("<II", data, opt + 112 + 3 * 8)
    secs = []
    for i in range(nsec):
        o = opt + opt_size + 40 * i
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
        secs.append((va, max(vsize, rawsize), rawptr))

    def rva2off(rva):
        for va, size, raw in secs:
            if va <= rva < va + size:
                return raw + (rva - va)
        return None

    entries = []
    base = rva2off(exc_rva)
    for i in range(exc_size // 12):
        b, e, u = struct.unpack_from("<III", data, base + 12 * i)
        if b == 0 and e == 0:
            continue
        chained = False
        uo = rva2off(u & ~1)
        if uo is not None:
            flags = data[uo] >> 3
            chained = bool(flags & 0x4)
        entries.append({"begin": image_base + b, "end": image_base + e, "chained": chained})
    return image_base, entries
