"""Deterministic robustness (mutation) test for the PE header/directory parsers.

Real Windows system binaries are mutated at test time (never committed): truncations, single-byte flips in the
headers / data directories / section table, data-directory values set to 0, 0xFFFFFFFF and just past SizeOfImage,
and e_lfanew pointing past EOF. Every call must either return a result or raise PeError/PeDirectoryError
(ProtectionError for scan_protection, which wraps PeError fail-closed). Any other exception is a bug.

The mutation set is fully deterministic (no random state): truncation every 64 bytes over the first 4 KiB plus a
fixed sample beyond, then a fixed list of structural offsets. Nothing is hard-coded from one machine: offsets are
resolved from the file that is read at test time.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import pytest

from redharness.analysis.pe_dirs import scan_imports, scan_imports_image
from redharness.analysis.pe_image import PeError, parse_pe
from redharness.analysis.protection import ProtectionError, scan_protection

MAX_CALL_SECONDS = 2.0
TRUNCATION_STEP = 64
TRUNCATION_LIMIT = 0x1000

TARGET_FILES = (
    Path(r"C:\Windows\System32\drivers\null.sys"),
    Path(r"C:\Windows\System32\drivers\beep.sys"),
    Path(r"C:\Windows\System32\notepad.exe"),
)

# Filled in only for cases that were observed to fail (a parser bug is recorded here, never fixed in the parser).
# key = parametrized case id, value = xfail reason.
KNOWN_BAD: dict[str, str] = {}


@dataclass(frozen=True)
class Mutation:
    """A mutation that is resolved against the bytes read at test time."""

    kind: str
    args: tuple[int, ...] = ()


def _truncation_lengths(size: int) -> list[int]:
    lengths = list(range(TRUNCATION_STEP, TRUNCATION_LIMIT + 1, TRUNCATION_STEP))
    lengths += [size // 2, size * 3 // 4, size * 9 // 10,
                size - 1024, size - 256, size - 64, size - 1]
    return [n for n in lengths if 0 < n < size]


def _mutations(size: int) -> list[Mutation]:
    """Every mutation is listed here; only `size` (from the file) is needed to enumerate truncations."""
    out = [Mutation("trunc", (n,)) for n in _truncation_lengths(size)]
    # Header offsets that do not depend on e_lfanew.
    out.append(Mutation("flip", (0x00,)))       # MZ signature
    out.append(Mutation("flip", (0x3C,)))       # e_lfanew (low byte)
    # Offsets relative to e_lfanew (resolved at test time).
    for rel in (4, 6, 20, 22, 24):              # machine, nsec, SizeOfOptionalHeader, Characteristics, magic
        out.append(Mutation("flip_rel", (rel,)))
    # Offsets relative to the optional header.
    for rel in (16, 56, 60):                    # AddressOfEntryPoint, SizeOfImage, SizeOfHeaders
        out.append(Mutation("flip_opt", (rel,)))
    # Data directory entries: import (1), TLS (9), delay import (13); rva/size low byte.
    for index in (1, 9, 13):
        for field in (0, 1):
            out.append(Mutation("flip_dd", (index, field)))
    # Section table: first and last entry, every structural field.
    for section in (0, -1):
        for field in (0, 8, 12, 16, 20, 36):
            out.append(Mutation("flip_section", (section, field)))
    # Data directory rva/size set to 0, 0xFFFFFFFF and just past SizeOfImage.
    for index in (1, 9, 13):
        for field in (0, 1):
            for value in (0, 1, 2):
                out.append(Mutation("set_dd", (index, field, value)))
    # e_lfanew pointing past EOF (exactly at EOF and far beyond it).
    out.append(Mutation("set_elfanew", (-1,)))
    out.append(Mutation("set_elfanew", (0xFFFFFFFF,)))
    return out


def _params() -> list:
    params = []
    for path in TARGET_FILES:
        if not path.is_file():
            params.append(pytest.param(path, None, id=f"{path.name}::missing-file",
                                       marks=pytest.mark.skip(reason=f"real system binary not present: {path}")))
            continue
        size = path.stat().st_size
        for mutation in _mutations(size):
            case_id = f"{path.name}::{mutation.kind}{mutation.args}"
            mark = ()
            if case_id in KNOWN_BAD:
                mark = (pytest.mark.xfail(strict=True, reason=KNOWN_BAD[case_id]),)
            params.append(pytest.param(path, mutation, id=case_id, marks=mark))
    return params


PARAMS = _params()
if not any(p.values[0].is_file() for p in PARAMS if p.values and p.values[0] is not None):
    pytest.skip("no real Windows PE binaries available (non-Windows host)", allow_module_level=True)


# ------------------------------------------------------------------------------------------ mutation engine

def _apply(data: bytes, mutation: Mutation) -> tuple[bytes, str]:
    """Returns (mutated bytes, human-readable description). Offsets are resolved from the input file."""
    size = len(data)
    if mutation.kind == "trunc":
        n = mutation.args[0]
        return data[:n], f"truncate to {n} bytes (file size {size})"
    buf = bytearray(data)
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if mutation.kind == "flip":
        offset = mutation.args[0]
        buf[offset] ^= 0xFF
        return bytes(buf), f"flip byte at file offset 0x{offset:x}"
    if mutation.kind == "flip_rel":
        offset = e + mutation.args[0]
        buf[offset] ^= 0xFF
        return bytes(buf), f"flip byte at file offset 0x{offset:x} (e_lfanew 0x{e:x} + 0x{mutation.args[0]:x})"
    opt = e + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    dirs_at = opt + (112 if magic == 0x20B else 96)
    if mutation.kind == "flip_opt":
        offset = opt + mutation.args[0]
        buf[offset] ^= 0xFF
        return bytes(buf), f"flip optional-header byte at file offset 0x{offset:x} (opt + 0x{mutation.args[0]:x})"
    if mutation.kind == "flip_dd":
        index, field = mutation.args
        offset = dirs_at + 8 * index + 4 * field
        buf[offset] ^= 0xFF
        return bytes(buf), (f"flip data directory {index} {'rva' if field == 0 else 'size'} "
                            f"low byte at file offset 0x{offset:x}")
    if mutation.kind == "flip_section":
        section, field = mutation.args
        nsec = struct.unpack_from("<H", data, e + 6)[0]
        sizeopt = struct.unpack_from("<H", data, e + 20)[0]
        idx = nsec - 1 if section == -1 else section
        offset = opt + sizeopt + 40 * idx + field
        buf[offset] ^= 0xFF
        return bytes(buf), (f"flip section {idx} field +0x{field:x} byte at file offset 0x{offset:x} "
                            f"({nsec} sections)")
    if mutation.kind == "set_dd":
        index, field, value_sel = mutation.args
        offset = dirs_at + 8 * index + 4 * field
        size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        value = (0, 0xFFFFFFFF, (size_of_image + 0x10) & 0xFFFFFFFF)[value_sel]
        struct.pack_into("<I", buf, offset, value)
        return bytes(buf), (f"set data directory {index} {'rva' if field == 0 else 'size'} = 0x{value:x} "
                            f"at file offset 0x{offset:x}")
    if mutation.kind == "set_elfanew":
        value = size if mutation.args[0] == -1 else mutation.args[0]
        struct.pack_into("<I", buf, 0x3C, value & 0xFFFFFFFF)
        return bytes(buf), f"set e_lfanew = 0x{value:x} (file size 0x{size:x})"
    raise AssertionError(f"unknown mutation kind: {mutation}")


# ----------------------------------------------------------------------------------------------- the targets

def _scan_imports_image_bytes(data: bytes):
    img = parse_pe(lambda off, n: data[off:off + n], len(data))
    return scan_imports_image(img, lambda off, n: data[off:off + n])


# name -> (callable, allowed exception types)
TARGETS = (
    ("parse_pe", lambda d: parse_pe(lambda off, n: d[off:off + n], len(d)), (PeError,)),
    ("scan_imports", scan_imports, (PeError,)),
    ("scan_imports_image", _scan_imports_image_bytes, (PeError,)),
    ("scan_protection", scan_protection, (ProtectionError,)),
)
IMPORT_TARGETS = frozenset({"scan_imports", "scan_imports_image"})


@lru_cache(maxsize=None)
def _baseline_import_extent(path_str: str) -> tuple[int, bool]:
    """Highest file offset the unmutated import/TLS walk reads, and whether the file has such tables at all.

    Used only to decide whether a truncation really removed table bytes: a 64-byte slack absorbs the read
    windows `_read_cstr` uses (it can over-read up to 63 bytes past the terminating NUL).
    """
    data = Path(path_str).read_bytes()
    img = parse_pe(lambda off, n: data[off:off + n], len(data))
    high = 0

    def read(off: int, n: int) -> bytes:
        nonlocal high
        high = max(high, off + n)
        return data[off:off + n]

    profile = scan_imports_image(img, read)
    has_tables = bool(profile.imports or profile.delay_imports or profile.tls_callbacks)
    return high, has_tables


def _truncated_table_bytes(path: Path, mutation: Mutation, mutated_len: int) -> bool:
    high, has_tables = _baseline_import_extent(str(path))
    return has_tables and mutated_len + 64 <= high


@pytest.mark.parametrize("path,mutation", PARAMS)
def test_pe_parsers_survive_mutation(path: Path, mutation: Mutation):
    data = path.read_bytes()
    mutated, description = _apply(data, mutation)
    for name, call, allowed in TARGETS:
        started = time.perf_counter()
        try:
            result = call(mutated)
            error: Exception | None = None
        except Exception as exc:  # noqa: BLE001 - the exception type is exactly what is under test
            result, error = None, exc
        elapsed = time.perf_counter() - started

        assert elapsed <= MAX_CALL_SECONDS, (
            f"{name} took {elapsed:.3f}s (> {MAX_CALL_SECONDS}s) on {path.name}: {description}")

        if error is not None:
            assert isinstance(error, allowed), (
                f"{name} raised unhandled {type(error).__name__}: {error} -- {path.name}: {description}")
            continue

        if name in IMPORT_TARGETS and result.complete:
            assert not _truncated_table_bytes(path, mutation, len(mutated)), (
                f"{name} claimed complete=True although the truncation removed import/delay-import/TLS table "
                f"bytes -- {path.name}: {description}; unknowns={result.unknowns!r}")
