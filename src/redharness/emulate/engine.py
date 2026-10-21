"""Runs one emulation request with the Unicorn CPU emulator (imported lazily: the rest of the harness works without it).

The function is entered with the request's calling convention and a return address that points at an unmapped
sentinel; reaching the sentinel with a real return is the only successful end. With `end` (a code range, version 2)
reaching `end` is the only successful end, and returning to the sentinel first is a failure ("left the range").
Analyst pre-writes (`memory`) and register values (`registers`) are applied after the frame, before the first
instruction. Everything else stops the emulation with an explicit reason and NO result: a call into an imported API
(named), an unmapped or protection-violating access, an interrupt, `syscall`/`sysenter`, `in`/`out`, `cpuid`, an
invalid instruction, or the instruction/time limit. The request is emulated twice in two fresh emulator instances;
differing results are reported as nondeterministic (e.g. `rdtsc`).

No target code runs natively: Unicorn interprets/translates the instructions into its own sandboxed guest memory.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

from ..analysis.pe_image import PeError, parse_pe
from .loader import LOW_ADDRESS, Layout, LayoutError, plan

RUNS = 2
STACK_HEADROOM = 0x100
RANGE_HEADROOM = 0x2000     # code range: room above SP for the enclosing function's locals and home slots


class EmulatorMissing(RuntimeError):
    """The `unicorn` package is not installed in this environment."""


class BadRequest(ValueError):
    """The request cannot be laid out on this image (e.g. a stack pre-write outside the mapped stack)."""


def emulator_identity() -> dict:
    """{name, version} of the installed emulator; EmulatorMissing if absent."""
    try:
        import unicorn
    except ImportError as e:  # pragma: no cover - exercised by a monkeypatched test
        raise EmulatorMissing(f"the 'unicorn' package is not installed ({e})") from e
    return {"name": "unicorn", "version": str(unicorn.__version__)}


def _prot(U: Any, perm: str) -> int:
    return ((U.UC_PROT_READ if "r" in perm else 0) | (U.UC_PROT_WRITE if "w" in perm else 0)
            | (U.UC_PROT_EXEC if "x" in perm else 0))


def _frame(request: dict, layout: Layout, arg_values: list[int]) -> tuple[dict[str, int], int, list[int], int]:
    """(register values, entry SP, stack words from SP upwards incl. the return address, expected SP after return)."""
    conv, n_regs = request["convention"], 0
    headroom = RANGE_HEADROOM if "end" in request else STACK_HEADROOM
    regs: dict[str, int] = {}
    if request["arch"] == "x64":
        names = ("rcx", "rdx", "r8", "r9")
        for name, v in zip(names, arg_values):
            regs[name] = v
        stack_args = arg_values[4:]
        words = [layout.ret_sentinel, 0, 0, 0, 0] + stack_args     # return address + 32-byte shadow space
        base = (layout.stack_top - headroom - 8 * len(words)) & ~0xF
        sp = base + 8                                                # RSP+8 is 16-aligned at entry (call pushed 8)
        return regs, sp, words, sp + 8
    if conv == "fastcall":
        n_regs = 2
    elif conv == "thiscall":
        n_regs = 1
    for name, v in zip(("ecx", "edx")[:n_regs], arg_values):
        regs[name] = v
    stack_args = arg_values[n_regs:]
    words = [layout.ret_sentinel] + stack_args
    base = (layout.stack_top - headroom - 4 * len(words)) & ~0xF
    sp = base + 12                                                   # ESP+4 is 16-aligned at entry
    callee_pops = 0 if conv == "cdecl" else 4 * len(stack_args)
    return regs, sp, words, sp + 4 + callee_pops


def _buffer_addresses(request: dict, layout: Layout) -> tuple[dict[int, int], list[int]]:
    """(argument index -> buffer address, scratch buffer addresses)."""
    idx = [i for i, a in enumerate(request["args"]) if a["kind"] == "buffer"]
    return {i: b[2] for i, b in zip(idx, layout.buffers)}, [b[2] for b in layout.scratch]


def _resolve(ref: dict, arg_bufs: dict[int, int], scratch: list[int]) -> int:
    kind = ref["kind"]
    if kind in ("int", "image_ptr"):
        return ref["value"]
    if kind == "arg_ptr":
        return arg_bufs[ref["arg"]] + ref["offset"]
    if kind == "buf_ptr":
        return scratch[ref["buf"]] + ref["offset"]
    raise BadRequest(f"unknown value reference {kind!r}")


def _prewrites(request: dict, layout: Layout, sp: int, arg_bufs: dict[int, int], scratch: list[int],
               psize: int) -> list[tuple[int, bytes]]:
    """(address, bytes) of every analyst pre-write, in request order. BadRequest if a stack pre-write is outside the
    mapped stack (image and buffer targets were checked by spec against the image and the buffer sizes)."""
    out = []
    mask = (1 << (8 * psize)) - 1
    for i, m in enumerate(request.get("memory", [])):
        if "ptr" in m:
            data = (_resolve(m["ptr"], arg_bufs, scratch) & mask).to_bytes(psize, "little")
        else:
            data = bytes.fromhex(m["hex"])
        t = m["target"]
        if t == "va":
            va = m["va"]
        elif t == "sp":
            va = sp + m["offset"]
            if not layout.stack_ok(va, len(data)):
                raise BadRequest(f"memory[{i}]: sp{m['offset']:+#x} (0x{va:x}, {len(data)} bytes) is outside the "
                                 f"mapped stack [0x{layout.stack_lo:x}, 0x{layout.stack_top:x})")
        elif t == "arg":
            va = arg_bufs[m["arg"]] + m["offset"]
        else:
            va = scratch[m["buf"]] + m["offset"]
        out.append((va, data))
    return out


def plan_frame(request: dict, layout: Layout) -> dict:
    """The deterministic frame of a request (no emulator): argument values, registers, entry SP, stack words, the
    analyst's pre-writes. BadRequest if something does not fit."""
    psize = 8 if request["arch"] == "x64" else 4
    arg_bufs, scratch = _buffer_addresses(request, layout)
    arg_values = [arg_bufs[i] if a["kind"] == "buffer" else _resolve(a, arg_bufs, scratch)
                  for i, a in enumerate(request["args"])]
    regs, sp, words, sp_expected = _frame(request, layout, arg_values)
    if not layout.stack_ok(sp, psize * len(words)):
        raise BadRequest("the call frame does not fit in the stack")
    for name, ref in request.get("registers", {}).items():
        regs[name] = _resolve(ref, arg_bufs, scratch)
    return {"arg_values": arg_values, "regs": regs, "sp": sp, "words": words, "sp_expected": sp_expected,
            "prewrites": _prewrites(request, layout, sp, arg_bufs, scratch, psize), "scratch": scratch}


def _reg_id(X: Any, name: str) -> int:
    return getattr(X, "UC_X86_REG_" + name.upper())


def _readable(uc: Any, U: Any, va: int, length: int) -> bool:
    end = va + length
    for begin, last, perms in uc.mem_regions():
        if begin <= va <= last and perms & U.UC_PROT_READ:
            if end - 1 <= last:
                return True
            va = last + 1
            return _readable(uc, U, va, end - va)
    return False


def _run_once(U: Any, X: Any, request: dict, layout: Layout) -> dict:
    is64 = request["arch"] == "x64"
    rng = "end" in request
    frame = plan_frame(request, layout)
    uc = U.Uc(U.UC_ARCH_X86, U.UC_MODE_64 if is64 else U.UC_MODE_32)
    psize = 8 if is64 else 4
    uc.mem_map(layout.image_base, layout.image_size, U.UC_PROT_ALL)
    for va, data in layout.chunks:
        uc.mem_write(va, data)
    for slot, target in layout.iat_writes:
        uc.mem_write(slot, target.to_bytes(psize, "little"))
    uc.mem_map(layout.stack_lo, layout.stack_top - layout.stack_lo, U.UC_PROT_READ | U.UC_PROT_WRITE)
    bufs = iter(layout.buffers)
    for a in request["args"]:
        if a["kind"] != "buffer":
            continue
        region, rsize, bva = next(bufs)
        uc.mem_map(region, rsize, U.UC_PROT_READ | U.UC_PROT_WRITE)
        if a["init_hex"]:
            uc.mem_write(bva, bytes.fromhex(a["init_hex"]))
    for b, (region, rsize, bva) in zip(request.get("buffers", []), layout.scratch):
        uc.mem_map(region, rsize, U.UC_PROT_READ | U.UC_PROT_WRITE)
        if b["init_hex"]:
            uc.mem_write(bva, bytes.fromhex(b["init_hex"]))
    arg_values, sp, sp_expected = frame["arg_values"], frame["sp"], frame["sp_expected"]
    uc.mem_write(sp, b"".join(w.to_bytes(psize, "little") for w in frame["words"]))
    for va, data in frame["prewrites"]:         # analyst pre-writes: after the frame, before the first instruction
        uc.mem_write(va, data)
    for va, size, perm in layout.perms:         # image permissions last (a pre-write into read-only data is allowed)
        uc.mem_protect(va, size, _prot(U, perm))
    R = X
    for name, v in frame["regs"].items():
        uc.reg_write(_reg_id(R, name), v)
    uc.reg_write(R.UC_X86_REG_RSP if is64 else R.UC_X86_REG_ESP, sp)
    if is64:
        uc.reg_write(R.UC_X86_REG_GS_BASE, layout.teb_base)

    events: list[dict] = []
    kinds = {U.UC_MEM_READ_UNMAPPED: "unmapped_read", U.UC_MEM_WRITE_UNMAPPED: "unmapped_write",
             U.UC_MEM_FETCH_UNMAPPED: "unmapped_fetch", U.UC_MEM_READ_PROT: "protection_read",
             U.UC_MEM_WRITE_PROT: "protection_write", U.UC_MEM_FETCH_PROT: "protection_fetch"}

    def on_mem(uc_: Any, access: int, address: int, size: int, value: int, _d: Any) -> bool:
        events.append({"kind": kinds.get(access, f"memory_access_{access}"), "address": address, "size": size})
        return False

    def on_intr(uc_: Any, intno: int, _d: Any) -> None:
        events.append({"kind": "interrupt", "number": intno})
        uc_.emu_stop()

    def on_insn(name: str):
        def cb(uc_: Any, *_a: Any) -> Any:
            events.append({"kind": "instruction", "instruction": name})
            uc_.emu_stop()
            return 0
        return cb

    uc.hook_add(U.UC_HOOK_MEM_UNMAPPED | U.UC_HOOK_MEM_PROT, on_mem)
    ret_slot_read: list[bool] = []

    def on_ret_slot(uc_: Any, access: int, address: int, size: int, value: int, _d: Any) -> None:
        ret_slot_read.append(True)

    uc.hook_add(U.UC_HOOK_MEM_READ, on_ret_slot, None, sp, sp + psize - 1)   # only the return-address slot
    uc.hook_add(U.UC_HOOK_INTR, on_intr)
    for name, ins in (("syscall", R.UC_X86_INS_SYSCALL), ("sysenter", R.UC_X86_INS_SYSENTER),
                      ("in", R.UC_X86_INS_IN), ("out", R.UC_X86_INS_OUT), ("cpuid", R.UC_X86_INS_CPUID)):
        uc.hook_add(U.UC_HOOK_INSN, on_insn(name), None, 1, 0, ins)

    pc_reg = R.UC_X86_REG_RIP if is64 else R.UC_X86_REG_EIP
    until = request["end"] if rng else layout.ret_sentinel
    t0 = time.monotonic()
    err = None
    try:
        uc.emu_start(request["function"], until, timeout=request["timeout_ms"] * 1000,
                     count=request["max_instructions"])
    except U.UcError as e:
        err = str(e)
    elapsed = time.monotonic() - t0
    pc = uc.reg_read(pc_reg)
    out: dict[str, Any] = {"pc": pc}
    if events:
        ev = dict(events[0])
        addr = ev.get("address")
        if ev["kind"] == "unmapped_fetch" and layout.import_at(addr) is not None:
            out.update(stop="import_call", api=layout.import_at(addr))
        elif rng and ev["kind"] == "unmapped_fetch" and addr == layout.ret_sentinel:
            out.update(stop="left_range", end=request["end"])
        elif addr is not None and is64 and layout.in_teb(addr):
            out.update(stop="teb_access", offset=addr - layout.teb_base)
        else:
            out.update(stop=ev.pop("kind"), **ev)
            if addr is not None and addr < LOW_ADDRESS:
                out["note"] = ("low address: a NULL-pointer access" + ("" if is64 else
                               " or an fs:-relative TEB/PEB access (not modeled)"))
        return out
    if err is not None:
        out.update(stop="cpu_exception", error=err)
        return out
    if pc != until:
        hit_time = elapsed * 1000 >= request["timeout_ms"] * 0.95
        out.update(stop="time_limit" if hit_time else "instruction_limit")
        return out
    sp_after = uc.reg_read(R.UC_X86_REG_RSP if is64 else R.UC_X86_REG_ESP)
    # A real return: the return-address slot at the entry SP was read (a `ret` pops it) AND the stack pointer is where
    # the convention puts it after the return. Reaching the sentinel by a jump, or with an unbalanced stack (wrong
    # convention or argument count), is not a return and gives no result. A code range has no return to check.
    if not rng and (not ret_slot_read or sp_after != sp_expected):
        out.update(stop="bad_return", sp_entry=sp, sp_after=sp_after, sp_expected=sp_expected,
                   ret_slot_read=bool(ret_slot_read))
        return out
    names = list(("rax", "rdx") if is64 else ("eax", "edx")) + list(request.get("output_registers", []))
    regs_out = {n: uc.reg_read(_reg_id(R, n)) for n in names}
    ret = regs_out["rax" if is64 else "eax"]
    outputs = []
    for i, o in enumerate(request["outputs"]):
        src = o["source"]
        if src == "arg":
            va = arg_values[o["arg"]] + o["offset"]
        elif src == "buf":
            va = frame["scratch"][o["buf"]] + o["offset"]
        elif src == "va":
            va = o["va"]
        elif src == "reg":
            va = uc.reg_read(_reg_id(R, o["reg"])) + o["offset"]
        else:
            va = ret + o["offset"]
        if not _readable(uc, U, va, o["length"]):
            out.update(stop="output_unreadable", output=i, address=va, length=o["length"])
            return out
        data = bytes(uc.mem_read(va, o["length"]))
        got = {"index": i, "address": va, "length": o["length"], "sha256": hashlib.sha256(data).hexdigest()}
        if o.get("digest"):
            got["digest"] = True
        else:
            got["hex"] = data.hex()
        outputs.append(got)
    if rng:
        out.update(stop="range_end", registers=regs_out, sp_entry=sp, sp_after=sp_after, arg_values=arg_values,
                   outputs=outputs)
    else:
        out.update(stop="return", registers=regs_out, sp_entry=sp, sp_after=sp_after, sp_expected=sp_expected,
                   stack_balanced=sp_after == sp_expected, arg_values=arg_values, outputs=outputs)
    return out


def run_request(data: bytes, request: dict) -> dict:
    """Emulates `request` (spec.build_request) on the PE file `data`. Returns
    {"ok": bool, "stop": .., "emulator": {...}, "layout": {...}, ...}; ok=True only for a deterministic return (or,
    with `end`, a deterministic arrival at `end`)."""
    ident = emulator_identity()
    import unicorn as U
    from unicorn import x86_const as X
    try:
        img = parse_pe(lambda off, n: data[off:off + n], len(data))
        layout = plan(img, lambda off, n: data[off:off + n], request)
    except (PeError, LayoutError) as e:
        return {"ok": False, "stop": "layout_error", "error": str(e), "emulator": ident}
    if not layout.image_base <= request["function"] < layout.image_base + layout.image_size:
        return {"ok": False, "stop": "layout_error", "error": "function is outside the image", "emulator": ident}
    try:
        plan_frame(request, layout)
    except BadRequest as e:
        return {"ok": False, "stop": "bad_request", "error": str(e), "emulator": ident}
    runs = [_run_once(U, X, request, layout) for _ in range(RUNS)]
    res: dict[str, Any] = {"emulator": ident, "layout": layout.describe(), **runs[0]}
    if any(r != runs[0] for r in runs[1:]):
        res.update(ok=False, stop="nondeterministic",
                   second={k: runs[1].get(k) for k in ("stop", "pc", "registers")})
        return res
    res["ok"] = runs[0]["stop"] == ("range_end" if "end" in request else "return")
    res["deterministic"] = True
    res["runs"] = RUNS
    return res


__all__ = ["run_request", "emulator_identity", "EmulatorMissing", "BadRequest", "plan_frame", "RUNS"]
