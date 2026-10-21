"""`emulate` request: validation of the tool arguments into ONE canonical request (pure Python, no emulator needed).

The canonical request is what enters the evidence `parameters` (and so the evidence id): the same request on the same
target gives the same `ev_`. It holds no floats (the evidence id projection forbids them): the time limit is stored in
milliseconds. Version 2 fields (`buffers`, `memory`, `registers`, `output_registers`, `end`, new argument and output
forms) enter the canonical request only when used, so a version 1 request keeps its evidence id.
Design: docs/design/emulation.md (sections 4-6 and 13).
"""

from __future__ import annotations

from typing import Any

from ..analysis.pe_image import VIEWS, normalize_views

LAYOUT_VERSION = 1

CONVENTIONS = {"x86": ("cdecl", "stdcall", "fastcall", "thiscall"), "x64": ("ms64",)}
DEFAULT_CONVENTION = {"x86": "cdecl", "x64": "ms64"}
GPRS = {"x64": ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
        "x86": ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp")}
SP_REG = {"x64": "rsp", "x86": "esp"}
RETURN_REGS = {"x64": ("rax", "rdx"), "x86": ("eax", "edx")}

MAX_ARGS = 16
MAX_BUFFER = 1 << 20            # one argument or scratch buffer
MAX_BUFFERS_TOTAL = 4 << 20     # all argument and scratch buffers together
MAX_SCRATCH = 16
MAX_OUTPUTS = 16
MAX_OUTPUT_BYTES = 4096         # one output read (bytes recorded)
MAX_OUTPUTS_TOTAL = 16384       # all byte-recording output reads together
MAX_DIGEST_BYTES = MAX_BUFFER   # one digest-only output read (only length + SHA-256 recorded)
MAX_DIGEST_TOTAL = 4 << 20
MAX_PREWRITES = 64
MAX_PREWRITE_TOTAL = 64 << 10
MAX_SP_OFFSET = 16 << 20
DEFAULT_MAX_INSTRUCTIONS = 2_000_000
MAX_INSTRUCTIONS = 100_000_000
DEFAULT_TIMEOUT_S = 10.0
MAX_TIMEOUT_S = 60.0
DEFAULT_STACK = 1 << 20
MIN_STACK, MAX_STACK = 64 << 10, 16 << 20
DEFAULT_OUTPUT_VIEWS = ("ascii",)
SCN_EXECUTE = 0x2000_0000

BUFFER_KEYS = {"hex", "buffer", "ascii", "utf16"}


class SpecError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


def _bad(msg: str) -> SpecError:
    return SpecError("BAD_ARGUMENT", msg)


def parse_int(value: Any, what: str) -> int:
    """int (not bool), '0x..' hex or decimal string; a leading '-' is allowed (two's complement is applied later)."""
    if isinstance(value, bool):
        raise _bad(f"{what}: a bool is not a number")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip().replace("_", "")
        neg = s.startswith("-")
        body = s[1:] if neg else s
        try:
            n = int(body, 16) if body.lower().startswith("0x") else int(body, 10)
        except ValueError:
            raise _bad(f"{what}: {value!r} is not a number (write hex as '0x..')") from None
        if not body or body.lower() == "0x":
            raise _bad(f"{what}: empty number")
        return -n if neg else n
    raise _bad(f"{what}: expected an integer or a '0x..' string, got {type(value).__name__}")


def _views(spec: dict, what: str) -> list[str]:
    v = spec.get("view", spec.get("views"))
    if v is None:
        return list(DEFAULT_OUTPUT_VIEWS)
    try:
        return list(normalize_views(v))
    except ValueError as e:
        raise _bad(f"{what}: {e}") from e


def _bytes(a: dict, k: str, what: str, *, nul: bool) -> bytes:
    v = a[k]
    if not isinstance(v, str):
        raise _bad(f"{what}.{k} must be a string")
    if k == "hex":
        try:
            return bytes.fromhex(v.replace(" ", ""))
        except ValueError:
            raise _bad(f"{what}.hex is not an even-length hex string") from None
    if k == "ascii":
        try:
            return v.encode("ascii") + (b"\0" if nul else b"")
        except UnicodeEncodeError:
            raise _bad(f"{what}.ascii must be ASCII (use utf16 or hex)") from None
    return v.encode("utf-16-le") + (b"\0\0" if nul else b"")


def _encoded_len(v: str, k: str, *, nul: bool) -> int:
    """Upper bound of the decoded length of `v` in bytes, from the string length alone: two characters per hex byte,
    one per ASCII character, two per UTF-16 character; a buffer's NUL terminator adds one byte (ascii) or two (utf16).
    Lets a limit be checked before the bytes exist (a huge literal must not be materialised to be refused)."""
    if k == "hex":
        return len(v) // 2
    if k == "ascii":
        return len(v) + (1 if nul else 0)
    return 2 * len(v) + (2 if nul else 0)


def _raw_len(a: dict, k: str, what: str, *, nul: bool) -> int:
    """`_encoded_len` of a data field, checking only that it is a string (no allocation)."""
    v = a[k]
    if not isinstance(v, str):
        raise _bad(f"{what}.{k} must be a string")
    return _encoded_len(v, k, nul=nul)


def _buffer(a: dict, what: str) -> dict:
    """A buffer spec ({"hex"|"ascii"|"utf16": .., "size"?} or {"buffer": N}) -> {"kind":"buffer","size","init_hex"}."""
    keys = set(a) - {"size"}
    if len(keys) != 1 or not keys <= BUFFER_KEYS:
        raise _bad(f"{what}: give exactly one of {{\"hex\":\"..\"}}, {{\"buffer\":N}}, {{\"ascii\":\"..\"}}, "
                   "{\"utf16\":\"..\"} (optional \"size\" to enlarge a hex/ascii/utf16 buffer)")
    (k,) = keys
    if k == "buffer":
        if "size" in a:
            raise _bad(f"{what}: use either buffer=N or size, not both")
        init, size = b"", parse_int(a["buffer"], what + ".buffer")
    else:
        # Size limits are checked on the RAW string first: an oversize literal is refused before it is decoded.
        if _raw_len(a, k, what, nul=True) > MAX_BUFFER:
            raise _bad(f"{what}: buffer size must be 1..{MAX_BUFFER} bytes")
        explicit = parse_int(a["size"], what + ".size") if "size" in a else None
        if explicit is not None and not 1 <= explicit <= MAX_BUFFER:
            raise _bad(f"{what}: buffer size must be 1..{MAX_BUFFER} bytes")
        init = _bytes(a, k, what, nul=True)
        size = len(init) if explicit is None else explicit
        if size < len(init):
            raise _bad(f"{what}: size {size} is smaller than the initial content ({len(init)} bytes)")
    if not 1 <= size <= MAX_BUFFER:
        raise _bad(f"{what}: buffer size must be 1..{MAX_BUFFER} bytes")
    return {"kind": "buffer", "size": size, "init_hex": init.hex()}


def _offset(o: dict, what: str) -> int:
    off = parse_int(o.get("offset", 0), what + ".offset")
    if off < 0:
        raise _bad(f"{what}.offset must be >= 0")
    return off


class _Ctx:
    """What a reference may point at: buffer arguments (index -> size) and scratch buffers (sizes)."""

    def __init__(self, arch: str, arg_bufs: dict[int, int], scratch: list[int]):
        self.arch, self.bits = arch, 64 if arch == "x64" else 32
        self.arg_bufs, self.scratch = arg_bufs, scratch

    def ref(self, v: Any, what: str) -> dict:
        """A value reference: integer | {"va", "length"?} | {"arg", "offset"?} | {"buf", "offset"?}."""
        if not isinstance(v, dict):
            n = parse_int(v, what)
            if not -(1 << (self.bits - 1)) <= n < (1 << self.bits):
                raise _bad(f"{what}: {n} does not fit in {self.bits} bits")
            return {"kind": "int", "value": n & ((1 << self.bits) - 1)}
        if "va" in v:
            if set(v) - {"va", "length"}:
                raise _bad(f"{what}: an image pointer is {{\"va\":\"0x..\", \"length\"?:N}}")
            va = parse_int(v["va"], what + ".va")
            if not 0 < va < (1 << self.bits):
                raise _bad(f"{what}.va must be a positive {self.bits}-bit address")
            out = {"kind": "image_ptr", "value": va}
            if "length" in v:
                n = parse_int(v["length"], what + ".length")
                if not 1 <= n <= MAX_BUFFER:
                    raise _bad(f"{what}.length must be 1..{MAX_BUFFER}")
                out["length"] = n
            return out
        for key, kind, sizes in (("arg", "arg_ptr", self.arg_bufs), ("buf", "buf_ptr", dict(enumerate(self.scratch)))):
            if key in v:
                if set(v) - {key, "offset"}:
                    raise _bad(f"{what}: a buffer pointer is {{\"{key}\":i, \"offset\"?:k}}")
                idx, off = parse_int(v[key], f"{what}.{key}"), _offset(v, what)
                if idx not in sizes:
                    raise _bad(f"{what}.{key}: {idx} is not a " +
                               ("buffer argument" if key == "arg" else "scratch buffer (see `buffers`)"))
                if off > sizes[idx]:
                    raise _bad(f"{what}.offset {off} is past the end of the buffer ({sizes[idx]} bytes)")
                return {"kind": kind, key: idx, "offset": off}
        raise _bad(f"{what}: expected an integer, {{\"va\"}}, {{\"arg\"}} or {{\"buf\"}}")


def _arg(i: int, a: Any, ctx: _Ctx) -> dict:
    what = f"args[{i}]"
    if isinstance(a, dict) and set(a) & BUFFER_KEYS:
        return _buffer(a, what)
    return ctx.ref(a, what)


def _target_size(out: dict, ctx: _Ctx, what: str) -> int:
    if out["source"] == "arg":
        idx = out["arg"]
        if idx not in ctx.arg_bufs:
            raise _bad(f"{what}.arg: argument {idx} is not a buffer argument")
        return ctx.arg_bufs[idx]
    idx = out["buf"]
    if not 0 <= idx < len(ctx.scratch):
        raise _bad(f"{what}.buf: {idx} is not a scratch buffer (see `buffers`)")
    return ctx.scratch[idx]


def _output(i: int, o: Any, ctx: _Ctx) -> dict:
    what = f"outputs[{i}]"
    if not isinstance(o, dict):
        raise _bad(f"{what}: must be an object {{arg:i, length}} | {{buf:j, length}} | {{va:'0x..', length}} | "
                   "{ret:true, length} | {reg:'name', length}")
    src = [k for k in ("arg", "buf", "va", "ret", "reg") if k in o]
    if len(src) != 1:
        raise _bad(f"{what}: give exactly one of arg (buffer argument), buf (scratch buffer), va (address), ret "
                   "(pointer in the return register) or reg (pointer in a register)")
    unknown = set(o) - {"arg", "buf", "va", "ret", "reg", "length", "offset", "view", "views", "digest"}
    if unknown:
        raise _bad(f"{what}: unknown keys {sorted(unknown)}")
    digest = o.get("digest", False)
    if not isinstance(digest, bool):
        raise _bad(f"{what}.digest must be true or false")
    cap = MAX_DIGEST_BYTES if digest else MAX_OUTPUT_BYTES
    length = parse_int(o.get("length"), what + ".length") if "length" in o else None
    out: dict[str, Any]
    if src[0] in ("arg", "buf"):
        out = {"source": src[0], src[0]: parse_int(o[src[0]], f"{what}.{src[0]}"), "offset": _offset(o, what)}
        size = _target_size(out, ctx, what)
        if length is None:
            length = min(size - out["offset"], cap)
        if out["offset"] + length > size:
            kind = "buffer argument" if src[0] == "arg" else "scratch buffer"
            raise _bad(f"{what}: offset+length is outside {kind} {out[src[0]]} ({size} bytes)")
    elif src[0] == "va":
        va = parse_int(o["va"], what + ".va")
        if va < 0 or "offset" in o:
            raise _bad(f"{what}: va must be a non-negative address (no offset with va)")
        out = {"source": "va", "va": va}
    elif src[0] == "ret":
        if o["ret"] is not True:
            raise _bad(f"{what}.ret must be true")
        out = {"source": "ret", "offset": _offset(o, what)}
    else:
        reg = str(o["reg"]).strip().lower()
        if reg not in GPRS[ctx.arch] + (SP_REG[ctx.arch],):
            raise _bad(f"{what}.reg: {o['reg']!r} is not a general-purpose register of {ctx.arch}")
        out = {"source": "reg", "reg": reg, "offset": _offset(o, what)}
    if length is None or not 1 <= length <= cap:
        raise _bad(f"{what}: length must be 1..{cap}" + ("" if digest else " (digest:true allows up to "
                                                              f"{MAX_DIGEST_BYTES} bytes, recording only the SHA-256)"))
    out["length"] = length
    if digest:
        out["digest"] = True
    else:
        out["views"] = _views(o, what)
    return out


def _prewrite(i: int, m: Any, ctx: _Ctx) -> dict:
    what = f"memory[{i}]"
    if not isinstance(m, dict):
        raise _bad(f"{what}: must be an object with one target (va | sp | arg | buf) and one data field "
                   "(hex | ascii | utf16 | ptr)")
    targets = [k for k in ("va", "sp", "arg", "buf") if k in m]
    data = [k for k in ("hex", "ascii", "utf16", "ptr") if k in m]
    if len(targets) != 1 or len(data) != 1:
        raise _bad(f"{what}: give exactly one target (va | sp | arg | buf) and one data field (hex | ascii | utf16 | "
                   "ptr)")
    unknown = set(m) - {"va", "sp", "arg", "buf", "offset", "hex", "ascii", "utf16", "ptr"}
    if unknown:
        raise _bad(f"{what}: unknown keys {sorted(unknown)}")
    t = targets[0]
    out: dict[str, Any] = {"target": t}
    if t == "va":
        if "offset" in m:
            raise _bad(f"{what}: no offset with va")
        out["va"] = parse_int(m["va"], what + ".va")
        if out["va"] <= 0:
            raise _bad(f"{what}.va must be a positive address")
    elif t == "sp":
        if "offset" in m:
            raise _bad(f"{what}: the sp value is the offset")
        out["offset"] = parse_int(m["sp"], what + ".sp")
        if abs(out["offset"]) > MAX_SP_OFFSET:
            raise _bad(f"{what}.sp must be within +-{MAX_SP_OFFSET}")
    else:
        out[t], out["offset"] = parse_int(m[t], f"{what}.{t}"), _offset(m, what)
    if data[0] == "ptr":
        out["ptr"] = ctx.ref(m["ptr"], what + ".ptr")
        n = ctx.bits // 8
    else:
        raw = _bytes(m, data[0], what, nul=False)
        if not raw:
            raise _bad(f"{what}: empty data")
        out["hex"], n = raw.hex(), len(raw)
    if t in ("arg", "buf"):
        size = _target_size({"source": t, t: out[t]}, ctx, what)
        if out["offset"] + n > size:
            raise _bad(f"{what}: offset+data ({out['offset']}+{n}) is outside the buffer ({size} bytes)")
    return out


def prewrite_size(m: dict, bits: int) -> int:
    return bits // 8 if "ptr" in m else len(m["hex"]) // 2


def prewrite_bound(m: Any, bits: int) -> int:
    """Upper bound of a pre-write's data length in bytes, from the raw arguments only (no decoding or encoding): a
    pointer is one machine word, a hex/ascii/utf16 string is bounded by its character count. 0 when the item is not an
    object with exactly one data field, so that `_prewrite` reports that error itself."""
    if not isinstance(m, dict):
        return 0
    data = [k for k in ("hex", "ascii", "utf16", "ptr") if k in m]
    if len(data) != 1:
        return 0
    if data[0] == "ptr":
        return bits // 8
    v = m[data[0]]
    if not isinstance(v, str):
        return 0
    return _encoded_len(v, data[0], nul=False)


def arg_registers(arch: str, convention: str, nargs: int) -> tuple[str, ...]:
    """The registers the calling convention loads from the first arguments."""
    regs = {"ms64": ("rcx", "rdx", "r8", "r9"), "fastcall": ("ecx", "edx"), "thiscall": ("ecx",)}.get(convention, ())
    return regs[:nargs]


def build_request(*, arch: str, function: Any, args: Any = None, convention: Any = None, outputs: Any = None,
                  max_instructions: Any = DEFAULT_MAX_INSTRUCTIONS, timeout_s: Any = DEFAULT_TIMEOUT_S,
                  stack_size: Any = DEFAULT_STACK, buffers: Any = None, memory: Any = None, registers: Any = None,
                  output_registers: Any = None, end: Any = None) -> dict:
    """Validates the tool arguments for an image of `arch` ('x86' | 'x64'). SpecError on anything malformed.
    Image-dependent checks (image pointers, image pre-writes, `end`) are in `check_image`."""
    if arch not in CONVENTIONS:
        raise SpecError("EMU_ARCH_UNSUPPORTED", f"emulation supports x86 and x64 PE images, not {arch}")
    bits = 64 if arch == "x64" else 32
    fn = parse_int(function, "function")
    if fn <= 0:
        raise _bad("function must be a positive VA")
    conv = DEFAULT_CONVENTION[arch] if convention in (None, "") else str(convention).strip().lower()
    if conv not in CONVENTIONS[arch]:
        raise _bad(f"convention {conv!r} is not valid for {arch}; use one of {', '.join(CONVENTIONS[arch])}")
    buffers = [] if buffers is None else buffers
    if not isinstance(buffers, list) or len(buffers) > MAX_SCRATCH:
        raise _bad(f"buffers must be a list of at most {MAX_SCRATCH} buffer specs")
    cbufs = []
    for j, b in enumerate(buffers):
        if not isinstance(b, dict):
            raise _bad(f"buffers[{j}]: must be an object such as {{\"hex\":\"..\"}} or {{\"buffer\":N}}")
        cbufs.append(_buffer(b, f"buffers[{j}]"))
    args = [] if args is None else args
    if not isinstance(args, list) or len(args) > MAX_ARGS:
        raise _bad(f"args must be a list of at most {MAX_ARGS} items")
    # buffer arguments first (a pointer argument may refer to any buffer argument, before or after it)
    arg_bufs = {i: _buffer(a, f"args[{i}]")["size"] for i, a in enumerate(args)
                if isinstance(a, dict) and set(a) & BUFFER_KEYS}
    ctx = _Ctx(arch, arg_bufs, [b["size"] for b in cbufs])
    cargs = [_arg(i, a, ctx) for i, a in enumerate(args)]
    if sum(a["size"] for a in cargs + cbufs if a["kind"] == "buffer") > MAX_BUFFERS_TOTAL:
        raise _bad(f"argument and scratch buffers total more than {MAX_BUFFERS_TOTAL} bytes")
    outputs = [] if outputs is None else outputs
    if not isinstance(outputs, list) or len(outputs) > MAX_OUTPUTS:
        raise _bad(f"outputs must be a list of at most {MAX_OUTPUTS} items")
    couts = [_output(i, o, ctx) for i, o in enumerate(outputs)]
    if sum(o["length"] for o in couts if not o.get("digest")) > MAX_OUTPUTS_TOTAL:
        raise _bad(f"outputs total more than {MAX_OUTPUTS_TOTAL} bytes; read less per call or use digest:true")
    if sum(o["length"] for o in couts if o.get("digest")) > MAX_DIGEST_TOTAL:
        raise _bad(f"digest outputs total more than {MAX_DIGEST_TOTAL} bytes")
    memory = [] if memory is None else memory
    if not isinstance(memory, list) or len(memory) > MAX_PREWRITES:
        raise _bad(f"memory must be a list of at most {MAX_PREWRITES} pre-writes")
    cmem: list[dict] = []
    total = 0
    for i, m in enumerate(memory):
        total += prewrite_bound(m, bits)   # running budget on the raw lengths, before this pre-write is decoded
        if total > MAX_PREWRITE_TOTAL:
            raise _bad(f"pre-writes total more than {MAX_PREWRITE_TOTAL} bytes")
        cmem.append(_prewrite(i, m, ctx))
    if sum(prewrite_size(m, bits) for m in cmem) > MAX_PREWRITE_TOTAL:   # exact sizes (defense next to the bound)
        raise _bad(f"pre-writes total more than {MAX_PREWRITE_TOTAL} bytes")
    registers = {} if registers is None else registers
    if not isinstance(registers, dict):
        raise _bad("registers must be an object {name: value}")
    taken = arg_registers(arch, conv, len(cargs))
    cregs: dict[str, dict] = {}
    for name, v in registers.items():
        n = str(name).strip().lower()
        if n not in GPRS[arch]:
            raise _bad(f"registers: {name!r} is not a settable register of {arch} ({', '.join(GPRS[arch])}; the "
                       "stack pointer is fixed by the frame, use memory pre-writes with sp)")
        if n in taken:
            raise _bad(f"registers: {n} is already loaded from args by the {conv} convention")
        if n in cregs:
            raise _bad(f"registers: {n} given twice")
        cregs[n] = ctx.ref(v, f"registers.{n}")
    oregs: list[str] = []
    if output_registers not in (None, [], ""):
        names = output_registers if isinstance(output_registers, list) else [output_registers]
        allowed = GPRS[arch] + (SP_REG[arch],)
        for name in names:
            n = str(name).strip().lower()
            if n == "all":
                oregs.extend(allowed)
            elif n in allowed:
                oregs.append(n)
            else:
                raise _bad(f"output_registers: {name!r} is not a general-purpose register of {arch} or 'all'")
        oregs = sorted(set(oregs) - set(RETURN_REGS[arch]))
    mi = parse_int(max_instructions, "max_instructions")
    if not 1 <= mi <= MAX_INSTRUCTIONS:
        raise _bad(f"max_instructions must be 1..{MAX_INSTRUCTIONS}")
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)) or not 0 < timeout_s <= MAX_TIMEOUT_S:
        raise _bad(f"timeout_s must be a number in (0, {int(MAX_TIMEOUT_S)}]")
    st = parse_int(stack_size, "stack_size")
    if not MIN_STACK <= st <= MAX_STACK:
        raise _bad(f"stack_size must be {MIN_STACK}..{MAX_STACK} bytes")
    st = (st + 0xFFFF) & ~0xFFFF
    req: dict[str, Any] = {"function": fn, "arch": arch, "convention": conv, "args": cargs, "outputs": couts,
                           "max_instructions": mi, "timeout_ms": int(round(float(timeout_s) * 1000)),
                           "stack_size": st, "layout_version": LAYOUT_VERSION}
    # version 2 fields only when used: a version 1 request stays canonically identical (same evidence id)
    if cbufs:
        req["buffers"] = cbufs
    if cmem:
        req["memory"] = cmem
    if cregs:
        req["registers"] = dict(sorted(cregs.items()))
    if oregs:
        req["output_registers"] = oregs
    if end not in (None, ""):
        e = parse_int(end, "end")
        if e <= 0 or e == fn:
            raise _bad("end must be a positive VA different from the start (function)")
        req["end"] = e
    return req


def _refs(request: dict):
    """(where, reference) for every value reference in the request."""
    for i, a in enumerate(request["args"]):
        if a["kind"] != "buffer":
            yield f"args[{i}]", a
    for n, r in request.get("registers", {}).items():
        yield f"registers.{n}", r
    for i, m in enumerate(request.get("memory", [])):
        if "ptr" in m:
            yield f"memory[{i}].ptr", m["ptr"]


def check_image(request: dict, image_base: int, size_of_image: int, size_of_headers: int,
                sections: list[tuple[str, int, int, int]]) -> None:
    """Image-dependent checks. sections: (name, rva, extent, flags). SpecError (BAD_ARGUMENT) on a violation:
    an image pointer outside the image, an image pre-write outside the image or onto the headers or an executable
    section (the emulated code is always the target's own code), an `end` outside the image."""
    lo, hi = image_base, image_base + size_of_image
    for where, r in _refs(request):
        if r["kind"] == "image_ptr":
            n = r.get("length", 1)
            if not (lo <= r["value"] and r["value"] + n <= hi):
                raise _bad(f"{where}: image pointer 0x{r['value']:x}" + (f"+{n}" if "length" in r else "") +
                           f" is outside the image [0x{lo:x}, 0x{hi:x})")
    bits = 64 if request["arch"] == "x64" else 32
    for i, m in enumerate(request.get("memory", [])):
        if m["target"] != "va":
            continue
        a, n = m["va"], prewrite_size(m, bits)
        if not (lo <= a and a + n <= hi):
            raise _bad(f"memory[{i}]: 0x{a:x}+{n} is outside the image [0x{lo:x}, 0x{hi:x})")
        if a < lo + size_of_headers:
            raise _bad(f"memory[{i}]: 0x{a:x} is in the PE headers; only data may be pre-written")
        for name, rva, extent, flags in sections:
            s0, s1 = lo + rva, lo + rva + extent
            if flags & SCN_EXECUTE and a < s1 and a + n > s0:
                raise _bad(f"memory[{i}]: 0x{a:x}+{n} overlaps the executable section {name}; code is never "
                           "pre-written (the emulated code must be the target's own)")
    if "end" in request and not lo <= request["end"] < hi:
        raise _bad(f"end 0x{request['end']:x} is outside the image [0x{lo:x}, 0x{hi:x})")


def check_pe_image(request: dict, img: Any) -> None:
    """check_image for a PeImage."""
    check_image(request, img.image_base, img.size_of_image, img.size_of_headers,
                [(s.name, s.rva, s.extent, s.flags) for s in img.sections])


__all__ = ["build_request", "check_image", "check_pe_image", "SpecError", "parse_int", "CONVENTIONS", "VIEWS",
           "LAYOUT_VERSION", "GPRS", "arg_registers", "prewrite_size"]
