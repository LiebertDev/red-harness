"""Turns a successful emulation into evidence (authority `cpu-emulation`, confidence `derived`).

The raw text uses the `read_bytes` dump format for output bytes (`segment N ...` header, indented `0x..: aabbccdd_..`
hex rows, `-- view --` typed views), so the verifier reads hex bytes as bytes, not numbers. The evidence id covers the
canonical request (function, convention, arguments with their initial bytes, outputs, limits, layout version), the
emulator identity and the result; it does not cover the elapsed time. The same request on the same target and the
same emulator version gives the same `ev_`.
"""

from __future__ import annotations

from typing import Any

from ..analysis import section_notes
from ..analysis.pe_image import PeImage, _hex_lines, _view_lines
from ..core.cas import Cas
from ..core.result import Status
from ..evidence.model import EMULATION_AUTHORITY, build_evidence

TOOL = "emulate"
TOOL_VERSION = "2"   # 2: `section <name> <R/W/X>: ...` lines for the image addresses the request names
BASIS = ("CPU emulation of the file image, not a run of the program: no loader relocations, no CRT/TLS/DllMain "
         "initialisation, no OS state; imported APIs are not modeled")
LIMITATIONS = (
    "observation of CPU EMULATION (Unicorn) of the target's code from the file image: it shows what this code computes "
    "from these arguments in the emulator, not what the program does when it runs",
    "the image starts in its on-disk state at the preferred base: no relocations, no CRT/DllMain/TLS initialisation, "
    "no TEB/PEB/heap/handles; globals hold their file values (uninitialized data is zero)",
    "imported APIs are not resolved: a call to any of them stops the emulation (no stubs, no invented return values)",
    "the arguments and initial buffer bytes were chosen by the analyst and are recorded in the parameters; other inputs "
    "of the real function (globals set at run time, other threads, the real CPU's cpuid/rdtsc) are absent",
    "deterministic: two emulations in fresh emulator instances gave identical registers and outputs",
    "argument buffers are page-granular: an overrun of up to 15 bytes past a buffer's end does not fault",
)


def _hx(n: int, width: int) -> str:
    return "0x%0*x" % (width, n)


def _kind(a: dict) -> str:
    k = a["kind"]
    if k == "buffer":
        return f"buffer {a['size']} bytes"
    if k == "image_ptr":
        return "image pointer" + (f", {a['length']} bytes" if "length" in a else "")
    if k == "arg_ptr":
        return f"pointer to arg{a['arg']}+0x{a['offset']:x}"
    if k == "buf_ptr":
        return f"pointer to buf{a['buf']}+0x{a['offset']:x}"
    return "int"


def _section_lines(request: dict, img: PeImage) -> list[str]:
    """TOOL_VERSION 2 (analysis/section_notes.py): the PE section + R/W/X of every image address the REQUEST names
    (start, end, image-pointer arguments/registers/pre-written pointers, image pre-write targets), grouped by
    section. Only addresses the analyst passed; what the emulated code itself read is not tracked."""
    named: list[tuple[str, int]] = [("function", request["function"])]
    if "end" in request:
        named.append(("end", request["end"]))
    for i, a in enumerate(request["args"]):
        if a.get("kind") == "image_ptr":
            named.append((f"arg{i}", a["value"]))
    for r, ref in sorted((request.get("registers") or {}).items()):
        if isinstance(ref, dict) and ref.get("kind") == "image_ptr":
            named.append((r, ref["value"]))
    for i, m in enumerate(request.get("memory", [])):
        if m["target"] == "va":
            named.append((f"pre-write memory[{i}] target", m["va"]))
        if isinstance(m.get("ptr"), dict) and m["ptr"].get("kind") == "image_ptr":
            named.append((f"pre-write memory[{i}] pointer", m["ptr"]["value"]))
    groups: dict[str, list[str]] = {}
    for label, va in named:
        w = section_notes.where(img, va)
        if w is not None:
            groups.setdefault(w, []).append(f"{label} 0x{va:x}")
    return [f"section {w}: {', '.join(items)}" for w, items in groups.items()]


def render(request: dict, res: dict, img: PeImage) -> str:
    is64 = request["arch"] == "x64"
    w = 16 if is64 else 8
    ident = res["emulator"]
    lines = [f"emulate function=0x{request['function']:x} arch={request['arch']} convention={request['convention']} "
             f"image_base=0x{img.image_base:x} emulator={ident['name']}-{ident['version']}"]
    rng = "end" in request
    args = []
    for i, (a, v) in enumerate(zip(request["args"], res["arg_values"])):
        args.append(f"arg{i}=0x{v:x} ({_kind(a)})")
    lines.append("args: " + (" ".join(args) if args else "(none)"))
    for j, (b, va) in enumerate(zip(request.get("buffers", []), res["layout"].get("scratch", []))):
        lines.append(f"scratch buf{j}=0x{va:x} ({b['size']} bytes)")
    # analyst inputs are summarised, never printed as bytes: their content is in the parameters, and the raw text holds
    # only what the emulation produced
    for i, m in enumerate(request.get("memory", [])):
        where = {"va": lambda: f"va 0x{m['va']:x}", "sp": lambda: f"sp{m['offset']:+#x}",
                 "arg": lambda: f"arg{m.get('arg')}+0x{m['offset']:x}",
                 "buf": lambda: f"buf{m.get('buf')}+0x{m['offset']:x}"}[m["target"]]()
        what = f"pointer ({_kind(m['ptr'])})" if "ptr" in m else f"{len(m['hex']) // 2} bytes"
        lines.append(f"pre-write memory[{i}] {where}: {what} (analyst input, in the parameters)")
    if request.get("registers"):
        lines.append("initial registers set by the analyst: " + " ".join(sorted(request["registers"])))
    lines += _section_lines(request, img)
    runs = res.get("runs", 2)
    if rng:
        lines.append(f"stop = reached end 0x{request['end']:x} (deterministic over {runs} emulations); code range "
                     f"from 0x{request['function']:x}: the code before the start did not run")
    else:
        lines.append(f"stop = returned to the caller (deterministic over {runs} emulations)")
    regs = res["registers"]
    if is64:
        rax, rdx = regs["rax"], regs["rdx"]
        lines.append(f"{'final' if rng else 'return'} rax={_hx(rax, w)} ({rax}) eax=0x{rax & 0xFFFFFFFF:08x} "
                     f"({rax & 0xFFFFFFFF}) rdx={_hx(rdx, w)}")
    else:
        eax, edx = regs["eax"], regs["edx"]
        lines.append(f"{'final' if rng else 'return'} eax={_hx(eax, w)} ({eax}) edx={_hx(edx, w)}")
    extra = [n for n in request.get("output_registers", [])]
    if extra:
        lines.append("registers: " + " ".join(f"{n}={_hx(regs[n], w)}" for n in extra))
    if not rng:
        lines.append("stack after return: " + ("balanced" if res["stack_balanced"] else
                     f"NOT balanced (sp 0x{res['sp_after']:x}, expected 0x{res['sp_expected']:x} for "
                     f"{request['convention']}: the calling convention or argument count may be wrong)"))
    for k, (o, got) in enumerate(zip(request["outputs"], res["outputs"]), 1):
        va, n = got["address"], got["length"]
        src = {"arg": lambda: f"arg{o['arg']}+0x{o['offset']:x}", "va": lambda: "va",
               "ret": lambda: f"ret+0x{o['offset']:x}", "buf": lambda: f"buf{o.get('buf')}+0x{o['offset']:x}",
               "reg": lambda: f"{o.get('reg')}+0x{o['offset']:x}"}[o["source"]]()
        if o.get("digest"):
            lines.append(f"segment {k} OUTPUT outputs[{got['index']}] {src} 0x{va:x}..0x{va + n:x} len={n} "
                         "digest-only")
            lines.append(f"  sha256={got['sha256']}")
            continue
        lines.append(f"segment {k} OUTPUT outputs[{got['index']}] {src} 0x{va:x}..0x{va + n:x} len={n}")
        data = bytes.fromhex(got["hex"])
        lines += ["  " + ln for ln in _hex_lines(va, data)]
        for v in o["views"]:
            lines.append("  -- %s --" % v)
            lines += ["  " + ln for ln in _view_lines(v, va, data, img)]
    return "\n".join(lines) + "\n"


def build_emulation_evidence(cas: Cas, *, job_sha: str, request: dict, res: dict, img: PeImage,
                             elapsed_ms: int) -> tuple[dict, str]:
    """(evidence record, raw text). Only a deterministic return (or, with `end`, a deterministic arrival at `end`)
    becomes evidence (ValueError otherwise)."""
    rng = "end" in request
    want = "range_end" if rng else "return"
    if not (res.get("ok") is True and res.get("stop") == want and res.get("deterministic") is True):
        raise ValueError("only a deterministic, returned emulation (or a range that reached its end) becomes "
                         "evidence")
    raw = render(request, res, img)
    ident = res["emulator"]
    limitations = [BASIS, *LIMITATIONS]
    if not res["layout"]["perms_enforced"]:
        limitations.append("section permissions were NOT enforced (a section does not start on a page boundary): "
                           "the whole image was read/write/execute")
    if not rng and not res["stack_balanced"]:
        limitations.append("the stack pointer after return differs from the convention's expectation")
    if rng:
        limitations.append(f"code range 0x{request['function']:x}..0x{request['end']:x}: the state when execution "
                           "reached the end address; the code before the start did not run, and what it would have "
                           "set up (registers, stack locals, buffers) was supplied by the analyst")
    if request.get("memory") or request.get("registers"):
        limitations.append(f"the analyst pre-wrote {len(request.get('memory', []))} memory region(s) and set "
                           f"{len(request.get('registers', {}))} register(s) before the first instruction "
                           "(recorded in parameters.memory / parameters.registers)")
    if any(o.get("digest") for o in request["outputs"]):
        limitations.append("digest-only outputs record the SHA-256 and length of the region, not its bytes")
    limitations += [f"imports: {n}" for n in res["layout"]["import_notes"]]
    locations: list[dict] = [{"kind": "address", "space": "va", "start": request["function"]}]
    if rng:
        locations.append({"kind": "address", "space": "va", "start": request["end"]})
    end = img.image_base + img.size_of_image
    for o, got in zip(request["outputs"], res["outputs"]):
        if o["source"] == "va" and img.image_base <= got["address"] and got["address"] + got["length"] <= end:
            locations.append({"kind": "address-range", "space": "va", "start": got["address"],
                              "end": got["address"] + got["length"]})
    outs = [{k: g[k] for k in ("index", "address", "length", "sha256")} | ({"digest": True} if g.get("digest") else {})
            for g in res["outputs"]]
    result: dict[str, Any] = {"stop": want, "deterministic": True, "runs": res.get("runs", 2),
                              "registers": res["registers"]}
    if not rng:
        result["stack_balanced"] = res["stack_balanced"]
    result.update(sp_entry=res["sp_entry"], sp_after=res["sp_after"])
    if not rng:
        result["sp_expected"] = res["sp_expected"]
    result.update(arg_values=res["arg_values"], outputs=outs, layout=res["layout"])
    params = {**request, "emulator": dict(ident)}
    ev = build_evidence(
        cas, subject_sha256=job_sha, tool=TOOL, operation="emulate", raw=raw.encode("utf-8"), status=Status.OK,
        confidence="derived", authority=EMULATION_AUTHORITY, parameters=params, tool_version=TOOL_VERSION,
        engine=ident["name"], engine_version=ident["version"], elapsed_ms=elapsed_ms, result=result,
        locations=locations,
        environment={"isolation": "process", "executor": "cpu-emulator", "native_execution": False},
        coverage={"scope": "emulation", "relationship": "unknown"}, limitations=limitations,
        architecture=request["arch"])
    return ev, raw
