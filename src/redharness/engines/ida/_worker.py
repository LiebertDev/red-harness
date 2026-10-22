"""idalib worker process. NEVER imported in the main process; runs as `python -I _worker.py <request.json>`.

Uses only the standard library + idapro/IDA modules (does not import redharness). The result is written atomically
to the request's `result_path` file: {"ok": true, ...} or {"ok": false, "error": ...}.
IDA's stdout noise does not leak into the result. Success is additionally verified in the main process by exit code.
"""

import json
import os
import sys
import traceback


def write_result(path, doc):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def resolve_function(fn):
    import ida_funcs
    import ida_idaapi
    import ida_name
    ea = fn
    if isinstance(fn, str):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, fn)
        if ea == ida_idaapi.BADADDR:
            raise LookupError("NAME_NOT_RESOLVED: name could not be resolved: %s" % fn)
    f = ida_funcs.get_func(ea)
    if f is None:
        raise LookupError("NO_FUNCTION_AT_ADDRESS: no function at address: 0x%x" % ea)
    return f


def op_probe(req):
    import idapro
    ver = idapro.get_library_version()
    return {"version": ".".join(str(x) for x in ver) if ver else ""}


STRINGS_MINLEN = 4
_MAX_SCAN_BYTES = 64 * 1024 * 1024


def utf16_runs(data, base, minlen=STRINGS_MINLEN):
    """ASCII-range UTF-16LE runs in a raw byte string: [(address, byte_length, text)]. The length also counts a
    following UTF-16 NUL terminator (IDA's C_16 length rule). Only runs starting at an even address."""
    import re
    out = []
    for m in re.finditer(rb"(?:[\x09\x0a\x0d\x20-\x7e]\x00){%d,}" % minlen, data):
        if (base + m.start()) % 2:
            continue
        raw = m.group(0)
        n = len(raw) + (2 if data[m.end():m.end() + 2] == b"\x00\x00" else 0)
        out.append((base + m.start(), n, raw.decode("utf-16le")))
    return out


def collect_strings(idautils, ida_nalt, ida_bytes, ida_segment):
    r"""IDA's string list (C + UTF-16 [+ UTF-32]) plus a raw UTF-16LE scan over all sections (strings can sit inside .text, so the code section cannot be skipped).
    The raw scan is needed: IDA can skip a string in bytes already defined as other data
    (e.g. the leading `\` of a `\Device\name` string defined separately, so IDA shows 'Device\name').
    A raw run replaces the IDA records it covers."""
    sc = idautils.Strings(default_setup=False)
    types = [ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16, ida_nalt.STRTYPE_C_32]
    sc.setup(strtypes=types, minlen=STRINGS_MINLEN, only_7bit=False, ignore_instructions=False,
             display_only_existing_strings=False)
    rows = [{"address": s.ea, "length": s.length, "kind": str(s.strtype), "value": str(s)} for s in sc]
    raw = []
    seg = ida_segment.get_first_seg()
    while seg is not None:
        size = seg.end_ea - seg.start_ea
        if 0 < size <= _MAX_SCAN_BYTES:
            data = ida_bytes.get_bytes(seg.start_ea, size)
            if data:
                raw.extend(utf16_runs(data, seg.start_ea))
        seg = ida_segment.get_next_seg(seg.start_ea)
    for ea, n, text in raw:
        rows = [r for r in rows if not (ea <= r["address"] < ea + n)]
        rows.append({"address": ea, "length": n, "kind": str(ida_nalt.STRTYPE_C_16), "value": text})
    rows.sort(key=lambda r: r["address"])
    return rows


def op_analyze(req):
    import idapro
    rc = idapro.open_database(req["target"], True)
    if rc != 0:
        raise RuntimeError("open_database rc=%s" % rc)
    import ida_entry
    import ida_funcs
    import ida_ida
    import ida_hexrays
    import ida_idp
    import ida_nalt
    import idautils
    import idc
    funcs = []
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        funcs.append({"address": ea, "name": idc.get_func_name(ea), "size": f.end_ea - f.start_ea})
    import ida_bytes
    import ida_segment
    strs = collect_strings(idautils, ida_nalt, ida_bytes, ida_segment)
    entry = None
    if ida_entry.get_entry_qty():
        entry = ida_entry.get_entry(ida_entry.get_entry_ordinal(0))
    info = {
        "arch": ida_idp.get_idp_name() or "",
        "bits": 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16),
        "entry": entry,
        "decompiler": bool(ida_hexrays.init_hexrays_plugin()),
        "imagebase": ida_nalt.get_imagebase(),
    }
    idapro.close_database(True)
    return {"functions": funcs, "strings": strs, "info": info}


def op_decompile(req):
    import idapro
    rc = idapro.open_database(req["target"], False)
    if rc != 0:
        raise RuntimeError("open_database rc=%s" % rc)
    try:
        import ida_hexrays
        import idc
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("DECOMPILER_UNAVAILABLE: Hex-Rays is unavailable for this database")
        f = resolve_function(req["function"])
        # IDA 9.5 only: a decompiler budget (milliseconds, 0 = none) that aborts a runaway function with
        # MERR_TIMEOUT instead of letting the Job Object kill the worker. 9.4 has no such API, so nothing changes.
        timeout_ms = int(req.get("decompile_timeout_ms") or 0)
        hf = None
        if timeout_ms > 0 and hasattr(ida_hexrays, "set_decompiler_timeout"):
            ida_hexrays.set_decompiler_timeout(timeout_ms)
            hf = ida_hexrays.hexrays_failure_t()
        try:
            cf = ida_hexrays.decompile(f.start_ea, hf) if hf is not None else ida_hexrays.decompile(f.start_ea)
        except ida_hexrays.DecompilationFailure as e:
            raise RuntimeError("DECOMPILE_FAILED: %s" % e)
        if cf is None:
            if hf is not None and hf.code == ida_hexrays.MERR_TIMEOUT:
                raise RuntimeError("DECOMPILE_TIMEOUT: MERR_TIMEOUT after %d ms" % timeout_ms)
            raise RuntimeError("DECOMPILE_FAILED: empty result")
        return {"address": f.start_ea, "name": idc.get_func_name(f.start_ea), "text": str(cf)}
    finally:
        idapro.close_database(False)


def _target_info(ea):
    """(name, string value or None, strtype as text) at `ea`: IDA's name there (function, label, __imp_ slot) and, when
    a string literal is defined there, its decoded value."""
    import ida_bytes
    import idc
    name = idc.get_name(ea) or ""
    if not ida_bytes.is_strlit(ida_bytes.get_flags(ea)):
        return name, None, ""
    st = idc.get_str_type(ea)
    raw = idc.get_strlit_contents(ea, -1, st)
    if raw is None:
        return name, None, ""
    # get_strlit_contents returns the text already converted to UTF-8, whatever the literal's width
    return name, raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw), str(st)


def op_xrefs(req):
    import idapro
    rc = idapro.open_database(req["target"], False)
    if rc != 0:
        raise RuntimeError("open_database rc=%s" % rc)
    try:
        import ida_funcs
        import idautils
        import idc
        ea = req["address"]
        it = idautils.XrefsTo(ea, 0) if req["direction"] == "to" else idautils.XrefsFrom(ea, 0)
        out = []
        total = 0
        for x in it:
            total += 1
            if len(out) < req["limit"]:
                f = ida_funcs.get_func(x.frm)
                tname, tstr, tkind = _target_info(x.to)
                out.append({"from": x.frm, "to": x.to, "kind": idautils.XrefTypeName(x.type),
                            "is_code": bool(x.iscode),
                            "from_function": idc.get_func_name(f.start_ea) if f else "",
                            "to_name": tname, "to_string": tstr, "to_string_kind": tkind})
        return {"xrefs": out, "total": total}
    finally:
        idapro.close_database(False)


def _norm_signed32(v):
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v & 0x80000000 else v


_REGNAMES = None


def _regnames():
    """All register names in IDA's current processor module (lowercase)."""
    global _REGNAMES
    if _REGNAMES is None:
        import ida_idp
        names = set()
        for r in range(0, 160):
            for sz in (1, 2, 4, 8, 16):
                nm = ida_idp.get_reg_name(r, sz)
                if nm:
                    names.add(nm.lower())
        _REGNAMES = names
    return _REGNAMES


def _operand(insn, n, ea, ptr_bytes):
    """Single operand -> common-contract dict (see OperandInfo in engines/base.py)."""
    import re
    import ida_idp
    import ida_lines
    import ida_ua
    op = insn.ops[n]
    # print_operand returns IDA's colorized text (COLOR_ON/OFF + color-code control bytes): strip the tags first
    text = re.sub(r"\s+", " ", ida_lines.tag_remove(ida_ua.print_operand(ea, n) or "")).strip()
    size = ida_ua.get_dtype_size(op.dtype)
    t = op.type
    d = {"k": "other", "t": text, "r": "", "b": "", "i": "", "sc": 0, "d": None, "v": None, "sz": size}
    if t == ida_ua.o_reg:
        d.update(k="reg", r=ida_idp.get_reg_name(op.reg, size or ptr_bytes).lower())
    elif t == ida_ua.o_imm:
        d.update(k="imm", v=int(op.value) & 0xFFFFFFFFFFFFFFFF)
    elif t in (ida_ua.o_near, ida_ua.o_far):
        d.update(k="near", v=int(op.addr))
    elif t == ida_ua.o_mem:
        d.update(k="mem", v=int(op.addr))
    elif t in (ida_ua.o_phrase, ida_ua.o_displ):
        if op.specflag1:  # SIB present: base/index/scale from the bracket text, using register names
            inner = text[text.find("[") + 1:text.rfind("]")].lower()
            rs = [x for x in re.findall(r"[a-z][a-z0-9]*", inner) if x in _regnames()]
            m = re.search(r"\*\s*(\d+)", inner)
            base, index = (rs + ["", ""])[:2] if len(rs) > 1 else ((rs[0] if rs else ""), "")
            scale = int(m.group(1)) if m else (1 if index else 0)
        else:
            base = ida_idp.get_reg_name(op.phrase, ptr_bytes).lower()
            index, scale = "", 0
        d.update(k="mem", b=base, i=index, sc=scale,
                 d=_norm_signed32(int(op.addr)) if t == ida_ua.o_displ else 0)
    if d["v"] is not None and d["k"] in ("mem", "near") or (t == ida_ua.o_imm and _is_offset(ea, n)):
        import ida_name
        nm = ida_name.get_name(d["v"]) or ""
        d["y"] = nm
    return d


def _is_offset(ea, n):
    import ida_bytes
    return bool(ida_bytes.is_off(ida_bytes.get_flags(ea), n))


def op_disassemble(req):
    import re
    import idapro
    rc = idapro.open_database(req["target"], False)
    if rc != 0:
        raise RuntimeError("open_database rc=%s" % rc)
    try:
        import ida_bytes
        import ida_funcs
        import ida_ida
        import ida_ua
        import idautils
        import idc
        ptr = 8 if ida_ida.inf_is_64bit() else 4
        count = int(req["count"])
        start = int(req["address"])
        eas = []
        fn_addr, fn_name, stop = None, "", ""
        complete = True
        if req.get("whole_function"):
            f = ida_funcs.get_func(start)
            if f is None:
                raise LookupError("NO_FUNCTION_AT_ADDRESS: no function at address: 0x%x" % start)
            fn_addr, fn_name = f.start_ea, idc.get_func_name(f.start_ea)
            eas = sorted(set(idautils.FuncItems(f.start_ea)))
            eas = [e for e in eas if ida_bytes.is_code(ida_bytes.get_flags(e))]
            total = len(eas)
            if total > count:
                eas = eas[:count]
                complete = False
                stop = "COUNT: returned %d of %d instructions" % (count, total)
        else:
            f = ida_funcs.get_func(start)
            if f is not None:
                fn_addr, fn_name = f.start_ea, idc.get_func_name(f.start_ea)
            ea = start
            while len(eas) < count:
                if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
                    complete = False
                    stop = "NOT_CODE: 0x%x" % ea
                    break
                eas.append(ea)
                ea += ida_bytes.get_item_size(ea)
            else:
                complete = False
                stop = "COUNT: %d instructions" % count
            total = len(eas)
        out = [_insn_row(ea, ptr) for ea in eas]
        return {"insns": out, "function_address": fn_addr, "function_name": fn_name, "total": total,
                "full": complete, "stop_reason": stop, "counts": {"insns": len(out)}}
    finally:
        idapro.close_database(False)


def _insn_row(ea, ptr):
    """One instruction -> common-contract row (see InsnInfo in engines/base.py)."""
    import re
    import ida_bytes
    import ida_ua
    import idc
    insn = ida_ua.insn_t()
    ln = ida_ua.decode_insn(insn, ea)
    if ln <= 0:
        raise RuntimeError("DECODE_FAILED: 0x%x" % ea)
    ops = []
    for n in range(8):
        if insn.ops[n].type == ida_ua.o_void:
            break
        ops.append(_operand(insn, n, ea, ptr))
    raw = ida_bytes.get_bytes(ea, ln) or b""
    line = idc.generate_disasm_line(ea, 0) or ""
    line = re.sub(r"\s+", " ", line.split(";")[0]).strip()
    mnem = (ida_ua.print_insn_mnem(ea) or "").lower()
    return {"a": ea, "s": ln, "b": raw.hex(), "m": mnem, "t": line, "o": ops}


def op_disasm_funcs(req):
    """The whole-function instruction lists of many functions in ONE run (build comparison). Functions in address
    order (the order of the exported function list) from index `first`; a chunk ends at the first function boundary
    after `max_insns` instructions and `next_index` says where the next chunk starts."""
    import idapro
    rc = idapro.open_database(req["target"], False)
    if rc != 0:
        raise RuntimeError("open_database rc=%s" % rc)
    try:
        import ida_bytes
        import ida_funcs
        import ida_ida
        import idautils
        import idc
        ptr = 8 if ida_ida.inf_is_64bit() else 4
        first = int(req.get("first", 0))
        max_insns = int(req.get("max_insns", 60000))
        per_function = 20000
        starts = sorted(idautils.Functions())
        out, used, idx = [], 0, first
        while idx < len(starts):
            if out and used >= max_insns:
                break
            ea = starts[idx]
            f = ida_funcs.get_func(ea)
            eas = sorted(set(idautils.FuncItems(f.start_ea)))
            eas = [e for e in eas if ida_bytes.is_code(ida_bytes.get_flags(e))]
            kept = eas[:per_function]
            rows = [_insn_row(e, ptr) for e in kept]
            full = len(kept) == len(eas)
            out.append({"function_address": f.start_ea, "function_name": idc.get_func_name(f.start_ea),
                        "size": f.end_ea - f.start_ea, "insns": rows, "total": len(eas), "full": full,
                        "stop_reason": "" if full else "COUNT: returned %d of %d instructions" % (len(kept), len(eas)),
                        "counts": {"insns": len(rows)}})
            used += len(rows)
            idx += 1
        return {"functions": out, "function_total": len(starts), "first": first,
                "next_index": idx if idx < len(starts) else None, "counts": {"functions": len(out)}}
    finally:
        idapro.close_database(False)


def _stack_param_extent(callee_ea, ptr):
    """Bytes of stack parameters in the callee's prototype (from the stack pointer at the call), None if unknown."""
    import ida_nalt
    import ida_typeinf
    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, callee_ea):
        if ida_typeinf.guess_tinfo(tif, callee_ea) != ida_typeinf.GUESS_FUNC_OK:
            return None
    if tif.is_ptr():
        tif = tif.get_pointed_object()
    if not tif.is_func():
        return None
    fi = ida_typeinf.func_type_data_t()
    if not tif.get_func_details(fi):
        return None
    if fi.is_vararg_cc():
        return None
    ext = 0
    for a in fi:
        if a.argloc.is_stkoff():
            size = a.type.get_size()
            if size in (None, ida_typeinf.BADSIZE):
                return None
            ext = max(ext, a.argloc.stkoff() + max(size, ptr))
        elif not a.argloc.is_reg1() and not a.argloc.is_reg2():
            return None            # scattered / custom locations: not modelled
    return ext


def op_callargs(req):
    import idapro
    rc = idapro.open_database(req["target"], False)
    if rc != 0:
        raise RuntimeError("open_database rc=%s" % rc)
    try:
        import ida_bytes
        import ida_funcs
        import ida_ida
        import ida_idp
        import ida_ua
        import idautils
        ptr = 8 if ida_ida.inf_is_64bit() else 4
        f = ida_funcs.get_func(int(req["address"]))
        if f is None:
            raise LookupError("NO_FUNCTION_AT_ADDRESS: no function at address: 0x%x" % int(req["address"]))
        out = []
        for ea in sorted(set(idautils.FuncItems(f.start_ea))):
            if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
                continue
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea) <= 0 or not ida_idp.is_call_insn(insn):
                continue
            op = insn.ops[0]
            target = int(op.addr) if op.type in (ida_ua.o_near, ida_ua.o_far, ida_ua.o_mem) else None
            ext = _stack_param_extent(target, ptr) if target is not None else None
            out.append({"a": ea, "t": target, "e": ext})
        return {"calls": out, "function_address": f.start_ea, "counts": {"calls": len(out)}}
    finally:
        idapro.close_database(False)


OPS = {"probe": op_probe, "analyze": op_analyze, "decompile": op_decompile, "xrefs": op_xrefs,
       "disassemble": op_disassemble, "callargs": op_callargs, "disasm_funcs": op_disasm_funcs}


def main():
    req = json.load(open(sys.argv[1], encoding="utf-8"))
    path = req["result_path"]
    try:
        out = OPS[req["op"]](req)
        out["ok"] = True
        write_result(path, out)
    except BaseException as e:  # noqa: BLE001 - every error is reported fail-closed
        write_result(path, {"ok": False, "error": "%s: %s" % (type(e).__name__, e),
                            "trace": traceback.format_exc()[-2000:]})
        return 1
    return 0


if __name__ == "__main__":
    rc = main()
    sys.stdout.flush()
    sys.exit(rc)
