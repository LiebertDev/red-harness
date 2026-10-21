"""Text view of a PE import table for the MCP `imports` tool: one `<IAT slot VA> <dll>!<name>` line per symbol,
module-qualified so claims can quote `kernel32.dll!CreateFileW` verbatim."""
from __future__ import annotations

from .pe_dirs import ImportedFunction, ImportProfile


def _safe(s: str) -> str:
    # Escape the separator and the escape character itself first, so a crafted field cannot forge another
    # module-qualified import (`\` -> `\x5c` before `!` -> `\x21`, preventing a literal `\x21` from being read as `!`).
    return (s.replace("\\", "\\x5c").replace("!", "\\x21")
            .replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t"))


class ImportSymbol:
    __slots__ = ("dll", "name", "ordinal", "thunk_rva", "delay")

    def __init__(self, f: ImportedFunction, delay: bool) -> None:
        self.dll, self.name, self.ordinal, self.thunk_rva, self.delay = f.dll, f.name, f.ordinal, f.thunk_rva, delay


def import_symbols(prof: ImportProfile, dll: str | None = None) -> list[ImportSymbol]:
    """All imports (delay-load included) in a deterministic order: IAT slot RVA, then dll, then symbol."""
    want = dll.lower() if dll else None
    out = [ImportSymbol(f, t.delay) for t in prof.all_tables for f in t.functions
           if want is None or f.dll.lower() == want or f.dll.lower() == want + ".dll"]
    out.sort(key=lambda x: (x.thunk_rva, x.delay, x.dll.lower(), x.name or "", x.ordinal or 0))
    return out


def qualified_name(sym: ImportSymbol) -> str:
    """`<dll>!<name>` (ordinal imports `<dll>!#<n>`), escaped like the imports tool's lines."""
    return f"{_safe(sym.dll)}!" + (_safe(sym.name) if sym.name is not None else f"#{sym.ordinal}")


def iat_slot_names(prof: ImportProfile) -> dict[int, str]:
    """IAT slot VA -> `dll!name` (first symbol wins on a duplicated slot)."""
    out: dict[int, str] = {}
    for sy in import_symbols(prof):
        out.setdefault(prof.image_base + sy.thunk_rva, qualified_name(sy))
    return out


def format_import_line(sym: ImportSymbol, image_base: int) -> str:
    sym_name = _safe(sym.name) if sym.name is not None else f"#{sym.ordinal}"
    return f"0x{image_base + sym.thunk_rva:x} {_safe(sym.dll)}!{sym_name}" + (" [delay]" if sym.delay else "")
