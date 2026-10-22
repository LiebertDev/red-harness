"""Common static engine interface. Engine-independent: IDA and Ghidra implement the same contract.

Operations mirror the MCP tool list: target open/analysis (`job_open` + analysis prerequisite), `functions_list`,
`decompile`, `xrefs`, `strings_search`, `disassemble`.

Contract (fail-closed):
- No operation raises an exception for an engine error; it returns an `EngineResult`. Only `status is Status.OK`
  is success. Engine not installed gives `Status.TOOL_MISSING` ("unavailable"), timeout `TIMEOUT`,
  memory overrun `MEMORY_LIMIT`, crash/exit code/corrupt output `ERROR`, truncated output `PARTIAL`.
- A failed result is not cached.
- The target identity is its SHA-256; addresses are virtual addresses (VA, int).
- Text coming from the target (strings, decompilation) is untrusted data: `untrusted_content=True`.
"""

from __future__ import annotations

import abc
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generic, TypeVar

from ..core.result import Status

T = TypeVar("T")

# Stable engine error codes: a closed set, identical for every engine. An engine reports one by starting its error text
# with `CODE: ` (IDA worker, Ghidra script); the backend lifts it into `EngineResult.code`, the MCP layer into the tool
# error code. Anything else stays the plain `Status` (ERROR / TIMEOUT / TOOL_MISSING ...).
NO_FUNCTION_AT_ADDRESS = "NO_FUNCTION_AT_ADDRESS"    # the address is not inside a function the engine defined
NAME_NOT_RESOLVED = "NAME_NOT_RESOLVED"              # a function name matched no function (or more than one)
OUT_OF_IMAGE = "OUT_OF_IMAGE"                        # the address lies outside the PE image (set by the MCP layer)
DECOMPILE_FAILED = "DECOMPILE_FAILED"                # the decompiler ran and produced no usable output
DECOMPILE_TIMEOUT = "DECOMPILE_TIMEOUT"              # the decompiler budget was exhausted
DECOMPILER_UNAVAILABLE = "DECOMPILER_UNAVAILABLE"    # the engine has no usable decompiler
ENGINE_ERROR_CODES = frozenset({NO_FUNCTION_AT_ADDRESS, NAME_NOT_RESOLVED, OUT_OF_IMAGE, DECOMPILE_FAILED,
                                DECOMPILE_TIMEOUT, DECOMPILER_UNAVAILABLE})
_CODE_RE = re.compile(r"^(?:\w+ failed: )?(?:worker|script) error: (?:[\w.$]+: )?(" + "|".join(sorted(ENGINE_ERROR_CODES))
                      + r")(?:: |$)")


def split_error(detail: str) -> tuple[str, str]:
    """(stable code, message) of a backend error detail like `decompile failed: worker error: LookupError: CODE: text`;
    ("", detail) when it carries no code. Only the leading error prefix counts: text from the target never sets a code."""
    m = _CODE_RE.match(detail or "")
    if m is None:
        return "", detail
    return m.group(1), detail[m.end():].strip() or m.group(1)


@dataclass(frozen=True)
class EngineInfo:
    name: str
    available: bool
    version: str = ""
    detail: str = ""


@dataclass(frozen=True)
class TargetInfo:
    """Summary of a target whose analysis has finished."""
    sha256: str
    path: str
    arch: str = ""
    bits: int = 0
    entry: int | None = None
    function_count: int = 0
    string_count: int = 0
    decompiler: bool = False
    image_base: int | None = None  # preferred/loaded image base (VA - image_base = RVA)


@dataclass(frozen=True)
class FunctionInfo:
    address: int
    name: str
    size: int


@dataclass(frozen=True)
class StringInfo:
    address: int
    length: int
    kind: str
    value: str


@dataclass(frozen=True)
class XrefInfo:
    from_addr: int
    to_addr: int
    kind: str
    is_code: bool
    from_function: str = ""
    to_name: str = ""          # engine symbol/label at `to` (function, data label, import); "" = none
    to_string: str | None = None   # string value defined at `to`, if any
    to_string_kind: str = ""   # engine string kind (feeds encoding_tag)


@dataclass(frozen=True)
class Page(Generic[T]):
    items: list[T]
    total: int
    offset: int
    has_more: bool


@dataclass(frozen=True)
class DecompileInfo:
    address: int
    name: str
    text: str
    total_chars: int


@dataclass(frozen=True)
class OperandInfo:
    """Engine-independent instruction operand. The text is the engine's own notation (IDA/Ghidra differ); the structural
    fields are common. All integers are two's-complement bit patterns: the consumer masks to its own width (`& 0xFFFFFFFF`).

    kind: "reg" | "imm" | "mem" | "near" | "other"
    - reg:  `reg` (lowercase name).
    - imm:  `value`.
    - mem:  `base`/`index`/`scale`/`disp` (signed); with no base and no index, `value` = absolute/resolved VA
            (including x64 RIP-relative: the engine has resolved the target).
    - near: branch/call target `value` (VA).
    `sym`: if `value` is an address, the symbol name at that address (e.g. `IoCreateDevice` for an IAT entry); the
    engine's automatic names (`sub_…`, `FUN_…`, `dword_…`) may also appear, the consumer filters them.
    """
    kind: str
    text: str
    reg: str = ""
    base: str = ""
    index: str = ""
    scale: int = 0
    disp: int | None = None
    value: int | None = None
    size: int = 0
    sym: str = ""  # engine symbol at the `value` address (import name, function/data name); empty if none


@dataclass(frozen=True)
class InsnInfo:
    address: int
    size: int
    bytes_hex: str
    mnemonic: str  # lowercase, NO prefix (rep/lock)
    operands: tuple[OperandInfo, ...]
    text: str      # the engine's own instruction notation (evidence quotes are taken from this text)


@dataclass(frozen=True)
class Disassembly:
    items: list[InsnInfo]
    function_address: int | None  # function the instructions belong to (if any)
    function_name: str
    total: int                    # total instructions found (before truncation)
    complete: bool                # False: truncated by `count` or by hitting a non-code byte
    stop_reason: str = ""


@dataclass(frozen=True)
class FunctionBody:
    """One function with all its instructions (chunks included), in address order."""
    address: int
    name: str
    size: int                    # as the engine's function list reports it
    disassembly: Disassembly


@dataclass(frozen=True)
class FunctionBodies:
    """A chunk of consecutive functions (address order, as in `functions`) with their instructions."""
    items: list[FunctionBody]
    total: int                   # functions in the target
    next_index: int | None       # index of the first function of the next chunk; None = this was the last


@dataclass(frozen=True)
class EngineResult(Generic[T]):
    status: Status
    data: T | None = None
    detail: str = ""
    cached: bool = False
    duration_s: float = 0.0
    untrusted_content: bool = False
    extra: dict = field(default_factory=dict)
    code: str = ""  # stable error code (ENGINE_ERROR_CODES) when the failure is one of them, else ""

    @property
    def ok(self) -> bool:
        return self.status.is_success and self.data is not None


class Engine(abc.ABC):
    name: str = "engine"

    @abc.abstractmethod
    def probe(self) -> EngineInfo:
        """Whether the engine is installed and its version (real probe)."""

    @abc.abstractmethod
    def open_target(self, path: str | Path) -> EngineResult[TargetInfo]:
        """Analyzes the target by its SHA-256; if it is cached it is not analyzed again (`cached=True`)."""

    @abc.abstractmethod
    def functions(self, sha256: str, *, offset: int = 0, limit: int = 100) -> EngineResult[Page[FunctionInfo]]:
        ...

    @abc.abstractmethod
    def decompile(self, sha256: str, function: int | str, *, max_chars: int = 200_000) -> EngineResult[DecompileInfo]:
        """`function`: address (any VA inside the function) or name. `Status.PARTIAL` if truncated."""

    @abc.abstractmethod
    def xrefs(self, sha256: str, address: int, *, direction: str = "to",
              limit: int = 200) -> EngineResult[list[XrefInfo]]:
        """`direction`: "to" | "from"."""

    def disassemble(self, sha256: str, address: int, *, count: int = 200,
                    whole_function: bool = False) -> EngineResult[Disassembly]:
        """Instruction list. `whole_function=False`: up to `count` instructions starting at `address` (stops on
        hitting a non-code byte). `True`: all instructions of the function containing `address` (in address order,
        including extra chunks). A result that exceeds `count` or ends early returns `Status.PARTIAL` (complete=False).

        NOT abstract: old/fake engines that do not know this method return `TOOL_MISSING` ("unsupported"),
        never a silently empty result or an exception."""
        return EngineResult(Status.TOOL_MISSING, None, f"{self.name}: disassemble unsupported")

    def disassemble_functions(self, sha256: str, *, first: int = 0,
                              max_insns: int = 60_000) -> EngineResult[FunctionBodies]:
        """The whole-function instruction lists of consecutive functions, from function index `first` (address order, the
        order of `functions`), stopping at the first function boundary after `max_insns` instructions; `next_index`
        continues. Used by the build comparison. Default: one `functions` page plus one whole-function `disassemble` per
        function (correct, slow on an engine that starts a process per call: the real engines override it with a
        single bulk run). A function the engine cannot disassemble gives an error, never an empty body."""
        page = self.functions(sha256, offset=first, limit=200)
        if not page.ok:
            return EngineResult(page.status, None, page.detail, duration_s=page.duration_s)
        items: list[FunctionBody] = []
        used = 0
        for fn in page.data.items:
            if items and used >= max_insns:
                break
            r = self.disassemble(sha256, fn.address, count=20_000, whole_function=True)
            if r.data is None:
                return EngineResult(r.status, None, f"0x{fn.address:x}: {r.detail}")
            items.append(FunctionBody(fn.address, fn.name, fn.size, r.data))
            used += len(r.data.items)
        done = first + len(items)
        return EngineResult(Status.OK, FunctionBodies(items, page.data.total,
                                                      done if done < page.data.total else None), untrusted_content=True)

    def decode(self, sha256: str, address: int, *, count: int = 64) -> EngineResult[Disassembly]:
        """Instructions decoded linearly from `address` up to and including the first return or unconditional jump,
        WITHOUT changing the engine's database (code the engine's own analysis did not reach, e.g. an __except
        block only the unwind data points to). Default: the engine's linear `disassemble` (existing code only)."""
        return self.disassemble(sha256, address, count=count)

    def call_args(self, sha256: str, address: int) -> EngineResult[dict[int, int | None]]:
        """For every call instruction of the function containing `address`: how many bytes of stack parameters the
        callee's prototype occupies, measured from the stack pointer at the call (x64: the home space included when
        the prototype places parameters there), or None when the engine has no prototype for the callee (indirect
        call, untyped function, varargs). NOT abstract: engines without it return TOOL_MISSING and every call counts
        as unknown."""
        return EngineResult(Status.TOOL_MISSING, None, f"{self.name}: call_args unsupported")

    @abc.abstractmethod
    def strings(self, sha256: str, *, pattern: str | None = None, offset: int = 0,
                limit: int = 100) -> EngineResult[Page[StringInfo]]:
        """`pattern`: regex (re.search); None means all."""
