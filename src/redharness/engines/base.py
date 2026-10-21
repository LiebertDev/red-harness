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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generic, TypeVar

from ..core.result import Status

T = TypeVar("T")


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
class EngineResult(Generic[T]):
    status: Status
    data: T | None = None
    detail: str = ""
    cached: bool = False
    duration_s: float = 0.0
    untrusted_content: bool = False
    extra: dict = field(default_factory=dict)

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
