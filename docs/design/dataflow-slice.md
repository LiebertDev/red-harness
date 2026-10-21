# `dataflow_slice`: where a checked value comes from

Status: option D accepted with a narrowed MVP (section 6, which overrides sections 2-5 where they differ). The core
slicer and the MCP tool are implemented in `src/redharness/analysis/dataflow/` and `src/redharness/mcp/session.py` with
synthetic unit tests; the real-binary proof on the host's own system DLLs is in `tests/heavy/test_dataflow_real.py`.

## 0. The gap

Analyst models find the comparison or check in a function but miss where the compared value comes from. Three shapes
recur:

1. a stack buffer initialised byte by byte (or dword by dword) before the check, often with junk instructions in
   between, then compared in a loop or passed to `strcmp`/`memcmp`;
2. a constant assembled through several register moves and arithmetic (`mov eax, K; shl eax, 4; add eax, ecx`);
3. a value loaded from an image section through pointer arithmetic (`mov esi, offset tbl; mov eax, [esi+8]`,
   `movdqa xmm0, xmmword ptr [rip+X]`).

The decompiler output sometimes shows these and sometimes does not (obfuscation, failed decompilation, a buffer split
over several variables). `disassemble` shows every instruction, but the model has to do the def-use bookkeeping by hand
and loses track. The proposal is a bounded, on-demand, read-only tool that does that bookkeeping and prints it as
verifiable evidence lines.

## 1. Use cases and non-goals

### 1.1 Use cases

- U1. Given the address of a `cmp`/`test`/`call strcmp`-like instruction, list the writes that reach each value it reads,
  recursively, inside the function.
- U2. Reconstruct a stack buffer from the stores that initialise it, byte by byte, each byte with the address of the
  instruction that wrote it, and print the fully determined runs as a byte string (and as text when printable).
- U3. Fold constants through register moves and arithmetic, and say which instructions produced the final value.
- U4. Resolve loads from image sections when the address is constant after folding: print the bytes from the file
  image and the section note (name and R/W/X), with an explicit note when the section is writable (the file value is
  only the initial value).
- U5. Say explicitly where a value is NOT known: return value of a call (callee named, not followed), memory through an
  unknown pointer, a function argument, a buffer whose address escaped to a call, a loop-varying index, an
  unmodelled instruction, a join of different values. Never a guess.
- U6. Point the analyst at the next proof step: the slice gives a candidate value; a behaviour claim about it still
  needs `run_controlled` (static evidence is SUPPORTED at most), and a computed value can be cross-checked with `emulate`.

### 1.2 Non-goals

- No symbolic execution engine, no SMT, no path constraints. Joins are merged, not split.
- No whole-program or inter-procedural analysis. Callees are named, never entered. Globals written elsewhere are
  reported as "initial file value", never as the run-time value.
- No unbounded work: bounded by one function, an instruction cap, a step cap and a fixpoint iteration cap (section 3.5).
  Limits are deterministic counts, never wall-clock (a wall-clock stop is not reproducible and could not be cached).
- No architectures other than x86 and x64 PE in v1 (other targets get `ARCH_UNSUPPORTED`).
- No deobfuscation pass. Junk instructions are handled only because a backward slice ignores writes that do not reach
  the use; if the engine's disassembly itself is wrong (overlapping instructions), the slice is wrong in the same
  place, and the output says which engine produced the instructions and CFG.
- No change to what a claim can reach: static evidence stays SUPPORTED at most.

## 2. Engine options

Grounding in the current code:

- `engines/base.py`: the common contract already has `InsnInfo` (address, size, bytes, mnemonic without prefix, engine
  text) and `OperandInfo` (`kind` reg/imm/mem/near, `reg`, `base`/`index`/`scale`/`disp`, resolved `value`, `size`,
  `sym`). `Engine.disassemble(whole_function=True)` returns every instruction of a function in address order. There is
  no CFG and no stack-pointer information in the contract.
- `engines/ida/_worker.py` (`op_disassemble`, `_operand`): fills the structural operand fields from `insn_t`; memory
  operand size comes from `get_dtype_size(op.dtype)`; SIB base/index are recovered from the bracket text.
- `engines/ghidra/scripts/RHQuery.java` (`operandJson`): same contract from `getOpObjects`; memory operands carry
  `size=0` (only register and scalar operands get a size), so a harness-side slicer must take memory width from the
  other operand or from the `byte/word/dword/qword/xmmword ptr` keyword in the text unless the engine supplies it.
  Each query is one headless JVM run, cached per query (`results/<key>.json`).
- `analysis/driver.py` (`_resolve_handler`) already does a one-register lookback over `InsnInfo` in pure Python, with
  explicit unknowns. The slicer generalises that approach.
- `mcp/session.py`: `disassemble`/`decompile` go through the step cache and end with section notes
  (`analysis/section_notes.py`: `where(img, va)` -> `.rdata R--`). `read_bytes` reads the SHA-verified CAS copy via
  `PeImage`; the slicer reads image constants the same way.

### 2.1 Options

- A. IDA Hex-Rays microcode: `ida_hexrays.gen_microcode` at a chosen maturity, def/use lists per `minsn_t`
  (`mblock_t.build_use_list`/`build_def_list`) or use-def chains from the MBA graph (`get_ud`), stack variables as
  `mop_S`. Very precise (stack variables, SP tracking, dead-code removal), but IDA-only, needs a working decompiler for
  the function, and later maturities merge stores (a 16-byte `qmemcpy` replaces 16 byte stores), which loses the
  per-byte source address. The API surface is large and has shifted between IDA versions.
- A2. Hex-Rays ctree visitors (`ida_hexrays.ctree_visitor_t`) over `cfunc_t`: easy to write, but a ctree expression is
  a reconstruction; mapping back to the instruction that wrote a byte is lossy. IDA-only.
- B. Ghidra HighFunction P-code: decompile in `RHQuery.java`, walk `Varnode.getDef()` / `getDescendants()` in SSA.
  Precise for register and non-escaping stack values; an address-taken stack buffer (the common case: it is passed to
  `strcmp`) turns into `STORE`/`PTRSUB` chains that need extra work. Ghidra-only, one decompile per query in a fresh
  JVM.
- B2. Ghidra raw per-instruction P-code (`Instruction.getPcode()`, no decompiler) exported to a harness interpreter:
  exact per-instruction semantics including implicit effects, but there is no IDA counterpart of the same shape, so the
  two engines would diverge.
- C. Harness-side slicer over the engine's `InsnInfo` stream: pure Python in `analysis/`, works with both engines, every
  step is one engine instruction with its own text and address. Needs an x86 semantics table (registers read/written,
  implicit operands, value transfer), its own CFG from branch operands, and its own stack-pointer tracking (weak after
  calls with callee stack cleanup, and after `and esp, -N` alignment).
- D. C plus an optional engine `flow` query: the engine supplies what it already knows and the harness cannot derive
  well: the stack-pointer delta before each instruction (IDA `ida_frame.get_spd`; Ghidra `CallDepthChangeInfo`), the
  basic blocks with successor edges including resolved switch tables (IDA `ida_gdl.FlowChart`; Ghidra
  `BasicBlockModel`), and the access width of memory operands. The slicer itself stays harness-side and
  engine-independent; without the `flow` query it falls back to C and says so in the output.
- E. C with a third-party decoder (capstone `regs_access()` on the engine's own instruction bytes) for implicit
  register effects: adds a runtime dependency for something a ~150-mnemonic table covers; useful only as an independent
  cross-check.

API names above are from the vendor SDK documentation and are UNVERIFIED on the installed engine versions; Phase 3
checks them before use.

### 2.2 Scores

1-5, higher is better. Engine parity: works the same with IDA and Ghidra (Ghidra is the default engine for users who
bring their own). Fidelity: each output step maps to one engine instruction with quotable text. Robustness: still works
when decompilation fails or the code is obfuscated. Precision: SP, aliasing, constants, joins. Risk: implementation and
version risk (higher = less risk). Testability: unit-testable without an engine. Cost: per-call run time.

| Option | Parity | Fidelity | Robustness | Precision | Risk | Testability | Cost | Total |
|---|---|---|---|---|---|---|---|---|
| A. Hex-Rays microcode | 1 | 3 | 2 | 5 | 2 | 2 | 3 | 18 |
| A2. Hex-Rays ctree | 1 | 2 | 2 | 3 | 3 | 2 | 3 | 16 |
| B. Ghidra HighFunction | 2 | 3 | 2 | 4 | 2 | 2 | 2 | 17 |
| B2. Ghidra raw P-code | 2 | 5 | 4 | 5 | 3 | 3 | 3 | 25 |
| C. Harness slicer only | 5 | 5 | 3 | 3 | 4 | 5 | 5 | 30 |
| **D. Harness slicer + engine `flow` (CHOSEN)** | 5 | 5 | 4 | 4 | 4 | 5 | 4 | **31** |
| E. C + capstone semantics | 5 | 4 | 4 | 4 | 3 | 4 | 4 | 28 |

C and D differ only where the engine knows more than the harness: D gains robustness (engine-resolved switch-table
successors and code the engine has already separated from junk bytes) and precision (32-bit code with `push`/`pop` and
stdcall callees, where esp-relative stack addressing is unusable without the callee's stack cleanup; Ghidra memory
widths), and pays one cached engine query per function. D degrades to C when the engine lacks the query, so it never
blocks.

### 2.3 Decision and reasons

D. The slicer lives in `src/redharness/analysis/dataflow/` and consumes only the common contract; both engines gain one
small optional `flow` operation.

- Engine parity: the same algorithm on IDA and Ghidra output, so both engines can be compared on the same function
  (a cross-engine diff is part of the real proof, section 4.2).
- Evidence fidelity: the output is a list of engine instructions (address + the engine's own text) with harness
  annotations in fixed `key=value` fields. That is the shape the verifier already handles for `disassemble`.
- Robustness: no decompiler needed; a function the decompiler rejects can still be sliced.
- Testability: synthetic `InsnInfo` streams drive the whole slicer in unit tests (known answers without an engine).
- Hex-Rays microcode is kept as a possible later IDA-only cross-check, not a dependency.

## 3. Design

### 3.1 Engine contract addition (optional)

```python
@dataclass(frozen=True)
class BlockInfo:
    start: int                 # VA of the first instruction
    end: int                   # VA after the last instruction
    succs: tuple[int, ...]     # successor block starts (engine-resolved, incl. switch-table targets)
    kind: str                  # "normal" | "ret" | "indirect" (unresolved successors) | "noreturn"

@dataclass(frozen=True)
class FunctionFlow:
    disassembly: Disassembly            # whole function, same rows as disassemble(whole_function=True)
    sp_delta: dict[int, int | None]     # SP before the instruction minus SP at entry (bytes); None = engine unsure
    mem_width: dict[tuple[int, int], int]  # (insn VA, operand index) -> access width in bytes, where known
    blocks: list[BlockInfo]

class Engine:
    def flow(self, sha256: str, address: int, *, max_insns: int = 20_000) -> EngineResult[FunctionFlow]:
        """NOT abstract: engines without it return TOOL_MISSING ("unsupported") and the slicer uses its own CFG/SP."""
```

- IDA worker `op_flow`: `idautils.FuncItems` (as `op_disassemble`), `ida_frame.get_spd(func, ea)` per instruction,
  `ida_gdl.FlowChart(func, flags=FC_PREDS)` for blocks and successors, operand width from `get_dtype_size`.
- Ghidra `RHQuery.java` `opFlow`: `getInstructions(f.getBody())`, `CallDepthChangeInfo` for the depth per address,
  `BasicBlockModel` code blocks and their destinations within the body, memory width from the instruction's P-code
  `LOAD`/`STORE` output size.
- New op name, so existing query caches stay valid (IDA `RESULT_REV` is not bumped; the Ghidra query key carries
  `"op":"flow","rev":1`). Row validation is fail-closed like `disassembly_from_doc` (count mismatch, a block outside the
  function, a successor that is not a block start -> the whole `flow` result is rejected and the slicer falls back,
  stating it).

### 3.2 Analysis model

Locations:
- registers, normalised to the full register family with a byte range (`al` = rax[0], `ah` = rax[1], `ax` = rax[0:2],
  `eax` = rax[0:4]; a 32-bit write on x64 zeroes rax[4:8]); `xmm0..15` as 16-byte locations; flags are ignored
  (`cmp`/`test` define nothing the slice follows);
- stack bytes, as offsets from a stack base: `sp0` (the stack pointer at entry) and, after `and esp/rsp, -N`, a second
  base `spA` (aligned frame); offsets on different bases are never compared;
- image bytes (an absolute VA inside the PE image);
- other memory (pointer not known): never a definite location.

Abstract values per register (forward pass): `Const(n)`, `StackAddr(base, off)`, `Unknown(origin)` where origin is one
of `arg` (a value live at entry: argument register or `[sp0+k]`, k > 0), `call:<site>`, `mem:<site>`, `join:<site>`,
`unmodelled:<site>`, `loop:<site>`. Image pointers are `Const` values that fall inside the image.

Passes:
1. CFG and SP: from `flow` if available, else harness-derived (branch mnemonics + `near` operands; `ret`/`jmp reg`
   end blocks; a block with no known predecessor that is not the entry gets the note "possible indirect-jump target,
   predecessors unknown"). Harness SP: `push`/`pop`/`sub|add esp, imm`/`enter`/`leave`/`ret`; after a `call` the
   callee's stack cleanup is unknown on x86 unless the engine supplied SP, so esp-relative accesses after that point
   become `Unknown(sp-unknown:<call site>)`; ebp/rbp-based accesses are unaffected.
2. Forward reaching definitions + constant/stack-address propagation over the CFG, byte-granular for stack bytes,
   iterated to a fixpoint with a hard iteration cap. At a join, equal values stay; different values become
   `Unknown(join)` and keep the list of reaching definitions.
3. Backward slice from the query: for each value the query instruction reads, take its reaching definitions; for each
   definition, recurse into what that definition read (address registers of a memory operand included); stop at
   constants, image bytes, unknown origins, the step cap or the depth cap.

Instruction semantics (`analysis/dataflow/x86.py`), a closed table:
- moves: `mov`, `movabs`, `movzx`, `movsx`, `movsxd`, `lea`, `xchg`, `push`, `pop`, `bswap`, `cmovcc` (may-def: result
  is a join of old and new), `setcc` (Unknown 0/1);
- arithmetic with folding: `add sub and or xor not neg inc dec shl shr sar rol ror imul` (2/3-operand); zero idioms
  `xor r,r`, `sub r,r`, `pxor x,x`, `xorps x,x`;
- sign extension: `cdq cqo cwde cdqe cbw cwd`;
- SSE moves: `movd movq movaps movups movdqa movdqu movss movsd` (16-byte stack and image transfers);
- string ops `stos movs` (and `lods` as a read) with a `rep` prefix taken from the instruction bytes (`InsnInfo.mnemonic`
  carries no prefix by contract): handled when ecx/rcx, edi/rdi (and esi/rsi) are known constants or stack addresses
  and the count is under the buffer cap, else `Unknown(loop)` over the possibly written range;
- `call`: defines eax/rax (`Unknown(call:<site>)` with the callee name from the operand `sym` or the IAT slot), clobbers
  the caller-saved set of the ABI (x86: eax ecx edx; x64 ms64: rax rcx rdx r8-r11 xmm0-5); every stack buffer whose
  address was passed to the call (argument register or pushed value holding `StackAddr`) is marked "may be written by
  the callee" from that point on;
- anything else: if it may write a tracked location (destination operand by Intel convention, or an implicit effect the
  table does not know), the location becomes `Unknown(unmodelled:<site> <mnemonic>)` and coverage is `partial`.

Memory width: `OperandInfo.size` if > 0, else the `flow` width, else the other operand's register width, else the
`byte/word/dword/qword/xmmword ptr` keyword in the engine text (IDA and Ghidra both print it), else Unknown width (the
store is reported, its bytes are not used).

Aliasing rule: a store through an `Unknown` pointer on a path between a buffer write and the query may overwrite the
buffer only if the buffer's address escaped (was stored to memory, passed to a call, or copied to a register that was
later clobbered unknowingly). Escaped buffers get the note "may be overwritten via unknown pointer at <site>" on the
affected bytes, and those bytes are excluded from the assembled run.

Loops: a store inside a CFG cycle whose address register varies across iterations is `Unknown(loop)` for the whole range
the register can cover if that range is known, otherwise for the buffer. Recognising simple counted copy loops
(`mov al, [src+i]; mov [dst+i], al; inc i; cmp i, N; jl`) is Phase 4 and optional.

### 3.3 Query

- `address` (required, hex VA): an instruction inside a function.
- `operand` (optional int): slice only this operand of the instruction (default: every operand the instruction reads,
  including the address registers of a memory operand; for a `call`, the argument registers and stack argument slots of
  the ABI up to 4/6 slots, labelled as such).
- `location` (optional): an explicit location live at `address`: a register name (`eax`), a stack slot given as a
  frame-relative memory expression (`[ebp-0x20]`, `[rsp+0x40]`), or `sp0-0x24`. Engine stack-variable names that encode
  an offset (Ghidra `local_24`, IDA `var_20`) are accepted with their engine's convention; a Hex-Rays `vN` name is
  refused with "pass the stack location shown in the decompiler declaration comment".
- `size` (optional, bytes, 1..4096): for a buffer location, how many bytes to reconstruct. Default: the extent of
  contiguous writes reaching the location, capped.
- `max_steps` (optional, default 200, max 1000): definitions printed before the slice is cut.
- `detail`: `summary` | `full` (as the other large-output tools); `offset`/`max_chars` paging for `full` as in
  `decompile`.

Errors (no evidence): `BAD_ARGUMENT`, `NOT_IN_FUNCTION`, `NO_INSTRUCTION` (address not an instruction start),
`ARCH_UNSUPPORTED`, engine failures as for `disassemble`.

### 3.4 Output format

Plain text, one fact per line, fixed `key=value` annotations after the engine's own text. Addresses and values in `0x`
form (never the IDA `..h` form, so numbers are backable without the disassembly-only number rule). No instruction byte
field (so no byte run is mistaken for a hex token). Engine text goes through `_line_safe` and the whole reply is wrapped
as untrusted target content. Illustrative (synthetic addresses, IDA-style text):

```
slice target=0x401085 function=0x401000 name=sub_401000 insn: cmp al, [ebp+ecx-20h]
flow source=engine:ida cfg=engine sp=engine blocks=9 insns=212 abi=x86-cdecl/stdcall
query reads: al | byte [ebp+ecx-20h] -> stack sp0-0x24+ecx (index ecx not constant: whole buffer)
use al @0x401085
  def 0x40107e | mov al, [esi+ecx] | reads mem[esi+ecx] value=unknown origin=mem esi=arg(sp0+0x4)
  unknown: al at 0x401085 comes from memory through esi = argument 1 (not followed)
use buffer stack:sp0-0x24 size=0x20 (reaching writes before 0x401085, all paths)
  def 0x401010 | mov byte ptr [ebp-20h], 41h | writes sp0-0x24+0x0 size=1 value=0x41
  def 0x401019 | mov dword ptr [ebp-1Fh], 45444342h | writes sp0-0x24+0x1..+0x4 size=4 value=0x45444342
  def 0x401020 | mov byte ptr [ebp-1Bh], 46h | writes sp0-0x24+0x5 size=1 value=0x46 supersedes=0x401019[+0x4]
  ...
  bytes +0x00..+0x1c defined=29/32 source=per-def lines above
  run +0x00..+0x1c len=29 hex=41424344464748... ascii="ABCDFGH..."
  unknown: +0x1d..+0x1f no write reaches 0x401085 (uninitialised on every path)
const 0x401040 | mov eax, offset unk_402100 | value=0x402100 image=.rdata R--
  def 0x401047 | movdqa xmm0, xmmword ptr [eax+10h] | reads image 0x402110 size=16 section=.rdata R-- hex=00112233445566778899aabbccddeeff
unknown: eax at 0x401060 = return value of call 0x40105b (call ds:GetTickCount), callee not followed
unknown: buffer stack:sp0-0x64 passed to call 0x401070 (call _fgets) at 0x40106c; bytes after that call may be written by the callee
coverage: complete | partial reasons=step_cap,unmodelled:0x401033 cmpxchg8b,sp-unknown:0x40102b
limitations: ABI assumption x86 cdecl/stdcall callee-saved ebx esi edi ebp; callees not entered; image values are the file's initial bytes
; section .text R-X: 0x401010..0x401085 (instructions above)
; section .rdata R--: 0x402100..0x40211f (image data above)
```

Rules:
- Each `def` line: instruction VA, engine text, what it writes (location and byte range), the folded value when constant,
  `supersedes=` when a later write overrides some of its bytes.
- Buffer reconstruction: every byte's source is the `def` line whose range covers it and that is not superseded on any
  path; a byte with two different reaching writes is `conflict` (both sites listed). The `run` line covers only
  maximal ranges of bytes that are definite on every path (no conflict, no unknown, no "may be written"). `hex=` is
  printed only for runs of 9+ bytes (more than 16 hex digits = byte-string class, verifier v21); shorter runs are backed
  by the per-def `value=` numbers and the text form. `ascii="..."` is printed only if every byte is 0x20..0x7e (a
  trailing NUL is reported as `nul_terminated=yes`); `utf16="..."` only for an even run of printable/00 pairs. A `"` or
  `\` inside is escaped and the line gets `escaped=yes`.
- Image loads: VA, size, `section=<name> <RWX>` (from `section_notes.where`), bytes from the SHA-verified CAS copy. A
  writable section adds `note=initial file value, section is writable`; bytes beyond the section's raw data are
  `unknown: zero-fill/uninitialised region` (not printed as zeros).
- `unknown:` lines are mandatory for every leaf that is not a constant or image byte, and each names its origin.
- Truncation and coverage markers: `coverage: complete` only if the function was fully disassembled, every needed
  instruction was modelled, the SP was known where it mattered, no cap was hit, and the CFG had no unresolved indirect
  edges reaching the query. Otherwise `coverage: partial reasons=...` and the evidence status is `PARTIAL`. A cut by
  `max_steps` prints `cut: N more definitions not shown (max_steps)`; a cut by the reply budget pages with
  `next_offset` like `decompile`.
- Section notes at the end, as for `disassemble`/`decompile` (`range_notes` + `name_notes`).

Evidence record: `operation=dataflow_slice`, `authority=shipped-artifact`, `confidence=derived` (like `decompile`),
`locations` = every instruction VA printed plus every image range read (with size), `coverage.scope =
slice:0x<target>`, `limitations` as printed.

Summary (`detail=summary`): `defs`, `unknowns` (count by origin), `buffers` (base, offset, size, defined bytes, runs with
length), `consts` (count), `coverage`, `flow_source`, first lines as preview; the full text stays in the ledger under the
same `ev_`.

### 3.5 Limits

| Limit | Value | When hit |
|---|---|---|
| instructions per function | 20 000 | PARTIAL; definitions from missing instructions are `unknown: function truncated` |
| fixpoint iterations | 20 x blocks | PARTIAL `fixpoint_cap`; affected locations become `Unknown(join)` |
| printed definitions | `max_steps` (200 default, 1000 max) | `cut:` line, PARTIAL |
| recursion depth | 64 | `unknown: depth cap` at the leaf |
| buffer size | 4096 bytes | `size` refused above it |
| reply size | 24 000 chars per page (`RESPONSE_BUDGET`) | paging via `offset` |

All limits are counts, so the same request always gives the same output and the same `ev_`.

### 3.6 MCP tool, scope, cache

- Name `dataflow_slice(address, operand=None, location=None, size=None, max_steps=200, detail="summary", offset=0,
  max_chars=12000)`. It is the 17th MCP tool (the tool count is capped at 20).
- Effect: `_READ` (`reads_files`, `mutates_session`), the same as `disassemble`/`decompile`; no new manifest operation.
  Added to `GAP_TOOLS` (a failed call is a coverage gap) and `LONG_TOOLS` (journaled start, resumable).
- Step cache key: tool `dataflow_slice`, canonical args `{address, operand, location, size, max_steps, rev}` where `rev`
  is a slicer revision constant (`SLICER_REV`, bumped when output for the same input changes), target SHA, session
  `TOOL_VERSION`, engine version. Embedding `rev` in the args (precedent: the Ghidra xrefs query key) invalidates only
  this tool when the slicer changes. `detail`/`offset`/`max_chars` are not in the key (same `ev_` for summary and full).
- Engine query cache: the new `flow` op has its own key (op name + `rev`), so it neither invalidates nor reuses
  `disassemble` results. Image bytes come from the CAS copy (SHA-verified on first use), no separate cache.

### 3.7 Claims and verifier

What becomes backable with the existing verifier (version 21), no code change:
- `quote` atoms: any engine instruction text in a `def` line (verbatim, as in `disassemble`).
- `address` atoms: every printed instruction VA and every image range read is in `locations`.
- numbers: `value=0x..`, image VAs, offsets: `0x` tokens are numbers in any evidence; the slice never relies on IDA `..h`
  numbers.
- byte strings: `hex=` runs of 9+ bytes are whole hex tokens (`constant` atom or value in the claim text).
- strings: `ascii="..."`/`utf16="..."` text is in the raw output, so a quoted string value in an `observation` +
  `present` claim is supported verbatim.

Example claim: kind `observation`, text "the buffer compared at 0x401085 is initialised on all paths to `ABCDFGH...`
by the stores at 0x401010..0x401040", atoms `{"type":"quote","evidence_id":"ev_..","text":"mov byte ptr [ebp-20h], 41h"}`,
`{"type":"address","evidence_id":"ev_..","value":"0x401010"}`. It reaches SUPPORTED at most. "This is the accepted
password" is a `behavior` claim and still needs `run_controlled`; the slice only tells the analyst what to run.

Verifier impact: none required. Two deliberate format choices make that true: values in `0x` form (the disassembly-only
`..h` rule is not needed) and no instruction byte field (no accidental hex tokens). Residual risk, stated in the tool
limitations: a slicer bug could print a wrong assembled string that the verifier would then accept as an observation.
Mitigations: runs are printed only for bytes definite on every path; every byte points to a quotable `def` line; unit
tests with known answers; real proofs against an independent mechanism (section 4.2). If a later review wants the
verifier to treat assembled runs as `derived` (like the `derivation` atom), that is a separate verifier version.

## 4. Test plan

### 4.1 Unit tests (`tests/unit/test_dataflow_slice.py`, synthetic `InsnInfo` streams, no engine)

Each test builds instructions in both IDA-style and Ghidra-style text (`[ebp+var_20]` vs `[EBP + -0x20]`) to prove the
slicer uses the structural fields, not the text.

1. Byte-by-byte stack init, junk instructions interleaved (dead writes to other registers, `xchg eax, eax`, a jump over
   garbage), then a compare loop: the buffer is reconstructed, each byte points to its store, junk is absent.
2. Mixed widths and overlap: dword then byte overwriting part of it; `supersedes=` and the effective bytes.
3. Constant through moves: `mov eax, K; shl eax, 4; lea ecx, [eax+K2]; add ecx, edx(const)` -> value and chain.
4. Image constant via pointer arithmetic with a fake `PeImage`: `.rdata` load (bytes + section), `.data` load
   (writable note), a load beyond raw data (unknown, not zeros), a load outside the image (unknown).
5. Call result: `call ds:GetTickCount; mov [ebp-4], eax` -> `unknown ... return value of call` with the callee name.
6. Escape: buffer address pushed to a call before the compare -> "may be written by the callee", excluded from runs.
7. Join: two paths write different bytes -> `conflict` with both sites, no run over it; equal values on both paths ->
   definite.
8. Loop-varying store index -> `Unknown(loop)` over the range.
9. `rep stosd` and `rep movsd` (prefix from bytes) with constant ecx; same with unknown ecx -> unknown range.
10. x86 esp-relative addressing with pushes; a stdcall call without engine SP -> `sp-unknown`, with engine SP -> resolved.
11. `and esp, -16` alignment -> second base `spA`; ebp-relative still on `sp0`.
12. x64: `movaps xmm0, [rip+X]` (`.rdata`) then `movups [rsp+20h], xmm0` and `mov dword [rsp+30h], imm` -> 20-byte
    buffer; 32-bit write zero-extends.
13. Unmodelled instruction writing the tracked register -> unknown + `coverage: partial`.
14. Caps: `max_steps` cut line, fixpoint cap, size cap refusal; determinism (same input -> identical text).
15. Output hygiene: no instruction byte field, no `..h` numbers in annotations, `hex=` only for 9+ bytes, escaping.
16. MCP layer with a fake engine: scope effect check (refused without the static permission), step cache hit (same `ev_`),
    summary/full share the `ev_`, evidence `locations` contain every printed VA, `flow` TOOL_MISSING -> fallback note.
17. Verifier round trip: observation claim with the `ascii` string + quote + address atoms citing slice evidence ->
    SUPPORTED; the same as `behavior` -> UNVERIFIED (`BEHAVIOR_NEEDS_EXECUTION`); partial slice evidence never backs
    PROVEN; a string not in the output -> `VALUE_NOT_IN_EVIDENCE`.
18. Optional cross-check test (skipped if capstone is not installed): the semantics table's register read/write sets agree
    with capstone `regs_access()` on a fixed corpus of encodings. Test-only; capstone is not a runtime dependency.

### 4.2 Real proofs (Phase B and later, heavy tests, host quiet, both engines)

For every case: slice with IDA and with Ghidra, compare the structural output (defs, values, bytes, unknowns) across
engines, and compare the bytes against an independent ground truth computed from the raw file bytes. Record the file's
SHA-256 and the engine versions with the proof (`tests/heavy/test_dataflow_real.py`).

- (a) A system DLL function whose check compares input against a stack buffer initialised among junk instructions (found
  by a bounded scan of a system DLL's functions; the chosen file is identified by SHA-256). Slice at the check
  instruction. Ground truth: decode the initialising instructions from the raw file bytes in the test and require
  byte-exact reconstruction; where the reconstructed value has an observable effect, try it with `run_controlled` and
  quote the accepting output (behaviour proof through the normal path).
- (b) A system binary function that builds a stack string with immediate stores (found by the same bounded scan; the
  chosen file is identified by SHA-256). Ground truth: `emulate` over a code range that ends after the last store (when
  the range has no imported call) with the buffer read back; byte-exact comparison, plus per-store manual check against
  `disassemble` evidence.
- (c) A `.rdata` constant load (`movdqa`/`movaps` from a RIP-relative address, or a table read through a constant base
  and index). Ground truth: `read_bytes` at the same VA: identical bytes, and the slice's section note equals the
  `read_bytes` segment line.

Pass criteria: byte-exact match on every definite byte; every non-definite byte is covered by an `unknown:` or `conflict`
line; the two engines agree, or the disagreement is traced to an engine disassembly or CFG difference and written down.

## 5. Effort and phases

| Phase | Content | Size |
|---|---|---|
| 1 | `analysis/dataflow/` core: x86 table, harness CFG/SP, forward pass, backward slice, buffer reconstruction, image reads, renderer; unit tests 1-15 | M (2-3 agent-days) |
| 2 | MCP tool in `session.py` + `server.py`, effects table, step cache, evidence, usage docs, server instructions line; unit tests 16-17 | S (1 day) |
| 3 | Engine `flow` op: IDA worker + `RHQuery.java` + contract + fake engine; heavy tests on one small binary per engine | S/M (1-2 days) |
| 4 | Precision extras: `rep` string ops edge cases, SSE paths, optional counted copy loops; cross-check test 18 | M (1-2 days) |
| 5 | Real proofs (a)(b)(c) on both engines and a cross-engine diff | S (1 day + run time) |

Total 6-9 agent-days. Phases 1-2 alone already give a usable tool (harness CFG/SP); Phase 3 removes most `sp-unknown`
leaves on 32-bit code. Each phase ends with its unit tests green; nothing is called done without the Phase 5 real proofs
(fakes are regression guards only).

## 6. MVP scope (accepted after review)

- "Definite" is a formal output condition: at a join a byte or register keeps its value only if every incoming state
  gives the same value; the supporting write sites of all paths stay as provenance (the same value from different
  writes is definite). Unresolved/indirect edges (an indirect jump gets edges to every block), a block without a known
  predecessor, a truncated disassembly and the fixpoint cap make the affected values unknown. The output states that
  the guarantee covers the CFG built from the engine's decoded instructions.
- Explicit instruction allowlist only: width-correct `mov` (x64 32-bit writes zero the upper half, 8/16-bit writes keep
  the rest, tracked per byte), `movzx`/`movsx`/`movsxd`, `cbw`/`cwde`/`cdqe`, `cwd`/`cdq`/`cqo`, `lea` as arithmetic,
  `add sub and or xor shl/sal shr not neg inc dec`, `xchg`, `push`/`pop`/`leave` while the stack offset is known.
  Flag-dependent ops (`cmovcc`, `setcc`, `adc`, `sbb`), SSE, string ops with or without `rep`, x87 stores and unsupported
  widths give `unknown:` with the instruction named; a mnemonic with unknown implicit effects makes every general
  register unknown and the coverage partial.
- Calls: Windows x86/x64 ABI volatile registers become unknown, eax/rax is the call's return value (callee named); a
  frame address that escaped (stored, pushed, held in a register at the call, or lost through an unsupported operation)
  makes the frame from that address upward unknown at every later call (assumption A1, printed when used).
- Stack: frame-pointer-relative slots and simple known stack-pointer deltas only; `and esp/rsp, -N`, an x86 call (callee
  cleanup unknown) and unknown deltas make the stack pointer unknown, never merged. Stores through the stack pointer
  while its offset is unknown are assumed not to overlap frame-pointer-relative slots (assumption A2, printed when used).
- A1/A2 marking: a value that holds only because A1 or A2 was applied (a frame byte below a havoc point, a frame byte
  that survived an ignored stack-pointer store, and every value computed from such bytes) carries the tag and is
  printed with `assumes=A1`/`assumes=A2` (value, byte-range and `run` lines, summary `assumptions`); the assumption
  text is printed only when it influenced a reported value. Such a value is never presented as unconditional; the
  marker is part of the evidence text a claim cites.
- Packaging: core (open) static analysis, like `emulate`.

### 6.1 Additions found necessary on real binaries (slicer revision 2)

- Spilled frame pointers: debug builds store `lea eax, [ebp-0x64]` into a frame slot and reload it before every use.
  A frame address stored into a pointer-sized frame slot is kept byte by byte (spilled-pointer bytes) and a reload of
  exactly that slot gives the frame address back; a partial or mixed read loses it (escape). Spilled frame addresses
  anywhere in the frame (pushed arguments included) escape at the next call.
- Frame address at a non-constant offset (RANGE): the join of two frame addresses on the same base (a pointer advanced
  in a loop) or a frame address plus an unknown index is "the frame from offset X upward" (A1). A load through it is
  reported as the frame buffer starting at X; a store through it makes the frame from X upward unknown (A1).
- Last-write candidates: a definite frame byte that a call or a store through an escaped/indexed address may have
  overwritten becomes unknown but keeps its last definite value (`unknown last=0x..`). Ranges of such bytes are
  printed as `candidate ... NOT definite: last write of each byte ...`, separate from the definite `run` lines. They
  tell the analyst which value to test with `run_controlled` (or to cross-check with `emulate`); they are never a
  definite value.
- `cstr="..."`: printable bytes up to the first NUL when the whole range is not printable.
- Blocks without any edge into them (no indirect jump in the function) are not entered: dead code after an
  unconditional jump in junk-obfuscated code would otherwise make every later value unknown. Paths through them are
  not covered and the coverage says so (`block without a known predecessor not analysed ...`); a target inside such a
  block is analysed from an all-unknown state.
- Import address slots (from the PE import tables) are never read as values: the loader fills them.
- The function's analysis is reused in-process for later queries into the same function (keyed by target, engine
  version, function and slicer revision; two functions kept), so slicing several compares of one large function costs
  one analysis.

Review fixes (slicer revision 3):
- x64 calls: the 32-byte home (shadow) space at the call's stack pointer belongs to the callee; its bytes become
  non-definite at every x64 call with a known stack pointer (a definite byte keeps its last value as a candidate).
  Stack arguments above it and x86 pushed arguments are not modelled as callee-writable (no ABI argument decoding).
- Blocks without a known predecessor are still not entered, but where such a block (possibly an exception handler:
  there are no exception-dispatch edges) flows into an analysed block, every value arriving there becomes non-definite;
  frame addresses in registers and spilled frame pointers are kept (assumption: such a path restores the frame
  pointer), and the coverage names the block and the join. Follow-up, not built: take handler/funclet entry edges from
  the engines (IDA function tails / EH function info, Ghidra exception handlers) instead of this taint.
- The per-process analysis cache key includes a digest of the decoded instruction stream and its completeness.

### 6.2 Verifier impact after all (version 23)

Section 3.7 said no verifier change was needed. With `candidate` lines and `assumes=` markers that is no longer true:
their text appears verbatim in the evidence, so a claim quoting them would be SUPPORTED like a definite value.
Verifier version 23 (`docs/design/evidence-schema.md` section 4.16) treats those lines as conditional: a value or quote
backed only by them leaves the claim UNVERIFIED (`VALUE_ONLY_CONDITIONAL` / `QUOTE_ONLY_CONDITIONAL`) unless something
unconditional backs it too. Written values on `writes ...` annotations carry `assumes=` when they hold only under A1/A2
(slicer revision 3), so they are conditional as well.

### 6.3 Exception edges and callee parameter areas (slicer revision 4)

Exception edges (closes the "no exception-dispatch edges" limit where the data is exact):
- Source: the image's own x64 unwind data (`analysis/dataflow/seh.py`), not an engine heuristic. A `RUNTIME_FUNCTION`
  whose `UNWIND_INFO` has an exception handler that the import table names `__C_specific_handler` (or
  `__GSHandlerCheck_SEH`) carries a `C_SCOPE_TABLE`; each row with a non-zero `JumpTarget` is a `__try/__except`: an
  exception raised in [BeginAddress, EndAddress) continues at JumpTarget in the same function. Rows with
  JumpTarget 0 (`__finally` funclets), chained unwind info, other language handlers (C++ EH `__CxxFrameHandler*`),
  and x86 frame-based SEH give no edges. The same edges are used with every engine; an edge is used only when its
  target is a decoded instruction of the function and its try range covers some of them.
- Fixpoint: before every instruction inside a try range, the state an exception raised there would carry is joined
  into the `__except` block's entry state (the frame as it is, x64 volatile registers unknown). The block is then
  analysed like any other; the taint fallback of 6.1 remains for blocks that still have no known predecessor
  (filter funclets that IDA includes in the function, C++ catch continuations, x86 SEH).
- An engine may not have decoded the `__except` block at all (Ghidra's analysis never reaches it: the address is not
  code in its program). The tool then asks the engine to decode it from the edge target up to the first return or
  unconditional jump without changing its database (`Engine.decode`; Ghidra: `PseudoDisassembler`), adds those
  instructions to the function's stream and says so in the evidence limitations; a query address inside such a
  block is sliced in the function whose scope table points to it.
- Proof (`tests/heavy/test_dataflow_real.py`): on the CRT DllMain dispatcher of three small system DLLs, IDA (block
  in its function body) and Ghidra (block decoded on demand), the `__except` blocks (8 per function) are analysed;
  inside the first one `ebx` is `0x0 definite` from its own `xor ebx, ebx`; the same slice without the edges reports
  the block as not reachable and taints its join.
- Follow-up, not built: C++ EH continuations (FuncInfo / FH4 tables) and engine-provided handler edges.

Callee-writable parameter areas (closes "stack arguments above the home space and x86 pushed arguments"):
- The engine reports, per call instruction, how many bytes of stack parameters the callee's prototype occupies from
  the stack pointer at the call (`Engine.call_args`; IDA: the callee's type info, guessed if absent, stack-located
  arguments; Ghidra: the callee's (thunked/external) signature when its source is not DEFAULT, stack parameters).
  Varargs, untyped and indirect callees are unknown.
- Known: exactly [sp, sp + max(area, 0x20 on x64)) becomes non-definite at the call (last values kept as
  candidates). Unknown: a 16-argument window (x64 home space + 0x80 bytes, x86 0x40 bytes) becomes non-definite and
  every frame byte above it is tagged `assumes=A3` (it survives only under that assumption; verifier v23 treats it
  as conditional).
- Proof: IDA 9.4 and Ghidra report 0x38 for a `CreateFileW` call (7 parameters: home space + 3 stack slots) in a
  system DLL, and the documented x86 areas for `IsDebuggerPresent`, `GetTickCount`, `srand`, `GetModuleHandleA`,
  `GetProcAddress`, `strcspn` in the 32-bit benchmark target; the slice after the `CreateFileW` call shows those
  0x18 bytes non-definite with the reason "parameter area of call ... 0x38 bytes".
