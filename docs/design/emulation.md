# `emulate` tool: one function of the target in a CPU emulator, as evidence

Status: IMPLEMENTED (unit tests on synthetic PEs; real-binary proof on the host's ntdll.dll, x64 and x86). Version 2
(section 13: pre-writes, image pointers, more outputs, code ranges; verifier 20).
Code: `src/redharness/emulate/` (`spec.py` request, `loader.py` memory layout, `engine.py` Unicorn runner,
`worker.py` + `host.py` bounded worker process, `evidence.py` evidence record), `src/redharness/mcp/emulate_tool.py`,
`src/redharness/evidence/emulation.py` (verifier record check). Tests: `tests/unit/test_emulate.py`,
`tests/heavy/test_emulate_real.py`.

## 1. What it is for, and what it is not

Static tools show code and file bytes. Some values exist only after code runs over them: a string table decoded by a
small loop, a constant computed at startup, the output of a checksum or hash routine, a buffer unpacked by a routine.
`emulate` executes ONE function (or any code region that ends in a `ret`) of the target in a CPU emulator, with
arguments the analyst chooses, and records the registers and the memory it asks for as evidence.

It is an observation of EMULATION. The image starts in its on-disk state, nothing of the operating system exists, and
the analyst chose the inputs. A recovered value therefore shows what this code computes from these inputs in the
emulator; it does not show what the program does when it runs. Claims say so (section 8).

## 2. API shape: scored options

Scores 1-5 (higher is better): evidence binding (are the emulated bytes provably the target's?) / host safety /
packaging (is the emulator available where the code runs?) / speed / tool-count cost (cap 20) / testability without a
sandbox.

| Option | Binding | Safety | Packaging | Speed | Tool cost | Testability | Total |
|---|---|---|---|---|---|---|---|
| A. Helper library inside `compute` (Windows Sandbox) | 2 | 5 | 1 | 1 | 5 | 2 | 16 |
| **B. Dedicated `emulate` tool, bounded worker process on the host (CHOSEN)** | 5 | 3 | 5 | 5 | 3 | 5 | **26** |
| C. Dedicated `emulate` tool run inside Windows Sandbox | 5 | 5 | 2 | 1 | 3 | 2 | 18 |
| D. A mode of `run_controlled` | 2 | 5 | 2 | 1 | 5 | 2 | 17 |

- A: the target is not staged into the compute sandbox; code bytes would have to come in as `read_bytes` inputs
  (1 KiB per read) and the analyst's own Python would drive the emulator, so the result is a model computation, not an
  emulation of the target. The pinned compute runtime has no `_ctypes`, which the Unicorn binding needs; adding it
  weakens the pinned runtime. Every call costs a sandbox session (~25-40 s, exclusive lock).
- B: structured arguments only (no analyst code), the target bytes come from the SHA-256-verified job copy, the
  evidence id covers the full request, and the emulator interprets the code; nothing runs natively. Sub-second, fully
  testable on the host. Safety is not 5: the emulator processes target-controlled instructions on the host, so an
  emulator bug reachable by crafted code would run inside the worker process. Mitigations (section 2.1): the
  operation is off by default, and the worker is a separate, hardened, bounded process. If the threat model requires
  a real isolation boundary, option C is the upgrade path (same request/evidence format, different runner).
- C: strongest isolation, but needs a ctypes-enabled runtime plus the emulator staged into the sandbox and the slow
  sandbox start for every call.
- D: mixes execution evidence (`controlled-replay`, which can reach PROVEN) with emulation (which never can). Eliminated.

### 2.1 Worker hardening and residual risk

What the worker process gets (`emulate/host.py`, `emulate/worker.py`, `emulate/harden.py`):
- The base interpreter in isolated mode (`-I`; not a venv launcher, which would need a child process), started
  suspended and assigned to a Job Object before it runs: 1 GiB memory cap, wall-clock cap, kill on close, and
  `ActiveProcessLimit=1`, so the worker cannot start any child process.
- Low integrity: the worker lowers its own token to Low (S-1-16-4096) right after reading its job from stdin and
  BEFORE it reads the target or loads the emulator; if that fails it refuses the job (`EMU_WORKER_FAILED`). At Low
  integrity the default no-write-up policy denies writes to Medium-labelled locations: the user profile, the
  repository, the job store, the temp folder.
- It reads only the SHA-256-verified job copy and re-hashes it.
- Verified for real by `tests/unit/test_emulate.py::test_worker_runs_at_low_integrity_and_cannot_write_or_spawn`
  (also run as a probe job, `host.probe_worker(dir)`): the worker's token is Low; creating a file in the test's temp
  folder and in the repository fails with "Permission denied"; starting a child process fails (Windows error 1816,
  job quota); creating a file in a folder explicitly labelled Low works (control).

Residual risk (not closed; reasons to keep `emulate` off by default and to choose option C where it matters):
- Reads are not restricted: a compromised worker can read whatever the user can read (no-read-up is not the default
  policy) and could leak it through any channel it can open.
- Network access is not restricted (no firewall rule or AppContainer).
- Low-labelled locations (`%LOCALAPPDATA%Low`, `%TEMP%\Low`) and objects stay writable.
- The short bootstrap before the lowering runs at the caller's integrity (harness code only, no target bytes).
- The process still runs as the same user (not a restricted or separate account); kernel attack surface is shared.
- A Job Object and an integrity level are not a security boundary in the sense of a VM or Windows Sandbox.

## 3. Memory model

- The PE image is mapped at its PREFERRED image base, so no relocation is needed and none is applied. Bytes come from
  the same chunk plan as `read_bytes`: the headers and the raw data of every section. The rest of a section's virtual
  size is zero, as the Windows loader zero-fills it (loader behaviour, not invented content).
- Section permissions (read/write/execute from the section flags) are enforced page by page when every section starts
  on a page boundary; a write into `.text`/`.rdata` or a jump into data stops the emulation. If a section is not
  page-aligned the whole image is read/write/execute and the evidence says so (`perms_enforced=false`).
- Imports: every import-address-table slot (imports and delay imports) is overwritten with a unique sentinel address
  in an UNMAPPED range. A call into ANY imported API faults there; the emulation stops and names the API. Fail
  closed: if a declared import, delay-import or TLS table cannot be read completely, or a slot cannot be redirected,
  nothing is emulated (`EMU_LAYOUT`): a slot left with its file value could send a call anywhere.
- An arena of 64 MiB outside the image holds the stack (default 1 MiB, 64 KiB-16 MiB), the argument buffers (each in
  its own page run, ending 0-15 bytes before an unmapped gap so an overrun stops the emulation) and the sentinels: the
  return address, the import sentinels and, on x64, the GS base (TEB). The arena is the first of a fixed candidate list
  that does not overlap the image, so the layout (and every address in the evidence) depends only on the image and the
  request.
- Nothing else exists: no TEB/PEB, no heap, no handles, no CRT/DllMain/TLS initialisation. Globals hold their file
  values.

## 4. Calling conventions and arguments

- x86: `cdecl` (default), `stdcall`, `fastcall` (first two in ECX/EDX), `thiscall` (first in ECX). Stack arguments are
  32-bit words; ESP+4 is 16-byte aligned at entry.
- x64: Microsoft x64 (`ms64`): RCX, RDX, R8, R9, then the stack after the 32-byte shadow space; RSP+8 is 16-byte
  aligned at entry.
- An argument is an integer (`5`, `"0x10"`, negative values in two's complement) or a buffer passed by pointer:
  `{"hex": ".."}`, `{"ascii": ".."}` / `{"utf16": ".."}` (NUL added), `{"buffer": N}` (zero bytes), with an optional
  `size` to enlarge a buffer. Integer register arguments only: no floating-point/XMM arguments and no structures by
  value.
- A result needs a REAL return: the return-address slot at the entry stack pointer must have been read (a `ret` pops
  it) and the stack pointer at the sentinel must be exactly where the convention puts it (x64 entry+8, cdecl entry+4,
  stdcall/fastcall/thiscall entry+4+stack argument bytes). A jump to the sentinel or an unbalanced stack (wrong
  convention or argument count) is `EMU_BAD_RETURN`, no evidence.

## 5. Limits and determinism

- `max_instructions` (default 2,000,000, max 100,000,000) and `timeout_s` (default 10, max 60) bound each emulation;
  the worker process has a wall-clock and memory cap on top. Reaching a limit is `EMU_LIMIT`, never a result.
- Every request is emulated twice in two fresh emulator instances; any difference (e.g. `rdtsc`) is
  `NONDETERMINISTIC` and nothing is recorded. The same request on the same target and emulator version gives the same
  evidence id.

## 6. Outputs

The return registers are always recorded (x64: RAX, also EAX and RDX; x86: EAX, EDX). Memory is read after the return
on request, at most 16 reads of 4 KiB (16 KiB in total): `{"arg": i, "length": N, "offset"?}` (a buffer argument),
`{"va": "0x..", "length": N}` (image or arena memory, e.g. a global table the function decoded in place) and
`{"ret": true, "length": N}` (memory at the pointer in EAX/RAX). Each read is printed in the `read_bytes` dump format
(hex rows plus requested typed views; `ascii` by default). An unreadable range is `EMU_OUTPUT_UNREADABLE`.

## 7. Unsupported events: stop, never stub

The emulation stops with an explicit error and NO evidence on: a call into an imported API (`EMU_UNSUPPORTED_API`, with
`dll!name`), a TEB/PEB access (`EMU_UNSUPPORTED_API`; x64 `gs:`; on x86 an `fs:` read shows up as an unmapped read at
a low address and is labelled as possibly NULL or TEB), unmapped memory (`EMU_UNMAPPED_ACCESS`), a section-permission
violation (`EMU_PROTECTION_FAULT`), an interrupt or `syscall`/`sysenter`/`in`/`out`/`cpuid`
(`EMU_UNSUPPORTED_INSTRUCTION`), an invalid instruction or CPU exception (`EMU_FAULT`), a limit (`EMU_LIMIT`),
nondeterminism, reaching the return address without a real return (`EMU_BAD_RETURN`, section 4) and unreadable
import tables (`EMU_LAYOUT`, section 3). No API is stubbed and no return value is invented: a stub would make the result depend on a guess that
the evidence could not show. The error tells the analyst to record an unknown (`unknown_record`) or emulate a smaller
region that avoids the call.

## 8. Evidence and claims

- Record: `operation=emulate`, `authority=cpu-emulation`, `confidence=derived`,
  `environment={isolation: process, executor: cpu-emulator, native_execution: false}`. `parameters` hold the canonical
  request (function VA, architecture, convention, every argument with its initial bytes, outputs, limits, stack size,
  layout version) and the emulator name and version; `result` holds the stop reason, registers, stack check, argument
  values (buffer addresses), output addresses with SHA-256 digests and the layout facts. Elapsed time is not part of the
  id. The raw text is the human-readable dump; `limitations` state the basis (emulation of the file image, not a run).
- Verifier (version 19): an emulation record must be a deterministic return to the caller with no native execution and
  its request recorded, else `EMULATION_RECORD_INVALID` (REJECTED). A value, 0x literal or constant atom found in its
  output backs only an `observation` + `present` claim; the value is reported with `support: emulation` and the check
  `EMULATION` is added. In a behavior claim it backs nothing (`VALUE_DERIVED_NEEDS_EXECUTION`; behavior still needs
  `run_controlled`), and it can never make anything PROVEN or back an absence claim (its coverage is `unknown`).
- The record does not carry function names: a claim that names the routine also cites the evidence that names it
  (`functions_list`, `decompile`), otherwise the name is an unbacked term.
- The report prints a "Basis: CPU emulation ..." line under every finding that cites emulation evidence.

## 9. Scope effect

New effect `emulates_target_code`, allowed only by the manifest operation `emulate` (off by default; `run_controlled`
and `compute` do not imply it). The tool also launches a process (the worker), so `launches_process` now accepts
`emulate` as well. Kernel-mode images may be emulated (nothing runs natively); their kernel imports stop the
emulation like any other import.

## 10. Packaging

- The emulator is the `unicorn` Python package (version 2.1.4, from PyPI) installed into the harness's own virtual
  environment: `pip install "unicorn==2.1.4"`, or `pip install -e ".[emulate]"`. It is an optional extra: without it
  the tool answers `EMULATOR_MISSING` and nothing runs.
- It is not added to the `compute` sandbox runtime (option A was not chosen).
- Licence scope: Red Harness does not bundle or redistribute Unicorn or Capstone. Unicorn is the optional `emulate`
  extra that the user installs from PyPI (`pip install "unicorn==2.1.4"`, or `pip install -e ".[emulate]"`); without it
  the tool answers `EMULATOR_MISSING`. Capstone is not a dependency of this build (there is no `disasm` extra); it is
  used only by optional tests when it is installed. Upstream, Unicorn's engine is licensed under GPLv2; the `unicorn`
  Python package's own metadata says BSD. Capstone uses its own BSD-style licence. Anyone who redistributes an
  environment that includes these packages must follow their licences. The Apache-2.0 licence of Red Harness covers the
  Red Harness source only; it does not relicense these optional third-party components.
- Unicorn on Windows raises and handles an access violation inside the first memory mapping of every emulator
  instance; Python's `faulthandler` (on in pytest) prints it as "Windows fatal exception" although nothing failed. The
  worker does not enable `faulthandler`; the unit tests switch it off for their module. The reason inside Unicorn was
  not investigated (UNVERIFIED).

## 11. Proof

- Unit tests (`tests/unit/test_emulate.py`, synthetic PEs with hand-assembled code): request validation, layout and
  permissions, import redirection, all four x86 conventions and ms64 (including the fifth, stack-passed argument),
  buffer and in-image outputs, every stop kind, nondeterminism (`rdtsc`), the worker process, the MCP tool, evidence
  determinism and the verifier rules.
- Real binary (`tests/heavy/test_emulate_real.py`, host only, no sandbox): `RtlComputeCrc32` of the host's x64 and x86
  (WOW64) `ntdll.dll` gives the same CRC-32 as Python's `zlib.crc32` for three inputs on both architectures (x86 as
  stdcall, stack balanced), and `_itoa` fills its output buffer with exactly Python's formatting of three values; an
  observation claim over the emulated CRC is SUPPORTED, the same claim naming the export is not (name not in evidence).
- Version 2: `tests/unit/test_emulate_v2.py` (request canonicalisation and v1 id stability, every new validation and
  image check, image pointers, scratch buffers with pointer pre-writes, register inputs/outputs, digest and
  register-pointer outputs, image-data pre-writes, code ranges incl. "left the range" and an import stop inside a
  range, verifier v20 stop/request matching, the stdio MCP path).

## 12. Not done / open

- No API stubs, no floating-point or structure-by-value arguments, no exception (SEH) dispatch, no TLS, no ARM/ARM64
  images. Code bytes can never be pre-written (section 13.2).
- x86 `fs:` segment base is not modeled (Unicorn 2.1.4 ignores a 32-bit FS base write).

## 13. Version 2: inputs in memory, image pointers, more outputs, code ranges

Goal: make realistic routines emulable. Version 1 covers a self-contained function whose inputs are integers and
fresh buffers. Real decode routines also take pointers to tables in `.rdata`, structures that point at other buffers,
and they often sit inside a function that first calls an API (`VirtualAlloc`, then the decode loop). Version 2 adds
what is needed for that and keeps every version 1 rule (no stubs, strict stops, two deterministic runs).

### 13.1 Scored options

Scores 1-5 (higher is better): expressiveness / evidence reproducibility / fail-closed safety / cost (code, tool
surface, verifier change).

| Need | Option | Expr. | Repro. | Safety | Cost | Total |
|---|---|---|---|---|---|---|
| inputs in memory | a. argument buffers only (version 1) | 2 | 5 | 5 | 5 | 17 |
| | **b. scratch buffers + typed pre-writes (image data, stack, buffers; bytes or pointers) (CHOSEN)** | 5 | 5 | 4 | 3 | **17** |
| | c. analyst Python that prepares the emulator | 5 | 2 | 1 | 2 | 10 |
| image pointers | a. plain integers (version 1) | 3 | 5 | 2 | 5 | 15 |
| | **b. `{"va": .., "length"?}` checked to lie inside the image (CHOSEN)** | 4 | 5 | 4 | 4 | **17** |
| outputs | **a. register outputs, register-pointer reads, digest-only reads of large regions (CHOSEN)** | 5 | 5 | 5 | 4 | **19** |
| | b. dump whole buffers into the evidence | 4 | 5 | 5 | 1 | 15 |
| code range | a. none (version 1) | 1 | 5 | 5 | 5 | 16 |
| | **b. `end` address: success = execution reaches `end`; same stops (CHOSEN)** | 5 | 5 | 4 | 3 | **17** |
| | c. stop after N instructions | 3 | 4 | 2 | 4 | 13 |

Inputs: b ties a on the sum, but a cannot express a table pointer inside a structure or a stack local of a code
range, which realistic routines need; c is rejected (analyst code would make the request
non-canonical and could stub APIs by hand). Range c is rejected: an instruction count is not a semantic boundary;
the result would depend on where the count happened to stop.

### 13.2 Request additions

All optional. A request that uses none of them is canonically identical to version 1, so its evidence id does not
change.

- Value references (an argument, a register value or a pointer pre-write): an integer; `{"va": "0x..", "length"?: N}`
  (a pointer into the target image; the address, and `length` bytes from it if given, must lie inside the image, else
  `BAD_ARGUMENT`); `{"arg": i, "offset"?: k}` (address of buffer argument i); `{"buf": j, "offset"?: k}` (address of
  scratch buffer j). Canonical kinds: `int`, `image_ptr`, `arg_ptr`, `buf_ptr`.
- `buffers`: scratch buffers, mapped like argument buffers but not passed; same forms as a buffer argument
  (`{"hex"}`, `{"ascii"}`, `{"utf16"}`, `{"buffer": N}`, optional `size`). They follow the argument buffers in the
  arena, each with its own unmapped guard gap.
- `memory`: pre-writes applied after the image, the buffers and the call frame are in place, before the first
  instruction. Target: exactly one of `"va"` (image memory), `"sp"` (offset from the entry stack pointer, for the
  locals of a code range), `"arg": i` or `"buf": j` (with optional `"offset"`). Data: exactly one of `hex`, `ascii`,
  `utf16` (no NUL added: a pre-write writes exactly the given bytes) or `ptr` (a value reference, written as a
  pointer-sized little-endian word). Rules: an image pre-write must lie inside the image and must not touch the
  headers or an executable section (the emulated code is always the target's own code); a buffer pre-write must fit in
  its buffer; a stack pre-write must lie inside the mapped stack. At most 64 pre-writes, 64 KiB in total. Pre-writes
  are part of the request (bytes as hex, pointers as references) and printed in the raw text, so the evidence shows
  that the analyst, not the target, put those bytes there.
- `registers`: initial values of general-purpose registers (x64 `rax rbx rcx rdx rsi rdi rbp r8`-`r15`, x86 `eax ebx
  ecx edx esi edi ebp`) as value references. The stack pointer is not settable (the frame fixes it; use `sp`
  pre-writes). A register that the calling convention already loads from `args` cannot be set twice.
- `output_registers`: extra registers recorded after the stop (the names above plus `rsp`/`esp`, or `"all"`). The
  return registers (x64 RAX/RDX, x86 EAX/EDX) are always recorded.
- Outputs: `{"buf": j, "offset"?, "length"}` (scratch buffer), `{"reg": name, "offset"?, "length"}` (memory at the
  pointer in a register after the stop; `ret` stays as the short form for RAX/EAX), and `"digest": true` on any
  output: only the length and SHA-256 of the region are recorded (no bytes), which allows up to 1 MiB per read (4 MiB
  in total), e.g. to compare a whole decoded stage with a known digest.

### 13.3 Code ranges (`end`)

- `function` is the start address and `end` the address at which the emulation stops successfully: the stop is
  `range_end` when the program counter reaches `end` (the instruction at `end` is not executed). The frame is built
  as for a call (convention, arguments, return sentinel), but the entry stack pointer is placed 8 KiB below the top of
  the stack so the locals and home slots of the enclosing function (positive offsets from the stack pointer) are
  mapped; `sp` pre-writes put values there.
- Every version 1 stop applies inside the range: internal calls run, an imported API stops the emulation. Returning
  to the sentinel before `end` is `EMU_BAD_RETURN` ("left the range"): a range result is only the state at `end`.
- No stack-balance check in range mode (no return happens); `stack_balanced` is absent from the result.
- `end` must be inside the image and differ from the start.

### 13.4 Evidence and verifier (version 20)

- The record keeps `operation=emulate`, `authority=cpu-emulation`, `confidence=derived`. A range result has
  `result.stop = "range_end"` and `parameters.end`; a function result keeps `stop = "return"`.
- Verifier version 20 (`evidence/emulation.py`): a record is valid if it is a deterministic `return` WITHOUT `end`, or
  a deterministic `range_end` WITH `end` in its parameters. Why the bump: version 19 rejected every stop other than
  `return`, so a range record would be `EMULATION_RECORD_INVALID`; the version marks that the accepted record set
  grew. What a valid record may back is unchanged (observation + present only, SUPPORTED at most, never behavior,
  absence or PROVEN). Claims that cite no range record verify exactly as in 19.
- A digest output prints `sha256=<64 hex>` on its own line; the digest is target-derived output like any other.
