# MCP server usage note

`rh mcp` is an MCP server speaking over stdio (official `mcp` Python SDK, pinned to version `1.30.0`).
It performs static analysis only on binaries **you own or are authorized to test**; if the manifest allows, it runs the target
in a controlled way in Windows Sandbox and observes the result (`run_controlled`).

## Setup
Requirements (Windows 10/11, Python 3.12, an engine, Windows Sandbox for the two tools that execute the target natively or
run model code), a copy-paste quickstart and client configuration are in `README.md`; this note has the details.
```
py -3.12 -m venv .venv
.venv\Scripts\pip install -e .[dev]
```
Data root: `RH_DATA_ROOT` (default `%USERPROFILE%\RedHarnessData`).
Sandbox window: `RH_SANDBOX_WINDOW=minimized` (default) | `normal`. In `minimized` mode WindowsSandbox.exe is started with
`SW_SHOWMINNOACTIVE` and, for up to 60 s after launch, a small background watcher (ctypes, polling every 200 ms)
minimizes each new window of our sandbox processes once without activating it and, if a sandbox window took the
foreground, hands it back to the previous window (best effort, failures ignored, debug log only). This is a best-effort
reduction, not a guarantee: Windows 10 (no `wsb` CLI) may still flash the window briefly, and the foreground restore can
be refused by the OS. Use `normal` to get the plain launch.

## Engines
Every MCP tool needs an analysis engine, because `target_open` opens the target through it; none of the 18 tools works
without one. Pick it with `rh mcp --engine ghidra` or `rh mcp --engine ida`; without the flag the server starts the IDA
engine. A requested engine that cannot be used (unknown name, Ghidra or JDK not found, `idapro` missing) makes `rh mcp` exit
with a non-zero code; the reason goes to stderr and, when the client has sent `initialize`, into the JSON-RPC error answer to
it (so the client shows the reason instead of "connection closed"). There is no silent fallback to the other engine.
Without the flag nothing is probed at startup: an unusable IDA shows up as `TOOL_MISSING` in `target_open`.

**Ghidra (free).** Ghidra 12.1.3 (the tested version; other 12.x releases are not tested) and a JDK 21 with `java` on
`PATH` or `JAVA_HOME` set. The install folder is the first of: `RH_GHIDRA_DIR`, `GHIDRA_INSTALL_DIR`, then (newest name first)
`ghidra_*` on the user's Desktop, `ghidra*` in the user folder, `ghidra*` in `%ProgramFiles%`, `C:\ghidra*`. A folder counts
only if it holds `support\analyzeHeadless.bat` and `Ghidra\application.properties`. At startup the server runs Ghidra's own
`LaunchSupport -jdk_home` to prove that a suitable JDK exists. Each operation runs `analyzeHeadless` in its own bounded
process (JVM heap 4 GB, job limit 6 GB); Ghidra's user settings are kept under `<data root>\ghidra_user`, not in your profile.
The first open of a target imports and analyses it once (minutes for a large binary); the project is cached under
`<data root>\cache\ghidra\<version>\<sha256>` and later queries open it read-only without re-analysis.

**IDA Pro.** IDA 9.x with a licence that includes `idalib`. The `idapro` Python package is deliberately not a dependency or
extra (its publisher on PyPI is unverified: supply-chain risk). Install it from the wheel in your IDA installation, into the
same virtual environment as `redharness`, using the exact file name found in that folder (pip rejects a `*` wildcard; do not
run `py-activate-idalib.py`):
```
.venv\Scripts\pip install "<IDA>\idalib\python\idapro-0.0.9-py3-none-any.whl"
```
`<IDA>` e.g. `C:\Program Files\IDA Professional 9.4`. The IDA folder (the one holding `idalib.dll`) is found from `RH_IDA_DIR`,
then `IDADIR`, then `%ProgramFiles%\IDA Professional*` (a stable release is always preferred over a beta; set
`RH_IDA_DIR` to pin a version). IDA cannot open a database whose path is 260+ characters, so keep `RH_DATA_ROOT` short
(`target_open` fails with `PATH_TOO_LONG` otherwise). The engine runs IDA in a separate Python process
(`sys.executable` of the server, or `RH_IDA_PYTHON`), so that Python must have `idapro`. If the folder is not found or
`idapro` is not installed the engine returns `TOOL_MISSING` and `target_open` fails with a message that names the missing
piece, how to install it, and `--engine ghidra` as the free alternative.

**Without any engine** only the standalone script `scripts/file_strings.py` runs, plus `rh compute-runtime`.

| Variable | Meaning |
|---|---|
| `RH_DATA_ROOT` | job store, cache, logs (default `%USERPROFILE%\RedHarnessData`) |
| `RH_GHIDRA_DIR`, `GHIDRA_INSTALL_DIR` | Ghidra install folder |
| `RH_IDA_DIR`, `IDADIR` | IDA install folder |
| `RH_IDA_PYTHON` | Python that has `idapro` (default: the server's own) |
| `RH_SANDBOX_MEMORY_MB` | Windows Sandbox memory, 512 to 16384 (default 2048) |
| `RH_SANDBOX_WINDOW` | `minimized` (default) or `normal` |

## Dynamic observation (Pro)
Dynamic observation (`run_controlled(observe=...)`: API trace and executable-memory digests) is available in the Pro
edition only. In the Core build, a `run_controlled` call that passes `observe` returns the error code `DYNAMIC_BACKEND_UNAVAILABLE`;
plain `run_controlled` is unaffected. The same holds for `captured_region`, which shows the bytes such an observation captured.

## Fix verification (the harness does not edit binaries)
The vendor rebuilds the product from source with a fix; the harness verifies, with the same evidence rules, that a finding
reproduces on the original build and not on the fixed build. Still 18 tools (cap 20): the second build is a parameter, not a tool.
1. Manifest: add `"fixed_target_sha256": "<sha256 of the fixed build>"` (must differ from `target_sha256`).
2. `target_open(target_path=<original>, manifest_path, fixed_target_path=<fixed build>)`; the reply has `fixed_build` (hash, `bound`).
   Without `fixed_target_path` the fixed build is declared but not runnable (`FIXED_BUILD_NOT_OPEN`).
3. Run the SAME case on both builds: `run_controlled(cases, target="original")` and `run_controlled(cases, target="fixed")`
   (the reply shows `build` and `target_sha256`; plain runs only, `observe` is original-only).
4. `claim_add(kind="fix_verification", requested="PROVEN", evidence_ids=[ev_original, ev_fixed], atoms=[{"type":"fix_pair",
   "original":{"evidence_id":ev_original,"quote":"License valid"}, "fixed":{"evidence_id":ev_fixed,"quote":"License invalid"}}],
   values=[{"value":"<input>","derived":true}])`. PROVEN needs both runs of the same input, both hash-bound; rules and codes in
   `docs/design/evidence-schema.md` section 4.11.
5. Static diff of the two builds: `functions_list(compare="fixed")` (a parameter of the existing tool; `offset`, `limit` and `detail` page it).
   One row per function, ordered changed, added, removed, then matched. Every pair row carries both builds' address, size,
   instruction count and the first 16 hex digits of two hashes: `bytes_sha256` (the instruction bytes as in the file) and
   `norm_sha256` (the instruction stream with registers, immediates and stack/frame offsets kept and the addresses of calls,
   jumps outside the function, data references and table bases normalized away). `changed` rows list the differing
   instructions (`hunk` lines, at most 5) with the counts of instructions added and removed. `matched` means the same
   normalized instruction stream and nothing more: a function that only moved has another `bytes_sha256` and the same
   `norm_sha256` (`moved=yes`), and a changed callee or constant behind a nameless address is not seen. Functions are paired
   by a stable unique name, then by equal `norm_sha256`, then by mnemonic similarity inside the gaps between already-paired
   functions (`pairing=` and `ratio=` say which, so a claim can state how a pair was found); the rest is `added` (fixed build
   only) or `removed` (original only). Only the engine's function boundaries and decoded instructions are used, so the diff is
   the same logic on Ghidra and IDA (the names, and so some pairings, differ between engines). The evidence has the original
   build as subject and the fixed build's SHA-256 in its parameters and in the first row, so a claim ("the function at
   `0x...` differs between the builds") quotes a row and is an ordinary observation. Instructions of the fixed build can be
   cited only through these rows. The first call analyses the fixed build in the engine (about as long as `target_open` took)
   and disassembles every function of both builds; later pages reuse it. Builds above 20000 functions or 2000000
   instructions are refused (`BUILD_TOO_LARGE`), never compared partially.
Demo (a sample license checker built twice from the same source, once with a fix): an input the original accepts (`<input-A>`)
is rejected by the fixed build, while another valid input (`<input-B>`) stays valid.

## Connecting an MCP client
Use absolute paths and put the engine settings in the server's environment. The full copy-paste quickstart is in `README.md`;
`.mcp.json.example` in the project root is the Claude Code entry with placeholder paths.

Claude Code: copy `.mcp.json.example` to `.mcp.json` in your project folder, replace the placeholders, start Claude Code there
and approve the `red-harness` server with `/mcp`.
```json
{
  "mcpServers": {
    "red-harness": {
      "type": "stdio",
      "command": "C:\\path\\to\\red-harness\\.venv\\Scripts\\rh.exe",
      "args": ["mcp", "--engine", "ghidra"],
      "env": {"RH_GHIDRA_DIR": "C:\\path\\to\\ghidra_12.1.3_PUBLIC", "RH_DATA_ROOT": "C:\\path\\to\\RedHarnessData"}
    }
  }
}
```
OpenAI Codex CLI (`~/.codex/config.toml`):
```toml
[mcp_servers.red-harness]
command = 'C:\path\to\red-harness\.venv\Scripts\rh.exe'
args = ["mcp", "--engine", "ghidra"]
env = { RH_GHIDRA_DIR = 'C:\path\to\ghidra_12.1.3_PUBLIC', RH_DATA_ROOT = 'C:\path\to\RedHarnessData' }
```
Any other stdio MCP client: command `C:\path\to\red-harness\.venv\Scripts\rh.exe`, arguments `mcp --engine ghidra`, the same
environment. The transport is newline-delimited JSON-RPC on stdin/stdout, so nothing else writes to stdout.
`scripts/quickstart_client.py` is a complete example client on the official `mcp` SDK. The server was verified with that
client; the client entries above follow those clients' documented formats and were not run in this project.
If a client only reports "connection closed", run the same command in a terminal: the reason is printed on stderr.

## Scope manifest (required)
`target_open` opens only with this JSON; it rejects if it is missing, malformed, expired, lacks the `static` permission, or the SHA-256 does not
match the target. For `run_controlled`, `allowed_operations` must also contain `"run_controlled"` (otherwise
`SCOPE_DENIED`, the sandbox is not touched); for `compute` it must contain `"compute"` (off by default; `run_controlled`
does not imply it and it does not allow running the target); for `emulate` it must contain `"emulate"` (off by default;
neither `run_controlled` nor `compute` implies it); the Pro-only `dynamic_observe` and `dynamic_memory` permissions are not used in the Core build:
```json
{
  "schema": "rh.scope/1",
  "target_sha256": "<sha256 of the target, lowercase>",
  "authorization": {"declared_by": "Your Name / Your Company", "basis": "owner",
                    "statement": "This binary belongs to us; static analysis is authorized."},
  "allowed_operations": ["static", "run_controlled"],
  "expires": "2026-12-31"
}
```
`basis`: `owner` | `authorized-test`. `expires` is optional.

## Tools (18; the cap is enforced by test: `MAX_TOOLS=20`)
| Tool | What it does |
|---|---|
| `target_open(target_path, manifest_path, fixed_target_path?, detail?)` | validates the manifest, opens/analyzes the target; if the same target is reopened, earlier evidence and claims return from the log (`resumed: true`); for a kernel-mode image it also returns the static driver facts (see "Kernel-mode targets"); always returns `target.protection`, the protection diagnosis (see "Protection diagnosis") with its `checks` candidate list (see "Check inventory"), `tools` (which tools are usable and why not) and a `next` hint (see "Availability report"); `detail='summary'` (default) or `'full'` |
| `functions_list(offset, limit, detail, compare?, engines?)` | paged function list (limit <= 200, response size bounded, `next_offset`). `compare="fixed"` (needs the fixed build given to `target_open`) returns instead a static function-level diff of the original build against the fixed build, see "Fix verification" step 5. `engines="both"` (IDA and Ghidra) returns instead where the two engines disagree about the function boundaries, see "Engine disagreement" |
| `decompile(function, offset, max_chars, detail)` | Hex-Rays output by address (`0x140001250`) or name; long output is paged with `offset`; ends with `// section .text R-X: ...` notes (the PE section + R/W/X of the function and of auto-named references such as `byte_140002040`) |
| `disassemble(address, end, count, detail)` | up to `count` (<= 500) instructions from a hex address, or the range `[address, end)`; line = address, bytes, text; response size bounded, `next_address` to continue; `PARTIAL` if it hits non-code bytes (use `read_bytes` for data bytes); ends with `; section ...` notes (the PE section + R/W/X of the instructions shown and of auto-named references such as `unk_140002040`) |
| `dataflow_slice(address, operand, location, size, max_steps, detail, offset, max_chars)` | where the values read by one x86/x64 instruction come from inside its function (docs/design/dataflow-slice.md): the reaching writes as `address | engine text | writes ...`, frame buffers rebuilt byte by byte (`run ... hex=/ascii=` only for bytes equal on every path of the CFG built from the engine's instructions), constants folded through moves, image loads with section, explicit `unknown:` lines; `coverage: partial` and status `PARTIAL` on a truncated function, indirect jump, unknown instruction or step cut; default `detail=summary`; static, same effects as `disassemble` |
| `xrefs(address, direction, limit)` | `to` / `from` cross-references. One line per xref: `<from> -> <to> <kind> code/data in <from_function> target=<name>` and, for a string literal, ` str="<value, max 120 chars>" enc=<label>`. `target` is the module-qualified import (`KERNEL32.dll!CreateFileW`) for an IAT slot, else the engine's symbol at `to`, so a claim "f calls kernel32.dll!CreateFileW" can quote it |
| `strings(pattern, offset, limit, detail)` | paged string list, optional regex; line = address, raw engine kind, `enc=<ascii\|utf-16le (UTF-16)\|utf-32le (UTF-32)\|utf-8\|8bit>`, value |
| `read_bytes(address \| rva \| section+offset, length, view, detail)` | raw bytes from the target PE file (static, does not call the engine; details below): hex dump + typed views; the part not in the file (.bss) is marked "runtime-only", NEVER given as zeros |
| `file_strings(pattern, min_length, encodings, max_hits, detail)` | bounded raw ASCII/UTF-16LE string scan of the target PE file (static, engine-free; includes overlay and non-mapped gaps): file offset, RVA, section, encoding, length, value (values over 4096 chars clipped and marked). `pattern`: case-insensitive regex, max 256 chars; nested quantifiers, back-references and more than 2 unbounded quantifiers are refused (`BAD_ARGUMENT`). Stops at `max_hits` (default 1000, max 10000), 200000 strings examined or a 10 s budget: then `PARTIAL`, `truncated`, `found` is a lower bound and a missing string is NOT proof of absence. `summary` returns counts, truncation info, the `ev_` id and a few sample lines; `full` is cut at the usual reply size |
| `imports(dll, offset, limit, detail)` | the target's import and delay-load import tables from the PE file (static, engine-free). One module-qualified line per symbol: `<IAT slot VA> <dll>!<name>` (e.g. `0x140002050 kernel32.dll!CreateFileW`), ordinal imports `<dll>!#<ordinal>`; `!` and `\` inside either field are escaped as `\x21` and `\x5c` (control characters as `\r`, `\n`, `\t`), so each line has exactly one literal `!` separator; delay-load imports end with ` [delay]`; ordered by slot address. `dll`: optional case-insensitive module filter; paged (`limit` <= 1000, size-capped, `next_offset`). A damaged table gives `PARTIAL` with the reason in the limitations. The address is the import slot, not the bound function address. `summary` returns counts and a preview |
| `run_controlled(cases, timeout_s, observe, detail)` | runs the target in Windows Sandbox (network off) case by case with `cases=[{"stdin":"..","argv":[..]}]`; each case is written to the log as `controlled-replay` evidence and returns with its own `ev_` id. The `observe` parameter is a Pro feature: in the Core build it returns `DYNAMIC_BACKEND_UNAVAILABLE`; see "Dynamic observation (Pro)" |
| `compute(code, inputs, timeout_s)` | runs the model's own Python 3.12 code (stdlib) in Windows Sandbox with a pinned embeddable CPython, twice; inputs only from this job's evidence; a deterministic, complete result is recorded as `sandboxed-computation` evidence (details below) |
| `emulate(function, args?, convention?, outputs?, max_instructions?, timeout_s?, stack_size?, detail?, buffers?, memory?, registers?, output_registers?, end?)` | executes ONE function (or the code range `[function, end)`) of the target in a CPU emulator (Unicorn, bounded worker process on the host; nothing runs natively) with the analyst's arguments, buffers, memory pre-writes and initial registers, twice; a deterministic return (or arrival at `end`) is recorded as `cpu-emulation` evidence with the return/final registers and the requested memory reads or SHA-256 digests; any imported API call, OS access or limit stops it with an error and no evidence (details below) |
| `captured_region(evidence_id?, event?, sha256?, size?, address?, offset?, length?, view?, ...)` | Pro feature: read-only hex / strings / disassembly views over the bytes a stored dynamic observation captured from an executable region; in the Core build it returns `DYNAMIC_BACKEND_UNAVAILABLE` (see "Dynamic observation (Pro)") |
| `claim_add(text, evidence_ids, atoms, kind, polarity, requested, values, supersedes, interpretation, behavior_class)` | passes the claim through the verifier; the verifier assigns the status. `kind`: `observation` (what is in code/data) or `behavior` (what happens when the program runs); a behavior claim is supported only by `run_controlled` evidence (see below). Every technical term of `text` (identifier, acronym, digit-bearing name, algorithm/format word) must be in a cited evidence, else UNVERIFIED `TERM_NOT_IN_EVIDENCE` (`terms_unsupported` in the reply); the model's own reading goes into `interpretation`, printed as unverified (docs/design/evidence-schema.md §4.12). A behavior claim declares `behavior_class` (`"acceptance_validation"` or `"ordinary"`; missing: UNVERIFIED `BEHAVIOR_CLASS_MISSING`); a validation claim (input accepted/rejected, key valid, password correct) also needs a `control_pair` atom bound to the input it names, else UNVERIFIED `CONTROL_PAIR_MISSING` (§4.17) |
| `unknown_record(question, reason, address, evidence_ids, severity, resolves, status)` | writes an unanswerable question to the unknowns ledger (instead of guessing); same question+address is one record. With `resolves=<unknown_id>` it instead CLOSES an earlier unknown: `status='resolved'` (default) cites the `evidence_ids` that answer it, `status='withdrawn'` gives a `reason`; the record is never deleted (see "Unknowns and coverage") |
| `coverage()` | coverage derived from the ledger and call log: tools run, functions/regions examined, truncated/timed-out/failed calls, open unknowns; also `tools`, the availability report |
| `report_build(format)` | re-verifies all claims and writes the report twice, from the same data: a Markdown file and a machine-readable JSON file (schema `rh.report/1`, `docs/schema/rh.report.1.schema.json`); includes the "Coverage and unknowns" section. `format` (`markdown` default, `json`, `both`) only chooses what the reply carries inline; both files are always written (`report_path`, `report_json_path`) |

Every output of the engine tools is an evidence record with an `ev_...` id and arrives with `untrusted_content: true` in an
`<untrusted_target_content>` block: instructions in text coming from the target are not followed. The same (tool, arguments,
target, engine version) does not run the engine a second time (`step_cached: true`; also in a new session).

### Kernel-mode targets
- `target_open` marks the job `kernel_mode` (`target.kernel_mode`, `target.kernel_reasons`) when the PE subsystem is NATIVE, the
  DllCharacteristics carry the WDM driver flag (0x2000) or the file name ends in `.sys`. Any one reason is enough.
- For such a job `run_controlled` (plain or with `observe`) is refused with `KERNEL_TARGET_NO_USERMODE_RUN`, and `compute` is refused when
  an input is bytes of a dynamic observation. This holds whatever the scope manifest allows (the check runs before the manifest check,
  and again inside the sandbox runner); a VM path is Phase 2. Static tools and `compute` on static evidence keep working.
- `target.driver` is a premium feature (Pro): in the Core build it is `{"available": false, "note": "premium feature not included in this build"}`.

### Protection diagnosis (`target.protection`)
`target_open` tells the analyst up front whether the binary shows known packer/protector indicators, so static results are read
with the right caveats. It is static (section names, byte signatures, entropy, entry point placement, vendor string/section markers);
nothing is unpacked or run, and it works without the engine's help. One `protection_scan` evidence (`derived`, engine `pe-static`) is
recorded per target and reused on reopen (`step_cached: true`).
- `diagnosis`: `INDICATORS_FOUND`, `NO_KNOWN_INDICATORS` or `UNKNOWN` (not a readable PE, file over 32 MiB, the scan failed, or the vendor/string
  check failed while the other checks found no strong or moderate indicator; `reason` says why and which check did not run, and
  `target_open` still succeeds). There is no "clean"/"not protected" value: `NO_KNOWN_INDICATORS` means only
  that the known markers were not found.
- `static_coverage` and `statement`: `likely_partial` (a strong indicator: decompile/disassemble may show only an unpacking stub; treat
  missing functions/strings/imports as unknown, not absent), `possibly_partial` (moderate indicators only), `no_known_indicators`
  (custom protectors, virtualization and obfuscation are still not detected) or `unassessed` (diagnosis UNKNOWN).
- `indicators` (strongest first; `indicator_count` is the total, `indicators_truncated` when the reply cut the list: 10 in summary,
  40 in full): `id` (P1...), `name` (`name:upx0` section name, `sig:UPX!` byte signature, `anomaly:entry_point_outside_code` /
  `wx_section` / `high_entropy_section` / `overlay_present`, `vendor:<id>`), `strength` (`strong`, `moderate`, `weak`), `section`,
  `rva` and `file_offset` (hex strings, only when known), `evidence_id` and `quote`. `quote` is the start of that indicator's line in
  the evidence (`indicator P2 name:upx0 ...`): cite it in `claim_add`. Weak signals alone (an overlay, one ordinary word such as
  "PECompact") keep the diagnosis at `NO_KNOWN_INDICATORS` and are listed as weak.
- `vendors` (up to 5): heuristic attribution from `analysis.vendors` with `id`, `name`, `kind` (protector / anti-cheat / drm), `score`,
  `confidence` (`moderate`/`strong`) and `evidence_id`. It is a hypothesis: a marker can sit in another product's detection list.
- `detail='full'` adds `sections` (name, rva, vsize, file_offset, raw_size, entropy as a string, R/W/X flags), `entry_point`, `notes`
  (for example "vendor attribution unavailable", status `PARTIAL`) and `why` per indicator.
- `pe_profile` (inside `target.protection`, same `evidence_id`): static PE profile, every field computed from the file bytes, as quotable `pe_profile ...` lines (40 in summary, all in full; `lines_truncated` says how many were cut). Per section: escaped name, RVA, virtual size, raw size, R/W/X, CODE/INITDATA/... flags, Shannon entropy (2 decimals, `not-measured` without raw bytes) and notes such as `writable+executable`, `virtual size >> raw size`, `high entropy`. Also: entry point RVA, containing section (or `outside any section`) and whether it is executable; overlay offset/size and, if the security directory is set, its offset/size and whether it lies in the overlay (location only, the signature is NOT validated); TLS presence, callback array RVA and up to 8 callback VAs (`unreadable` with a reason otherwise); import/export counts and a neutral `minimal_table` observation; PE32/PE32+, machine, subsystem, timestamp (header value), linker version, ASLR/DEP/CFG/high-entropy-VA header flags and debug directory types with the CodeView PDB file name only. A field that cannot be read is printed `unavailable(<reason>)`. The profile never names a packer; it shares the entry point, overlay and W+X rules with the diagnosis, and a disagreement would be listed in `notes` as `INCONSISTENT`.
- Kernel-mode images get the same block next to `target.driver`.
- The open-time scan counts in the `resume` step/evidence counts, but not as a code examination: `coverage()` keeps `NOT_EXAMINED` on a fresh job and reports the diagnosis in its `protection` field.

### Check inventory (`target.protection.checks`)
`target_open` also lists the CANDIDATES of protection and licensing checks the file shows, so the analyst knows where to read first. It is
static (imports, strings and instruction byte patterns), needs no engine and runs nothing; it adds no tool. One `check_inventory` evidence
(`derived`, engine `pe-static`) is recorded per target and protection coverage, and reused on reopen (`step_cached: true`).
- Closed taxonomy, one primary code per candidate: `C1` licence/key validation, `C2` anti-debug, `C3` anti-VM/sandbox, `C4` self-integrity/hash,
  `C5` machine/hardware id, `C6` signature/crypto verification, `C7` time/trial, `C8` network activation. The signal table is data
  (`analysis/check_taxonomy.py`): per signal a code, a kind (`import`, `string`, `pattern`), a strength (`strong`, `moderate`, `weak`), a reason and a
  false-positive note. Import and string signals of the anti-analysis catalogue are reused, not copied.
- `state`: `CANDIDATES_FOUND`, `NO_KNOWN_CANDIDATES` or `UNKNOWN`. There is no "no checks" value. `UNKNOWN` is reported when nothing was found and
  something was not readable or not assessed: unreadable or cut-short import tables, no named imports, a file that is not a parseable PE, no code
  section to scan, a file over 32 MiB, or a packed image (the protection diagnosis says `likely_partial` / `possibly_partial`: the visible
  imports and strings may belong to a stub). A capped scan is a coverage gap too: when one string needle has more than 64 matches, the later
  ones are not examined, so an empty result is `UNKNOWN` (the cap is the reason) and a result with candidates says its coverage is partial.
  `NO_KNOWN_CANDIDATES` means only that the known signals were not found; custom checks, obfuscated or
  stack-built strings, run-time resolved APIs and packed or virtualized code are not detected. Candidates found next to a gap are listed together with the
  gap (`unknowns`, `statement`).
- `candidates` (strongest first; `candidate_count` is the total, `candidates_truncated` when the reply cut the list: 10 in summary, 40 in full;
  `by_code` counts per category): `id` (K1...), `code`, `category`, `signal`, `kind`, `strength`, and by kind the `dll` / `function` / `iat_rva`
  (import; `calls` lists the call sites found), the `string` (inside an `untrusted_target_content` block; `refs` lists the code that points at it) or
  `in_function` (instruction pattern), `rva` / `file_offset` (hex strings, only when known), `evidence_id` and `quote`. `quote` is the start of the
  candidate's line in the evidence (`check K3 C2 signal=debugger-present`): cite it in `claim_add`. `detail='full'` adds `why`, `false_positives`,
  `apis`, `also` (other categories the same string matches), `with` (hash partner), `bytes`, `coverage`, `suppressed` and `notes`.
- Where the code is: for every listed string and import the scan looks for code that points at it (x64 RIP-relative `lea` / `mov` / `call` / `jmp`,
  x86 absolute operands) and, on x64, names the enclosing function from the `.pdata` table (`refs=0x1107@fn0x1070`). This is a byte-pattern match:
  confirm it with `xrefs` / `disassemble`. Without a function table (x86) the function is not named.
- Known false positives are handled by a stated rule and are never hidden. `suppressed` (evidence lines `suppressed rule=...`, `detail='full'`)
  lists what was not reported as a candidate: `crt-startup-cluster` (at least 5 of 10 imports that the statically linked C runtime startup pulls in
  together are present, so IsDebuggerPresent, GetSystemTimeAsFileTime, GetModuleHandle* and GetModuleFileName* are the runtime's own use until `xrefs`
  shows other code calling them; a real use of one of them in such a binary is therefore found only through the string / pattern signals),
  `needs-hash-partner` (module-path, memory-map and self-memory reads count as C4 only next to a hash or checksum signal) and `benign-url-host`
  (namespace, schema and certificate URLs). Every reported candidate carries its false-positive note. Process enumeration, `OpenProcess`, timing
  reads (`GetTickCount`, `QueryPerformanceCounter`, one `rdtsc`) and the exception filters are not checks.
- Evidence and claims: a candidate is an OBSERVATION. A claim such as "KERNEL32.dll imports IsDebuggerPresent (candidate C2)" with the `quote` atom is
  verified like any static evidence (SUPPORTED at most; every technical term of the text, for example the function name, the DLL name and `C2`, must occur
  in the cited evidence). "The program validates the key" is a behavior claim and needs `run_controlled`. The evidence never has complete coverage, so
  an absence claim ("there is no anti-debug check") cannot be supported by it (`ABSENCE_WITHOUT_COMPLETE_COVERAGE`).
- `coverage()` keeps `NOT_EXAMINED` on a fresh job (the open-time scans are not an examination of the code) and reports `checks` (`evidence_id`,
  `state`, `candidate_count`) next to `protection`. The step counts in the `resume` evidence counts.

### Engine disagreement (`functions_list(engines="both")`)
With IDA and Ghidra both installed, `functions_list(engines="both")` lists the function boundaries of the open target from both
engines and reports where they disagree, so one engine's boundaries are never trusted silently. It is an option of the existing
tool (no new tool); `offset`, `limit` and `detail` page the rows. The job engine is the one `rh mcp --engine` picked; the other
is started on demand under the install rules above, and its first call analyses the target (minutes for a large binary).
- Evidence: one inventory evidence per engine (`engines=both, engine=<name>`: a line per function,
  `0x140001000 name end=0x140001040 insns=12 chunks=1`; the end is taken from that engine's whole-function disassembly because
  the engines' own `size` fields measure different things) and one comparison evidence whose rows each name BOTH inventory ids
  (`ghidra_ev=ev_... ida_ev=ev_...`). A claim quotes a row and cites the three ids like any other output.
- Categories (closed; one row per disagreeing function): `END_DIFFERS` (same start, different end; `end_delta` is the second
  engine's end minus the first's), `ONLY_IN_ONE` (one engine has a function at a start where the other has no function and
  no instruction of any of its functions), `SPLIT_MERGED` (one engine's function starts inside a function of the other; the
  row names the container, and the `END_DIFFERS` row of that container is marked `explained_by`), `NAME_DIFFERS` (two real
  names; a generated name such as `sub_140001000` / `FUN_140001000` is no name, and a real name only one engine gives is
  counted in `named_only_by`, not as a disagreement). The header and `result` carry the count per category, `common`,
  `agreed` and which engine defines the function of each `ONLY_IN_ONE` / `SPLIT_MERGED` row.
- Coverage states in `result.state`: `BOTH_ENGINES`; `BOTH_ENGINES_STARTS_AND_NAMES_ONLY` (an engine gave no function extents:
  ends are not compared, `END_DIFFERS` / `SPLIT_MERGED` are not computed); `ONE_ENGINE` (the other engine is not installed,
  failed to open the target or to list it): status `PARTIAL`, `counts: null`, the reason in `engine_status`. Nothing was
  compared then: unknown, never agreement, and `coverage()` lists the call as incomplete.
- A row says what each engine reports, not which one is right (an `ONLY_IN_ONE` function can be a false positive of the engine
  that lists it, and real names can differ only in representation, mangled against demangled). Resolve it with `disassemble`
  or `xrefs`.
- `report_build` adds an "Engine disagreement" section to the Markdown and an `engine_disagreement` object to the JSON report
  (one document; present only when a comparison exists): state, the counts per category, both inventory ids and the comparison
  id.

### Controlled execution (`run_controlled`) and PROVEN
- Response: per case `evidence_id`, `status`, `exit_code`, `timed_out`, `truncated`, `content` (stdout, then `--- stderr ---`, then
  stderr; inside `<untrusted_target_content>`, limited to 4000 characters per case in the response, full raw output in the evidence).
  Target output is untrusted (may be fake or contain instructions); `_meta.provenance.untrusted_content=true`.
- `side_effects` (reply of every run, and `parameters.side_effects` of each case's evidence when non-empty): relative paths of
  files the target left in the sandbox's mapped work folder (for example `out/dropped.txt`), listed on the host just before the
  folder is deleted. The files the harness staged and the guest's own result records are left out. Symbolic links and
  junctions are never followed and appear as `<skipped link: ...>`; at most 2000 entries are listed (`<truncated: ...>`
  marks the rest), the reply shows the first 100 (`side_effects_total`, `side_effects_truncated`) and each name is clipped
  to 200 characters. Names come from the target: untrusted data. An empty list means nothing was observed in the mapped
  folder, never that the target had no side effects (the guest's `%TEMP%`, registry and anything outside the mapped
  folders are not visible). Staged input files are compared with a baseline taken before launch (size, mtime, SHA-256 for
  files up to 16 MiB; size and mtime only above that): a changed one is listed as `modified: <name>`, a removed one as
  `deleted: <name>`. The guest's own result records are never reported. A clipped name ends in `…[clipped]` and the
  count is in `side_effects_names_clipped` (reply and evidence parameters).
- Expected states give a short message: `SCOPE_DENIED` (not allowed in the manifest), `BUSY` (another sandbox is running: wait a minute and
  try once), `SANDBOX_UNAVAILABLE` (also on a non-Windows host: Windows Sandbox exists only on Windows, nothing runs); case timeout/truncation/session error comes in the response with `message`, and that evidence cannot back PROVEN.
- To get PROVEN: try the value the model proposed/computed as a case; `claim_add(kind="runtime_behavior"|"bypass_poc",
  behavior_class=..., requested="PROVEN", evidence_ids=[<run ev_>], atoms=[{"type":"quote","evidence_id":<run ev_>,"text":"License valid"}],
  values=[{"value":"<input>","derived":true}])`. The value must be an input to that execution, and the result must be bound by a quote from the output.
  A wrong input cannot be PROVEN (quote not in output -> REJECTED; value not tried in that execution -> UNVERIFIED). Static evidence does not give PROVEN. For a validation claim add the
  control pair of the next item.
- Behavior claims declare `behavior_class` (verifier 24, evidence-schema §4.17): `"acceptance_validation"` when the claim says an input is accepted or rejected, a key/licence is valid or a password is correct, otherwise `"ordinary"` (prints X, exits with N); without it the claim stays UNVERIFIED (`BEHAVIOR_CLASS_MISSING`). A validation claim (also every `bypass_poc` claim, and an `"ordinary"` one whose text still reads like a verdict) is PROVEN only with a `control_pair` atom over complete runs of the same build: one input the program accepts and one it rejects, inputs equal except the discriminator, each side bound to its own observed outcome, the two outcomes different, and the claim naming the input of the side `asserts` names. Run both inputs as two cases of one `run_controlled` call. One run alone leaves the claim UNVERIFIED (`CONTROL_PAIR_MISSING`). Ordinary behavior claims need no pair.
- Behavior claims and static evidence: claims like "the program accepts input X", "input X is the accepted value" count as `kind=behavior`. A value APPEARING in decompile output does not show it is the accepted input (a decoy string can resemble the program's expected input). With static evidence alone the most you get is `UNVERIFIED` (`issues`: `BEHAVIOR_NEEDS_EXECUTION`, enters the report only under "Unverified hypotheses"); with `run_controlled` evidence + a quote from the output it becomes `PROVEN`. Sentences describing code (`kind=observation`: "main compares with strcmp against a decoy string") can still be `SUPPORTED` as before.
- **Output integrity (mitigated, not absolute):** mapped folders stay writable by everyone inside the guest, so a target can still write files to the output
  folder; file access control is not trusted. Every result record is protected instead (`src/redharness/sandbox/integrity.py`): at session start the host writes a
  one-time nonce, the guest reads it into memory and acknowledges it, the host deletes the file and only then does the target start, so the nonce is in no file
  while the target runs; after the handshake the guest HMAC-authenticates the session, case and completion records. Each case MAC covers its ids, stdout/stderr SHA-256 and byte totals, exit code, timeout/truncation flags, launch-error hash, elapsed time and measured isolation fields; the host checks the record fields and MACs and compares the stream hashes with the bytes it read itself. A missing record or any verification failure is `INTEGRITY`: the session is rejected and no evidence is produced. Remaining limits: the trust root is nonce secrecy, so a guest-kernel or sandbox escape could still forge a record (not covered, not
  measured); files the target writes are reported as `side_effects` and are never accepted as results; the target's output remains untrusted content, and
  PROVEN = "observed in execution", not a guarantee of honesty. Every execution evidence's `limitations` field and the PROVEN response's `limitations` list state
  this.
- The verifier does not know the meaning of a quote. For a validation claim the control pair supplies the contrast (verifier 24):
  the accepted side's outcome must be observed in its own run and absent from the rejected run, and the other way round, so
  a single "License invalid" quote no longer proves "valid". The claim must name the input of the side it asserts, and
  a side whose quote or the claim's verdict words read as the other side is rejected; beyond that the label stays the claim's declaration.

### Model computation (`compute`)
Design and alternatives considered: `docs/design/compute-tool.md`. Short form:
- Runs in Windows Sandbox through the same pipeline as `run_controlled` (machine-wide lock, network off, separate low-IL user,
  nonce + HMAC output integrity). The "target" is the pinned `python.exe` from `python-3.12.10-embed-amd64.zip` (SHA-256 fixed in
  `compute/runtime.py`, 11 files with fixed hashes; no `_socket`/`_ssl`/`_ctypes`). The operator installs it once with
  `rh compute-runtime install <zip>` (no network use); if missing or modified: `COMPUTE_RUNTIME_MISSING`, nothing runs.
- `inputs`: at most 8, total 1 MiB; `name` is optional (`in0`, `in1`, ...). Easy path (verifier 11): `{"evidence_id", "select": {"offset", "length"}}`
  (or `{"address": "0x..", "length"}`) hands the code those bytes of a `read_bytes` evidence; the tool reads them from the ledger, so
  they are never retyped. Also `{"evidence_id", "raw": true}` (whole raw output), `{..., "quote": "exact text"}` or `{..., "const": "0x.."}`
  (must appear in that evidence as for derivation leaves). Pasted bytes `{"hex": ".."}` are auto-bound only if they EXACTLY equal a
  contiguous region of a `read_bytes` evidence of this job (binding recorded: evidence id, address, `auto: true`); otherwise they stay an
  unbound `literal` and the reply `warnings` say so. Bytes typed inside the code are never bound. The code gets
  `INPUTS = {name: bytes | int}` and prints its result. `random` is seeded with 0.
- Limits: `timeout_s` per run (default 30, max 300) -> `COMPUTE_TIMEOUT`; 64 KiB per output stream -> `OUTPUT_LIMIT`; non-zero exit ->
  `COMPUTE_ERROR` with the stderr tail; the two runs must be byte-identical -> otherwise `NONDETERMINISTIC`. None of these records evidence.
- Evidence: `authority=sandboxed-computation`, `confidence=derived`, raw = stdout; parameters hold `code_sha256` (code kept in CAS),
  input bindings (evidence id, kind, SHA-256), runtime hashes, limits. Same code + inputs = same `ev_`.
- Claims (verifier 7+, `docs/design/evidence-schema.md` §4.8): a printed value backs only an `observation` + `present` claim that also
  cites the static evidence of EVERY input (`support: computation`, at most SUPPORTED). Compute alone: `COMPUTE_ONLY` (REJECTED);
  inputs not cited: `VALUE_COMPUTE_NOT_BOUND` (UNVERIFIED); behavior claims and PROVEN: never (try the found key with `run_controlled`).

### CPU emulation (`emulate`)
Design, scored alternatives and limits: `docs/design/emulation.md`. Short form:
- Needs `"emulate"` in the scope manifest (off by default; neither `run_controlled` nor `compute` implies it) and the
  optional `unicorn` package in the harness environment (`pip install "unicorn==2.1.4"` or
  `pip install -e ".[emulate]"`; otherwise `EMULATOR_MISSING`, nothing runs).
- The PE image is mapped at its preferred base in its on-disk state (no relocation, no CRT/DllMain/TLS, no TEB/PEB or
  heap); section permissions are enforced; every import slot points at an unmapped sentinel. The worker runs at Low
  integrity in a one-process job.
- **Function or code range.** With `function` alone the function is entered with `convention` (x86 `cdecl` default,
  `stdcall`, `fastcall`, `thiscall`; x64 `ms64`, the only one) and a return address at a sentinel; reaching it is the only
  success (`stop: "return"`). With `end` (a VA inside the image, different from `function`) the call starts at `function`
  and stops successfully when the program counter reaches `end` (`stop: "range_end"`; the instruction at `end` does not
  run); returning to the caller first is `EMU_BAD_RETURN`. A range's stack pointer starts 8 KiB below the top so the
  enclosing function's locals/home slots are mapped (`sp` pre-writes fill them); a range result has no `stack_balanced`.
- **Arguments** (up to 16, in order): an integer (`1`, `"0x.."`), a buffer passed by pointer (`{"hex"}`, `{"ascii"}`,
  `{"utf16"}` (NUL added), `{"buffer": N}`; optional `size` enlarges it), or a value reference `{"va":"0x..","length"?}`
  (a pointer INTO the target image, e.g. an existing table or key in `.rdata`; address and length must lie in the image),
  `{"arg":i,"offset"?}` or `{"buf":j,"offset"?}` (address of a buffer argument / scratch buffer).
- **Scratch `buffers`** (up to 16): same forms as a buffer argument, not passed; refer to them with `{"buf":j,"offset"?}`
  in `args`, `registers` or `memory`. One buffer is at most 1 MiB; all argument and scratch buffers together at most 4 MiB.
- **`memory` pre-writes** (up to 64, 64 KiB total), applied after the image, buffers and call frame are in place and before
  the first instruction: exactly one target `{"va"}` (image DATA) | `{"sp":off}` (relative to the entry stack pointer) |
  `{"arg":i}` | `{"buf":j}` (with optional `offset`), and exactly one datum `hex` | `ascii` | `utf16` (exact bytes, no NUL
  added) | `ptr` (a value reference, written pointer-sized). An image pre-write must lie inside the image and must never
  touch the PE headers or an executable section: code is never pre-written (the emulated code is always the target's own).
  A buffer pre-write must fit its buffer; the `sp` offset is limited to ±16 MiB. Pre-writes are analyst input, recorded in
  the parameters and shown in the raw text.
- **`registers`** (initial GPR values, value references): x64 `rax` `rbx` `rcx` `rdx` `rsi` `rdi` `rbp` `r8`-`r15`, x86
  `eax` `ebx` `ecx` `edx` `esi` `edi` `ebp`; not the stack pointer (use `sp` pre-writes) and not a register the convention
  already loads from `args`. `output_registers` adds registers to report (the same names plus `rsp`/`esp`, or `"all"`);
  the return registers (x64 RAX/RDX, x86 EAX/EDX) are always reported.
- **`outputs`** (up to 16, read after the stop): `{"arg":i}`, `{"buf":j}`, `{"va":"0x.."}`, `{"ret":true}` or
  `{"reg":"name"}` (memory at the pointer held in a register), each with `length` (1..4096) and optional `offset`; `view`
  adds typed views; 16 KiB total. `"digest":true` records only the length and SHA-256 (not the bytes), allows up to 1 MiB
  per read and 4 MiB total, and SHA-256 is the only digest. The raw text prints `sha256=<64 hex>` for a digest output.
- Limits: `max_instructions` default 2,000,000 (max 100,000,000); `timeout_s` default 10 (max 60); `stack_size` 64 KiB
  to 16 MiB (default 1 MiB, rounded to 64 KiB); 16 arguments, 16 outputs, 16 buffers, 64 pre-writes.
- Stops (error, no evidence; record an unknown instead of guessing): `EMU_UNSUPPORTED_API` (names the imported API, or a
  TEB/PEB read), `EMU_UNMAPPED_ACCESS`, `EMU_PROTECTION_FAULT`, `EMU_UNSUPPORTED_INSTRUCTION` (interrupt, `syscall`,
  `sysenter`, `in`/`out`, `cpuid`), `EMU_FAULT`, `EMU_LIMIT` (instruction or time limit), `NONDETERMINISTIC` (the two
  emulations differ), `EMU_OUTPUT_UNREADABLE`, `EMU_BAD_RETURN` (reached the return address without a real `ret` or with a
  stack the convention does not expect; a range that left before `end`), `EMU_LAYOUT` (unreadable import tables: nothing
  runs), `EMULATOR_MISSING`, `ARTIFACT_CHANGED` (the stored target copy no longer matches its SHA-256), `EMU_WORKER_FAILED`
  (Low-IL hardening failed; nothing ran), `EMULATE_PLATFORM_UNSUPPORTED` (not Windows: the hardened worker is unavailable, nothing ran), `SCOPE_DENIED`, `OUT_OF_IMAGE`, `EMU_ARCH_UNSUPPORTED` (not x86/x64) and
  `BAD_ARGUMENT` (a request that does not fit the image: pointer, pre-write, `end`, buffer or limit). No API is ever
  stubbed.
- Evidence: `authority=cpu-emulation`, `confidence=derived`, `environment.native_execution=false`; parameters hold the
  canonical request (function, `end`, convention, arguments with initial bytes, scratch buffers, pre-writes, initial
  registers, outputs, limits, layout version) and the emulator version, so the same request gives the same `ev_`. The raw
  text prints the return (or final) registers in hex and decimal and each output in the `read_bytes` dump format.
- Claims (verifier 20): a value from the output backs only an `observation` + `present` claim (`support: emulation`,
  check `EMULATION`, at most SUPPORTED) — an observation of what this code computes from the analyst's inputs, never what
  the program does when run. Behavior claims, absence claims and PROVEN: never. A record is valid only as a deterministic
  `return` without `end` or a deterministic `range_end` with `end` (else `EMULATION_RECORD_INVALID`). Write in the claim
  that the value comes from emulation. The record has no function names: cite `functions_list`/`decompile` evidence to
  name the routine. The report prints a "Basis: CPU emulation" line under such findings.

### Tool effect table and scope permissions
Each tool's possible effects are defined in the table in `src/redharness/mcp/effects.py`. Before the tool runs, every call is checked against the scope manifest according to this table: if one of the tool's
explicit effects is not allowed in the manifest, the call is rejected with `SCOPE_DENIED` before processing (the rejection is also logged);
a tool not in the table is rejected with `TOOL_NOT_IN_EFFECT_TABLE`. Every tool requires at least `static`. Effect -> permission link:
`executes_foreign_code` -> `run_controlled`; `executes_model_code` -> `compute` only; `emulates_target_code` -> `emulate`
only; `launches_process` -> `run_controlled`, `compute` or `emulate`; `writes_files` (outside the job store) -> `run_controlled`, `patch_poc` or `compute`; `mutates_target` -> `patch_poc`; `network` -> no manifest can allow it (the tool is always rejected).
Running the operator-configured analysis engine (IDA/Ghidra) does not count as an effect; `mutates_session` is an append-only write to the job store
(log, evidence, report). The table is generated exactly from code and a test checks that it matches the document:

| Tool | reads_files | writes_files | launches_process | executes_foreign_code | executes_model_code | emulates_target_code | instruments_process | captures_memory | network | mutates_target | mutates_session | idempotent | required permission |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `target_open` | yes | - | - | - | - | - | - | - | - | - | yes | yes | static |
| `functions_list` | yes | - | - | - | - | - | - | - | - | - | yes | yes | static |
| `decompile` | yes | - | - | - | - | - | - | - | - | - | yes | yes | static |
| `disassemble` | yes | - | - | - | - | - | - | - | - | - | yes | yes | static |
| `dataflow_slice` | yes | - | - | - | - | - | - | - | - | - | yes | yes | static |
| `xrefs` | yes | - | - | - | - | - | - | - | - | - | yes | yes | static |
| `strings` | yes | - | - | - | - | - | - | - | - | - | yes | yes | static |
| `read_bytes` | yes | - | - | - | - | - | - | - | - | - | yes | yes | static |
| `file_strings` | yes | - | - | - | - | - | - | - | - | - | yes | yes | static |
| `imports` | yes | - | - | - | - | - | - | - | - | - | yes | yes | static |
| `run_controlled` | yes | yes | yes | yes | - | - | - | - | - | - | yes | - | static + run_controlled + run_controlled/compute/emulate + run_controlled/patch_poc/compute |
| `compute` | yes | yes | yes | - | yes | - | - | - | - | - | yes | yes | static + compute + run_controlled/compute/emulate + run_controlled/patch_poc/compute |
| `emulate` | yes | - | yes | - | - | yes | - | - | - | - | yes | yes | static + emulate + run_controlled/compute/emulate |
| `captured_region` | yes | - | - | - | - | - | - | yes | - | - | yes | yes | static + dynamic_memory |
| `claim_add` | - | - | - | - | - | - | - | - | - | - | yes | yes | static |
| `unknown_record` | - | - | - | - | - | - | - | - | - | - | yes | yes | static |
| `coverage` | - | - | - | - | - | - | - | - | - | - | - | yes | static |
| `report_build` | - | - | - | - | - | - | - | - | - | - | yes | yes | static |
| `run_controlled#observe` | yes | yes | yes | yes | - | - | yes | - | - | - | yes | - | static + dynamic_observe + run_controlled + run_controlled/compute/emulate + run_controlled/patch_poc/compute |
| `run_controlled#observe+memory` | yes | yes | yes | yes | - | - | yes | yes | - | - | yes | - | static + dynamic_memory + dynamic_observe + run_controlled + run_controlled/compute/emulate + run_controlled/patch_poc/compute |

("a/b": one is enough, "+": all are required; "yes" = effect present, "-" = absent; "NEVER" = no scope manifest can allow it; the table is generated by `effects_markdown()`.)

### Raw byte reading (`read_bytes`)
Reads only from the PE file (the SHA-verified copy in CAS); does not call IDA/Ghidra, does not run the target, needs no new permission
(same effect as `disassemble`/`strings`: file read + session record; `static` suffices). `disassemble` deliberately returns an empty `PARTIAL`
at a data address (not code); use this for constant arrays or function-pointer tables.
- Addressing (exactly one): `address` (VA, hex), `rva` (hex), or `section` (name, case-insensitive) + `offset`. An address/offset outside the image
  gives `OUT_OF_IMAGE` (not counted as a coverage gap). `length` 1..1024 (default 64); more is clamped, `next_address` gives the continuation
  point (`requested_length` shows what was asked).
- Output (`result`): `va`, `rva`, `length`, `file_bytes`, `uninitialized_bytes`, `unmapped_bytes`, `section`, `file_offset`,
  `segments[]` (`kind`: `file` | `uninitialized` | `unmapped`). If the range crosses section boundaries it is split into pieces.
- **Bytes not in the file are never invented.** `.bss` and the virtual part beyond raw size (`UNINITIALIZED`, "not in file; runtime-only")
  and sectionless gaps (`UNMAPPED`) are NOT SHOWN as bytes; the status becomes `PARTIAL` and `limitations` says so. Learn the values from code or
  with `run_controlled`.
- Format: the hex dump always comes (16 bytes/line, 4-byte groups joined by `_`, file order; VA at line start). `view` (comma-separated string or
  list; default `ptr`): `u8`, `u16`, `u32`, `u64` (little-endian, hex + decimal), `ptr` (the target's pointer width; a value falling inside the
  image is labeled with the section it points to: `-> .text`), `ascii`, `utf16` (printable strings, at least 2 characters), `all`.
  If the response would exceed 24000 characters it is not silently truncated: `BAD_ARGUMENT`, asking for fewer views/less length.
- Values are on-disk bytes: relocations are not applied (pointers are relative to the preferred image base), import
  tables are not bound; they may differ at runtime (evidence `limitations` field).
- Evidence: `engine=pe-static`, an `ev_` id (VA/RVA/section+offset reduce the same read to the same id; `step_cached` on the same parameters),
  locations VA and RVA `address-range`. In claims, value (`0xdeadbeef` or decimal), `quote` and `address` atoms work with the existing
  verifier. Since verifier 8 the location range is NOT a value: a low-RVA (header) read no longer makes small invented numbers pass.
  A number in a `read_bytes` claim is supported only by the typed views (explicit radix) or the `0x..:` address prefix of the raw output (since verifier 9 the hex-dump bytes are NOT numbers: `12 34 56` never supports the decimal 12), a `constant` atom, or an
  `address` atom (give `{"type":"address","evidence_id":...,"space":"rva","value":"0x2c"}` to cite an address; it backs the hex
  literal / hex-form value, not a decimal result value).
  The same holds for the instruction-byte field of `disassemble` lines (`0x401000: 55 push ebp` does not give the number 55).

### Engine error codes (`decompile`, `disassemble`, `xrefs`, `dataflow_slice`)
A failed engine call returns an MCP error whose code comes from one closed set, identical for IDA and Ghidra (an engine failure
with none of these keeps its plain status code: `ERROR`, `TIMEOUT`, `TOOL_MISSING`, `MEMORY_LIMIT`). The message says what to try next.
No evidence is written for a failed call, so the step cache is untouched; the code is in the call journal and `coverage.failed_calls`.

| Code | Meaning | Typical tools |
|---|---|---|
| `NO_FUNCTION_AT_ADDRESS` | the address is inside the image but no function covers it (data, or code the engine did not define as a function); `disassemble` it or look in `functions_list` | `decompile`, `dataflow_slice` |
| `NAME_NOT_RESOLVED` | the function name matched no function, or (Ghidra) more than one; pass an address | `decompile` |
| `OUT_OF_IMAGE` | the address lies outside the PE image (below the image base or beyond SizeOfImage), so there is no function there; not counted as a coverage gap (same code as `read_bytes`) | `decompile`, `dataflow_slice` |
| `DECOMPILE_FAILED` | the decompiler ran and produced no usable output | `decompile` |
| `DECOMPILE_TIMEOUT` | the decompiler budget was exhausted (never an empty result) | `decompile` |
| `DECOMPILER_UNAVAILABLE` | the engine has no usable decompiler (status `TOOL_MISSING`) | `decompile` |

`disassemble` and `xrefs` do not need a function: an address with no decodable code gives a `PARTIAL` disassembly and an empty xref
list, not an error; they use the same codes only for an engine-side failure. Engines report a code by starting their error text with it
(`src/redharness/engines/base.py`: `ENGINE_ERROR_CODES`); text from the target never sets one.

### Response mode: `detail` and paging
`functions_list`, `decompile`, `disassemble`, `strings`, `read_bytes`, `file_strings`, `imports` take `detail: "summary" | "full"` (default `full`); `dataflow_slice` too (default `summary`).
`summary`: no `content` in the response; `summary` (counts, next page), a short `preview` (at most 5 lines, inside `<untrusted_target_content>`)
and the `ev_` id return. The full evidence is in the ledger in both modes and the id is the same (`detail` is not an evidence parameter):
calling again with `full` does not run the engine (`step_cached: true`), and claims can quote from the evidence even a line not shown in the summary.
Paging: `functions_list`/`strings` `offset`+`limit` -> `next_offset`; `decompile` `offset`+`max_chars`
-> `shown.next_offset`; `disassemble` `address`+`count`/`end` -> `next_address`. `driver_scan` is not part of the tool set.

### Availability report (`tools`) and next-tool hint (`next`)
`tools/list` always returns the same tools. What is usable for the open target is reported instead, in `target_open` and
`coverage` (`tools`):

```json
"tools": {"usable": ["target_open", "functions_list", "decompile", "...", "report_build"],
          "unavailable": {"run_controlled": {"kind": "scope", "code": "SCOPE_DENIED",
                                             "reason": "allowed_operations lacks 'run_controlled'"}, "...": {}},
          "note": "Harness guidance, not evidence about the target (do not cite it). A call applies the same checks; tools/list does not change."}
```
- `kind` says why a tool is not usable (the first reason that applies): `scope` (the manifest's `allowed_operations` lack the
  permission, see the effect table), `target` (kernel-mode image: `run_controlled` is never allowed), `edition` (a Pro
  implementation, e.g. `captured_region` or `observe`, is not part of this build), `platform` (`emulate` runs on Windows hosts
  only), `extra` (an optional package is not installed: `unicorn` for `emulate`), `engine` (the engine has no decompiler for this
  target: `decompile`), `runtime` (the pinned Python for `compute` is not installed), `sandbox` (Windows Sandbox is not
  available: `run_controlled`, `compute`). `code` is the error a call would return.
  One condition, one `code`, here and in the tool's own replies:

  | `kind` | condition | `code` |
  |---|---|---|
  | `registry` | the tool is not in the effect table | `TOOL_NOT_IN_EFFECT_TABLE` |
  | `target` | kernel-mode image: `run_controlled` | `KERNEL_TARGET_NO_USERMODE_RUN` |
  | `target` | `functions_list(compare="fixed")` without an open fixed build | `FIXED_BUILD_NOT_OPEN` |
  | `scope` | `allowed_operations` lacks the permission | `SCOPE_DENIED` |
  | `edition` | the Pro implementation is not in this build | `DYNAMIC_BACKEND_UNAVAILABLE` |
  | `platform` | `emulate` on a host that is not Windows (nothing ran) | `EMULATE_PLATFORM_UNSUPPORTED` |
  | `extra` | `emulate` without the `unicorn` package | `EMULATOR_MISSING` |
  | `engine` | `decompile` with an engine that has no decompiler | `TOOL_MISSING` |
  | `runtime` | `compute` without the pinned Python runtime | `COMPUTE_RUNTIME_MISSING` |
  | `sandbox` | `run_controlled` / `compute` without Windows Sandbox | `SANDBOX_UNAVAILABLE` |

- It is the same decision a call makes: `Hub.call` runs `mcp/availability.py::blocker` before every tool, and the report is
  built from it, so the report cannot disagree with a call (tests/unit/test_availability.py checks every tool over a matrix of
  manifests and installations). `run_controlled(observe)` rows appear in `unavailable` when `run_controlled` is usable but the
  observe permission or the Pro tracer is not. A tool that is usable can still fail on its arguments.
  Error precedence of one call: the kernel-mode refusal (`run_controlled`), then no target (`NO_TARGET`), then the scope
  (`SCOPE_DENIED`), then availability (`DYNAMIC_BACKEND_UNAVAILABLE`, `EMULATE_PLATFORM_UNSUPPORTED`, `EMULATOR_MISSING`, `TOOL_MISSING`,
  `COMPUTE_RUNTIME_MISSING`, `SANDBOX_UNAVAILABLE`), and only then the tool's own checks: argument validation (`BAD_ARGUMENT`)
  and the engine error codes. So a malformed `observe` on a build without the Pro tracer returns
  `DYNAMIC_BACKEND_UNAVAILABLE`, not `BAD_ARGUMENT`.
- `next`: a successful reply of a tool that has follow-ups in the registry (`ToolSpec.follow_ups`) ends with a one-line hint,
  e.g. after `functions_list`: `hint, not evidence (never cite it): decompile (read a candidate); xrefs (find its callers)`.
  Only tools that are usable right now are named (a tool the scope does not grant is not suggested), the words are fixed registry
  text and never target data, and the hint is added after the evidence is recorded: it is in no evidence, no journal and no
  report, so a quote of it is rejected (`QUOTE_NOT_IN_RAW`). Error replies and `claim_add`/`unknown_record`/`coverage`/
  `report_build` carry no hint.
- Output budget: the report is about 1 KB and the hint under 260 characters; both ride along with `detail='summary'` replies.
- Eval note: the eval prompts mention both fields (`blind.GUIDANCE_NOTE`); eval results made before this change saw different
  tool output and are not strictly comparable with later ones.

### Unknowns and coverage
- `unknown_record`: the model records a question it cannot answer instead of guessing (question, reason, related address, evidence ids,
  severity). The record is an `rh.unknown/1` event (`reason` and `address` are optional fields; the id derives from question+address).
- Closing an unknown (no extra tool, to stay under the tool cap): `unknown_record(resolves="unk_...", status="resolved", evidence_ids=["ev_..."])`
  when evidence now answers it (at least one valid, not invalidated `ev_` id of this job is REQUIRED), or
  `unknown_record(resolves="unk_...", status="withdrawn", reason="...")` when the question no longer matters (the reason is REQUIRED).
  Pass nothing else (no question/address). It writes an `UNKNOWN_UPDATED` journal event (`expected_revision` guards against a stale
  record) and moves the record to `resolved`/`withdrawn` with a `resolution` ({status, evidence_ids, reason?}); the original question,
  reason and supporting evidence stay, nothing is deleted. Closing again with the same status and evidence is a no-op; a different
  resolution of a closed unknown is `UNKNOWN_ALREADY_CLOSED`. Other errors: `UNKNOWN_NOT_FOUND`, `UNKNOWN_EVIDENCE_ID`,
  `BAD_RESOLUTION` (missing evidence ids / reason). A resolution is the model's claim that the cited evidence answers the question;
  the report lists it with those ids so a reader can check. A closed unknown no longer counts as a gap (`open_unknowns`), a
  recorded question with the same text and address keeps its closed status.
- `coverage`: computed from the ledger and the `TOOL_CALL` log, not from the model's statement. `assessment`: `NOT_EXAMINED` (no evidence),
  `INCOMPLETE` (truncated/partial evidence, a failed/timed-out call, or an open unknown exists) or `NO_RECORDED_GAPS`.
  **No value means "clean"**: missing coverage is unknown, not absence; `NO_RECORDED_GAPS` only says there is no recorded
  gap. If the same (tool, arguments) later gives full output, the old gap closes.
- `coverage` also lists `closed_unknowns` (+ `resolved_unknowns_total`, `withdrawn_unknowns_total`) next to `open_unknowns`.
- `report_build`: the report has a "Coverage and unknowns" section (assessment, tools run, truncated calls, unconsumed
  lists, open unknowns, and a "Resolved and withdrawn unknowns" subsection with the cited evidence); the response carries the `coverage` summary. Missing coverage does not make the report "clean".
- `report_build` JSON (`rh.report/1`): the same document the Markdown is rendered from, so the two cannot disagree. It holds the target identity (`sha256`, format, architecture), the scope digest and allowed operations, the verifier version, the tool and engine versions, `findings` (claim id, kind, status, text, atoms with quotes and addresses, cited evidence ids, the verifier's record), `hypotheses` (always `UNVERIFIED`, with structured `reasons` and a `class`; never mixed into findings), `unknowns` (with an `open` flag), `coverage`, and an `evidence` index of what the claims cite (operation, parameters, hashes, locations as hex strings). A model's `interpretation` is carried next to a finding with `interpretation_verified: false`: the status does not cover it. Every quote, claim text and parameter is data, JSON-escaped and ASCII-only in the file; the document says `untrusted_content: true`. `format="json"` returns the document inline only if it is at most 30000 characters (`report_json_truncated` otherwise); the file is always whole. The schema file validates the output (`tests/unit/test_report_json.py`).

### Output format
All address fields are hex strings (`"0x140001250"`: `result.address`, `target.entry`, `target.image_base`, `parameters.function`...).
Verifier issues tell the model what to do via `issues[].hint`.

### Claim atoms
- `{"type":"quote","evidence_id":"ev_..","text":"text appearing verbatim in the evidence's raw output (>=4 characters)"}`
- `{"type":"address","evidence_id":"ev_..","value":"0x140001250"}`; optional `"space":"va"|"rva"`. If `space` is not given, both VA and RVA
  are tried; if `space` is wrong, it is rejected and the message names the right space (RVA = VA - image_base; the server writes both as locations).
- `{"type":"constant","evidence_id":"ev_..","value":"0x5EC2E7A1"}`
- `{"type":"exit_code","evidence_id":"ev_<run_controlled>","code":0}` (verifier 17): the process exit code of that one
  `run_controlled` case. It checks `code` against the exit code recorded in the run evidence and works only on a
  `run_controlled` `ev_`: static, `compute` and dynamic-observation evidence are REJECTED (`EXIT_CODE_NEEDS_RUN_EVIDENCE`),
  a different recorded code is REJECTED (`EXIT_CODE_MISMATCH`). A run with no recorded exit code (crash/session error) or
  one that is not complete (truncated, unclean session) leaves the claim UNVERIFIED (`EXIT_CODE_NOT_RECORDED`,
  `EXIT_CODE_RUN_NOT_COMPLETE`); a timed-out run is failed evidence and rejected. Present claims only. A Windows exit code is a
  32-bit value: `-1073741819` and `3221225477` (`0xC0000005`) are the same code; write a negative code in the claim text as
  `0x...` (a text `-1` is read as the number 1). A verified code backs the same number in the text only where it stands in an
  exit-code phrase (`exit code N`, `exit status N`, `exits with [code] N`, `returns N to the operating system`, where `N` is decimal,
  signed or the `0x` pattern); the same number anywhere else (an address, a count) and any other number still need their own evidence. Example: `claim_add(kind="behavior", behavior_class="ordinary", requested="PROVEN", evidence_ids=[ev_run],
  text="The program exits with code 0 when given `<candidate-input>`.", atoms=[{"type":"exit_code","evidence_id":ev_run,"code":0}],
  values=[{"value":"<candidate-input>","derived":true}])` (the input must be one the run was given).
- `{"type":"control_pair","asserts":"accepted","discriminator":{"source":"stdin","index":0},"accepted":{"evidence_id":"ev_<run A>","outcome":{"type":"quote","quote":"License valid"}},"rejected":{"evidence_id":"ev_<run B>","outcome":{"type":"exit_code","code":1}}}` (verifier 24): contrasting `run_controlled` cases of the job's target build.
  `discriminator.source` is `stdin` (`index` = the stdin line that differs; omit it to let the whole stdin differ) or
  `argv` (`index` = the argv item, required); everything else (argv, stdin, support files) must be equal. A side may list
  repeated cases of one input as `"evidence_ids":[...]`. An outcome is an exact quote of that case's stdout or stderr or
  its recorded exit code (side effects are recorded per session, not per case, so they are not an outcome). Every case
  must also be in `evidence_ids`. `asserts` (`accepted` | `rejected`) names the side the claim is about: the claim
  names that side's discriminator input (in the text or in `values`; compared as recorded and with surrounding
  whitespace removed) and not the other side's; one claim per side; sides that differ only in whitespace are invalid.
  Malformed, a claim that names the wrong input or none, verdict words or a quoted outcome that contradict the side, uncited, not a `run_controlled` run of the target build (two builds use
  `fix_pair`), inputs differing outside the discriminator, or an outcome its own case does not show: REJECTED
  `CONTROL_PAIR_INVALID`. A truncated run or unclean session: UNVERIFIED `CONTROL_PAIR_INCOMPLETE` (a timed-out run is
  failed evidence and rejected, as everywhere). An outcome that also holds on the other side: UNVERIFIED
  `CONTROL_PAIR_SAME_OUTCOME`. Repeats of one input that disagree, the same input on both sides, or another cited complete
  run of a side's input without that side's outcome: UNVERIFIED `CONTROL_PAIR_UNSTABLE`. A valid pair also binds the
  claim to the run output for PROVEN.

Every `0x...` literal in the claim text must be supported by an atom or evidence. Static evidence gives at most
`SUPPORTED` (`PROVEN` only with `run_controlled` evidence, see above). A claim without evidence becomes
`REJECTED`. Record an unevidenced idea with `requested: "UNVERIFIED"`: it enters the report only in the
"Unverified hypotheses" section.

### Claim kind, retraction and partial support (`claim_add`)
- `kind`: `observation` | `behavior` (old names `static_fact` = observation, `runtime_behavior` = behavior; `bypass_poc` is a behavior class). Recommended to provide. If omitted, the server infers it from the text ("doğru parola", "geçerli anahtar", "kabul edilir", "accepted", "valid key", "correct password"... or observation markers: address, `sub_...`, "function/string/calls..."); if ambiguous, `behavior` (fail-closed). Even if `observation` was stated, if the text explicitly claims behavior the kind is converted to `behavior` and the response shows `kind_source: overridden` + `KIND_OVERRIDDEN_TO_BEHAVIOR`; rewrite the text as "what is in the code" or verify with `run_controlled`. The response returns `kind` and `kind_source`.
- `supersedes: [claim_id]`: retracts your earlier claim and replaces it with the new one. The old claim stays in the ledger (append-only) but does not appear in the report; if the new claim is REJECTED nothing is retracted. The response has `superseded: [...]`.
- Partial support: for a multi-value claim the response contains `values_supported` / `values_unsupported` (reason and `derived` flag) and a `message` naming the problem value. Send the supported part as a separate claim; observe the derived value with `run_controlled` or make it a separate hypothesis. When `target_open` lists earlier claims it marks retracted ones `superseded: true`.
- `report_build.counts`: `unsupported_claims` counts only unsupported claims that enter the FINDINGS and must always be 0 (if not, it is an error); `claims_without_evidence`, `claims_value_not_in_evidence`, `claims_behavior_without_execution` are its parts. Hypotheses are separate: `hypotheses` = `hypotheses_without_evidence` + `hypotheses_value_not_in_evidence` + `hypotheses_behavior_needs_execution` + `hypotheses_other`; retracted ones are `superseded`. (In the old version `unsupported_claims` counted hypotheses; be careful when comparing with old eval outputs.)

## Log and resume
`data_root\jobs\job_<sha[:16]>\events.jsonl` is a hash-chained, append-only log; every tool call (including rejected ones)
is written as a `TOOL_CALL` event. Rejected `target_open` calls (since no job was opened) are written to
`data_root\mcp\pre-open-<pid>.jsonl`. Reports are under `jobs\<id>\report\`. A job can be open in only one server process at a time
(`JOB_LOCKED`).

### Resume after a crash or power loss
Start a new session and call `target_open` with the same target and manifest. The reply has `resumed: true`, `previous`
(evidence and claim ids, unchanged) and a short `resume` block: `steps_finished`, `evidence`, `claims_by_status`,
`open_unknowns`, `report_built`, `interrupted` and what was repaired (`torn_bytes_dropped`, `lock_reclaimed`,
`sandbox_recovery`). There is no separate `job_status` tool.
- A call that was running when the server died is listed under `interrupted` with status `INTERRUPTED` and its arguments.
  It produced no evidence and was never ok. Re-issue it: finished steps come from the step cache (`step_cached: true`,
  same `ev_` id, no engine rerun), only the cut-off step runs. A cut-off `run_controlled`/`compute` is simply run again
  (a short sandbox run is re-run, not resumed).
- Repairs are appended to the hash chain, never silent: `JOURNAL_TORN_TAIL_DROPPED` (half-written last line),
  `LOCK_RECLAIMED` (dead server's lock), `TOOL_INTERRUPTED`, `SANDBOX_RECOVERED`. A newline-terminated line that does not
  verify is NOT a torn write and is never repaired (`JOURNAL_CORRUPT`).
- Sandbox: the sandbox journal (`sandbox/journal.jsonl`) notes the Windows Sandbox processes this harness started. Recovery
  closes only those, records the run as `SANDBOX_RUN_FAILED` with reason `INTERRUPTED`, deletes its work folder and leaves
  other Windows Sandbox instances alone (a following `run_controlled` then returns `BUSY`).

## Exporting and importing a job (Pro)
Job bundle export and import (`rh export`, `rh import`) is available in the Pro edition only.
In the Core build both commands print a notice that the feature is not included and exit with status 2.

## Limits (UNVERIFIED / open)
- `patch_poc` is not a tool and will not be one (fix verification on a vendor-rebuilt binary instead); `evidence_get` is not in this skeleton; (`job_status` is carried by the `resume` block of `target_open`). There is no tool to resolve an unknown (`resolved`): if the same (tool, arguments) gives full output only the coverage gap closes, the recorded unknown stays open.
- The claim verifier is version 24 (term binding; `exit_code` and `control_pair` atoms): technical terms in a claim must appear in the cited evidence, else UNVERIFIED `TERM_NOT_IN_EVIDENCE`.
- Kernel-mode targets are refused for execution (`KERNEL_TARGET_NO_USERMODE_RUN`).
- Engines: IDA and a Ghidra 12.1.3 headless backend both exist (`src/redharness/engines/`); `rh mcp` starts the IDA engine by default; `rh mcp --engine ida|ghidra` selects one explicitly (unknown name or an engine that is not available exits non-zero, no silent fallback; the engine is passed in-process, no environment variable). Address translation: the server adds an RVA location next to the VA location in IDA evidence
  (if the image base is known); no file-offset location is produced.
