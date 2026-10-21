# `compute` tool: the model's own computation, isolated and evidence-bound

Status: implemented and unit-tested with a fake sandbox; the real Windows Sandbox path is covered by an opt-in heavy test.
Code: `src/redharness/compute/`, `src/redharness/evidence/compute.py`,
`src/redharness/mcp/compute_tool.py`. Tests: `tests/unit/test_compute.py`, `tests/heavy/test_compute_real.py`.

## 1. Why a compute tool

Some static-analysis questions cannot be answered by reading code and data alone: inverting a hash or checksum by
brute force, evaluating an expression over a table of constants (together with data-byte reading, `read_bytes`), or
decoding a blob with a small custom routine. Without a way to run code the analyst can only record the question with
`unknown_record` ("needs code execution"), so a capability gap, not a budget limit, ends the investigation. The
compute tool closes that gap while keeping the result evidence-bound (see the sections below).

## 2. Where it runs

Options considered, compared on isolation, speed (start + work), generality, implementation risk and reuse of existing
infrastructure:

| Option | Isolation | Speed | Generality | Risk | Reuse |
|---|---|---|---|---|---|
| **A. Windows Sandbox via the `run_controlled` pipeline (chosen)** | strong | slow start | any code | low | full |
| B. Restricted interpreter on the host (AST allowlist, limited `exec`) | none | fast | wide | high | partial |
| C. Host subprocess + Job Object + AppContainer/low IL | weak | fast | any code | medium | little |
| D. Hyper-V VM | strong | very slow | any code | medium | none |
| E. Fixed primitive set, no code (FNV/CRC inversion, table decode) | strong | fast | narrow | low | partial |

- A: exactly the `run_controlled` pipeline (`sandbox/runner.py` `_run_locked`): machine-wide single-sandbox lock,
  interrupted-session recovery, `.wsb` (network disabled, input read-only), guest.ps1 (separate non-admin user + low IL,
  runner-owned pipe, nonce + HMAC output integrity, process tree killed after each case). Cost: a cold start of roughly 20 s
  and the exclusive lock (compute and `run_controlled` run one after another; `BUSY`
  when taken).
- B: a pure-Python AST/`exec` sandbox is known to be escapable (object graph via `__subclasses__`, frame objects, ...); it
  is NOT a security boundary. The model's code processes target bytes, so injected text in the target can steer the model
  into running code on the host; this breaks the rule that no untrusted code runs on the host. Eliminated.
- C: fast, but isolation rests only on Windows token restrictions; a Job Object is not isolation. Host
  file system and kernel are shared. Reopened only if the Sandbox becomes permanently unusable.
- D: strongest, but there is no infrastructure for it.
- E: safe and fast and solves case A, but fits the "works on an unknown target" criterion poorly and every new algorithm
  needs a new primitive (target-specific code is forbidden). The `derivation` atom (§4.7) already covers this class.

Result: A. The speed cost is accepted: one session (two runs) per computation.

## 3. Language and runtime

Windows Sandbox is a clean Windows image without Python (guest.ps1 uses only PowerShell and .NET Framework; the design does not rely on any interpreter that might
exist in the image, because the interpreter is staged).

| Option | Model fluency | Speed | Supply-chain risk | Determinism | Extra setup |
|---|---|---|---|---|---|
| **Embeddable CPython 3.12.10, pinned SHA-256 (chosen)** | high | slow | low | good | some |
| C# (.NET Framework `Add-Type`/`csc.exe`, built into Windows) | good | fast | none | good | none |
| PowerShell | low | very slow | none | fair | none |
| CPython + numpy | good | fast | high | good | much |
| Small C compiler (tcc) | fair | fast | high | good | much |

C# is attractive but was not chosen: the typical need is a short script computation, and models make fewer compile
errors in Python; a compile error costs a turn and money. If Python is too slow (a pure-Python loop is on the order of
10^7 simple operations/s; a flat 10^9 scan takes hours) C# can be added as a second language (`language` parameter; only
`python` today). A short-hash inversion does not need a 10^9 scan: FNV-1a is invertible byte by byte, so
meet-in-the-middle is 10^5 + 10^4 steps (if the model chooses it).

Runtime (`compute/runtime.py`):
- `python-3.12.10-embed-amd64.zip`, SHA-256 `4acbed6d…25a3c3` pinned in code. Provenance: its MD5 equals the value published by
  the python.org API; `python.exe` and `python312.dll` have valid Authenticode signatures (Python Software Foundation).
  python.org does not publish SHA-256 for this release; the SHA-256 was computed locally.
- Only 11 files are extracted, each with a pinned SHA-256: `python.exe`, `python312.dll`, `python3.dll`, `python312.zip`
  (stdlib), `python312._pth`, `vcruntime140.dll`, `vcruntime140_1.dll`, `unicodedata.pyd`, `_decimal.pyd`, `_bz2.pyd`,
  `_lzma.pyd`. NOT staged: `_socket`, `_ssl`, `select`, `_ctypes`, `_multiprocessing`, `_overlapped`, `_asyncio`,
  `_hashlib` + OpenSSL, `_sqlite3`, `pyexpat`, `winsound`, ... hashlib md5/sha1/sha2/sha3/blake2 work through built-in modules
  with this file set. This trimming is NOT a security boundary (`subprocess` works through the
  built-in `_winapi`); it only shrinks the surface. The boundary is the Sandbox.
- Installation uses no network: the operator downloads the zip and runs `rh compute-runtime install <zip>`; on a hash
  mismatch nothing is written. Every `compute` call re-hashes the 11 files; any difference gives `COMPUTE_RUNTIME_MISSING`
  and nothing runs.
- Staging: the same mechanism as the VC++ DLLs (`sandbox/support.py`): files go into `in/bin` (read-only) and the guest copies
  them into a fresh work folder per run; `python.exe` is the runner's "target" (the guest re-verifies its SHA-256,
  `GUEST_HASH_MISMATCH`). The bootstrap `rh_boot.py` reads `{"code", "inputs"}` JSON from stdin, provides `INPUTS`
  (`name -> bytes | int`), seeds `random` with 0 and runs the code. Command: `python.exe -I -B -X utf8 rh_boot.py`.

## 4. Limits

| Limit | Value | When exceeded |
|---|---|---|
| Wall clock (per run) | default 30 s, max 300 s | `COMPUTE_TIMEOUT`: explicit error, no evidence; a timeout is NEVER a result |
| CPU time | bounded by the wall clock (the guest kills the process tree); no separate CPU quota (Job Object) | - |
| Output | 64 KiB per stream (stdout, stderr) | `OUTPUT_LIMIT`: a cut output is not a result, no evidence |
| Code | 64 KiB | `BAD_ARGUMENT` (before the sandbox opens) |
| Inputs | at most 8, 1 MiB total | `BAD_ARGUMENT` |
| Network | `.wsb` `Networking=Disable`; `_socket` not staged | - |
| File access | the work folder holds only the interpreter + bootstrap; the target binary is not staged; no host folder | - |
| Memory | Sandbox `MemoryInMB` (`RH_SANDBOX_MEMORY_MB`) | process failure -> `COMPUTE_FAILED`/`COMPUTE_ERROR` |
| Error | exit code != 0 | `COMPUTE_ERROR` + last 1500 bytes of stderr; no evidence |

Inputs come only from evidence in this job's ledger. Easy path (verifier 11): `{"evidence_id","select":
{"offset","length"}}` (or `{"address":"0x..","length"}`) gives the code those bytes of a `read_bytes` evidence; the tool
decodes them from the ledger's dump, so the model never retypes bytes (`name` is optional: `in0`, `in1`, ...; `select` may be
omitted for a one-segment dump; on other evidence `{evidence_id}` means `raw`). Other forms: `{"…","raw":true}` (whole raw
output), `{"…","quote":"exact text"}` (>= 4 characters, must be in the raw output) or `{"…","const":"0x…"}` (numerically equal
in the raw output; the verifier's `_raw_numbers` rules). Unknown/invalidated evidence, evidence of another target, a quote or
constant not found, a select outside one file segment, or a compute output as input is refused. Constants and bytes written
inside the code are NOT bound (the record says so).

Auto-binding (a model that reads bytes with `read_bytes` and then pastes them into `compute` would otherwise leave a correct
claim UNVERIFIED `VALUE_COMPUTE_NOT_BOUND`): a pasted literal `{"hex":".."}` (spaces/`_` allowed) is compared with every
FILE region of the job's static `read_bytes` evidence. Only EXACT equality of a contiguous region counts (at least 4 bytes;
no fuzzy or partial-with-edits matching; no other target's evidence; the lowest evidence id and first occurrence win). A hit
is recorded like an explicit range, `{kind:"range", evidence_id, va, bytes, sha256, auto:true}`, and shown in the reply
(`warnings`). A literal that matches nothing is recorded as `{kind:"literal", evidence_id:null}`: valid, but it binds nothing,
so a claim stays UNVERIFIED as before (the reply says "NOT bound" and how to bind). Typed views (u32...) are not a separate
input form: the code gets bytes and can `struct.unpack` them (no bootstrap change, the runtime pin is untouched).
Limitation: if two read_bytes evidence items contain the same bytes, the lowest id is bound, and the claim must cite that one.

Dynamic memory bytes (verifier 13): `{"evidence_id": ev_dyn, "select": {"event": SEQ, "offset": N | "address":
"0x..", "length": M}}` on a `dynamic-observation` evidence hands the code bytes the tracer captured from an executable
region (`offset` from the region base; `event` may be omitted when exactly one event has bytes; `length` defaults to the
rest of the captured bytes). Only captured bytes can be selected (a short capture, an unchanged exit dump or an event
without bytes gives `COMPUTE_INPUT_NOT_IN_RAW` naming what exists). The binding is `{kind:"memrange", evidence_id,
event, offset, va, bytes, sha256}` and is re-derived from the sealed document by the verifier. Without `select` a
dynamic evidence is still a whole-document `raw` input (unbound for value support). Soundness: see evidence-schema §4.8.

Accepted remaining risk: the `compute` permission is permission to run any code inside the Sandbox (native code
included; `subprocess` is possible). Its isolation equals `run_controlled`; the target binary is not staged. That is why it
is a separate permission that is off by default (§6).

## 5. Evidence semantics (verifier version 7; input kinds `range`/`literal`: version 11; `memrange`: version 13)

Record: `authority=sandboxed-computation`, `confidence=derived`, `operation=compute`, `environment.isolation=windows-sandbox`,
`coverage.relationship=unknown` (never backs an absence claim). Raw blob = stdout. `parameters`: `language`,
`code_sha256` (code kept in CAS; re-runnable), `code_bytes`, `inputs[]` (`name`, `evidence_id`, `kind`, `authority`,
`sha256`, `bytes`, `quote`/`const`; for `kind=range`: `va`, `auto`; `kind=literal`: `evidence_id=null`), `runtime` (`id`, `zip_sha256`, `exe_sha256`, `boot_sha256`), `argv`, `runs=2`,
`timeout_ms`, `max_output_bytes`. `result`: `exit_code=0`, `deterministic=true`, `runs`, `output_sha256`, `stderr_sha256`.
`evidence_links` = input evidence. Duration and run_id are not part of the id: same code + inputs + runtime + output =
same `ev_` (checked by a test).

Determinism: two independent processes in one session with the same stdin; stdout, stderr and exit code must be
byte-identical. Otherwise `NONDETERMINISTIC` and NO evidence is written (options: reject 5 / record as "nondeterministic" 2;
a recorded record that supports nothing is only noise, and the model sees the error and fixes the code). String hash
randomization is on (`-I` ignores `PYTHONHASHSEED`); two processes get different seeds, so set-order dependence is very
likely caught. Limit: one session, one machine; a fault shared by both runs (e.g. time zone) is not caught.

Verifier rules (`evidence/compute.py`, `evidence/verifier.py`; schema `docs/design/evidence-schema.md` §4.8):
1. Record consistency (every verification, `report_build` included): isolation allowed (`COMPUTE_NOT_ISOLATED`),
   `deterministic` and `runs >= 2` (`COMPUTE_NONDETERMINISTIC`), output hash / exit code and code blob
   (`COMPUTE_RECORD_INVALID`), every input re-derived from its evidence and its SHA-256 compared (`COMPUTE_INPUT_MISMATCH`).
   Broken record: the claim is REJECTED.
2. `COMPUTE_ONLY`: a claim that rests only on compute evidence is REJECTED (a computation is not evidence about the target).
3. Value support only in a `kind=observation` + `polarity=present` claim and only from a BOUND compute record: complete
   (strength full) and EVERY input from `shipped-artifact` evidence that the claim cites. The supported value carries
   `"support":"computation"`. The claim is at most SUPPORTED (`PROVEN_STATIC_CLAIM` if PROVEN is requested). This is the
   ceiling and condition of the `derivation` atom (§4.7.2); the difference is that the arithmetic runs in the Sandbox, not
   in the verifier.
4. A value in an unbound compute output: `VALUE_COMPUTE_NOT_BOUND` (UNVERIFIED) in an observation claim; a `0x` literal in
   the text is `HEX_LITERAL_UNSUPPORTED` (REJECTED) under the existing rule.
5. Behavior claims: compute supports nothing (`VALUE_DERIVED_NEEDS_EXECUTION`, `BEHAVIOR_NEEDS_EXECUTION`); it is not
   `controlled-replay`, so it counts neither for PROVEN nor for the output binding (`PROVEN_NEEDS_OBSERVED_OUTPUT`). The
   intended path: compute finds a candidate -> `run_controlled` tries it on the target -> the behavior claim is bound to the
   execution output (tested end to end).
6. Compute evidence cannot be a `derivation` leaf (leaves are `shipped-artifact` only).
7. (version 11) A `range` input (explicit or auto-bound) is re-derived from its evidence (address + length) and its SHA-256
   compared; it counts as bound when that evidence is cited and static. A `literal` input has no evidence id, so the record is
   valid but never bound. Records with only `raw`/`quote`/`const` inputs verify identically to version 10.
Claims that cite no compute evidence verify exactly as in version 6 (the version 5 golden corpus passes unchanged).

Remaining meaning limit: the verifier does not know whether the code models the target CORRECTLY; it only makes "this
code gives this output on these inputs" reproducible. Hence the SUPPORTED ceiling and the `support: computation` marker;
the report template does not print that distinction in a separate section yet (OPEN, same as §4.7.2).

## 6. MCP surface and permission

| Option | Clarity for the model | Permission separation | Tool-count cost | Code risk |
|---|---|---|---|---|
| **New `compute` tool (chosen)** | clear | clean | one more tool | low |
| `run_controlled(mode="compute")` | muddled | weak | none | high |

Extending `run_controlled` keeps the tool count but puts two meanings (observe the target / your own computation) into
one tool: evidence kind, inputs and permission would change by mode, and the model could pick the wrong one. The tool
count stays well below the cap.

Effect: new flag `executes_model_code` -> manifest operation `compute` (only that). `launches_process`/`writes_files` are
also allowed by `compute`. Result: `compute` is OFF BY DEFAULT; the `run_controlled` permission does not enable `compute`,
and `compute` does not allow running the target (tested). Manifest: `"allowed_operations": ["static", "compute"]`.

## 7. Test status

Unit (`tests/unit/test_compute.py`, fake sandbox; the fake guest runs the real bootstrap with the test host's Python, and
the only code it runs is test code): default deny without touching the sandbox, effect-table separation, pinned install
and tamper detection, explicit error when not installed, evidence fields and input binding, re-run = same `ev_`, timeout
is an explicit error, output cap, exception + traceback, determinism rejection, input-binding refusals, verifier
semantics (bound observation SUPPORTED with `support: computation`, compute alone REJECTED, unbound UNVERIFIED, never for
behavior, tampered record REJECTED), and the compute -> `run_controlled` -> PROVEN flow.

Not covered by the unit tests:
- The embeddable CPython starting inside the real Windows Sandbox as the separate low-IL user, its timings and determinism
  (`tests/heavy/test_compute_real.py`, marked `real_sandbox`).
- There is no separate CPU quota.
