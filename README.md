# Red Harness

An evidence-bound static reverse-engineering harness for binaries **you own or are authorized to test**.

It is an MCP server (`rh mcp`, stdio) with 18 tools: static analysis through an IDA or Ghidra engine
(functions, strings, xrefs, decompile, disassemble, raw byte and raw string reading), controlled execution in Windows Sandbox when the
scope manifest allows it, a sandboxed `compute` tool for the model's own Python, and fix verification. Every claim a
model records has to cite evidence ids, quotes and addresses; a claim verifier checks them against the
evidence ledger and rejects or downgrades claims it cannot support. Behavior claims are proven only by a controlled run,
not by a value appearing in code. Whatever was not examined is reported as unknown, never as "clean".

Design notes are in `docs/design/`, the tool surface is in `docs/usage-mcp.md` and `docs/tool-design.md`, and the
privacy rules for tracked files are in `docs/privacy-guard.md`. Third-party attributions: `NOTICE`; optional third-party components and their licences: `THIRD_PARTY_NOTICES.md`.

## How is this different
Tool-wrapper MCP servers give an agent reverse-engineering tools and pass the tool output through; nothing checks what the
agent then says about the binary. Red Harness adds that check:
- **Every claim is verified against recorded evidence.** A claim cites evidence ids, quotes and addresses. A deterministic
  verifier (no model) re-checks each one against the evidence ledger and rejects or downgrades what the evidence does not
  support. Every status and reason it can give is listed in [`docs/verifier-messages.md`](https://github.com/LiebertDev/red-harness/blob/main/docs/verifier-messages.md).
- **Behavior is proven only by a run.** "This input is accepted" is never read off the code: it needs a controlled run of the
  target, and static evidence alone leaves such a claim unverified.
- **Targets run in Windows Sandbox.** Native execution of the target happens only there (network off, output records
  authenticated), and only when the scope manifest allows it.
- **Unexamined is unknown.** What was not looked at is reported as an unknown with its coverage, never as "clean".

## Quickstart in 5 minutes
Install the `red-harness-core` package (the command it installs is `rh`; Python 3.12 on Windows):
```
pipx install red-harness-core
rh deps list                       # is Ghidra found? if not: rh deps show ghidra; it needs a JDK 21
rh quickstart C:\Windows\System32\notepad.exe
```
From a checkout instead: `pipx install .` (or build a wheel with `python -m build --wheel` and install the file from `dist`).
No model and no API key needed. `rh quickstart` checks the prerequisites, writes a scope manifest for the file (use a file you
own or are authorized to analyse), opens it with Ghidra (else IDA), runs a small static pass through the same code path as the
MCP tools, records two example claims that quote real evidence, builds the report and prints where it is, a short summary and
how to connect Claude Code or another MCP client. The first open runs the engine's analysis once (133 s for notepad.exe with
Ghidra 12.1.3 in our run); a repeat run is served from the cache (1 s).

## Demo
Real output of `rh quickstart C:\Windows\System32\notepad.exe --engine ghidra` (Ghidra 12.1.3, Windows 10; the data folder
path is shown as `<DATA_ROOT>`):
```
Static pass with ghidra (the first open analyses the whole binary once; a cached result is reused later)
  target_open     x86 64-bit, 498 functions, 557 strings, protection NO_KNOWN_INDICATORS (140s)
  functions_list  498 functions, evidence ev_04e98a81e9b3894d
  imports         301 symbols from 28 DLLs, evidence ev_7e00c8229285bd85
  strings         100 of 557 returned, evidence ev_c01e6dbb5a5ea895
  claim_add       SUPPORTED: The target imports GDI32.dll!CreateDCW at 0x140026800.
  claim_add       SUPPORTED: The target contains the string Unknown exception at 0x1400273d0.

Summary
  target     notepad.exe, entry 0x140023bd0, sha256 da5807bb0997cc6b...
  pe profile PE32+ x64 windows_gui 7 sections aslr=yes dep=yes cfg=yes
  claims     2 recorded, 2 verified by the claim verifier
  report     2 findings, 0 hypotheses, 0 unsupported claims in findings (must be 0)
  coverage   NO_RECORDED_GAPS; not 'clean': functions listed 200/498, strings 100/557, nothing decompiled

Report: <DATA_ROOT>\jobs\job_da5807bb0997cc6b\report\report-8d4209bf00e1cef1.md
Total time: 142s
```
The generated report is in [`docs/examples/notepad-quickstart-report.md`](https://github.com/LiebertDev/red-harness/blob/main/docs/examples/notepad-quickstart-report.md); each claim
cites evidence ids and quotes, and the coverage section lists what was not examined. [`docs/examples/README.md`](https://github.com/LiebertDev/red-harness/blob/main/docs/examples/README.md)
explains each section.
## Use from your agent
One command registers the MCP server (the absolute path of the installed `rh`, with the engine it found) in the AI coding
clients on this machine and installs the Red Harness skill, so your agent knows the evidence workflow:
```
rh setup --dry-run                 # shows what would change, with diffs; writes nothing
rh setup                           # applies it; restart the client afterwards
rh setup --client claude-code      # only one client: claude-code, codex, cursor, gemini, claude-desktop
rh setup --print                   # only prints the configuration snippets, touches nothing
rh setup --uninstall               # removes only the red-harness entry and the skill file it installed
```
Claude Code and Codex CLI are configured through their own `claude mcp add` / `codex mcp add`; Cursor
(`~/.cursor/mcp.json`), Gemini CLI (`~/.gemini/settings.json`) and Claude Desktop (`claude_desktop_config.json`, classic or
Microsoft Store install) through their JSON files, merged. The skill goes to `~/.claude/skills/red-harness/` (Claude Code) and
`~/.agents/skills/red-harness/` (Codex CLI, Gemini CLI); `--no-skill` skips it. Every file is copied to
`<name>.rh-backup-<timestamp>` before it changes, existing servers and settings are kept, and a second run changes nothing.
A `red-harness` entry that does not run `rh mcp`, or a skill file you edited, is reported and left alone (`--force`
overrides that).
Then ask your agent, for example: "reverse engineer `C:\path\to\tool.exe`; I own it". Use only binaries you own or are
authorized to test.

## Editions
This repository is the **Core** edition (Apache-2.0). **Pro** is a separate commercial edition. The MCP tool surface (18 tools)
is the same in both; Pro adds capabilities behind the same tools and a few extra commands.

| | Core (this repo, Apache-2.0) | Pro (commercial) |
|---|---|---|
| Static MCP tools (functions, strings, xrefs, decompile, disassemble, `read_bytes`, `file_strings`, `imports`) | yes | yes |
| Evidence ledger, claim verifier, report | yes | yes |
| Ghidra and IDA engines | yes | yes |
| `run_controlled` and `compute` in Windows Sandbox | yes | yes |
| Protection diagnosis (including vendor attribution) | yes | yes |
| Check inventory (candidate protection / licensing checks in `target_open`) | yes | yes |
| Dynamic observation (`run_controlled(observe=...)`: API trace, executable-memory digests) | no | yes |
| Job bundle export and import (`rh export`, `rh import`) | no | yes |
| Vendor audit pack (driver facts in `target_open`, driver/service/bundle/workspace triage scripts) | no | yes |
| Evaluation and benchmark suite (`rh eval`, `rh bench`) | no | yes |
| Kernel / Phase 2 lab | no | yes |
| Studio UI | no | planned |

In the Core build the Pro-only entry points answer in a fixed way: `run_controlled` with `observe` returns
`DYNAMIC_BACKEND_UNAVAILABLE` ("premium feature not included in this build"), the Pro CLI commands print a premium notice and
exit with status 2, and the driver facts in `target_open` are `{"available": false, "note": "premium feature not included in this build"}`.
To ask about Pro: open a thread in [GitHub Discussions](https://github.com/LiebertDev/red-harness/discussions).

## Requirements
- **Windows 10 or 11, 64-bit** (developed and tested on Windows 10 Pro). The server, the engines and every static tool run
  on any edition.
- **Python 3.12** (`py -3.12`). The only runtime dependency is the `mcp` SDK, pinned and installed by pip.
- **One analysis engine: Ghidra (free) or IDA Pro** (see "Engines"). No MCP tool works without an engine, because
  `target_open` opens the target through it.
- **Windows Sandbox, only for the two tools that execute the target natively or run model code** (`run_controlled` and
  `compute`). Windows Sandbox is part of Windows 10/11 **Pro, Enterprise and Education** (not Home); it needs hardware
  virtualization enabled in the firmware and the optional Windows feature "Windows Sandbox" switched on (restart
  required). Without it those two tools return `SANDBOX_UNAVAILABLE` and everything else keeps working. The sandbox gets
  2048 MB of memory by default (`RH_SANDBOX_MEMORY_MB`, 512 to 16384). `emulate` also executes target code, but in a CPU
  emulator inside a restricted host process, not in Windows Sandbox; it is off by default.
  - `compute` also needs a pinned embeddable CPython, installed once: `rh compute-runtime` prints the download address and the
    expected SHA-256, then `rh compute-runtime install python-3.12.10-embed-amd64.zip`.
- Memory: the Ghidra engine runs a JVM with a 4 GB heap (6 GB job limit); the IDA engine is limited to 6 GB as well.

## Optional components
Red Harness bundles **no** third-party engine or library. The optional pieces are obtained by you, from their own
publishers, under their own licences, and none of them is covered by Red Harness's Apache-2.0 licence:
Unicorn (`emulate`), Capstone, Ghidra, IDA Pro/Home, the CPython embeddable package for `compute`, and Windows Sandbox.
See `THIRD_PARTY_NOTICES.md` (what each is for, how to get it, its licence and upstream link) and `licenses/README.md`.

`rh deps list` shows each component, whether it is present, its licence and its upstream link. `rh deps install emulate`
(or `capstone`) prints the licence notice, asks for confirmation (`--yes` skips the question) and then runs
`pip install` for the pinned version; it installs nothing else. Ghidra and IDA are never installed by `rh`: `rh deps show ghidra`
prints where to get them and which environment variable points Red Harness at them.

## Engines
Every MCP tool needs an analysis engine; choose one with `rh mcp --engine ghidra` or `rh mcp --engine ida`. Without the flag
the server starts the IDA engine. A requested engine that is not usable stops the server with the reason on stderr and in the
error answer to the client's `initialize` request; there is no silent fallback to the other engine.

**Ghidra (free).**
1. Ghidra 12.1.3 (the version this project is tested with): download the zip from
   <https://github.com/NationalSecurityAgency/ghidra/releases> and extract it anywhere.
2. A JDK 21 (for example Eclipse Temurin 21), with `java` on `PATH` or `JAVA_HOME` set. Check with `java -version` in a new terminal.
3. Tell the server where Ghidra is: set `RH_GHIDRA_DIR` (or `GHIDRA_INSTALL_DIR`) to the extracted folder, the one that
   contains `support\analyzeHeadless.bat`. Without either variable the server looks for `ghidra_*` on your Desktop, for `ghidra*` in
   your user folder and in `%ProgramFiles%`, and for `C:\ghidra*` (newest name first).
4. Start the server with `rh mcp --engine ghidra`. The first open of a target runs Ghidra's full analysis once (minutes for a
   large binary; about two and a half minutes for a 200 KB system program on a desktop PC); the result is cached under the data
   root and later opens and queries reuse it.

**IDA.** IDA 9.x with a licence that includes `idalib` (IDA's headless library): the Pro editions. IDA Home and Classroom are listed by Hex-Rays as shipping idalib since 9.4; not yet tested by us. The Python package `idapro` that
talks to it is deliberately not a dependency of this project (its publisher on PyPI is unverified); install it from the wheel in
your IDA installation into the same environment as `red-harness-core`:
```
.venv\Scripts\pip install "<IDA>\idalib\python\idapro-0.0.9-py3-none-any.whl"
```
(With a `pipx` install: `pipx inject red-harness-core "<IDA>\idalib\python\idapro-0.0.9-py3-none-any.whl"`.)
`<IDA>` is for example `C:\Program Files\IDA Professional 9.4`. Use the exact file name you find in that folder (`dir "<IDA>\idalib\python"`);
pip does not accept a `*` wildcard there. Do not run `py-activate-idalib.py`. The IDA folder is found automatically under
`%ProgramFiles%\IDA Professional*` or from `RH_IDA_DIR` / `IDADIR`. The engine runs IDA in a separate Python process; if that
Python is not the one with `idapro`, set `RH_IDA_PYTHON` to it. Without `idapro`, `target_open` fails with `TOOL_MISSING` and
a message that says exactly this.

**What works without any engine:** none of the 18 MCP tools. The standalone scripts in `scripts/` need no engine and execute
nothing (see "Standalone static CLIs"), and so does `rh compute-runtime`.

## Quickstart
This walk-through uses Ghidra and runs the same calls a model makes, from a small Python client that ships with the project.
Use a program you built or are authorized to analyze; below it is `C:\path\to\target.exe`.
```
py -3.12 -m venv .venv
.venv\Scripts\pip install -e .
set RH_GHIDRA_DIR=C:\path\to\ghidra_12.1.3_PUBLIC
```
(`set` is for cmd.exe; in PowerShell use `$env:RH_GHIDRA_DIR = "C:\path\to\ghidra_12.1.3_PUBLIC"`. Skip it if Ghidra sits in one
of the folders listed under "Engines".)
1. SHA-256 of the target, lowercase (the manifest rejects upper case):
   ```
   powershell -NoProfile -Command "(Get-FileHash 'C:\path\to\target.exe' -Algorithm SHA256).Hash.ToLower()"
   ```
2. Write the scope manifest `scope.json` next to it. The hash binds the manifest to this exact file; `basis` is `owner` or
   `authorized-test`; `allowed_operations` lists what the session may do (`static` is the minimum; `run_controlled` and
   `compute` must be added explicitly); an optional `"expires": "2027-12-31"` limits its lifetime.
   ```json
   {
     "schema": "rh.scope/1",
     "target_sha256": "<the lowercase hash from step 1>",
     "authorization": {
       "declared_by": "Your Name / Your Company",
       "basis": "owner",
       "statement": "This binary belongs to us; static analysis is authorized."
     },
     "allowed_operations": ["static"]
   }
   ```
3. Run the client (first open: Ghidra analyses the target once):
   ```
   .venv\Scripts\python scripts\quickstart_client.py C:\path\to\target.exe scope.json --engine ghidra
   ```
   It starts `rh mcp --engine ghidra`, lists the tools and makes five calls: `target_open(target_path, manifest_path)`,
   `strings(limit=20, detail="full")`, `claim_add(kind="observation", text, evidence_ids, atoms)` quoting the first string it got
   back, `coverage()` and `report_build()`. It ends with the path of the Markdown report, under
   `<data root>\jobs\<job id>\report\`. A model client makes exactly these calls with the arguments named above; the
   `claim_add` atoms are `{"type":"quote","evidence_id":"ev_...","text":"<string>"}` and
   `{"type":"address","evidence_id":"ev_...","value":"0x..."}`.

## Connect an MCP client
Use absolute paths. The server needs the engine settings in its environment.

Claude Code: copy `.mcp.json.example` to `.mcp.json` in your project folder, replace the placeholder paths, start Claude Code and
approve the `red-harness` server with `/mcp`.
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
Any other stdio MCP client: run the command `C:\path\to\red-harness\.venv\Scripts\rh.exe` with the arguments `mcp --engine ghidra`
and the environment variables above. The protocol runs over the process's stdin and stdout (one JSON-RPC message per line), so
nothing else may write to stdout. `scripts/quickstart_client.py` is a complete example client built on the official `mcp` SDK.
The server side was verified with that SDK client; the client entries above follow those clients' documented formats.

If a client only says "connection closed", start the same command in a terminal: the reason is printed on stderr.

## Development and tests
Install with the test extra and run the default suite (no engine and no Windows Sandbox needed):
```
py -3.12 -m venv .venv
.venv\Scripts\pip install -e .[dev]
.venv\Scripts\python -m pytest -m "not heavy"
```
- `heavy` tests need a real Ghidra/IDA or Windows Sandbox; they are not part of the default run.
- Unit tests point `RH_DATA_ROOT` at a temp directory; `RedHarnessData` or any other directory need not exist beforehand.
- Real Windows Sandbox tests run only with `RH_ALLOW_REAL_SANDBOX=1` (otherwise skipped).
- Engine paths and the `idapro` install are described under "Engines" above and in `docs/usage-mcp.md`.

## Standalone static CLIs
Read-only helper in `scripts/` that needs no engine, no Windows Sandbox and executes nothing: `file_strings.py` (it prints its usage in its module docstring).

## Scope
Use it only on targets you own or are explicitly authorized to test. The scope manifest is required, binds the target
SHA-256 and lists the effects (for example `run_controlled`, `compute`) a session may use.
