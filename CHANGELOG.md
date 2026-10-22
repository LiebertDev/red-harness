# Changelog

All notable user-facing changes. The project follows [Semantic Versioning](https://semver.org/); the format follows
[Keep a Changelog](https://keepachangelog.com/).

## 0.1.0 - first public release

The Core edition (Apache-2.0): an MCP server with 18 tools, an evidence ledger, a deterministic claim verifier and a
report builder, on top of a Ghidra or IDA engine. Windows 10/11, Python 3.12.

### Added
- **Quickstart.** `rh quickstart <binary>` checks the prerequisites, writes a scope manifest for the file, opens it, runs a
  small static pass through the same code path as the MCP tools, records two example claims that quote real evidence and
  builds the report. No model and no API key. A real report is in `docs/examples/`.
- **`rh setup` and the agent skill.** One command registers the MCP server in Claude Code, Codex CLI, Cursor, Gemini CLI
  and Claude Desktop and installs the Red Harness skill that teaches the agent the evidence workflow. `--dry-run` shows
  diffs, `--print` only prints the snippets, `--uninstall` removes only what `rh setup` added; every changed file is backed
  up first and a second run changes nothing.
- **CI.** Unit tests on Linux and Windows for pushes to `main` and for pull requests (actions pinned by commit SHA).
- **Core-only wheel check.** `scripts/check_wheel.py` fails if a built wheel contains an optional (Pro) module or a file that
  is not in the source tree.
- **Dataflow: exception handlers.** `dataflow_slice` no longer reports a value as definite in a function whose exception
  handlers it cannot model (x64 unwind data, x86 SEH/C++ EH registration, including statically linked prolog helpers that the
  engine left unnamed). Such values are marked non-definite with the reason, and the coverage says so.
- **IDA decompile timeout.** With IDA 9.5 and later `decompile` stops at a decompiler budget and returns
  `DECOMPILE_TIMEOUT` instead of occupying the engine until the process is killed. `RH_IDA_DECOMPILE_TIMEOUT` (seconds) sets
  the budget.
- **Engine error codes.** Engine failures a model can act on use one closed set of codes, identical for IDA and Ghidra
  (`NO_FUNCTION_AT_ADDRESS`, `NAME_NOT_RESOLVED`, `OUT_OF_IMAGE`, `DECOMPILE_FAILED`, `DECOMPILE_TIMEOUT`,
  `DECOMPILER_UNAVAILABLE`); the message says what to try next.
- **Check inventory.** `target_open` lists candidate protection and licensing checks in eight categories (licence/key
  validation, anti-debug, anti-VM, self-integrity, machine id, signature verification, time/trial, network activation),
  each with the evidence it rests on. Candidates are observations, not proof that a check runs; an empty result over a
  capped or unreadable scan is `UNKNOWN`, never "no checks".
- **Unknown resolution.** `unknown_record(resolves=<unknown id>, status="resolved" | "withdrawn")` closes an earlier unknown
  with the evidence that answers it, or with a reason. Nothing is deleted.
- **JSON report.** `report_build` also writes a machine-readable report (`rh.report/1`, schema in `docs/schema/`) from the
  same document as the Markdown report.
- **Original/fixed build diff.** `functions_list(compare="fixed")` returns a function-level static diff between the original
  build and the fixed build given to `target_open`.
- **Engine disagreement.** `functions_list(engines="both")` runs the function inventory on IDA and Ghidra and lists where
  they disagree (same start with a different end, a function only one engine defines, a function one engine split or
  merged, different names), each row citing both engines' evidence; `report_build` adds an "Engine disagreement"
  section. If only one engine is installed the reply says nothing was compared.
- **Tool availability report.** `target_open` and `coverage` list which tools are usable for the open target and, for each
  unavailable one, why (scope, target, edition, platform, extra package, engine, runtime, sandbox) and the error code a call
  would return; a `next` hint names the usual next tool.
- **Verifier messages.** `docs/verifier-messages.md` lists every claim status and reason code the verifier can emit and how to
  fix it.

### Changed
- **Verifier 24 (affects `claim_add` callers).** Every behavior claim declares `behavior_class`
  (`"acceptance_validation"` or `"ordinary"`); without it the claim stays `UNVERIFIED` (`BEHAVIOR_CLASS_MISSING`). A claim that an
  input is accepted or rejected needs a `control_pair` atom: two complete runs of the same build whose inputs differ only
  in the named discriminator and whose outcomes differ, with the claim naming the input of the side it asserts. Claims stored as
  `SUPPORTED` or `PROVEN` under an earlier verifier version are re-verified by `report_build` and can move to `UNVERIFIED`.

### Known limits
- Static tools run on Windows only; Linux and macOS are listed in `ROADMAP.md`.
- `emulate` runs the target's code in an emulator inside a restricted host process; read `SECURITY.md` before enabling it.
- Dynamic observation (`run_controlled(observe=...)`, `captured_region`), job bundles, the vendor audit pack, the evaluation
  suite and the kernel lab are not part of the Core edition; those entry points answer that they are unavailable.
