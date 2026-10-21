# MCP tool design principles

These principles are written for Red Harness's evidence/claim model. For usage see `docs/usage-mcp.md`, for the evidence schema `docs/design/evidence-schema.md`.

## 1. Before adding a tool
- Start from the analyst's question; look at the closest existing tool. If the intent and result contract are the same, extend
  that tool (e.g. `detail`); add a new one only if a different result or a different permission is needed.
- Tool count is context cost: `MAX_TOOLS=20` is enforced by a test; the server currently registers 18 tools (`TOOL_NAMES` is the single source).
- Name a tool by action and object (`disassemble`, `unknown_record`); do not mix discovery, execution and modification in one tool.

## 2. Contract
- Strict input: explicit target identity (SHA-256 in the session), addresses as hex strings (`"0x140001250"`), no needless options.
- Every target-derived output is an `ev_` evidence record; the response carries source addresses, coverage and limitations. Target
  text is given in an `<untrusted_target_content>` block, with `untrusted_content: true`.
- Observed / derived / inferred stay separate (`confidence`). Truncated, partial or timed-out output is never counted as complete
  (`strength`); error messages are short and tell the model what to do.
- **Missing coverage is unknown, not absence.** Use `unknown_record` instead of guessing; what was examined is read from the ledger
  via `coverage`; the report never says "clean" with missing coverage.
- A limit is set only for a real format/permission/measured-resource constraint; when a limit is exceeded, the truncation is
  reported explicitly (`next_offset`, `next_address`, `limitations`).

## 3. Large output
- Do not silently truncate a response: `detail: "summary" | "full"` and pagination. `summary` gives a short summary + preview + `ev_`;
  the full evidence stays in the ledger (the id is the same in both modes; calling again with `full` does not re-run the engine).
  The preview is also target text and comes in the marked block.

## 4. Effects and permission
- Each tool's effect flags are kept explicitly in a table (`src/redharness/mcp/effects.py`): reads/writes files, starts processes,
  runs foreign code, network, modifies the target, appends to the session record, idempotent or not.
- The permission decision derives from the table, not from a tool's own `if`: every open effect is bound to an operation in the scope
  manifest (`run_controlled`, `patch_poc`); an effect with no counterpart (network) is opened by no manifest. A tool not in the table
  is rejected. Rejected calls are logged and visible via `coverage.denied_calls`.
- MCP hints (`readOnlyHint`, `idempotentHint`, `openWorldHint`) must be consistent with the table (tested).
- Running the operator-configured analysis engine does not count as an effect; running the target does.

## 5. Lifecycle and verification
- A tool that acquires a resource must have a clear owner and release observation; cleanup success must not override the primary result.
- A real engine/sandbox claim is made only by a real engine/sandbox test; fake-engine tests do not prove it
  (mark such claims UNVERIFIED). When discoverability changes, evaluate with a real model on broad, direct and negative
  tasks; schema validity does not show tool-selection success.
