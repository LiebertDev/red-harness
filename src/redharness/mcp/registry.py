"""The tool registry: one `ToolSpec` per MCP tool, in the order the tools are listed.

Adding a tool is: one entry here, the `@tool("name")` handler in `server.py`, the Hub method, and a row in
docs/usage-mcp.md (plus the effect table, which is generated from the entries). Everything else is derived from this
table (tool list, effect table, MCP annotations, Studio user-only / execution sets, eval exposure rule and note) or
checked against it (tests/unit/test_tool_wiring.py: registration, doc rows, real-run test, export deny list).

Core module: imports no premium module (a premium tool only names its implementation path).
"""

from __future__ import annotations

from .toolspec import ToolEffects, ToolSpec, validate_specs

_READ = ToolEffects(reads_files=True, mutates_session=True)
_E2E = "tests/heavy/test_mcp_e2e_ida.py::test_end_to_end_license_sample"   # one end-to-end run through the MCP wire

SPECS: tuple[ToolSpec, ...] = (
    ToolSpec("target_open", ToolEffects(reads_files=True, mutates_session=True), read_only=False, exposure="always",
             real_tests=(_E2E, "tests/heavy/test_check_inventory_real.py::test_the_engine_confirms_every_reported_code_location"),
             user_only=True,
             follow_ups=(("functions_list", "list functions"), ("strings", "find text and candidates"),
                         ("imports", "see which APIs it uses"),
                         ("run_controlled", "only way to prove what it does when run"))),
    ToolSpec("functions_list", _READ, read_only=True, exposure="always",
             real_tests=(_E2E, "tests/heavy/test_build_diff_real.py::test_build_diff_finds_the_one_function_the_fix_changed",
                         "tests/heavy/test_engine_disagreement_real.py::"
                         "test_ida_and_ghidra_disagreements_are_classified_and_independently_recounted"),
             follow_ups=(("decompile", "read a candidate"), ("xrefs", "find its callers"))),
    ToolSpec("decompile", _READ, read_only=True, exposure="always",
             real_tests=(_E2E,),
             follow_ups=(("xrefs", "callers and users"), ("dataflow_slice", "origin of a compared value"),
                         ("emulate", "recover a computed value"))),
    ToolSpec("disassemble", _READ, read_only=True, exposure="always",
             real_tests=(_E2E,),
             follow_ups=(("dataflow_slice", "origin of a compared value"), ("xrefs", "callers and users"))),
    # harness slice over the engine's disassembly + the CAS copy: same effects as disassemble
    ToolSpec("dataflow_slice", _READ, read_only=True, exposure="always",
             real_tests=("tests/heavy/test_dataflow_real.py::test_stack_string_matches_raw_store_decoding",),
             follow_ups=(("read_bytes", "check a constant in the file"), ("emulate", "recover a computed value")),
             eval_note=" (where the values a compare reads come from: writes, stack buffers, constants)"),
    ToolSpec("xrefs", _READ, read_only=True, exposure="always",
             real_tests=("tests/heavy/test_dataflow_real.py::test_except_block_is_analysed_through_scope_table_edges",),
             follow_ups=(("decompile", "read the function"), ("disassemble", "see the instructions"))),
    ToolSpec("strings", _READ, read_only=True, exposure="always",
             real_tests=("tests/heavy/test_resume_kill.py::test_mcp_server_killed_mid_call_then_resumed",),
             follow_ups=(("xrefs", "who uses a string"), ("file_strings", "scan the raw file too"))),
    # reads the target PE file (CAS copy), does not call the engine: no new permission needed
    ToolSpec("read_bytes", _READ, read_only=True, exposure="always",
             real_tests=("tests/heavy/test_dataflow_real.py::test_rdata_constant_matches_read_bytes",),
             follow_ups=(("compute", "decode these bytes"),),
             eval_note=" (reads data bytes from the file)"),
    # raw ASCII/UTF-16LE file scan (CAS copy, engine-free, bounded): no new permission needed
    ToolSpec("file_strings", _READ, read_only=True, exposure="always",
             real_tests=("tests/heavy/test_file_strings_real.py::test_entries_reread_from_the_file_and_independent_hits_present",),
             follow_ups=(("read_bytes", "bytes around a hit"),)),
    # PE import/delay-import tables parsed from the CAS copy (engine-free): no new permission needed
    ToolSpec("imports", _READ, read_only=True, exposure="always",
             real_tests=("tests/heavy/test_imports_real.py::test_notepad_imports_match_an_independent_parse",),
             follow_ups=(("xrefs", "callers of an API"),)),
    ToolSpec("run_controlled",
             ToolEffects(reads_files=True, writes_files=True, launches_process=True, executes_foreign_code=True,
                         mutates_session=True, idempotent=False),
             read_only=False, exposure="operation",
             real_tests=("tests/heavy/test_exit_code_atom_real.py::test_recorded_exit_code_is_the_real_one",), operation="run_controlled",
             execution_summary="Runs the target program in the isolated Windows Sandbox (executes foreign code).",
             follow_ups=(("captured_region", "view captured memory"),)),
    # deterministic: same code+input = same ev_
    ToolSpec("compute",
             ToolEffects(reads_files=True, writes_files=True, launches_process=True, executes_model_code=True,
                         mutates_session=True),
             read_only=False, exposure="operation",
             real_tests=("tests/heavy/test_compute_real.py::test_real_sandbox_compute_is_deterministic_and_bound",), operation="compute",
             execution_summary="Runs Python code written by the model in the isolated sandbox.",
             eval_note=" (sandboxed Python over bytes bound to @read_bytes@ evidence)"),
    # bounded worker process on the host; same request = same ev_
    ToolSpec("emulate",
             ToolEffects(reads_files=True, launches_process=True, emulates_target_code=True, mutates_session=True),
             read_only=False, exposure="operation",
             real_tests=("tests/heavy/test_emulate_real.py::test_rtl_compute_crc32_matches_zlib",), operation="emulate",
             execution_summary="Interprets target code in a CPU emulator on this host; nothing is run natively.",
             eval_note=" (runs the target's own code in a CPU emulator on chosen inputs)"),
    # views of bytes a stored dynamic observation captured: reads the stored document only (CAS), runs nothing; it shows
    # target memory, so it needs the memory permission the capture needed (dynamic_memory), not run_controlled again
    ToolSpec("captured_region", ToolEffects(reads_files=True, captures_memory=True, mutates_session=True),
             read_only=False, exposure="operation",
             real_tests=("tests/heavy/test_captured_region_real.py::test_captured_payload_bytes_equal_the_build_output",), tier="pro", premium_module="src/redharness/mcp/region_tool.py",
             impl_modules=("redharness.mcp.region_tool", "redharness.dynamic.region_view"),
             operation="dynamic_memory",
             eval_note=" (hex, strings or disassembly of executable memory a run captured; cite the view "
                       "together with its observation)"),
    ToolSpec("claim_add", ToolEffects(mutates_session=True), read_only=False, exposure="always",
             real_tests=(_E2E, "tests/heavy/test_control_pair_real.py::test_the_pair_verifies"),
             eval_note=" (a behavior claim needs behavior_class; a validation claim, e.g. 'key X is accepted', "
                       "also needs a control_pair atom: one run the program accepts and one it rejects)"),
    ToolSpec("unknown_record", ToolEffects(mutates_session=True), read_only=False, exposure="always",
             real_tests=(_E2E,)),
    ToolSpec("coverage", ToolEffects(), read_only=True, exposure="always",
             real_tests=(_E2E,)),
    ToolSpec("report_build", ToolEffects(mutates_session=True), read_only=False, exposure="always",
             real_tests=(_E2E,)),
)

validate_specs(SPECS)

SPEC_BY_NAME: dict[str, ToolSpec] = {s.name: s for s in SPECS}
TOOL_NAMES: tuple[str, ...] = tuple(s.name for s in SPECS)


def spec(name: str) -> ToolSpec:
    """The spec of `name`; an unknown tool raises KeyError (a handler without a spec cannot be registered)."""
    try:
        return SPEC_BY_NAME[name]
    except KeyError:
        raise KeyError(f"tool {name!r} has no ToolSpec in mcp/registry.py") from None
