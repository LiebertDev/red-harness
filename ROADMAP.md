# Roadmap

No dates. An item is built when someone has a measured need for it; open an issue with the evidence (see
`CONTRIBUTING.md`). This list covers the Core edition only.

## Planned when asked for

- **Linux and macOS for the static tools.** The server, the evidence ledger, the verifier, the report and the static tools
  (`functions_list`, `strings`, `xrefs`, `decompile`, `disassemble`, `read_bytes`, `file_strings`, `imports`) currently
  target Windows hosts and PE images. Support for other hosts and executable formats will be built when a real user asks
  for it. `run_controlled` and `compute` need Windows Sandbox and stay Windows-only.

## Considered, not scheduled

- **More precise dataflow around exception handlers.** `dataflow_slice` marks values non-definite in functions whose
  exception handlers it cannot model. Parsing the C++ and x86 handler tables would restore precision there.
- **A stronger boundary for `emulate`.** The emulator runs in a restricted host process (see `SECURITY.md`). Running the
  same request inside Windows Sandbox would give an isolation boundary with the same request and evidence format.
- **Tested IDA Home and Classroom support.** These editions are listed by the vendor as shipping `idalib` since 9.4 and are
  not yet tested here.
