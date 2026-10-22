# Example: `rh quickstart` on notepad.exe

`notepad-quickstart-report.md` is the report that `rh quickstart C:\Windows\System32\notepad.exe --engine ghidra` wrote on
Windows 10 with Ghidra 12.1.3 (analysis about 140 s on the first open). It is the generated file, unedited: nothing was
trimmed and no value was changed. The report itself contains no file-system paths. In the terminal output shown in the
main README, the user-specific data folder is replaced by the placeholder `<DATA_ROOT>`; nothing else is altered.

notepad.exe is a Microsoft program. The report holds only what the harness computed (hash, addresses, counts, two short
strings), no code from the program.

## What each section shows

- **Header.** The SHA-256 of the analysed file (the scope manifest is bound to the same hash), the job id, and the
  verifier's counts: verified findings, hypotheses, and the rejected or dropped claims. "Unsupported claims that reached
  the findings" must always be 0; anything else is a bug.
- **Verified findings.** Each claim has an id, a status (`SUPPORTED` here), the statement, its kind (`observation`: what the
  code or data is; a `behavior` claim would need a controlled run), and the evidence it cites. Evidence ids look like
  `ev_...` and point at a record in the evidence ledger (the tool, its arguments and its full output). The quote is
  copied from the target's output and is untrusted data; the verifier checked that the quoted value really occurs in the
  cited evidence. The address is the one the engine reported (`0x140026800` for the import, `0x1400273d0` for the string).
- **Unverified hypotheses.** Ideas that could not be proven land here and never in the findings. This run has none.
- **Coverage and unknowns.** What was and was not examined. `NO_RECORDED_GAPS` does not mean "clean": the
  lines below it say that only 200 of 498 functions and 100 of 557 strings were listed and that nothing was decompiled.
  Whatever was not examined is unknown, not absent. Open unknowns are questions a model recorded with `unknown_record`.

The job and evidence ids are specific to this run, and a different Windows build of notepad.exe has a different hash and
different addresses.
