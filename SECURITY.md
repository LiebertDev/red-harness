# Security policy

## Reporting a vulnerability

Report privately with GitHub's "Report a vulnerability" form on the Security tab of this repository. Do not open a public
issue for a vulnerability. Please include the `rh version` output, the engine, the Windows version, and the smallest steps
or files that reproduce it (a target binary, a scope manifest, the exact tool call). Do not send binaries you are not allowed
to share.

This is a small project: reports are read and answered on a best-effort basis, with no fixed response time. Only the latest
release is supported.

What counts as a vulnerability here, besides the usual:

- a claim the verifier marks `SUPPORTED` or `PROVEN` that the cited evidence does not support (a false accept);
- a way for a target or its output to make a tool run something the scope manifest does not allow, or to write evidence
  that was not produced by the recorded tool call;
- an escape from the isolation described below.

Not in scope: findings about the analysed binaries themselves, and the third-party tools Red Harness drives (Ghidra, IDA,
Unicorn, Windows Sandbox); report those to their publishers.

## Threat model in short

Red Harness is for analysing binaries you own or are authorized to test. The target and everything derived from it are
untrusted data.

- **Scope manifest.** Every session needs a manifest that binds the target by SHA-256 and lists the operations it may use.
  Everything not listed is refused. No manifest can allow the network effect; tools that need it are always rejected.
- **Target content is data.** Tool output that comes from the target is marked untrusted and carries an evidence id. The
  verifier is deterministic code and uses no model, but it checks that quotes, addresses and values are in the cited
  evidence; it does not understand what a quote means.
- **Native execution** (`run_controlled`, `compute`) happens only in Windows Sandbox with the network off. Result records
  are authenticated with an HMAC whose nonce is kept out of any file while the target runs.
- **Static analysis** runs the Ghidra or IDA engine on the host, with memory limits but not in a sandbox. Opening a hostile
  binary relies on the engine's own parsers.
- **`emulate`** is off unless the manifest allows it. It runs one function in a CPU emulator inside a restricted host
  process (Job Object limits, Low integrity token), on Windows only, and never calls the target's imports.

### Documented residual risks

- **The `emulate` worker is not a security boundary.** A Job Object and an integrity level are not a VM. A compromised
  worker can read any file the user can read and can use the network, because reads and network access are not restricted;
  Low-labelled locations stay writable and the process runs as the same user. Enable `emulate` only for targets you would
  also analyse in the engine. See `docs/design/emulation.md`.
- **Output integrity is mitigated, not absolute.** Mapped folders stay writable inside the sandbox, so a target can write
  files to the output folder; those are reported as side effects and never accepted as results. The trust root is the
  secrecy of the nonce, so a sandbox or guest-kernel escape could still forge a record. `PROVEN` means "observed in a
  controlled execution", not that the program was honest. See `docs/usage-mcp.md`.
- **Verifier limits.** The verifier does not know what a quote means: attaching a quote such as "License invalid" to a claim
  about a valid license is not caught. A model's free-text interpretation is not covered by a claim's status.

This document describes the design as implemented; it is not a guarantee beyond what the other documentation states.
