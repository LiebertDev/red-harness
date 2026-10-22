# Contributing

Thanks for looking. Bug reports with evidence and small, tested fixes are the most useful contributions. For a
vulnerability, see `SECURITY.md` instead of opening an issue.

## Development setup

Windows 10 or 11 and Python 3.12. No engine and no Windows Sandbox are needed for the default tests.

```
py -3.12 -m venv .venv
.venv\Scripts\pip install -e ".[dev,emulate]"
.venv\Scripts\python -m pytest tests/unit -m "not heavy and not real_sandbox and not hyperv"
```

- Unit tests run on Linux and Windows in CI. Tests marked `heavy`, `real_sandbox` or `hyperv` need a real engine, Windows
  Sandbox or Hyper-V and are not part of the default run.
- Unit tests point `RH_DATA_ROOT` at a temporary folder; nothing needs to exist beforehand.
- Check that you test this checkout and not an installed copy: `python -c "import redharness; print(redharness.__file__)"`
  must print a path under `src`.
- The built wheel must contain Core modules only: `python -m pip wheel --no-deps -w dist .` and then
  `python scripts/check_wheel.py dist --src src`.

## Rules for changes

Red Harness is an evidence tool, so changes are held to the same standard as claims.

- **Evidence first.** A change that claims a behavior (a fix, a new check, a faster path) comes with the test or the
  measurement that shows it. A fake or mock is a regression guard, not proof: a feature that talks to Ghidra, IDA or Windows
  Sandbox needs one real run, described in the pull request.
- **Verifier changes are conservative.** The verifier must fail closed. A change that can turn a rejection into a
  `SUPPORTED` or `PROVEN` needs a test for the false accept it must not allow. If the verifier's behavior changes, bump
  its version constant and update `docs/verifier-messages.md`.
- **New tools only for a measured need,** and wired end to end: MCP registration, scope permission, effect table,
  documentation, tests and a real run. The tool count in the documentation is checked by `tests/unit/test_doc_drift.py`.
- **Errors are explicit.** A failed call returns a code and writes no evidence; it never returns an empty or invented
  result. Unexamined means unknown, never "clean".
- **No secrets, personal paths or sample malware in the tree.** Test fixtures are small synthetic binaries or generated
  bytes. Do not commit third-party binaries.
- Code and documentation are in English. Keep them terse and factual.

## Commits and pull requests

- Short conventional messages in English: `fix:`, `feat:`, `docs:`, `test:`, `chore:`, with an optional scope, for
  example `fix(dataflow): ...`.
- One logical change per pull request, with the tests that cover it. Run the unit tests first.
- The public tree is generated from the maintainers' development tree. An accepted pull request is re-applied there and
  reaches this repository with a later release.

## Reporting bugs and asking for features

Use the issue templates. A bug report needs `rh version`, the engine, the exact tool reply and the evidence ids. A feature
request needs the measured need: what you tried, what failed and how you know.
