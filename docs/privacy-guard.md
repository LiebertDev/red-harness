# Privacy guard

The repo must contain no personal information (Windows user profile path, email address) and no secrets (API keys, tokens, private keys).

- Placeholders: `<HOME>`, `<REPO>`, `<RH_DATA_ROOT>`, `<IDA_DIR>`, `<GHIDRA_DIR>`, `<SCRATCH>`, `<REDACTED_EMAIL>`.
- The guard scans tracked files for personal paths, email addresses and secrets. Code reads an environment variable instead of a hard-coded local path, and optional local data directories are configured by environment variables.
- Third-party binaries are not tracked; keep samples and test targets outside the repository and refer to them by SHA-256 plus a source reference.
- Test: `tests/unit/test_no_personal_info.py` (`git ls-files` scan; allowlist: `users.noreply.github.com`, `example.com`).
- Pre-commit: `.githooks/pre-commit` performs the same check on staged files. Enable (once per clone):
  `git config core.hooksPath .githooks`
- Test and benchmark binaries (`RH_BENCH`, default `<RH_DATA_ROOT>/bench`) do not enter the repo; if you keep a record of them, keep only a manifest of SHA-256 digests.
