# Verifier messages

What `claim_add` (and `report_build`, which re-verifies every `SUPPORTED` or `PROVEN` claim) can tell you, what each message means and how to fix
it. The verifier is deterministic code, not a model; it decides the status, never the agent. This page describes verifier
version 24. The rules behind it are in `docs/design/evidence-schema.md`.

## Claim statuses

| Status | Meaning |
|---|---|
| `UNVERIFIED` | Recorded, but not backed. It goes to the report's hypotheses section, never to the findings. Either you asked for it (`requested="UNVERIFIED"`: no evidence is looked at), or the evidence fell short; the `issues` say how. |
| `SUPPORTED` | Every quote, address, value and technical term of the claim was found in the cited evidence. Static evidence, computations, derivations, emulation and dynamic observation alone never go beyond this. An `absent` claim never goes beyond this. |
| `PROVEN` | A `behavior` claim (what the program does when run) backed by a complete, isolated `run_controlled` run, with the result tied to that run's own output. Nothing else is `PROVEN`. |
| `REJECTED` | The claim contradicts or misuses the evidence (wrong quote, address outside the evidence, broken record, ...). `accepted` is `false`, and it never reaches the report. |

`kind` is `observation` (what the code or data is; alias `static_fact`) or `behavior` (what the program does when run;
also `runtime_behavior`, `bypass_poc`, `fix_verification`). Any other value is a `BAD_ARGUMENT`. A claim sent as
`observation` whose text asserts program behavior ("the password is correct") is treated as behavior
(`KIND_OVERRIDDEN_TO_BEHAVIOR`).

If `requested="PROVEN"` is not reached for an `observation` (or for a behavior claim that a dynamic observation backs),
the status is `SUPPORTED` and the missing conditions are listed as `DOWNGRADE` issues (nothing is silent). A `behavior`
claim without a complete controlled run is `UNVERIFIED`, not `SUPPORTED`, whatever was requested.

## How a reply reads

`claim_add` returns `status`, `accepted`, `issues`, `values_supported` / `values_unsupported` (with a reason each),
`terms_unsupported`, and a short `message`. Each issue is `{code, severity, detail}`:

| Severity | Effect |
|---|---|
| `REJECT` | The claim is `REJECTED`. |
| `UNVERIFY` | The claim stays `UNVERIFIED`. |
| `DOWNGRADE` | `PROVEN` was requested and not reached; the claim is `SUPPORTED`. |
| `CAP` | A behavior claim is `SUPPORTED` through a dynamic observation; the code says why it is not `PROVEN`. |
| `INFO` | Added by the ledger; the code explains a cap or a kind change. |

`checks` is a list of `{code, ok}` pairs and is informational; see the end of this page.

## Evidence problems (`REJECTED`)

| Code | Meaning | Fix |
|---|---|---|
| `NO_EVIDENCE` | The claim cites no evidence id. | Cite `ev_` ids from tool output, or send `requested="UNVERIFIED"` for a hypothesis. |
| `UNKNOWN_EVIDENCE_ID` | A cited id is not in this job's ledger. | Use an `ev_` id a tool returned in this job. |
| `EVIDENCE_FAILED` | The cited evidence is a timeout, memory-limit or error result; it supports nothing. | Redo the step and cite the new id. |
| `SUBJECT_SHA_MISMATCH` | The evidence is about another binary than this job's target. | Cite evidence from this job. |
| `EVIDENCE_INVALIDATED` | A cited evidence was invalidated. | Redo the step and cite the new id. |
| `EVIDENCE_ID_MISMATCH`, `EVIDENCE_NOT_MARKED_UNTRUSTED`, `RAW_BLOB_HASH_MISMATCH` | The stored evidence record is corrupt, edited or malformed (the id, the untrusted marker or the raw output hash does not check out). | Not fixable by the agent: reopen the target and redo the step. If it repeats, report it. |
| `COMPUTE_NOT_ISOLATED`, `COMPUTE_NONDETERMINISTIC`, `COMPUTE_RECORD_INVALID` | The `compute` record is not an isolated, deterministic computation with a consistent record. | Run `compute` again; make the code deterministic. |
| `COMPUTE_INPUT_MISMATCH` | An input recorded in the `compute` evidence no longer re-derives from the evidence it came from. | Run `compute` again. |
| `COMPUTE_ONLY` | Only `compute` evidence is cited. A computation is not evidence about the target by itself. | Also cite the static evidence the computation's inputs came from. |
| `INFERRED_ONLY` | All cited evidence is analyst inference. | Cite evidence a tool actually observed. |
| `EMULATION_RECORD_INVALID` | The `emulate` record is not a deterministic, non-native emulation with its request recorded. | Run `emulate` again; if it errors, record an unknown. |
| `REGION_VIEW_INVALID` | A `captured_region` record is not tied to an intact dynamic observation of this target (Pro), or claims more than that observation. | Call `captured_region` again on a valid observation. |
| `REGION_VIEW_PARENT_NOT_CITED` | A `captured_region` evidence is cited without the observation it was taken from (Pro). | Also cite that observation's id (named in the detail). |
| `DYNAMIC_OBSERVATION_INVALID`, `DYNAMIC_INTEGRITY`, `DYNAMIC_IDENTITY_MISMATCH`, `DYNAMIC_NOT_ISOLATED` | A dynamic observation record (Pro) is malformed, unsealed, belongs to another target or scope, or was not taken in an isolated environment. | Run `run_controlled(observe=...)` again. |
| `ABSENCE_WITHOUT_COMPLETE_COVERAGE` | `polarity="absent"`, but a cited evidence does not have complete coverage (truncated, partial, or a dynamic observation). | Do not claim absence; record an unknown with `unknown_record`, or cite complete-coverage evidence. |

## Atom problems (`REJECTED`)

An atom is a `quote`, `address`, `constant`, `api_sequence`, `exit_code`, `derivation` or `fix_pair` object attached to a
claim.

| Code | Meaning | Fix |
|---|---|---|
| `ATOM_EVIDENCE_NOT_LISTED` | An atom's `evidence_id` is missing or not in the claim's `evidence_ids`. | Put that id in `evidence_ids`. |
| `ATOM_TYPE_UNKNOWN` | The atom `type` is not one of the types above. | Use a supported type. |
| `QUOTE_TOO_SHORT` | A quote is shorter than 4 characters. | Quote at least 4 characters. |
| `QUOTE_NOT_IN_RAW` | The quote is not in the evidence's full raw output, byte for byte. | Copy the text exactly (case-sensitive) from the evidence. |
| `ADDRESS_UNRESOLVABLE` | The address is not valid hex, has more than 16 digits, or `space` is not `auto`, `va`, `rva` or `file_offset`. | Give `0x...` hex; omit `space` or use `va` / `rva`. |
| `ADDRESS_NOT_IN_LOCATIONS` | The address is not inside the locations the cited evidence reported. | Use an address that appears in that evidence. |
| `CONSTANT_UNRESOLVABLE` | A `constant` atom value is not a number. | Give `0x...` or a plain decimal. |
| `CONSTANT_NOT_IN_RAW` | The constant is not in that evidence's raw output. | Use a constant that appears in the output. |
| `HEX_LITERAL_MALFORMED` | A `0x` token in the claim text is not valid hex (or has a bad suffix). | `0x` followed by hex digits only. |
| `HEX_LITERAL_UNSUPPORTED` | A `0x` literal in the claim text is in no cited raw output, `constant` / `address` atom or exact reported address. A location range does not count. | Remove it from the text or back it with an atom. |

### `api_sequence` atom (dynamic observation, Pro)

| Code | Status | Meaning | Fix |
|---|---|---|---|
| `API_SEQUENCE_MALFORMED` | `REJECTED` | Bad `mode` (`exact` or `subsequence`), `calls` (1 to 512 names), `module`, `caller`, an unknown field, or a claim that is not `present`. | Fix the atom. |
| `API_SEQUENCE_NEEDS_DYNAMIC_EVIDENCE` | `REJECTED` | The atom's evidence is not a dynamic observation. | Cite a `run_controlled(observe=...)` observation. |
| `API_SEQUENCE_MISMATCH` | `REJECTED` | Coverage is complete and the observed calls do not match. | Correct the call list (the detail shows the first divergence). |
| `API_SEQUENCE_COVERAGE_INCOMPLETE` | `UNVERIFIED` | Coverage is incomplete, so the sequence cannot be verified; a missing event is not read as "absent". | Observe again with complete `api_trace` coverage. |

### `exit_code` atom

| Code | Status | Meaning | Fix |
|---|---|---|---|
| `EXIT_CODE_MALFORMED` | `REJECTED` | The atom is not `{type, evidence_id, code}` with an integer code, the code is outside 32 bits, or the claim is not `present`. | Fix the atom; write a negative status code in the text as `0x...`. |
| `EXIT_CODE_NEEDS_RUN_EVIDENCE` | `REJECTED` | The cited evidence is not a `run_controlled` run. Only a run proves an exit code. | Cite the run's id. |
| `EXIT_CODE_MISMATCH` | `REJECTED` | The run recorded a different exit code. | Use the code `run_controlled` reported. |
| `EXIT_CODE_NOT_RECORDED` | `UNVERIFIED` | The run recorded no exit code: the process did not finish normally (a timed-out or failed run is already rejected as failed evidence before this check). | Run it again. |
| `EXIT_CODE_RUN_NOT_COMPLETE` | `UNVERIFIED` | The run is not a complete isolated run: its status is not OK, its output was truncated, it timed out, or its isolation was not sufficient. | Run it again. |

### `derivation` atom

The verifier recomputes the value from quote and constant leaves of cited static evidence. Operations: `xor`, `add`, `sub`,
`concat`, `slice`, `le_bytes`, `be_bytes`.

| Code | Meaning | Fix |
|---|---|---|
| `DERIVATION_MALFORMED` | The atom is not `{type, value, expr}`, or the expression breaks a format or limit (depth, size, operation, arity, width). | Fix the expression. |
| `DERIVATION_RANGE` | The integer result is outside 0 to 2^64-1. | Give `bits` (8, 16, 32 or 64) for modular `add` / `sub`. |
| `DERIVATION_LEAF_NOT_STATIC` | A leaf's evidence is not cited, or is not static evidence of the target. Run input and output cannot be leaves. | Use leaves from cited static evidence only. |
| `DERIVATION_LEAF_NOT_IN_RAW` | A quote or constant leaf is not in that evidence's raw output. | Quote verbatim; constants must appear. |
| `DERIVATION_MISMATCH` | The verifier's result differs from the claimed `value`. | Fix the expression or the value. |

### `fix_pair` atom (`kind="fix_verification"`)

| Code | Status | Meaning | Fix |
|---|---|---|---|
| `FIX_PAIR_WRONG_KIND` | `REJECTED` | A `fix_pair` atom in a claim that is not `fix_verification`. | Use `kind="fix_verification"`. |
| `FIX_NO_FIXED_BUILD` | `REJECTED` | The scope manifest binds no fixed build. | Add `fixed_target_sha256` and open the fixed build in `target_open`. |
| `FIX_PAIR_MALFORMED` | `REJECTED` | Wrong shape, or the two quotes are equal or shorter than 4 characters. | `{type:'fix_pair', original:{evidence_id, quote}, fixed:{evidence_id, quote}}` with two different quotes. |
| `FIX_PAIR_EVIDENCE_NOT_LISTED` | `REJECTED` | One of the two run ids is not in `evidence_ids`. | Cite both runs. |
| `FIX_PAIR_BUILD_MISMATCH` | `REJECTED` | The original is not a run of the target, the fixed one is not a run of the fixed build, or they are swapped. | `original` from `run_controlled(target="original")`, `fixed` from `target="fixed"`. |
| `FIX_INPUTS_DIFFER` | `REJECTED` | The two runs used different argv or stdin. | Run the same input on both builds. |
| `FIX_QUOTE_NOT_IN_RAW` | `REJECTED` | A quote is not in its own run's output. | Quote text that is really in each run's output. |
| `FIX_STILL_REPRODUCES` | `REJECTED` | The original's reproduce quote also appears in the fixed build's output. | None: the finding is not fixed. |
| `FIX_BUILD_EVIDENCE_NEEDS_PAIR` | `REJECTED` | Fixed-build evidence is cited outside a `fix_pair`. | Use it only inside a `fix_pair`. |
| `FIX_NEEDS_BOTH_BUILDS` | `UNVERIFIED` | A `fix_verification` claim has no `fix_pair` atom. | Run both builds with the same input; cite both and a `fix_pair`. |
| `FIX_RUN_NOT_COMPLETE` | `UNVERIFIED` | One of the two runs is not a complete isolated run. | Run that build again. |

### `control_pair` atom (validation claims)

A behavior claim declares `behavior_class`: `acceptance_validation` (an input is accepted or rejected, a key or licence
is valid, a password is correct) or `ordinary` (prints X, exits with N). A validation claim (`acceptance_validation`,
every `bypass_poc`, or an `ordinary` claim whose text still reads like a verdict) needs
`{type:'control_pair', asserts:'accepted'|'rejected', discriminator:{source:'stdin'|'argv', index:N}, accepted:{evidence_id, outcome}, rejected:{evidence_id, outcome}}`:
two complete `run_controlled` cases of the target build, inputs equal except the discriminator, each side bound to its
own outcome (`{type:'quote', quote}` or `{type:'exit_code', code}`), the outcomes different, and the claim naming the
input of the side `asserts` names.

| Code | Status | Meaning | Fix |
|---|---|---|---|
| `BEHAVIOR_CLASS_MISSING` | `UNVERIFIED` | A behavior claim without `behavior_class`. | Resend with `acceptance_validation` or `ordinary`. |
| `CONTROL_PAIR_MISSING` | `UNVERIFIED` | A validation claim without a `control_pair` atom: one run alone is no contrast. | Run an input the program accepts and one it rejects; cite both and a `control_pair`. |
| `CONTROL_PAIR_INVALID` | `REJECTED` | Wrong shape; a case not cited, not a `run_controlled` run of the target build, or inconsistent; inputs that differ outside the discriminator or only in surrounding whitespace; an outcome its own case does not show; the claim names no input, or the other side's input, or its verdict words or a side's quote read as the other side. | Fix the atom or the claim text (one claim per side). |
| `CONTROL_PAIR_INCOMPLETE` | `UNVERIFIED` | A case was truncated or its session did not end cleanly. | Run it again. |
| `CONTROL_PAIR_SAME_OUTCOME` | `UNVERIFIED` | An outcome also holds on the other side. | Quote the text that differs, or use the two exit codes. |
| `CONTROL_PAIR_UNSTABLE` | `UNVERIFIED` | Repeats of one input disagree, the same input sits on both sides, or another cited run of a side's input does not show its outcome. | Report the observations; the target is not stable for that input. |

## Not backed (`UNVERIFIED`)

| Code | Meaning | Fix |
|---|---|---|
| `VALUE_NOT_IN_EVIDENCE` | A declared or text-extracted value (quoted string, number, long hex string) is not in the cited raw output. Numbers match by numeric equality, strings verbatim. Numbers in prose ("2 functions") count too. | Cite evidence that contains it, send the supported part as its own claim, or drop the value. |
| `VALUE_DERIVED_NEEDS_EXECUTION` | The value is marked `derived`, or only a derivation, computation or emulation backs it in a behavior claim. Static evidence cannot confirm a computed value. | Try the value with `run_controlled` and cite that run, or drop it. |
| `VALUE_COMPUTE_NOT_BOUND` | The value appears only in a `compute` output whose inputs are not all cited static evidence. | Cite the static evidence of every compute input (and use `kind="observation"`). |
| `VALUE_ONLY_CONDITIONAL` | The value, constant or `0x` literal appears only on conditional `dataflow_slice` lines (`candidate ... NOT definite`, `assumes=`, a clobbered byte's `last=`). | Cite evidence that shows it unconditionally, or test it with `run_controlled`. |
| `QUOTE_ONLY_CONDITIONAL` | A quote is found only on such conditional lines. | Same. |
| `TERM_NOT_IN_EVIDENCE` | A technical term in a `present` claim (an identifier, template name, section name, name with digits such as `FNV-1a`, an acronym such as `XOR`, or a word like `hash` or `encrypted`) is in no cited evidence. One issue per term; the detail names it. | Use the evidence's own names, cite evidence that shows the term, or move the reading into `interpretation` (unverified, not covered by the status). |
| `BEHAVIOR_NEEDS_EXECUTION` | A behavior claim without execution evidence tied to it. The codes in the next table follow it and say what is missing. | Run the input with `run_controlled`; cite that run and a quote from its output. If you only describe the code, resend as `kind="observation"`. |

These blockers follow `BEHAVIOR_NEEDS_EXECUTION` (severity `UNVERIFY`). When `PROVEN` was requested for an `observation`,
or for a behavior claim a dynamic observation backs, the same codes appear as `DOWNGRADE` (or `CAP`) and the claim is
`SUPPORTED`:

| Code | Meaning | Fix |
|---|---|---|
| `PROVEN_NEEDS_CONTROLLED_REPLAY` | No `run_controlled` evidence is cited. | Cite the id of a run. |
| `PROVEN_EVIDENCE_NOT_COMPLETE` | The run is not complete: not OK, truncated, timed out, or no exit code. | Run again (longer `timeout_s`) and cite the new id. |
| `ENV_ISOLATION_BELOW_SCOPE` | No complete run was in an isolation level the scope allows. | Run in an allowed isolated environment. |
| `PROVEN_NEEDS_OBSERVED_OUTPUT` | A run is cited but the result is not tied to its output. | Add a quote atom copied from the run's output (or a value that appears in it). |
| `PROVEN_DYNAMIC_NEEDS_RUN_OUTCOME` | A cited dynamic observation (Pro) has no complete run of the same case (argv, stdin, exit code). | Cite a complete `run_controlled` outcome of the same case. |

## Caps and downgrades (status stays `SUPPORTED`)

| Code | Meaning | Fix |
|---|---|---|
| `PROVEN_STATIC_CLAIM` | `PROVEN` was requested for an `observation`; observations are `SUPPORTED` at most. | For `PROVEN` use `kind="behavior"` with `run_controlled` evidence. |
| `PROVEN_ABSENCE` | `PROVEN` was requested for an absence claim. | None: absence cannot be proven. |
| `PROVEN_REGION_VIEW` | A captured-region view (Pro) is cited; a view of captured memory never backs `PROVEN`. | Cite a complete run outcome instead. |

## Added by the ledger (`INFO`)

| Code | Meaning |
|---|---|
| `KIND_OVERRIDDEN_TO_BEHAVIOR` | The claim was sent as `observation` but its text asserts program behavior, so it is verified as `behavior`. Rephrase it as what the code does, or verify it with a run. |
| `IMPORTED_BUNDLE_UNAUTHENTICATED`, `IMPORTED_BUNDLE_PROVENANCE` | The job came from an imported bundle (Pro) that is unauthenticated or whose provenance record is missing or altered; the status is capped at the bundle's recorded status. Re-run the analysis in this installation. |

## `claim_add` errors (no claim is recorded)

| Code | Meaning | Fix |
|---|---|---|
| `NO_TARGET` | No target is open. | Call `target_open` first. |
| `SCOPE_DENIED` | The manifest does not allow the base operation `static`. | Fix the scope manifest. |
| `KIND_REQUIRED` | `kind` is missing or blank. | Send `observation` (what the code or data is) or `behavior` (what happens when run). |
| `BAD_ARGUMENT` | An argument has the wrong type or value (empty text, unknown `kind`, polarity not `present` / `absent`, `requested` not `UNVERIFIED` / `SUPPORTED` / `PROVEN`, malformed `evidence_ids`, `atoms` or `supersedes`). | Fix the argument named in the message. |
| `INVALID_CLAIM` | The claim text or a declared value is invalid (empty text, `interpretation` over 2000 characters, a bad `supersedes` reference, a malformed or oversized `values` list). | Fix what the message names and resend. |
| `INTERNAL` | An unexpected error in the harness. | Report it as a bug. |

## Report labels

`report_build` re-verifies every `SUPPORTED` / `PROVEN` claim. A claim that is now `UNVERIFIED` moves to the hypotheses
section, a `REJECTED` one is dropped and counted as `failed_reverify`. Hypotheses carry one or more of these reasons:

| Reason | When |
|---|---|
| `NO_EVIDENCE` | The claim cites no evidence. |
| `VALUE_NOT_IN_EVIDENCE` | `VALUE_NOT_IN_EVIDENCE` or `VALUE_DERIVED_NEEDS_EXECUTION`. |
| `TERM_NOT_IN_EVIDENCE` | `TERM_NOT_IN_EVIDENCE`. |
| `BEHAVIOR_NEEDS_EXECUTION` | `BEHAVIOR_NEEDS_EXECUTION`. |
| `NOT_VERIFIED` | Any other `UNVERIFY` code (for example `VALUE_ONLY_CONDITIONAL`, `API_SEQUENCE_COVERAGE_INCOMPLETE`, `FIX_*`, `EXIT_CODE_*`, `CONTROL_PAIR_*`, `BEHAVIOR_CLASS_MISSING`). The claim's own verification record has the exact code. |

## Checks

`checks` shows which rule groups ran. A `false` check is not an error by itself; the matching issue is.

| Check | `ok` means |
|---|---|
| `EVIDENCE_INTEGRITY` | The cited evidence loaded and validated. |
| `NOT_INFERRED_ONLY` | Not all cited evidence is analyst inference. |
| `COMPUTE`, `EMULATION` | Only when such evidence is cited: no `COMPUTE_*` rejection / every emulation may back values here. |
| `ABSENCE_COVERAGE` | Only for `absent` claims: coverage is complete. |
| `ATOMS` | No atom was rejected. |
| `API_SEQUENCE`, `EXIT_CODE`, `DERIVATIONS`, `FIX_PAIR` | Only when such an atom (or a `fix_verification` claim) exists: it verified. |
| `CONTROL_PAIR` | Only for validation claims or claims with the atom: a valid pair is present. |
| `BEHAVIOR_CLASS` | Written only as `false`, when a behavior claim has no `behavior_class`. |
| `HEX_LITERALS` | Every `0x` literal in the text is backed. |
| `VALUES_IN_EVIDENCE` | Every declared or extracted value is backed. |
| `UNCONDITIONAL_BACKING` | Only with `dataflow_slice` evidence: nothing rests only on conditional lines. |
| `TERMS_IN_EVIDENCE` | Written only as `false`, when a term is unbacked. |
| `BEHAVIOR_NEEDS_EXECUTION` | Only for behavior claims: execution evidence is present. |
| `PROVEN_CONDITIONS` | Only for behavior claims or `PROVEN` requests: every condition for `PROVEN` holds. |
