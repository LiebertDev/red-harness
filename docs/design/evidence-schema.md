# Evidence and Claim Layer — Design

Status: implemented.
The schema version is fixed; adding a field requires a new `rh.*/N` version. Behavior that is not covered by tests is marked "UNVERIFIED".

## 1. Principles
1. Only server code produces evidence (from engine/`run_controlled` results). The agent has no tool that writes evidence (absent from the tool set). The agent only calls `claim_add` / `unknown_record`.
2. The verifier assigns status, not the agent. The agent declares `requested`, the server writes `status` (granted); the two are stored separately in the record. No status extraction from text.
3. Fail-closed: anything uncertain is rejected. No silent downgrades: if the granted status is lower than `requested`, the response says so via `issues`.
4. Everything from the target is untrusted data (§6); status/scope decisions are never read from target text.

## 2. Evidence record (`rh.evidence/1`)
- Identity: `ev_` + sha256(canonical JSON(semantic projection)). Uses `canonical()` from `core/journal.py` (sort_keys, tight separators; NOT RFC 8785, so the projection has no floats, only int/string).
- EXCLUDED from the projection (does not affect identity): `capture.elapsed_ms`, local paths, event time. So the same step served from cache or re-run yields the same `ev_` id (needed for the resume test). Included: subject, source, operation, parameters, raw.blob_sha256, result, capture (except elapsed_ms), locations, confidence, authority, environment, coverage, limitations, evidence_links.
- Read: `ev_` is recomputed on load; a mismatch gives `EVIDENCE_ID_MISMATCH`.
- Raw output lives in the CAS (`raw.blob_sha256`); the record holds only a bounded quote (`excerpt`, ≤2 KiB) and a small `result` (≤8 KiB, `result_blob_sha256` if larger).
- `confidence`: `observed` (tool saw it directly) | `derived` (deterministic computation from observations) | `inferred` (inference). `authority`: `shipped-artifact` (static) | `controlled-replay` (execution) | `historical-reference` | `external-service` | `analyst-inference` | `dynamic-observation` (§4.6; never yields PROVEN alone). `sandboxed-computation` (the model's own code run by `compute`, §4.8; always `confidence=derived`; never yields PROVEN, never backs behavior). `cpu-emulation` (the target's own code run in a CPU emulator by `emulate`, §4.13; always `confidence=derived`, never native execution; never yields PROVEN, never backs behavior). `dynamic-region-view` (a bounded view of bytes captured by a dynamic observation, made by `captured_region`, §4.15; always `confidence=derived`, linked to that observation; at most SUPPORTED, never PROVEN).
- `capture.status` is the core `Status` value (OK/PARTIAL/LIMIT_REACHED/TIMEOUT/MEMORY_LIMIT/ERROR); never parsed from text. TOOL_MISSING produces no evidence (step event only). Derived `strength`: `full` (OK, untruncated) | `partial` (PARTIAL/LIMIT_REACHED, or truncated, or output recovered after a timeout) | `failed` (TIMEOUT/MEMORY_LIMIT/ERROR).

```json
{"schema":"rh.evidence/1","evidence_id":"ev_<64hex>","untrusted_content":true,
 "subject":{"sha256":"<64hex>","format":"pe","architecture":"x64","derived_from_sha256":null},
 "source":{"tool":"strings_search","tool_version":"0.1.0","engine":"native","engine_version":"0.1.0"},
 "operation":"strings_search","parameters":{"regex":"IRP_MJ","section":null},
 "capture":{"status":"OK","strength":"full","truncated":false,"timed_out":false,"exit_code":null,"elapsed_ms":812},
 "raw":{"blob_sha256":"<64hex>","bytes":5321,"excerpt":"0x1a40: IRP_MJ_DEVICE_CONTROL\n"},
 "result":{"matches":[{"file_offset":6720,"text":"IRP_MJ_DEVICE_CONTROL"}]},
 "locations":[{"kind":"file-offset-range","start":6720,"end":6741}],
 "confidence":"observed","authority":"shipped-artifact",
 "environment":null,
 "coverage":{"scope":"all-sections","relationship":"complete"},
 "limitations":[],"evidence_links":[]}
```
- `locations[].kind`: `address` (va/rva), `address-range`, `file-offset`, `file-offset-range`, `artifact-path`. For PE, addresses are stored normalized as `AddressForm` (file_offset/rva/va/image_base/section) so matching happens in a single space.
- `environment` (required on execution evidence): `{id, platform, architecture, isolation}`; `isolation` is one of `none|process|container|virtual-machine|windows-sandbox`. The field is the runner's declaration; verifying that Sandbox was actually used is UNVERIFIED (open question 4).
- `coverage.relationship`: `complete|partial|unknown`. Missing coverage means unknown, not absence.
- `subject.derived_from_sha256`: for evidence on a rebuilt (fixed) build of the target, the original build's SHA; the two are tied together via `evidence_links`.

## 3. Claim record (`rh.claim/1`) and statuses
Statuses: `UNVERIFIED` (evidence link broken/awaiting re-verification, or evidence reference empty; NEVER among findings, see hypothesis rule), `SUPPORTED`, `PROVEN`, `REJECTED` (terminal; not in the report, counted only by id+code).
- Decision: There is NO separate `HYPOTHESIS` status. An `UNVERIFIED` claim with an empty evidence reference counts as a hypothesis and appears in a separate "Unverified hypotheses" report section; it never appears among findings (SUPPORTED/PROVEN).
- `kind` (verifier 3, see §4.4): `observation` (what is in the code/data: function, address, constant, flow) | `behavior` (what happens when the program runs: "this input is accepted", "this key is valid", "this branch is taken under this condition") | `bypass_poc` (behavior class). Old names are accepted: `static_fact` = observation, `runtime_behavior` = behavior. The record also holds `kind_source` (`declared|inferred|overridden`). `polarity`: `present` | `absent` (absence is not guessed from words, it is declared as a field).
- `claim_id` = `cl_` + sha256(normalized text, resolved kind, polarity, target SHA). With `claim_add(supersedes=[claim_id])` the model withdraws its earlier claim and replaces it with the new one (§4.5). Revision via `revision` + `expected_revision`.
- `atoms[]`: the agent's verifiable claim parts: `quote` (must appear verbatim in the evidence's raw output), `address` (must be in the evidence locations), `constant`. Flat JSON that is easy for a small model to produce. `claim_add` requires `text`; giving `kind` is recommended (if omitted the server determines it from the text, `behavior` if ambiguous), `polarity` defaults to `present`, `requested` defaults to SUPPORTED.

```json
{"schema":"rh.claim/1","claim_id":"cl_<64hex>","revision":1,"job_id":"job_x",
 "text":"Dispatch rutini IRP_MJ_DEVICE_CONTROL dizesine başvuruyor.","kind":"observation","kind_source":"declared","polarity":"present",
 "target_sha256":"<64hex>","requested":"SUPPORTED","status":"SUPPORTED","evidence_ids":["ev_<64hex>"],
 "atoms":[{"type":"quote","evidence_id":"ev_<64hex>","text":"IRP_MJ_DEVICE_CONTROL"},
          {"type":"address","evidence_id":"ev_<64hex>","space":"file_offset","value":"0x1a40"}],
 "verification":{"verifier_version":"1","checks":[{"code":"QUOTE_IN_RAW","ok":true}],"issues":[]}}
```

Transitions (all written to the event log; no rollback, only new events):
| From | To | Condition |
|---|---|---|
| none | SUPPORTED | all §4 general rules + at least one evidence `observed` or `derived` |
| none | PROVEN | SUPPORTED conditions + §4.2 (all) |
| none | REJECTED | any REJECT rule; an evidence-less claim ends here |
| SUPPORTED | PROVEN | new controlled-replay evidence via `claim_update` + §4.2 |
| SUPPORTED/PROVEN | UNVERIFIED | linked evidence became `EVIDENCE_INVALIDATED` (target SHA changed, blob/ID mismatch) or conflicting full evidence arrived; the conflict also opens an unknown automatically |
| UNVERIFIED | SUPPORTED/PROVEN/REJECTED | re-verification result |
An idea without evidence is not a claim: it goes to the unknowns ledger via `unknown_record` (§5).

## 4. Verifier rules (deterministic, no LLM)
Runs at `claim_add` time and at `report_build` (all claims from scratch, evidence re-read). If the two diverge, the report result prevails.
### 4.1 General (for SUPPORTED and PROVEN)
- `NO_EVIDENCE`/`UNKNOWN_EVIDENCE_ID`: evidence list empty or not in the log.
- `EVIDENCE_ID_MISMATCH`, `RAW_BLOB_HASH_MISMATCH`: recompute `ev_`; re-sha256 the raw blob in the CAS.
- `SUBJECT_SHA_MISMATCH`: `evidence.subject.sha256` (or `derived_from_sha256`) = the job's target SHA; at `report_build` the target copy in the CAS is also re-hashed.
- `EVIDENCE_FAILED`: `strength=failed` evidence supports nothing. `partial` only for `polarity=present` + SUPPORTED; NEVER for PROVEN and `absent`.
- `QUOTE_NOT_IN_RAW`: an atom quote must appear VERBATIM in the raw blob (case-sensitive, substring, no whitespace normalization); quote ≥ 4 characters. The check runs on the full blob, not the excerpt.
- `ADDRESS_NOT_IN_LOCATIONS`: the address is converted to a number and searched in the evidence's `locations` ranges (NOT string comparison); a PE address is brought into one space with `normalize_address(..., strict=True)`; if unresolvable, `ADDRESS_UNRESOLVABLE`.
- `HEX_LITERAL_UNSUPPORTED`: every `0x…` literal in the claim text (no length limit) must be found numerically in an `address`/`constant` atom, a POINT location (an exact address the tool reported) or raw output (version 8: a location RANGE no longer counts, see §4.9); boundary-blind substring matching is forbidden. Which tokens in raw output count as numbers (C/Hex-Rays suffixes, IDA `..h`) is in §4.7.1.
- `INFERRED_ONLY`: rejected if all evidence is `inferred`/`analyst-inference` (recorded as an unknown).
- `ABSENCE_WITHOUT_COMPLETE_COVERAGE`: for an `absent` claim the evidence must be `strength=full` and `coverage.relationship=complete` and the coverage must include the claim's scope; otherwise rejected. `absent` reaches SUPPORTED at most.
### 4.2 PROVEN (all required; if one is missing the granted status is SUPPORTED or rejection)
1. `PROVEN_NEEDS_CONTROLLED_REPLAY`: at least one evidence with `authority=controlled-replay` and `confidence=observed`; the target must really have been executed and output/exit code observed.
2. This evidence has `capture.status=OK`, `truncated=false`, `timed_out=false`, `exit_code` not null. Timed-out/truncated/recovered output cannot be PROVEN.
3. `ENV_ISOLATION_BELOW_SCOPE`: rejected if `environment.isolation` is weaker than the scope manifest requires (`windows-sandbox` or VM for foreign samples).
4. `CONTROL_PAIR_MISSING`: a `bypass_poc`/validation-logic claim requires both an accept (correct input) and a reject (wrong input) observation, and, when a fixed build is compared, an observation on each build; linked via `evidence_links`.
5. Decision: Findings from static analysis reach SUPPORTED at most; PROVEN is given only to a result actually executed and observed in an isolated environment. `observation` is SUPPORTED at most; the report shows "SUPPORTED (observed)" with the evidence's lowest `confidence`.

### 4.3 Result-value binding rule (verifier version 2)
Gap: even when quote, address and SHA are correct, if the CONCLUSION the claim reaches is not checked, a model can slip a value it computed in its head into the report (example: "once decoded the accepted input is `<candidate-input>`"; if the value is not in the quoted evidence, such a claim would still be SUPPORTED and the report would say `unsupported_claims: 0`).
- **Result value** = a concrete value the claim asserts: password/key string, numeric constant, address, computed result. Two sources: (1) `claim_add(values=[...])`, each item a string/integer or `{"value":..., "derived": true}`; (2) the server extracts automatically from the claim text: strings inside backticks, double/single and curly quotes, and decimal numbers (excluding letter-adjacent/unit-suffixed numbers such as `SHA-256`, `x86`, `16-bit`, `32 bytes`; a number inside quotes is not a separate value). `0x` literals in the text are checked numerically as before (`HEX_LITERAL_*`, rejection). A value does not escape even if the model leaves `values` empty.
- **Rule**: each value must either (a) appear verbatim in the raw output of a cited (`evidence_ids`) evidence: numeric equality for numbers (`0x10462` is not found inside `0x104620`; `0x3039` = `12345`), case-sensitive verbatim substring for strings; (version 8: an evidence `locations` range or point does NOT support a result value, see §4.9); or (b) be supported by execution evidence: a value marked `derived` is supported only by full/untruncated/exit-coded, sufficiently isolated `controlled-replay` evidence; it either appears verbatim in the output or was given to the execution as input (a line/word of the evidence's `parameters.stdin` or an `argv` item; no substring matching). This path is tested end to end with a fake sandbox; the real Windows Sandbox path is covered only by `tests/heavy`.
- **Consequence**: a claim whose value is unsupported CANNOT be SUPPORTED/PROVEN; it is recorded `UNVERIFIED` (not rejected), `VALUE_NOT_IN_EVIDENCE` appears in `issues` (or `VALUE_DERIVED_NEEDS_EXECUTION` if a derived value appears in static evidence), `severity: UNVERIFY`. A requested PROVEN also drops. `report_build` writes it to the "Unverified hypotheses" section, not to findings; a SUPPORTED recorded claim that loses its value on re-verification lands there too.
- **PROVEN path (verifier 2, with `run_controlled`)**: `kind=behavior|bypass_poc` (old name `runtime_behavior`) + citing `controlled-replay` evidence + the result must be BOUND TO OUTPUT (`PROVEN_NEEDS_OBSERVED_OUTPUT`): a `quote`/`constant` atom from the execution output, or a value appearing in the output. Supplying only the input is not enough. Wrong key: the "License valid" quote is not found in the output (REJECTED), or the value was not an input to that execution (UNVERIFIED). Limit: the verifier does not know the MEANING of a quote; if the model attaches a "License invalid" quote to a "valid" claim, this is not caught (`CONTROL_PAIR_MISSING` not implemented; UNVERIFIED).
- **Derived values**: a password computed from a transformation in the decompile (XOR, table, key derivation) is not found verbatim in static evidence; in this phase it is UNVERIFIED at most. The remedy is to OBSERVE the value in an isolated execution with `run_controlled` and obtain PROVEN/SUPPORTED via path (b); static analysis alone does not prove a computed result. Version 6 exception (§4.7.2): only in an `observation` claim, a `derivation` atom the verifier itself recomputes from static constants supports the value up to SUPPORTED; for "this input is accepted" (behavior) nothing changed.
- **Value given as execution input (version 6 tightening)**: the "given to the execution as input" support in path (b) is valid only in a `behavior`/`bypass_poc` claim (there PROVEN additionally requires an output binding). In version 5 an `observation` claim could reach SUPPORTED with a `derived` value the model itself passed to `run_controlled`; that meant the model's own input "proved" what the program is.
- **Report counters** (`report_build.counts`; meanings split in verifier 3): `unsupported_claims` counts ONLY unsupported claims that entered the findings section: `claims_without_evidence` (finding without evidence) + `claims_value_not_in_evidence` (finding with unsupported value) + `claims_behavior_without_execution` (behavior finding without execution evidence). By the gate rule it is always 0; if not 0 it is a BUG (the counter is computed from re-verified findings). Hypotheses are reported in separate, disjoint sets (in priority order): `hypotheses_without_evidence` (empty evidence reference), `hypotheses_value_not_in_evidence` (has evidence but unsupported value), `hypotheses_behavior_needs_execution` (`BEHAVIOR_NEEDS_EXECUTION`), `hypotheses_other`; `hypotheses` = sum of the four. Also `superseded` (number of withdrawn claims not entering the report). Older reports counted hypotheses in `unsupported_claims`; account for this change of meaning when comparing with older report/log counters.
- Known limit: automatic decimal extraction also treats numbers in prose (e.g. "2 functions", a date) as values and makes the claim UNVERIFIED if they are not in the evidence (fail-closed preference); the false-UNVERIFIED rate on real model output is not characterized. Value matching does not verify the value's MEANING: if a candidate string appears in the evidence in another context, it matches.

### 4.4 Claim kind and behavior rule (verifier version 3)
Gap: a VALUE appearing in static evidence (decompile output) does not prove that value is the input the program ACCEPTS. A string can appear in a `strcmp` call and still be only a decoy; a claim "the accepted input is `<candidate-input>`" would pass the value-binding rule, become SUPPORTED and enter "Verified findings" although the program's expected input is different.
- **Kinds**: `observation` (what is in the code/data; e.g. "main compares Str1 with the candidate `<candidate-input>` via strcmp") and `behavior` (what happens when the program runs; e.g. "the accepted input is X", "this input unlocks the program", "this input is accepted", "branch Y is taken under this condition"). `bypass_poc` is in the behavior class.
- **Rule**: a `behavior` claim is supported only by execution evidence: a full/untruncated/exit-coded/sufficiently isolated `controlled-replay` evidence must be cited and the result bound to output (§4.3 PROVEN path: quote atom from the output, or a value appearing in the output; a derived value must be an execution input). If these conditions hold the claim becomes PROVEN (even if SUPPORTED was requested). With static evidence only (or with an execution not bound to the output) it is UNVERIFIED at most (not rejected): `BEHAVIOR_NEEDS_EXECUTION` (+ the relevant `PROVEN_*`/`ENV_ISOLATION_BELOW_SCOPE` code) in `issues`, `severity: UNVERIFY`; it enters the report only under "Unverified hypotheses". `observation` claims can be SUPPORTED under the existing rules; if PROVEN is requested, SUPPORTED + `PROVEN_STATIC_CLAIM`. Behavior + `polarity=absent` is SUPPORTED at most (`PROVEN_ABSENCE`).
- **Kind determination** (`evidence/kinds.py`, deterministic): if the model gives `kind` it is used; if MISSING the server recognizes it from the text. Behavior patterns (EN/TR): STRONG = "correct/valid/accepted/real password|key|serial|...", "doğru/geçerli parola|anahtar...", "is accepted/valid/rejected/invalid", "password is `x`", "kabul/ret edilir", "geçerlidir", "unlocks", "accepts the password"; WEAK = "accepts", "rejects", "valid", "prints", "when ... entered", "çalıştırıldığında" etc. If no pattern matches, a positive sign of observation is sought (0x address, `sub_...` symbol, words like "function/string/calls/references/constant..."); if none, AMBIGUOUS ⇒ `behavior` (fail-closed). Even if the model explicitly says `observation`, if a STRONG pattern is present the kind is turned into `behavior`, `kind_source=overridden`, and `KIND_OVERRIDDEN_TO_BEHAVIOR` (severity INFO) appears in `issues`; WEAK patterns do not change an explicit `observation`. The heuristic is a crude rule set; a false-behavior (e.g. a sentence only describing code) makes the claim UNVERIFIED, a false-observation brings back the decoy-value class of hole: both rates on real model output are not characterized.
- **Limit**: the verifier does not know the MEANING of a quote/claim; if the model attaches an "Incorrect" output quote to an "is accepted" claim, this is not caught (the §4.3 limit applies). A model that deliberately words the text to avoid behavior patterns can bypass the heuristic; the real protection is the execution requirement, the patterns only catch the honest-but-mistaken model.

### 4.5 Withdrawal (`supersedes`) and partial support
- `claim_add(supersedes=[claim_id,...])`: if the new claim is NOT REJECTED (SUPPORTED/PROVEN/UNVERIFIED) the listed claims are withdrawn: for each, a `CLAIM_SUPERSEDED {claim_id, superseded_by}` event is written; the claim record STAYS in the ledger (append-only, no rollback) but `report_build` prints it neither in findings nor hypotheses and does not include it in counters (`counts.superseded`). Withdrawing another claim with an unknown/own id or an already withdrawn claim gives `INVALID_CLAIM`. A rejected new claim withdraws nothing. Re-adding a withdrawn claim with the same text does not undo the withdrawal; different text is required.
- Partial support: if the claim has several values, the `claim_add` response returns `values_supported` and `values_unsupported` (value, `derived`, reason) separately, and for a claim left UNVERIFIED by a single derived/unevidenced value it gives a `message` saying which value is the problem ("UNVERIFIED because of value(s) `4944` (derived)... Supported value(s): `17`... Resend the supported part as its own claim"). The report's hypothesis row lists `desteksiz değer` (unsupported value) and `desteklenen değer` (supported value) separately. The verifier does NOT split the claim itself: the model sends the supported part as a separate claim (withdrawing the old one with `supersedes` if needed).

### 4.6 Dynamic observation (`authority=dynamic-observation`, verifier version 4; `api_sequence` atom version 5)
Evidence with `authority=dynamic-observation` (a recorded API-call and executable-memory trace of one controlled run) is accepted by the verifier only if it passes three checks: (1) schema: the `rh.dynamic` document parses and its identity fields (run, target SHA-256, scope) match the job; (2) sealing: the document is re-checked against the content-addressed `ev_` id and the stored digests, and a mismatch fails verification; (3) matching: `api_sequence` atoms and quotes are compared with the sealed document, and coverage that is not `complete` gives UNVERIFIED rather than a rejection. A dynamic observation alone never yields PROVEN; PROVEN additionally needs a matched `run_controlled` result (rules in 4.2 and 4.4). Producing such evidence requires the Pro tracer; the Core build verifies dynamic-observation evidence but does not create it, and `run_controlled(observe=...)` returns `DYNAMIC_BACKEND_UNAVAILABLE`.

### 4.7 Number formats and the `derivation` atom (verifier version 6)
Motivation: two avoidable causes of blocked correct claims: the verifier's own engines did not recognize common number spellings, and the derived-value rule was too strict.

#### 4.7.1 Number recognition in raw output
- `0x…` and decimal tokens in raw output are also numbers with C/Hex-Rays integer suffixes: `u`, `l`, `ll`, `ul`, `ull`, `lu`, `llu`, `i64`, `ui64` (case as in C; e.g. `0x6D8C5A83E9463C96LL`, `0xCBF29CE484222325uLL`, `0xCu`, `10000uLL`). The suffix does not change the value.
- IDA disassembly hex `[0-9][0-9A-Fa-f]*h` (`20h`, `0F9B9B765h`) is a number ONLY in `operation=disassemble` evidence; inside quotes (`db '24h',0`) and `;` comments (`; CODE XREF: _main+2Ch`) it is not scanned. A decompile comment (`// [esp+20h]`) and a string dump do not yield numbers in this form.
- Unchanged: token boundary (no letter, digit, `_` before/after), numeric EXACT equality, no substring (`0x10462` is not found inside `0x104620LL`), no fuzzy matching. `push`, `high`, `arg_8h`, `var_1Ch`, `0x20h`, `0x12LLL` are NOT numbers. The recognized set only grows: a number absent from the evidence is still not found.
- In claim text a `0x…` literal may be written with the same suffixes (`0xCu` = 12); any other tail (`0x12zz`, `0x12LLL`) gives `HEX_LITERAL_MALFORMED`.
- Where applied (single source `_raw_numbers`): `QUOTE_NOT_IN_RAW` (full hex quote), `CONSTANT_NOT_IN_RAW`, `HEX_LITERAL_UNSUPPORTED`, result values, PROVEN output binding and dynamic observation binding.

#### 4.7.2 The `derivation` atom
Problem: correct, hand-verifiable computed values (`(17 ^ 0x1337) + 42 = 4944`, the piecewise XOR of an embedded key) were left UNVERIFIED because they do not appear literally in static evidence; since the model did the calculation in its head, arithmetic errors were not caught either.

Format (`src/redharness/evidence/derivation.py`):
```json
{"type":"derivation","value":"<candidate-input>",
 "expr":{"op":"concat","args":[
   {"op":"xor","args":[{"op":"slice","start":0,"end":5,"args":[{"quote":"VUTSRsqsw[ZY","evidence_id":"ev_…"}]},
                       {"const":"0x37","evidence_id":"ev_…"}]},
   {"op":"le_bytes","width":1,"args":[{"const":45,"evidence_id":"ev_…"}]}, "…"]}}
```
- Leaves: `{"quote": text, "evidence_id"}` (>= 4 characters, VERBATIM in raw output; its value is the UTF-8 bytes) and `{"const": integer | "0x.." | "decimal", "evidence_id"}` (numerically EXACTLY equal in raw output under the §4.7.1 rules). A leaf's evidence must be in the claim's `evidence_ids` list and `authority=shipped-artifact` (`DERIVATION_LEAF_NOT_STATIC`): `controlled-replay` (execution input `parameters`, stdout) and `dynamic-observation` can NEVER be leaves.
- Closed operation set: `xor` (int^int; bytes^int 0..255; equal-length bytes^bytes), `add`/`sub` (int; optional `bits` 8|16|32|64 for modular, otherwise result must be 0..2^64-1), `concat` (2..8 byte sequences), `slice` (`0 <= start < end <= length`), `le_bytes`/`be_bytes` (`width` 1|2|4|8, must fit). No other operations (no Caesar/rot, table lookup, hash: their meaning varies by engine/compiler and cannot be kept closed and unambiguous).
- Limits: depth <= 6, nodes <= 32, leaves <= 8, intermediate byte sequence <= 4096. Unknown field, type mismatch, limit exceeded: `DERIVATION_MALFORMED`/`DERIVATION_RANGE`.
- Decision: the verifier evaluates the expression deterministically; the result must EXACTLY equal `value` (bytes = the string's UTF-8; integer = integer or exact `0x`/decimal string). If not, the claim is REJECTED (`DERIVATION_MISMATCH`); if a leaf is missing, `DERIVATION_LEAF_NOT_IN_RAW`. When verified, `DERIVATIONS` appears in `checks`.
- Value support ONLY in a `kind=observation` and `polarity=present` claim: the matching result value (declared `derived` or extracted from the text) becomes `supported`, and the `values[]` item carries `"support":"derivation"` (report/response reads "recomputed, not executed"). The claim is SUPPORTED at most: if PROVEN is requested, `PROVEN_STATIC_CLAIM`; the derivation result does NOT satisfy the PROVEN output binding (`PROVEN_NEEDS_OBSERVED_OUTPUT`) or the dynamic observation binding.
- In a `behavior`/`bypass_poc` or `absent` claim the derivation is verified (still REJECTED if wrong) but supports no value: the value stays UNVERIFIED with `VALUE_DERIVED_NEEDS_EXECUTION`. "The correct password is X" still becomes PROVEN only via the route where X is passed to the execution and the output quoted (§4.3 (b), §4.4).
- A derivation does not support a `0x…` literal in the text (the `HEX_LITERAL_UNSUPPORTED` rule wants evidence/location); give a computed hex value via `values`.

Security assessment (decision: IMPLEMENTED, with its limits):
- Solid: the arithmetic. Every accepted derivation yields `value` by a closed, deterministic computation from leaves found literally in the cited static evidence; an arithmetic error sent with a derivation atom is REJECTED (an atom-less, head-computed value stays UNVERIFIED as in version 5).
- Closed false-accept paths: (1) model input: a leaf only from `shipped-artifact` evidence, execution evidence cannot be a leaf; (2) behavior: a derivation supports no value in a behavior claim, the PROVEN path is unchanged; (3) the decoy-value pattern (mistaking a static value for the "correct password"): the `kinds.py` STRONG pattern + behavior rule apply unchanged.
- Remaining risk (accepted): the verifier does not know the program ACTUALLY performs this computation; it verifies only the fact "with these constants this computation gives X". An interpretation error in an observation claim (wrong key fragment, a table in dead code) can stay SUPPORTED; this is the meaning limit every `observation` claim already carries (§4.3 last item, §4.4 Limit). New: with `slice`+`concat`+`le_bytes` an arbitrary short string can be built from characters/numbers in the evidence (bounded by leaves <= 8). A model that launders deliberately is outside the threat model as in §4.4 (patterns catch the honest-but-mistaken model; the real protection for behavior is the execution requirement, derivation does not loosen it). For an honest model, derivation is stricter than head computation.
- Report distinction: `"support":"derivation"` values should be shown as "computed, not executed"; the report template does not yet print this distinction in a separate section (OPEN WORK).

#### 4.7.3 Version transition
- `VERIFIER_VERSION = "6"`. Records containing neither the new number formats nor the `derivation` atom verify BIT-FOR-BIT identically to version 5 in `checks`/`issues`/`values`: `tests/fixtures/verifier_v5_golden.json` (21-claim corpus, produced with version 5 code; `tests/unit/_verifier_corpus.py`), `tests/unit/test_verifier_v6.py::test_v5_golden_corpus_verifies_identically`. The `DERIVATIONS` check and the `values[].support` field are written only if the relevant atom/value exists.
- Intentional differences (only in these records): (a) claims relying on suffixed/IDA numbers in raw output (REJECTED/UNVERIFIED in version 5, now per the rule); (b) `observation` + only an execution-input `derived` value (version 5 SUPPORTED, now UNVERIFIED; §4.3). When the version changes `report_build` re-verifies all claims (§7).
- Re-verification of previously recorded claims against the real ledger and content-addressed store is part of the version-change path (§7).

### 4.8 Computation evidence (`authority=sandboxed-computation`, verifier version 7)
Design, alternatives and limits: `docs/design/compute-tool.md`. Code: `src/redharness/evidence/compute.py`, `src/redharness/compute/`.
- **Record**: produced only by the `compute` tool for a clean result: both runs in one Windows Sandbox session OK, integrity-verified, not truncated, not timed out, exit 0, byte-identical stdout/stderr/exit code. `confidence=derived`, `environment.isolation=windows-sandbox`, `coverage.relationship=unknown` (never backs absence). Raw blob = stdout. `parameters`: `code_sha256` (code kept in CAS, re-runnable), `code_bytes`, `inputs[]` (`name`, `evidence_id`, `kind` raw|quote|const, `authority`, `sha256`, `quote`/`const`), `runtime` (`id`, `zip_sha256`, `exe_sha256`, `boot_sha256`), `argv`, `runs`, `timeout_ms`, `max_output_bytes`. `result`: `exit_code`, `deterministic`, `runs`, `output_sha256`, `stderr_sha256`. `evidence_links` = input evidence ids. Same code + inputs + runtime + output = same `ev_`.
- **Inputs** come only from the job ledger: the whole raw output, a verbatim quote (>= 4 characters), a constant numerically equal in the raw output (§4.7.1 rules) or (version 11) a byte range of a `read_bytes` evidence (`kind=range`, `{evidence_id, select}`; record: `va`, `bytes`, `auto`). A pasted literal (`{hex}`) whose bytes EXACTLY equal a contiguous FILE region of a static `read_bytes` evidence of the same target is recorded as an `auto: true` `range` binding to it (lowest evidence id, first occurrence; at least 4 bytes; no fuzzy, partial or cross-segment match); any other literal is recorded as `kind=literal` with no evidence id and binds nothing (the claim stays UNVERIFIED, `VALUE_COMPUTE_NOT_BOUND`). The verifier re-derives a `range` from the evidence (address + length) and compares the SHA-256, so auto-bound and explicit ranges verify identically. Compute output cannot be a compute input; constants and bytes written inside the code are not bound.
- **Record consistency** (every verification, including `report_build`): isolation allowed (`COMPUTE_NOT_ISOLATED`), `deterministic` and `runs >= 2` (`COMPUTE_NONDETERMINISTIC`), output hash / exit code / code blob (`COMPUTE_RECORD_INVALID`), every input re-derived from its evidence and its SHA-256 compared (`COMPUTE_INPUT_MISMATCH`). Any of these: REJECTED.
- **Dynamic memory inputs (verifier version 13)**: `{evidence_id: ev_dyn, select: {event, offset|address, length}}` on `dynamic-observation` evidence (operation `dynamic_observe`) hands the code bytes captured from an executable region; the record is `kind=memrange` with `event`, `offset`, `va`, `bytes`, `sha256`, `authority=dynamic-observation`. The verifier re-derives the bytes from the cited, sealed observation document and compares the SHA-256 (`COMPUTE_INPUT_MISMATCH` otherwise). Evidence that failed (timeout) cannot be an input. A `memrange` input counts as bound exactly when the observation is cited in the claim, the same condition as a static input; every other input kind still needs `shipped-artifact` evidence. Why this is sound and does not raise any ceiling: the claim stays `kind=observation`, `polarity=present` and at most SUPPORTED (`PROVEN_STATIC_CLAIM`), a behavior claim or PROVEN never rests on a computation (`VALUE_DERIVED_NEEDS_EXECUTION`, `PROVEN_NEEDS_CONTROLLED_REPLAY`), and what the value means is "this code over the bytes this observed run held in this region gives X"; the dynamic observation keeps its own limits (§4.6: one run, evadable instrumentation, coverage never `complete` for absence). The way to PROVEN is unchanged: try the computed key with `run_controlled` and quote its output.
- **Support rule** (same ceiling and condition as the `derivation` atom, §4.7.2): a value found in a compute output is supported only in a `kind=observation`, `polarity=present` claim, and only by a BOUND compute record: strength full and EVERY input from `shipped-artifact` evidence that the claim also cites (or, for a `memrange` input, from the cited `dynamic-observation` evidence). Such a value carries `"support":"computation"`; the claim is at most SUPPORTED (`PROVEN_STATIC_CLAIM` if PROVEN is requested). Unbound: `VALUE_COMPUTE_NOT_BOUND` (UNVERIFIED); a `0x` literal in the text backed only by an unbound compute output is `HEX_LITERAL_UNSUPPORTED` (REJECTED). A claim citing only compute evidence: `COMPUTE_ONLY` (REJECTED).
- **Never**: a behavior claim (`VALUE_DERIVED_NEEDS_EXECUTION` / `BEHAVIOR_NEEDS_EXECUTION`), PROVEN (`PROVEN_NEEDS_CONTROLLED_REPLAY`; not `controlled-replay`), the PROVEN output binding, a derivation leaf (leaves are `shipped-artifact` only). The way from a computed key to PROVEN is unchanged: try it with `run_controlled` and quote the output (§4.3 (b)).
- **Version**: introduced in 7; the `range`/`literal` input kinds are version 11 (version 10 cannot validate them); `memrange` and the trace-line quotes are version 13 (`VERIFIER_VERSION = "13"`). Records without these features verify bit-for-bit as before. Records with only `raw`/`quote`/`const` inputs give identical checks/issues/values in 11 (`tests/unit/test_compute_binding.py`). Claims that cite no compute evidence verify exactly as in version 6 (the version 5 golden corpus still passes unchanged); the `COMPUTE` check and `support: computation` appear only when compute evidence is cited.
- **Remaining meaning limit** (accepted): the verifier does not know whether the code models the target correctly; it only makes "this code gives this output on these inputs" reproducible. Hence the SUPPORTED ceiling. The report template does not yet print `support: computation` in a separate section (OPEN, same as §4.7.2).
- **Not covered by unit tests**: the real Windows Sandbox execution path (`tests/heavy/test_compute_real.py`); unit tests use the fake sandbox (`tests/unit/test_compute.py`).

### 4.9 Locations never back a value (verifier version 8)
Gap: the value check and the `0x` literal check counted `locations` ranges, so a `read_bytes` evidence at a low RVA range (`rva 0x0-0x400`, the headers) "contained" small integers and a claim of an invented small number (`77`, `0x2c`) passed because the number fell inside the cited range. The same held for every range-carrying evidence: strings matches (`file-offset-range`) and dynamic observation memory ranges (which also made a behavior claim look "bound" to the dynamic observation). Covered by `tests/unit/test_verifier_location_values.py`.
- A claim marks an address with the `address` atom (`space` va|rva|file_offset); no new field was needed. An address atom backs the SAME number only as a `0x` literal in the text or a hex-form value; it never backs a decimal result value (`44` for `0x2c`).
- Result values (declared or extracted): supported only by raw output (numeric equality), a `constant` atom, an address atom (hex form), a derivation/computation as before. A location (range or point) supports nothing here.
- `0x` literals in text: raw output, `address`/`constant` atom, or a POINT location (`address`/`file-offset`: an exact address the tool reported, e.g. "main (0x140001070)"). A location range never. Without the point exception, correct claims that name a function address in prose would have lost SUPPORTED. Residual: a literal equal to a reported function/xref/string address passes even if the prose uses it as a plain number.
- Version transition: `VERIFIER_VERSION = "8"`. Records whose numbers are backed by raw output, constant/address atoms or point locations verify bit-for-bit as in 7 (`tests/fixtures/verifier_v5_golden.json` still passes). Intentional differences: range-only literals REJECTED (`HEX_LITERAL_UNSUPPORTED`), location-only decimal/hex-form values UNVERIFIED (`VALUE_NOT_IN_EVIDENCE`).

### 4.10 Format-aware number extraction (verifier version 9)
Gap: raw output was scanned with one rule, so bytes printed without a radix were read as DECIMAL numbers. In `read_bytes` a hex-dump row of one 4-byte group or less (`0x..: 12`, `0x..: 123456` for bytes `12 34 56`) became the decimal 12 / 123456, so an invented decimal claim value was "supported" by the byte 0x12. The same held for the instruction-byte field of `disassemble` lines (`0x401000: 55 push ebp` gave 55). Covered by `tests/unit/test_verifier_number_regions.py`.
- Extraction is per evidence type (`verifier.numbers_of(raw, record)`, called by the verifier and the compute input binder): `read_bytes`: the hex-dump region of every segment contributes only its `0x<addr>:` prefix (an address, as before); bytes in the dump are never numbers; indented lines in that region that are not a dump row are dropped (fail-closed). Numbers come from the typed views (`u8` decimal, `u16`/`u32`/`u64`/`ptr` with `0x` and decimal) after their `-- view --` marker, and from the header/segment/limitation lines. Format boilerplate (`4-byte groups`, the `segment N` index) is not a value. `disassemble`: the byte field right after `0x<addr>:` is dropped before extraction; operands (`0x..`, IDA `..h`, plain decimals) and the address prefix are unchanged.
- `read_bytes` output format is UNCHANGED (evidence ids stable); the regions are told apart by the fixed markers (`segment`, `  -- view --`), which target data cannot forge (printable view lines escape newlines).
- Checked and unchanged: `decompile` (suffixed/`0x`/decimal C), `xrefs`, `strings`, `functions_list` (all addresses `0x`, `size=` labelled, symbols carry a `_`/letter boundary). Residual (UNVERIFIED): a symbol or string whose whole text is digits is a decimal token; `compute` prints are the model's own format (the tool description now says to print hex with `0x`; a bare digit string is decimal; the SUPPORTED ceiling and input binding still apply).
- Version transition: `VERIFIER_VERSION = "9"`. Records citing neither `read_bytes` nor `disassemble` evidence verify bit-for-bit as in 8 (golden corpus `tests/fixtures/verifier_v5_golden.json` unchanged). Intentional differences: decimal values / `0x` literals that only matched hex-dump bytes, opcode bytes or boilerplate numbers are UNVERIFIED / REJECTED.

### 4.11 Fix verification (`kind=fix_verification`, atom `fix_pair`, verifier version 15)
Context: the harness is a vendor tool and does not edit binaries. The vendor rebuilds the product from source with a fix; the harness checks, with the same evidence rules, that a finding F reproduces on the ORIGINAL build and no longer on the FIXED build.
- **Two builds, one analysis.** The scope manifest names the fixed build by `fixed_target_sha256` (next to `target_sha256`; they must differ); `target_open(..., fixed_target_path)` takes the file, which must hash to it (otherwise `SCOPE_DENIED`) and is copied to the CAS. `run_controlled(target="fixed")` runs it (`original` is the default). Static tools stay on the original. Each run is its own `controlled-replay` evidence whose `subject.sha256` is the SHA-256 of the build that actually ran (the sandbox runner re-hashes the staged file) and whose `parameters.build` is `fixed` for the fixed build; both hashes are therefore in the evidence and in the manifest.
- **The claim.** `kind=fix_verification` (behavior class) with one atom `{"type":"fix_pair","original":{"evidence_id","quote"},"fixed":{"evidence_id","quote"}}`. `original.quote` is text of the original build's output that shows F (e.g. `License valid`); `fixed.quote` is text of the fixed build's output that shows the new outcome (e.g. `License invalid`).
- **PROVEN only with both runs (all required, otherwise the claim is not PROVEN):**
  1. both evidence ids are cited in `evidence_ids` and are `controlled-replay` / `observed`; the original's subject is the job's target SHA-256, the fixed's is the manifest's `fixed_target_sha256` (swapped, wrong or foreign hashes: `FIX_PAIR_BUILD_MISMATCH`, REJECTED);
  2. the SAME input: equal `argv` and equal `stdin_sha256` on both runs (`FIX_INPUTS_DIFFER`, REJECTED);
  3. the original quote is in the original output (`FIX_QUOTE_NOT_IN_RAW`, REJECTED), the fixed quote is in the fixed output (a crash or an empty output is NOT a rejection: `FIX_QUOTE_NOT_IN_RAW`), and the original quote does NOT occur in the fixed output (`FIX_STILL_REPRODUCES`, REJECTED); the two quotes differ and are >= 4 characters;
  4. both runs are complete (`status OK`, not truncated, no timeout, exit code present, strength full, isolation sufficient); otherwise `FIX_RUN_NOT_COMPLETE`, UNVERIFIED (nothing is false, re-run that build);
  5. the usual behavior rules still apply to the claim's `values` (a derived value must be an input of the runs).
- **One-sided claims never prove a fix.** A `fix_verification` claim without a `fix_pair` (e.g. only the original run) is UNVERIFIED (`FIX_NEEDS_BOTH_BUILDS`); evidence of the fixed build cited anywhere outside a valid `fix_pair` is REJECTED (`FIX_BUILD_EVIDENCE_NEEDS_PAIR`), so the fixed build's run can never back an ordinary claim by itself; a `fix_pair` on another kind or on a job with no `fixed_target_sha256` is REJECTED (`FIX_PAIR_WRONG_KIND`, `FIX_NO_FIXED_BUILD`). `observe` is original-only.
- **What PROVEN means here.** For this input, the original build printed X and the fixed build did not and printed Y, observed inside Windows Sandbox. It says nothing about other inputs, other fixes of F or other findings, and the known risk of section 4.3 (the target writes its own result) applies to both runs. Whether the fixed binary was built from the vendor's fixed source is the vendor's statement, not something the harness proves; it only binds the hash.
- Version transition: `VERIFIER_VERSION = "15"`. Claims without the kind and the atom verify bit-for-bit as in 14 (`tests/unit/test_fix_verification.py`, existing golden tests unchanged).

### 4.12 The status covers the whole text: technical terms and `interpretation` (verifier version 16)
Gap: the verifier checked integrity, atoms (quote/address/constant/api_sequence/derivation), result values (quoted strings, decimals) and `0x` literals, and NOTHING ELSE of the text. A claim could pass every check (`EVIDENCE_INTEGRITY`, `NOT_INFERRED_ONLY`, `ATOMS`, `HEX_LITERALS`, `VALUES_IN_EVIDENCE` all ok) while naming things no cited evidence showed:
- A claim that a function "CRC-32 hashes the username and compares a PRNG-selected op chain": its quotes and values are in the cited evidence, but `CRC-32`, `PRNG` and `hashes` are in none of it (the hash function body was not cited) and nothing looked at them.
- A claim that a function formats a result as lowercase hex with a separator after every second byte: the quoted strings are present, but the formatting function's body was not cited, so `lowercase`/`hex` and the comparison operand are unbacked prose.
Root cause: a design gap, not a bug. "SUPPORTED" meant "the atoms and the extracted values are in the evidence"; every other word was free text that the status silently covered.

Design (option c: term binding + a separate `interpretation` field; deterministic, no LLM, the LLM never decides a verdict):
- **Status scope.** The status of a claim covers its `text`. Every TECHNICAL TERM of a `present` claim's text must be found in a cited evidence, otherwise the claim cannot be SUPPORTED/PROVEN: UNVERIFIED with one `TERM_NOT_IN_EVIDENCE` issue per term (severity `UNVERIFY`, detail = the term) and the check `TERMS_IN_EVIDENCE` (ok=false). Not REJECTED: the evidence is sound, only the wording claims more than it shows (same grade as `VALUE_NOT_IN_EVIDENCE`). The claim goes to the report's hypotheses with the reason `TERM_NOT_IN_EVIDENCE: term not in the cited evidence ...` (counted under `hypotheses_other`).
- **Term classes** (`evidence/terms.py`, applied after quoted/backticked spans and `0x` literals are removed, since those are values already checked by §4.3): identifier (contains `_`, letters+digits, an inner lower-to-upper case change, a dotted/`::` name with parts of >= 2 characters, or a word written as a call `name(`); compound (hyphenated token with a digit: `FNV-1a`, `SHA-256`; a number with a lower-case unit such as `64-bit`/`14-char` and all-digit compounds are not terms); acronym (>= 2 capitals; an inflection `XORs`/`XORed`/`XOR'lanmış` is dropped) except the closed notation set `API ASCII NUL NULL EOF DLL EXE ID VA RVA`; lexicon (a closed, a-priori list of stems + inflection: named hash/cipher/PRNG algorithms, representation words `hex lowercase uppercase endian unicode`, randomness `random pseudorandom prng rng`, mathematical properties `invertible reversible bijective injective one-way ...`, cryptographic purpose `encrypt decrypt cipher hash checksum obfuscat compress ...`). The lexicon is fixed by category and is not tuned on any claim set.
- **Binding.** Case-insensitive, `-` and `_` are one separator (a separator-less variant is also tried: `SHA-256` matches `sha256`), leading/trailing `_` ignored (`_main` matches `main`), token-bounded; whitespace is not a separator (the output line "Enter a valid key" does not back the identifier `valid_key`). Haystack: the searchable raw output of every cited evidence except `compute` and `analyst-inference` (the model's own code/output is not evidence about the target), plus the `stdin`/`argv` given to a cited run and a dynamic observation's own output. Closed aliases: `XOR` is backed by `^`; `hex` by a printf hex conversion (`%x`, `%02X`); an IDA auto-name `sub_<hex>`/`loc_<hex>` by a cited evidence whose `parameters.function`/`parameters.address` or a reported point location is that address. A lexicon stem may carry an inflection or a digit/separator tail (`decrypted` <- `decrypt_block`, `crc` <- `crc32`) but not more letters (`sha` is not found in `shadow`).
- **`interpretation`** (new optional `claim_add` field, <= 2000 characters, stored on the claim record only when given): the model's reading of the evidence (algorithm name, purpose, format). It is never passed to the verifier and the status never covers it; the report prints it under the finding as "Interpretation (model's reading, NOT verified; the status above does not cover it)". Scoring does not read it (strict grading reads `text`; grading-v2 only accepted claim texts). Not part of `claim_id`. Example: text `sub_1400017A8 multiplies by 0x100000001B3 in a loop over the username`, interpretation `looks like an FNV-1a hash`.
- **Not applied** to `polarity=absent` (an absence claim names what is not in the evidence; its gate is complete coverage, §4.1).
- **What the status still does NOT cover (residual):** plain English relations between anchored terms (`compares X with the entered serial`, `the computed password`, `every second byte`, `two digits per byte`), spelled-out numbers and ordinals, and lower-case identifiers without `_`/digit/case change (`scanf` is caught only when written as a call `scanf(`; `strcmp` in prose is not a term). Only an allowlist of permitted prose words would close this deterministically; it was rejected because it would make almost every current claim UNVERIFIED (most correct claims use ordinary verbs such as "sums", "packs", "divisible"). The rule therefore catches named algorithms/formats/properties and wrong identifiers, not wrong relations.

A claim whose wording the evidence does not show goes SUPPORTED -> UNVERIFIED with `TERM_NOT_IN_EVIDENCE` only; no other status changes (no PROVEN claim changes). Wording the evidence does not show can be fixed by rewording with the evidence's names or by moving the reading into `interpretation`.
- Scoring: strict scoring reads the recorded transcript/ledger statuses and never calls the verifier. A report rebuilt with version 16 would list fewer findings and the same `unsupported_claims` (0): the claims move to hypotheses.
- Version transition: `VERIFIER_VERSION = "16"`. The `TERMS_IN_EVIDENCE` check is written only when it fails, so a record whose terms are all backed verifies bit-for-bit as in 15 (`tests/fixtures/verifier_v5_golden.json` unchanged); the `interpretation` key exists only when given. Fake unit tests (edge cases only): `tests/unit/test_verifier_terms.py`.

### 4.13 Emulation evidence (`authority=cpu-emulation`, verifier version 19)
- Produced only by the `emulate` tool (`docs/design/emulation.md`): one function of the target executed in a CPU emulator
  from the file image, with the analyst's arguments. `confidence=derived`, `environment.native_execution=false`,
  coverage `unknown`. Only a deterministic return to the caller is recorded; every other end (imported API call, OS
  access, unmapped/protected memory, interrupt, limit, nondeterminism) is an error with no evidence.
- Record check: a cited emulation record must be an `emulate` record with its request in `parameters`, a complete
  capture and `result.stop=return`, `result.deterministic=true`; otherwise REJECTED `EMULATION_RECORD_INVALID`.
  Version 20: a code-range record (`parameters.end`, emulation request version 2) must instead have
  `result.stop=range_end`; the stop must match the request (`range_end` iff `end`).
- Value rule: a value, `0x` literal or `constant` atom found in its raw output backs only an `observation` + `present`
  claim (value `support: emulation`, check `EMULATION`, SUPPORTED at most). In a behavior claim it backs nothing
  (`VALUE_DERIVED_NEEDS_EXECUTION`), an absence claim cannot use it (coverage is never complete) and it never makes
  anything PROVEN: an emulated value shows what the code computes in the emulator, not what the program does.
- Output bytes are printed in the `read_bytes` dump format, so hex rows are bytes, not numbers (§4.10).
- Version transition: `VERIFIER_VERSION = "19"`. Claims that cite no emulation evidence verify bit-for-bit as in 18
  (the `EMULATION` check and the `emulation` support label appear only when it is cited).
  `VERIFIER_VERSION = "20"`: code-range records are accepted (record check above); what an emulation record may back
  is unchanged, and claims that cite no range record verify as in 19.

### 4.14 Value classes: no numeric collapse of byte strings (verifier version 21)
- Defect (found in review): a claim value of 64 zero hex digits (a SHA-256-like digest) was SUPPORTED against an
  emulation record. The value checker read the digit-only token as the decimal number 0, and the record contains a 0
  (`buf0+0x0`). Same class, reproduced on version 20 with static evidence: `0x` + 64 zeros (literal, quote or
  constant atom) = 0; a 62-character part of a real digest (string values were substrings); a digest written with a
  leading digit was not checked at all (neither a value nor a term); `0x5a` backed by the token
  `0x00000000000000000000005a`; `0090` backed by 90; `3.14` backed by `13.145`.
- Rule: every claimed token (text value, declared value, `0x` literal, quote/constant atom, derivation value or leaf)
  is classified before it is compared (`values.value_class`):
  - number: `0x` + 1..16 hex digits (any zero padding up to the 64-bit width is the same number: `0x5A`,
    `0x0000005A`, `0x000000000000005A` and `90` are equal; `0x00000000deadbeef` equals `0xdeadbeef`), or a bare decimal
    of 1..20 digits without a leading zero. Compared by exact numeric equality, as before.
  - hex string (byte string / digest / key): `0x` + more than 16 hex digits; a bare hex run of more than 16 characters;
    a bare decimal-form token with a leading zero (`00`, `0090`) or with more than 20 digits. Canonical form: the
    digits, lower case, no `0x`, leading zeros kept. Backed only by a WHOLE hex token of the cited evidence with the same
    canonical form (case-insensitive, the evidence token may carry `0x`; a token is bounded by non-word characters, so a
    part of a longer token or identifier never matches). Hex-dump rows of `read_bytes`/`emulate` and the instruction
    bytes of `disassemble` are not tokens (as for numbers, §4.10). A bare digit-only token is compared as written:
    `0x` + the same digits in the evidence matches (the text is the same), a different radix never does.
  - fraction: a decimal fraction (`1.5`): the exact token (`2.5` is not `2.50`).
  - string: everything else, unchanged (verbatim substring).
- Evidence side: a `0x` token of more than 16 digits or a decimal token of more than 20 digits is no longer a number
  (IDA `..h` allows one extra leading 0: `0FFFFFFFFFFFFFFFFh`). This also applies to `compute` constant inputs bound
  to an evidence (they use the same number extraction).
- Where it applies: an unbacked long `0x` literal in the text is REJECTED `HEX_LITERAL_UNSUPPORTED` (as a number
  literal is); an unbacked hex-string value is UNVERIFIED `VALUE_NOT_IN_EVIDENCE`; a long `0x` quote atom must be a
  whole token (`QUOTE_NOT_IN_RAW`); a hex-string constant atom must be a whole token (`CONSTANT_NOT_IN_RAW`); an
  address atom of more than 16 digits is `ADDRESS_UNRESOLVABLE`; a derivation leaf must be a number
  (`DERIVATION_MALFORMED`) and a derivation value that is a hex string never equals an integer result. A bare hex
  run of more than 16 characters is a value, not a term (§4.12).
- Decided, not changed: a padded number up to 16 digits keeps its numeric meaning (the verifier checks values, not
  widths; a claim about the width needs other backing); a short bare hex word without `0x` (`deadbeef`, `cafe`) stays a
  string (substring), because it is also an English-looking word and is usually quoted text.
- Version transition: `VERIFIER_VERSION = "21"`. Claims without such tokens verify bit-for-bit as in 20
  (`tests/fixtures/verifier_v5_golden.json` unchanged). Tests: `tests/unit/test_verifier_v21_values.py`.

### 4.15 Region-view evidence (`authority=dynamic-region-view`, verifier version 22)
- What it is: a bounded, read-only rendering (hex window, strings, linear disassembly) of bytes that the tracer captured from
  an executable region of ONE dynamic observation (`captured_region` tool, Pro). Always `confidence=derived`; `evidence_links` is
  exactly that observation; `parameters` name the observation (`observation_evidence_id`, `observation_blob_sha256`,
  `observation_sha256`), the event, the window and the views. Nothing is executed, repaired or rebuilt.
- It carries its observation's weakness: the capture strength of the view can never exceed the observation's (an incomplete
  observation, a head-only capture or a clipped window give `partial`; a failed observation gives `failed`), and
  `coverage.relationship` is never `complete` (no absence claim).
- Verifier: the record is REJECTED (`REGION_VIEW_INVALID`) unless the linked observation is an intact, not invalidated
  `dynamic-observation` record of the same target with the same stored document and body digest, and the view is not stronger than
  it; a claim that cites a view must also cite its observation (`REGION_VIEW_PARENT_NOT_CITED`). A view can back an
  `observation` + `present` claim (its strings and decoded instructions are searchable like any evidence text; its hex rows and
  instruction-byte fields are bytes, not numbers, §4.10); it can never be the basis of PROVEN (`PROVEN_REGION_VIEW`, a cap).
  The raw `bytes_hex` of the observation document stays unsearchable (§4.6).
- Version transition: `VERIFIER_VERSION = "22"`. Claims that cite no region view verify bit-for-bit as in 21.
  Tests: `tests/unit/test_verifier_region_view.py`.

### 4.16 Conditional `dataflow_slice` lines (verifier version 23)
- What is conditional: in `dataflow_slice` evidence (`operation=dataflow_slice`), a `candidate ... NOT definite` line (the
  last write of each byte, which a later call or a store through an escaped/indexed address may have overwritten), any
  line carrying `assumes=A1` / `assumes=A2` (the value holds only under that assumption; written values on `writes ...`
  lines carry the marker too), and a clobbered byte's `last=0x..`. Definite `run` lines, `value=... definite` lines
  without `assumes=`, and `writes ...` annotations without it are unconditional.
- Rule: the verifier blanks the conditional lines of each cited slice evidence and checks every result value, 0x
  literal, `constant` atom and `quote` atom again against what remains (plus every other cited evidence item). Backed
  ONLY by conditional lines -> the claim cannot be SUPPORTED: UNVERIFIED with `VALUE_ONLY_CONDITIONAL` (values,
  literals, constants) or `QUOTE_ONLY_CONDITIONAL` (quotes). The same value also backed unconditionally (another line
  of that evidence, or another cited evidence item such as a slice at an earlier point where the bytes are definite)
  -> unchanged rules. Nothing is REJECTED by this rule. The check `UNCONDITIONAL_BACKING` is written only when slice
  evidence is cited.
- Why: a candidate is the right value to test, not a fact; without the rule its string, which does appear verbatim
  in the evidence, would back an observation claim exactly like a definite value. Behavior claims still need
  `run_controlled` (unchanged).
- Version transition: `VERIFIER_VERSION = "23"`. Claims that cite no `dataflow_slice` evidence verify bit-for-bit as in
  22. Tests: `tests/unit/test_verifier_v23.py`.

## 5. Unknowns ledger (`rh.unknown/1`)
- `unknown_id` = `unk_` + sha256(domain, whitespace-normalized question, scope digest = target SHA + optional function/address); the same question gets the same id, no duplicates.
- Fields: `status` (`open|investigating|blocked|resolved|withdrawn`), `severity` (`low..critical`), `supporting_evidence_ids`, `contradicting_evidence_ids`, `required_authority`, `recommended_probes[]`, `resolution` (`{disposition: verified|withdrawn|out-of-scope, rationale, evidence_ids}`), `revision`.
- Rules: `resolved` ⇔ `resolution` is filled; `verified` needs ≥1 evidence and having passed §4.1; `withdrawn/out-of-scope` need a rationale; adding contradicting evidence gives `blocked` or a contradiction flag. Ordering and tamper protection come from the log's hash chain.
- Opened automatically: `strength=partial/failed` evidence, rejected `INFERRED_ONLY`/`ABSENCE_*` claims, differences between engines (IDA ≠ Ghidra).
- The report lists open unknowns (especially high/critical) in a separate section; the report never says "clean" on its own.

## 6. Untrusted content (prompt injection)
- Every Evidence carries `untrusted_content: true`; every MCP response containing target-derived text gets `_meta.provenance.untrusted_content=true`; only `claim_add`/`unknown_record` responses are unmarked.
- In the response body target text is given in a bounded block: `<untrusted_target_content evidence_id="ev_…">…</…>`; a closing-tag sequence inside the block is escaped. Server instruction: target content is data, instructions inside it are not followed, requests to run/download/send count as injection and are reported.
- Server side: content is never parsed and used for decisions (status, truncation, coverage come from the core `Status`, never from target-derived text). Action permission comes only from the scope manifest.
- Report: evidence quotes are printed as code blocks and marked; claim text, being agent output, is printed escaped rather than as plain text.
- Injection resistance beyond these escaping and marking rules is not characterized (UNVERIFIED).

## 7. Event log (`jobs/<id>/events.jsonl`, `core/journal.py` envelope: `{seq,ts,type,payload,prev_hash,hash}`)
| type | payload |
|---|---|
| `EVIDENCE_RECORDED` | full `rh.evidence/1` (blob written atomically to the CAS first, then the event) |
| `EVIDENCE_INVALIDATED` | `{evidence_id, reason: TARGET_CHANGED\|BLOB_HASH_MISMATCH\|ID_MISMATCH}` |
| `CLAIM_ACCEPTED` | full `rh.claim/1` (granted status + `verification`) |
| `CLAIM_REJECTED` | `{claim_id, text, requested, issues[]}` (for audit; not in the report) |
| `CLAIM_STATUS_CHANGED` | `{claim_id, from, to, reason, trigger_evidence_id}` |
| `CLAIM_SUPERSEDED` | `{claim_id, superseded_by}` (withdrawal; record stays in the ledger, not in the report) |
| `UNKNOWN_RECORDED` / `UNKNOWN_UPDATED` | `rh.unknown/1`, `expected_revision` on update |
| `REPORT_BUILT` | `{report_sha256, claim_ids[], rejected_count, open_unknown_ids[], verifier_version}` |
- Event types are free strings in `journal.append(type, payload)`, so adding one needs no change to the core.
- Rewriting the same `ev_`/`cl_` is a no-op (idempotent); `state.json` is derived from these events; the verifier builds state by replaying the log and does not trust a separate side store.
- Order: CAS blob first, then the event. A blob left over from a crash is a harmless orphan; there is no evidence without an event.
- `verification` inside `CLAIM_ACCEPTED` carries the verifier version; when the version changes `report_build` re-verifies all of them.

```json
{"seq":42,"ts":"2000-01-01T00:00:00.000000+00:00","type":"CLAIM_REJECTED","prev_hash":"<64hex>","hash":"<64hex>",
 "payload":{"claim_id":"cl_<64hex>","text":"Sürücü ağ erişimi yapmaz.","requested":"PROVEN",
  "issues":[{"code":"ABSENCE_WITHOUT_COMPLETE_COVERAGE","severity":"REJECT"},{"code":"PROVEN_NEEDS_CONTROLLED_REPLAY","severity":"REJECT"}]}}
```

## 8. Design notes
Content-addressed `ev_` ids; observed/derived/inferred confidence, authority, limitations, coverage and locations on every evidence; an unknowns ledger; the `untrusted_content` marker; fail/truncated never passes.

## 9. Failure modes this design avoids
- **Timeouts and truncation**: a result recovered after a timeout, or an existing output file, must not count as a clean success; evidence carries the core `Status` and only a full, untruncated, exit-coded execution can back PROVEN (§4.2).
- **Status from text**: truncation or error flags must not be read by searching output text for substrings such as "[truncated" or "error:", because target content can imitate them; status always comes from the core `Status` (§6).
- **Address normalization**: `normalize_address(..., strict=True)` is MANDATORY at every call site; non-strict mode yields a made-up file offset on a zero-padded tail. The caller verifies the target SHA before opening the PE.
- **Hex literal matching**: `0x` literals are compared numerically with token boundaries (`0x10462` is not found inside `0x104620`), never by unbounded substring matching, and short literals are checked too.
- **SHA binding**: the evidence's target SHA is compared with the job's target on every verification, and an address is matched to evidence locations.
- **Absence**: absence claims are declared with the `polarity` field, never extracted with a word-list regex that escapes when the wording changes.
- **Evidence ids**: `ev_` ids are full 256-bit SHA-256 digests, and a quote is checked against the full blob, not a head+tail excerpt.
- **Silent rewriting**: a failed verification must not silently downgrade PROVEN to SUPPORTED, rewrite claim text or mark all claims limited; every downgrade is reported in `issues`.
- **Keyless integrity checks**: a plain checksum catches corruption only, not forgery; forgery protection comes from "only the server produces evidence" (§1) and §11.1.

## 10. Open questions
Settled:
1. SETTLED: Static facts are SUPPORTED at most; no separate grade is added for `observed`+deterministic ones. PROVEN is given only to what was executed and observed in an isolated environment.
2. SETTLED: no `HYPOTHESIS` status is added. An `UNVERIFIED` claim with an empty evidence reference is a hypothesis; it goes in a separate "Unverified hypotheses" report section and is not mixed with findings.

Still open:
3. OPEN WORK: the false-rejection rate of the quote rule (min. 4 characters, verbatim match without whitespace normalization) on real Ghidra/IDA output is not characterized.
4. `environment.isolation` is the runner's declaration; can the core prove that Windows Sandbox was actually used? UNVERIFIED.
5. Should a cross-engine conflict (IDA ≠ Ghidra) make the claim UNVERIFIED or only open an unknown?

### Open risks
- **The target can write a fake result into the output folder.** `run_controlled` runs the target in Windows Sandbox, and mapped folders are writable by anyone inside the guest. Mitigations (`sandbox/integrity.py`, `sandbox/guest.ps1`): the target's stdout/stderr go through a runner-owned pipe and never touch files, the target runs as a separate non-admin user at Low integrity, and every record is HMAC'd with a one-time nonce the target cannot read. Not covered: a guest-kernel or sandbox escape, or a nonce leak. The remaining risk is stated in the `limitations` field of every `controlled-replay` evidence (`sandbox/evidence.py` `LIMITATIONS`) and the PROVEN response (`claim_add`) returns it as `limitations`. PROVEN means "observed in execution", not "the target honestly behaved this way".
- There is no independent proof that Sandbox was actually used (open question 4).

## 11. Known limits
There is no separate threat-model document; trust boundaries are written inside this schema (§4.6, §10 "Open risks"). This section collects the limits that remain open.

### 11.1 The seal is verifiable only during the run; a consistent rewrite by someone who can write to the data directory is not caught
- **Status:** `run_controlled` output integrity (`sandbox/integrity.py`) and the dynamic observation seal (`dynamic/seal.py`) are bound by HMAC-SHA256 to a
  per-run single-use nonce. The nonce exists only during the run (it is written briefly to the input file for the handshake and deleted after host acknowledgement;
  it does not enter the persistent record) and is then discarded. So the verifier cannot RE-CHECK the seal later: `report_build` and `claim_add`
  recompute only the `ev_` id, the CAS digest and the body digest (`parameters.observation_sha256`). The seal was verified once, when the evidence
  entered the ledger; it is not a persistent signature.
- **Consequence:** an attacker who can write to the data directory (`data_root`: CAS blobs and `events.jsonl`) and rewrites the CAS blob and the ledger record
  CONSISTENTLY with each other (blob content, `raw.blob_sha256`, `ev_` id, the event log's hash chain recomputed from scratch) is caught by no check. The hash chain is keyless:
  it catches corruption and ordering, not forgery.
  A forged evidence in the guise of `controlled-replay`/`dynamic-observation` can underpin PROVEN/SUPPORTED.
- **Scope:** directory write authority is OUTSIDE this project's trust boundary (the host operator is trusted); the limit also applies to all other evidence kinds. The seal only protects against
  the target inside the sandbox and the guest forging records. That this rewrite goes undetected is known from design, not from measurement (there is no deliberate attack test).
- **Deferred mitigations (NOT IMPLEMENTED, no code):**
  1. Sign the ledger head (last `hash` and `seq`) with a host key kept OUTSIDE the data directory; verification uses that public key and
     the key sits where an attacker who can write to the directory cannot reach it.
  2. An append-only external anchor (write a timestamped digest of the ledger head to a separate append-only record), so a later
     rewrite conflicts with the anchor.
  3. Attach the signature to the evidence record at the moment the seal is verified (e.g. a second nonce-less signature with the host key); can be combined with 1.
  Each needs key management and a workflow decision (no measured need, not added on "might be needed").
