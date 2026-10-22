"""Fail-closed claim verifier (deterministic, no LLM).

Rules (docs/design/evidence-schema.md section 4):
- A quote must appear byte-for-byte in the evidence's FULL raw blob (>= 4 characters; a hex literal is token-bounded).
- Addresses are converted to numbers and looked up in the evidence locations; every 0x literal in the text is compared
  numerically (no substring match: 0x10462 is not found inside 0x104620; 4-digit addresses are checked too).
- The evidence id is recomputed, the raw blob is re-hashed, the target SHA must match the job's target.
- Timeout/memory/error evidence supports nothing; truncated (partial) evidence can never back PROVEN.
- PROVEN only with isolated `controlled-replay` evidence; static evidence reaches SUPPORTED at most.
- Kind (kinds.py): a `behavior` claim ("this input is accepted", "the key is valid") is supported only by execution
  evidence and then becomes PROVEN; with static evidence alone it is UNVERIFIED at most (`BEHAVIOR_NEEDS_EXECUTION`).
  An `observation` (what is in code/data) can be SUPPORTED under the existing rules.
- Dynamic observation (`authority=dynamic-observation`, dynamic/): strictly validated (identity/scope/seal trail
  consistency, isolation); alone it reaches SUPPORTED at most; PROVEN additionally needs a complete
  `controlled-replay` run outcome of the same case (argv+stdin+exit code) (docs/design/evidence-schema.md section 4.6).
  It can never back an absence claim.
- `api_sequence` atom (version 5): ORDERED API-name list from the dynamic observation's raw document (default `exact`:
  repeats are kept, an extra/missing/reordered call does not match; explicit `subsequence`: the names occur in order,
  other calls may sit in between). While coverage is not complete, `exact` cannot be verified and a missing
  `subsequence` cannot be verified: the claim is UNVERIFIED (`API_SEQUENCE_COVERAGE_INCOMPLETE`), a missing event is
  not counted as "absent". With complete coverage an atom that does not hold is REJECTED.
  The atom does not loosen section 4.6: a dynamic observation alone reaches SUPPORTED at most.
- `exit_code` atom (version 17): the observed process exit code of ONE `run_controlled` execution
  ({"type":"exit_code","evidence_id":<run ev_>,"code":N}). It binds only to `controlled-replay` evidence of operation
  `run_controlled` (static, compute and dynamic-observation evidence can never prove an exit code: REJECTED
  `EXIT_CODE_NEEDS_RUN_EVIDENCE`); a different recorded code is REJECTED (`EXIT_CODE_MISMATCH`); a run with no recorded
  exit code or not a complete run (truncated, unclean session) is UNVERIFIED (`EXIT_CODE_NOT_RECORDED`,
  `EXIT_CODE_RUN_NOT_COMPLETE`), never accepted (timeout/error runs are already rejected as failed evidence).
  A verified code also backs the same number written in the claim text, but ONLY where that occurrence stands in an
  explicit exit-code phrase (`exit code N`, `exit status N`, `exits with N`, `exits with code N`, `returns N to the OS`;
  N is decimal, signed decimal or the 0x form of the 32-bit pattern). Every other occurrence of the same number (an
  address, a size, a count) stays governed by the normal value / hex-literal rules. Present claims only.
- Result values (values.py): every declared + text-extracted value must appear in the cited evidence's raw output
  verbatim (number: numeric equality; string: verbatim substring) or be backed by execution evidence. Otherwise the
  claim cannot be SUPPORTED: UNVERIFIED + `VALUE_NOT_IN_EVIDENCE`. A `derived` (computed) value is supported only if it
  appears in the output of isolated execution evidence; static evidence leaves a derived value UNVERIFIED at most.
- Number forms (version 6): `0x..` and decimal tokens in raw output with C/Hex-Rays suffixes (`u`, `l`, `ll`,
  `ul`, `ull`, `lu`, `llu`, `i64`, `ui64`; e.g. `0x6D8C5A83E9463C96LL`, `0xCu`), and, in `disassemble` evidence only,
  IDA `..h` hex (`20h`, `0F9B9B765h`; starts with a digit, quoted text and `;` comments excluded) count as numbers.
  Matching is still token-bounded and EXACT numeric equality; words/identifiers such as `push`, `high`, `arg_8h` are
  not numbers.
- `derivation` atom (version 6, derivation.py): a computed value is recomputed by the verifier from the quote/constant
  leaves in the cited STATIC (`shipped-artifact`) evidence with a closed operation set. It supports a value only in an
  `observation` + `present` claim (SUPPORTED at most); in a behavior claim and for PROVEN it supports nothing.
  Execution input/output cannot be a leaf. If the computation does not hold the claim is REJECTED (`DERIVATION_*`).
- `compute` evidence (version 7, compute.py; authority `sandboxed-computation`): isolated, deterministic computation
  of the model's code. REJECTED if record consistency (inputs re-derived from evidence, code blob, output digest,
  isolation, determinism) is broken. A value in its output is supported only with BOUND evidence (all inputs from the
  cited static evidence) and only in an `observation` + `present` claim (`support: computation`, SUPPORTED at most);
  in a behavior claim and for PROVEN it supports nothing. A claim resting only on compute evidence is REJECTED with
  `COMPUTE_ONLY`.
- `emulate` evidence (version 19, emulation.py; authority `cpu-emulation`): CPU emulation of the target's own code from
  the file image. REJECTED if the record is not a deterministic, returned, non-native emulation with its request
  recorded (`EMULATION_RECORD_INVALID`). A value (or 0x literal / constant atom) in its output is supported only in an
  `observation` + `present` claim (`support: emulation`, SUPPORTED at most; check `EMULATION`); in a behavior claim,
  an absence claim and for PROVEN it supports nothing (an emulated value is not what the program does when run).
  Its output bytes use the `read_bytes` dump format (hex rows are bytes, not numbers). Version 20: a code-range record
  (`end` in its request) is valid with a deterministic `range_end` stop instead of `return`.
- `captured_region` evidence (version 22, region_view.py; authority `dynamic-region-view`): a bounded view (hex, strings,
  disassembly) of bytes captured from an executable region of ONE dynamic observation. REJECTED if the record is not
  linked to an intact dynamic observation of this target, or claims a stronger capture than that observation
  (`REGION_VIEW_INVALID`), or if the claim does not also cite its observation (`REGION_VIEW_PARENT_NOT_CITED`). It backs
  an `observation` + `present` claim (SUPPORTED at most); it can never be the basis of PROVEN (`PROVEN_REGION_VIEW`, a
  cap, not a downgrade to UNVERIFIED) and its coverage is never complete (no absence claim).
- Location (version 8): an evidence `locations` RANGE does not SUPPORT a number by itself (a `read_bytes` range with a
  low RVA would "contain" small numbers); a location supports no decimal/declared result value. A number is supported
  in raw output, in a `constant` atom, or in an `address` atom where the claim declares it an address (hex-form
  literal/value only); a 0x literal in the text also passes if it equals a POINT address the tool itself reported
  (function/xref/string).
- Value classes (version 21, values.value_class): numbers are at most 64 bits (0x + <= 16 hex digits; a bare decimal
  of <= 20 digits without a leading zero); a longer or zero-padded-decimal token is a byte string compared as its
  exact canonical text against whole hex tokens of the evidence, never numerically; a decimal fraction is an exact
  token (docs/design/evidence-schema.md section 4.14).
- Conditional slice lines (version 23): in `dataflow_slice` evidence, `candidate ... NOT definite` lines, lines with
  `assumes=A1/A2` and clobbered bytes' `last=0x..` hold only conditionally. A value, 0x literal, constant atom or quote
  backed ONLY by such lines leaves the claim UNVERIFIED (`VALUE_ONLY_CONDITIONAL` / `QUOTE_ONLY_CONDITIONAL`) unless it
  is also backed unconditionally (another line, or another cited evidence item).
- `control_pair` atom (version 24, control_pair.py): contrasting complete `run_controlled` cases of ONE build (inputs
  equal except a named discriminator), each side bound to its own observed outcome (stdout/stderr quote or exit code),
  the outcomes differing; `asserts` names the side the claim is about and the claim must name that side's input (and
  not the other side's). Every behavior claim declares `behavior_class` ("acceptance_validation" | "ordinary"; missing:
  UNVERIFIED `BEHAVIOR_CLASS_MISSING`). A validation claim (acceptance_validation, kind `bypass_poc`, or an "ordinary"
  claim whose text reads like a verdict: backstop) without a valid pair is UNVERIFIED (`CONTROL_PAIR_MISSING`); a
  malformed or mismatched pair or binding is REJECTED (`CONTROL_PAIR_INVALID`); an incomplete run, contrast-free
  outcomes or disagreeing repeats are UNVERIFIED (`CONTROL_PAIR_INCOMPLETE`, `_SAME_OUTCOME`, `_UNSTABLE`). `fix_pair`
  (two builds) stays separate.
Status is the verifier's decision, not the agent's. If the PROVEN conditions are not met and the SUPPORTED conditions
are, SUPPORTED is granted and the downgrade is stated in `issues` (not silent).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from ..core.cas import Cas, CasError
from ..dynamic.match import check_api_sequence, check_api_subsequence
from ..dynamic.lines import output_text, suggest_lines, trace_text
from ..dynamic.model import SCHEMA_V2, TARGET_CALLERS, ObservationError, load_observation
from ..dynamic.validate import validate_record as validate_dynamic
from .model import (C_INT_SUFFIX, COMPUTE_AUTHORITY, DYNAMIC_AUTHORITY, EMULATION_AUTHORITY, ISOLATED, AddressError,
                    ClaimStatus, derive_strength, evidence_id_ok, hex_literals, location_contains,
                    location_contains_any_space, long_hex_literals, normalize_address, REGION_VIEW_AUTHORITY)
from . import compute as compute_ev
from . import emulation as emulation_ev
from . import control_pair as control_pair_ev
from . import region_view as region_view_ev
from .derivation import DerivationError, evaluate as evaluate_derivation, result_matches
from .kinds import is_behavior
from .terms import extract_terms, normalize_hay, term_backed
from .values import MAX_NUMBER_DEC_DIGITS, MAX_NUMBER_HEX_DIGITS, claim_number, effective_values, numeric, value_class

# 24: `control_pair` atom and the acceptance-validation rule (control_pair.py, docs/design/evidence-schema.md section
#    4.17). Every behavior claim (not bypass_poc / fix_verification) declares `behavior_class`; missing -> UNVERIFIED
#    `BEHAVIOR_CLASS_MISSING` (check `BEHAVIOR_CLASS`, written only then). A validation claim (acceptance_validation,
#    `bypass_poc`, or validation wording outside quoted output as a backstop) needs a valid control pair bound to the
#    input the claim names: without one it is UNVERIFIED (`CONTROL_PAIR_MISSING`), even when a single run would have
#    made it PROVEN in 23. The check `CONTROL_PAIR` is written only for such claims or when the atom is present.
#    Observation and fix claims verify bit-for-bit as in 23. Recorded 23 statuses stay as recorded until re-verified
#    (report_build re-verifies every claim; a v23 behavior claim then lacks behavior_class).
# 23: conditional slice lines (docs/design/evidence-schema.md section 4.16). In `dataflow_slice` evidence a line is
#    CONDITIONAL when it is a `candidate ... NOT definite` line (last writes that may have been overwritten), carries
#    `assumes=A1`/`assumes=A2` (holds only under that assumption), or shows a clobbered byte's `last=0x..`. A value, a
#    0x literal, a constant atom or a quote found in the cited evidence ONLY on such lines cannot make the claim
#    SUPPORTED: UNVERIFIED with `VALUE_ONLY_CONDITIONAL` / `QUOTE_ONLY_CONDITIONAL`, unless the same value/quote is also
#    backed unconditionally (another line of that evidence, or another cited evidence item). Claims that cite no
#    `dataflow_slice` evidence verify bit-for-bit as in 22.
# 22: `dynamic-region-view` (captured_region) evidence (see the module docstring). Its text is dump/disassembly format
#    (`captured_region` joins `read_bytes`/`emulate` in DUMP_OPERATIONS and `disassemble` in ASM_OPERATIONS: hex rows and
#    instruction-byte fields are bytes, not numbers). Claims that do not cite such evidence verify bit-for-bit as in 21.
# 21: no numeric collapse of byte strings (false accept found in review: a 64-zero "digest" was SUPPORTED because
#    the value checker read it as the decimal 0 and the emulation record contained a 0). A claimed token is classified
#    first (values.value_class): a NUMBER (0x + <= 16 hex digits, leading zeros allowed; bare decimal <= 20 digits
#    without a leading zero) is compared numerically as before; a HEX STRING (0x + > 16 digits, a bare hex run > 16
#    characters, a bare decimal with a leading zero or > 20 digits) by its exact canonical text (lower case, no 0x,
#    leading zeros kept) against whole hex tokens of the evidence (`_hex_tokens`); a decimal FRACTION as the exact token.
#    Applies to text values, declared values, 0x literals (a long one unbacked is HEX_LITERAL_UNSUPPORTED), quote and
#    constant atoms, derivation values/leaves; an address atom longer than 16 digits is ADDRESS_UNRESOLVABLE. Evidence
#    tokens longer than 64 bits are no longer numbers. A bare digest in the text, which version 20 did not check at all
#    when it began with a digit (no value, no term), is now a value. Claims without such tokens verify as in 20.
# 20: emulation records of a code range (emulate `end`, request version 2) are valid with stop=range_end; the stop must
#    match the request (range_end iff `end`). What an emulation record may back is unchanged. Claims that cite no
#    range record verify bit-for-bit as in 19.
# 19: `cpu-emulation` (emulate) evidence (see the module docstring). Claims that do not cite emulation evidence verify
#    bit-for-bit as in 18: the check `EMULATION` and the value support `emulation` appear only when it is cited.
# 18: three term-check false negatives closed (terms.py): (a) a template name is a term together with its argument
#    list (`std::vector<int>` is not backed by `std::vector<float>`; whitespace inside <...> is ignored); (b) `XOR` is
#    backed by `^` only as a binary operator between operands (`a ^ b`, `x^=y`), not by a `^` in a `[^...]` class or a
#    string (the `xor` word still backs it); (c) a dot-leading PE section name (`.pdata`, `.text`) is a term that must
#    appear exactly (case-insensitive), while sentence dots, `.5` and `foo.dll` are not terms. Nothing else is loosened.
#    Review: template needs `::`/known type, sections closed, `XOR` code operands, `<...>` keywords/nesting ignored, caret scan linear.
# 17: `exit_code` atom {evidence_id, code} (see the module docstring). Claims without this atom verify bit-for-bit as in 16:
#    the atom adds its own check `EXIT_CODE` only when present, and a PROVEN behavior claim may also name the run
#    outcome as its observed output.
# 16: technical terms of the claim text (terms.py, section 4.12). Every identifier, digit-bearing compound,
#    acronym and closed-lexicon word (algorithm/representation/randomness/property/crypto purpose) of a `present`
#    claim must be found in a cited non-compute evidence (raw output, run stdin/argv, observed output) or, for an IDA
#    auto-name, at a cited address; otherwise UNVERIFIED (`TERM_NOT_IN_EVIDENCE`, one issue per term) and the check
#    `TERMS_IN_EVIDENCE` (ok=False) is added. The check is written only when a term is unbacked, so a record whose
#    terms are all backed verifies bit-for-bit as in 15 (golden corpus unchanged).
# 15: fix verification. Claim kind `fix_verification` + atom `fix_pair` {original:{evidence_id,quote},
#    fixed:{evidence_id,quote}}: PROVEN only when BOTH builds were run (the original = the job's target SHA, the fixed =
#    the scope manifest's `fixed_target_sha256`), as complete isolated `controlled-replay` outcomes of the SAME input
#    (argv + stdin SHA-256), the reproduce quote is in the original output and not in the fixed output, and the fixed
#    output carries its own quote. Evidence of the fixed build is accepted only inside such a pair. Claims without
#    these features verify bit-for-bit as in 14.
# 14: the observed execution's own output(tracer protocol 3, optional `output` of an rh.dynamic/2 document). A
#    `quote` atom on dynamic evidence may also be a substring of that output rendered like a run_controlled blob
#    (stdout + "\n--- stderr ---\n" + stderr); its hex fields (`stdout_hex`/`stderr_hex`) are bytes, never searched as
#    text or numbers (like `bytes_hex`). The ceiling is unchanged (dynamic alone is at most SUPPORTED). Records without
#    `output` verify bit-for-bit as in 13.
# 13: dynamic memory evidence. (a) A `quote` atom on `dynamic-observation` evidence may also be a substring of its
#    rendered TRACE (`dynamic/lines.py`: one deterministic line per event, `[seq] api_call kernel32.dll!X caller=image`), a pure
#    function of the sealed document; a failed quote on such evidence names the lines to copy. (b) compute input kind
#    `memrange` (bytes captured from an executable region of a cited dynamic observation) binds like a static range; the
#    ceiling is unchanged (observation + present, SUPPORTED at most). (c) `bytes_hex` of a dynamic document is bytes, not
#    numbers. Records without these features verify bit-for-bit as in 12.
# 12: `api_sequence` atom optional `caller` ("image" | "dynamic"): compares only calls from that origin of an
#    `rh.dynamic/2` document (real backend rhtrace); `caller` on an rh.dynamic/1 document is MALFORMED. Atoms
#    without `caller` and all other records verify bit-for-bit as in 11.
# 11: compute input kinds `range` (a byte range of a read_bytes evidence, explicit `select` or AUTO-bound from an exactly matching
#    pasted literal) and `literal` (unbound pasted bytes). A range binding is re-derived from the evidence and bound exactly
#    like the other kinds; a literal binds nothing. Records without these kinds (all earlier ones) verify bit-for-bit as in 10.
# 10: issue/check detail and hint text is English; decisions, codes, checks and values are identical to 9.
# 9: format-aware number extraction. A `read_bytes` hex-dump region and the instruction-byte field of `disassemble`
#    lines carry bytes, not numbers: a digits-only group (`12`, `123456`) was read as a DECIMAL, so the invented
#    decimal 12 was "supported" by the byte 0x12. Only the typed views (explicit radix) and the `0x..:` address
#    prefix count in `read_bytes`; the format boilerplate (`4-byte groups`, `segment 1`) counts for nothing. Records
#    outside these two evidence types verify bit-for-bit as in 8 (golden corpus unchanged).
# 8: an evidence location (address/offset range or point) no longer supports a number by itself: only an `address`
#    atom does, and then only a hex literal / hex-form value (a literal equal to a reported POINT address also counts). Records whose numbers are backed by raw output, constant
#    atoms or address atoms verify bit-for-bit as in 7 (tests/unit/test_verifier_v6.py golden, test_verifier_location_values.py).
# 7: `sandboxed-computation` (compute) evidence. Claims that do not cite compute evidence are bit-for-bit as in 6.
# 6: suffixed/IDA number forms + the `derivation` atom. Claims without these forms and atom (version 5 and earlier)
#    give a bit-for-bit identical result in `checks`/`issues`/`values` (golden tests in tests/unit/test_verifier_v6.py).
# 5: api_sequence atom (claims produced with 4 carry no atom and give the same result)
VERIFIER_VERSION = "24"
MIN_QUOTE_LEN = 4
POINT_LOCATIONS = frozenset({"address", "file-offset"})  # exact addresses; the other kinds are spans
VALUE_ONLY_CONDITIONAL = "VALUE_ONLY_CONDITIONAL"
QUOTE_ONLY_CONDITIONAL = "QUOTE_ONLY_CONDITIONAL"
VALUE_ISSUE_CODES = frozenset({"VALUE_NOT_IN_EVIDENCE", "VALUE_DERIVED_NEEDS_EXECUTION", "VALUE_COMPUTE_NOT_BOUND",
                               VALUE_ONLY_CONDITIONAL})
SLICE_OPERATION = "dataflow_slice"
TERM_ISSUE_CODE = "TERM_NOT_IN_EVIDENCE"
COMPUTE_REJECTS = ("COMPUTE_NOT_ISOLATED", "COMPUTE_NONDETERMINISTIC", "COMPUTE_RECORD_INVALID",
                   "COMPUTE_INPUT_MISMATCH", "COMPUTE_ONLY")
BEHAVIOR_ISSUE_CODE = "BEHAVIOR_NEEDS_EXECUTION"
# Blockers that only cap a behavior claim at SUPPORTED (they do not make it UNVERIFIED) even when execution evidence exists
_CAP_ONLY_BLOCKERS = frozenset({"PROVEN_ABSENCE", "PROVEN_STATIC_CLAIM", region_view_ev.PROVEN_CAP})
DYNAMIC_PAIR_CODE = "PROVEN_DYNAMIC_NEEDS_RUN_OUTCOME"
API_SEQ_MODES = ("exact", "subsequence")
API_SEQ_MAX_CALLS = 512
API_SEQ_INCOMPLETE = "API_SEQUENCE_COVERAGE_INCOMPLETE"
FIX_KIND = "fix_verification"
_FIX_REJECTS = ("FIX_PAIR_MALFORMED", "FIX_NO_FIXED_BUILD", "FIX_PAIR_EVIDENCE_NOT_LISTED", "FIX_PAIR_BUILD_MISMATCH",
                "FIX_PAIR_WRONG_KIND", "FIX_INPUTS_DIFFER", "FIX_QUOTE_NOT_IN_RAW", "FIX_STILL_REPRODUCES",
                "FIX_BUILD_EVIDENCE_NEEDS_PAIR")
FIX_NEEDS_BOTH = "FIX_NEEDS_BOTH_BUILDS"
FIX_RUN_INCOMPLETE = "FIX_RUN_NOT_COMPLETE"
EXIT_CODE_REJECTS = ("EXIT_CODE_MALFORMED", "EXIT_CODE_NEEDS_RUN_EVIDENCE", "EXIT_CODE_MISMATCH")
EXIT_CODE_NOT_RECORDED = "EXIT_CODE_NOT_RECORDED"
EXIT_CODE_RUN_INCOMPLETE = "EXIT_CODE_RUN_NOT_COMPLETE"
_API_SEQ_REJECTS = ("API_SEQUENCE_MALFORMED", "API_SEQUENCE_NEEDS_DYNAMIC_EVIDENCE", "API_SEQUENCE_MISMATCH")

DERIVATION_REJECTS = ("DERIVATION_MALFORMED", "DERIVATION_RANGE", "DERIVATION_LEAF_NOT_STATIC",
                      "DERIVATION_LEAF_NOT_IN_RAW", "DERIVATION_MISMATCH")
STATIC_AUTHORITY = "shipped-artifact"  # a derivation leaf comes only from the target's own content (not execution input/output)

_HEX_FULL = re.compile(r"0[xX][0-9a-fA-F]+")
# C_INT_SUFFIX (model.py): suffix letters are not hex digits; a digit run does not spill into the suffix.
_RAW_HEX = re.compile(r"(?<![0-9A-Za-z_])0[xX]([0-9a-fA-F]+)" + C_INT_SUFFIX + r"(?![0-9A-Za-z_])")
_RAW_DEC = re.compile(r"(?<![0-9A-Za-z_])([0-9]+)" + C_INT_SUFFIX + r"(?![0-9A-Za-z_])")
# IDA disassembly hex: starts with a digit, ends with `h` (`20h`, `0F9B9B765h`); `push`/`arg_8h` do not match
_ASM_HEX = re.compile(r"(?<![0-9A-Za-z_])([0-9][0-9A-Fa-f]*)[hH](?![0-9A-Za-z_])")
_ASM_QUOTED = re.compile(r"'[^'\n]*'|\"[^\"\n]*\"")
# version 21: a whole hex token (optional 0x), bounded by non-word characters; for hex strings (byte strings, digests)
_HEX_TOKEN = re.compile(r"(?<![0-9A-Za-z_])(?:0[xX])?([0-9A-Fa-f]+)(?![0-9A-Za-z_])")
_ASM_COMMENT = re.compile(r";[^\n]*")
ASM_OPERATIONS = frozenset({"disassemble", region_view_ev.OPERATION})   # a region view prints the same `0xADDR: bytes text` lines
DUMP_OPERATIONS = frozenset({"read_bytes", "emulate", region_view_ev.OPERATION})   # emulate / a region view: same dump format
# disassemble line: `0x<addr>: <instruction bytes, even-length hex, no separators> <text>`; the byte field is no number
_ASM_BYTES = re.compile(r"^(0x[0-9a-fA-F]+:) (?:[0-9a-fA-F]{2})+(?= |$)", re.MULTILINE)
# read_bytes hex-dump row (4-byte groups joined by `_`) and the section markers around it
_DUMP_ROW = re.compile(r"^(\s*0x[0-9a-fA-F]+:) [0-9a-fA-F_]+$")
_DUMP_VIEW = re.compile(r"^\s+-- (\w+) --$")
_DUMP_SEGMENT = re.compile(r"^segment \d+ ")
_DUMP_FORMAT_LINE = "hex = file bytes in file order"


@dataclass
class Verdict:
    status: ClaimStatus
    checks: list[dict] = field(default_factory=list)
    issues: list[dict] = field(default_factory=list)
    values: list[dict] = field(default_factory=list)  # checked result values (+ supported flag)

    def to_record(self) -> dict:
        return {"verifier_version": VERIFIER_VERSION, "checks": self.checks, "issues": self.issues,
                "values": self.values}

    @property
    def codes(self) -> list[str]:
        return [i["code"] for i in self.issues]


def is_asm(rec: Mapping[str, Any] | None) -> bool:
    """IDA `..h` hex counts as a number only in disassembly evidence (not in text such as a decompile comment
    `[esp+20h]` or a string dump "24h")."""
    return bool(rec) and rec.get("operation") in ASM_OPERATIONS


def is_dump(rec: Mapping[str, Any] | None) -> bool:
    """`read_bytes` evidence: the hex dump carries bytes, not numbers (only the typed views give numbers, with an explicit radix)."""
    return bool(rec) and rec.get("operation") in DUMP_OPERATIONS


def is_dynamic(rec: Mapping[str, Any] | None) -> bool:
    return bool(rec) and rec.get("authority") == DYNAMIC_AUTHORITY


def numbers_of(raw: bytes, rec: Mapping[str, Any] | None) -> tuple[set[int], set[int]]:
    """Format-aware number extraction by evidence type (single entry point)."""
    return _raw_numbers(raw, is_asm(rec), is_dump(rec), is_dynamic(rec))


def _numeric_text(text: str, asm: bool, dump: bool) -> str:
    """Strips the regions that are not numbers: the disassemble instruction-byte field, the bytes of read_bytes hex-dump
    rows (the address prefix stays) and the format note/segment order. Typed-view lines (`0x..=..`, `0x.. 0x.. dec`) stay as is."""
    if asm:
        text = _ASM_BYTES.sub(lambda m: m.group(1), text)
    if dump:
        out, hex_region = [], True
        for ln in text.split("\n"):
            if ln.startswith(_DUMP_FORMAT_LINE):
                continue
            if _DUMP_SEGMENT.match(ln):
                hex_region = True
                ln = _DUMP_SEGMENT.sub("segment ", ln)
            else:
                m = _DUMP_VIEW.match(ln)
                if m:
                    hex_region = False
                elif hex_region and (ln.startswith(" ") or ln.startswith("0x")):
                    m = _DUMP_ROW.match(ln)
                    ln = m.group(1) if m else ""  # unrecognized indented line in the hex region: fail-closed, no number
            out.append(ln)
        text = "\n".join(out)
    return text


_DYN_BYTES = re.compile(rb'"(bytes_hex|stdout_hex|stderr_hex)":"[0-9a-f]*"')


def _blank_dyn_bytes(raw: bytes) -> bytes:
    """Hex-encoded bytes in a dynamic document (captured memory, the target's output) are data, not text or numbers."""
    return _DYN_BYTES.sub(lambda m: b'"' + m.group(1) + b'":""', raw)


def is_conditional_line(line: str) -> bool:
    """A `dataflow_slice` line that holds only conditionally (version 23): a last-write candidate, a value under an
    assumption, or a clobbered byte's last value."""
    return line.startswith("  candidate ") or " assumes=" in line or " last=0x" in line


def unconditional_raw(raw: bytes, rec: Mapping[str, Any] | None) -> bytes:
    """The raw output with the conditional lines blanked (same line count); unchanged for other evidence."""
    if not rec or rec.get("operation") != SLICE_OPERATION:
        return raw
    nl = b"\n"
    return nl.join(b"" if is_conditional_line(ln.decode("utf-8", "replace")) else ln for ln in raw.split(nl))


def _raw_numbers(raw: bytes, asm: bool = False, dump: bool = False, dyn: bool = False) -> tuple[set[int], set[int]]:
    """(hex, decimal) number sets; token-bounded, suffixes do not change the value. asm=True: IDA `..h` also goes into
    the hex set (outside quoted text and `;` comments); disassemble instruction bytes are not numbers.
    dump=True (read_bytes): hex-dump bytes are not numbers (version 9)."""
    text = _numeric_text(raw.decode("utf-8", "replace"), asm, dump)
    if dyn:   # captured memory bytes of a dynamic observation are bytes, not numbers
        text = _blank_dyn_bytes(text.encode("utf-8")).decode("utf-8")
    # version 21: a token longer than a 64-bit number (> 16 hex / > 20 decimal digits) is a byte string, not a number
    hexes = {int(m.group(1), 16) for m in _RAW_HEX.finditer(text) if len(m.group(1)) <= MAX_NUMBER_HEX_DIGITS}
    decs = {int(m.group(1)) for m in _RAW_DEC.finditer(text) if len(m.group(1)) <= MAX_NUMBER_DEC_DIGITS}
    if asm:   # IDA prefixes a 0 when the value starts with a letter: `0FFFFFFFFFFFFFFFFh` is still 64 bits
        code = _ASM_COMMENT.sub("", _ASM_QUOTED.sub(" ", text))
        hexes |= {int(m.group(1), 16) for m in _ASM_HEX.finditer(code)
                  if len(m.group(1)) <= MAX_NUMBER_HEX_DIGITS + (m.group(1)[0] == "0")}
    return hexes, decs


def _hex_tokens(raw: bytes, asm: bool = False, dump: bool = False, dyn: bool = False) -> set[str]:
    """Version 21: the whole hex tokens of an evidence output, canonical (lower case, without `0x`, leading zeros kept),
    for comparing a claimed hex string (byte string / digest; values.value_class). A token is a maximal run of hex
    digits, optionally after `0x`, bounded by non-word characters on both sides (so a part of a longer token, or of an
    identifier, is never a token). Like numbers (version 9): disassembly instruction bytes and read_bytes/emulate
    hex-dump rows are not tokens (their address prefix stays); captured memory of a dynamic observation is blanked."""
    text = (_blank_dyn_bytes(raw) if dyn else raw).decode("utf-8", "replace")
    if asm:
        text = _ASM_BYTES.sub(lambda m: m.group(1), text)
    if dump:
        text = "\n".join((m.group(1) if (m := _DUMP_ROW.match(ln)) else ln) for ln in text.split("\n"))
    return {m.group(1).lower() for m in _HEX_TOKEN.finditer(text)}


def hex_tokens_of(raw: bytes, rec: Mapping[str, Any] | None) -> set[str]:
    return _hex_tokens(raw, is_asm(rec), is_dump(rec), is_dynamic(rec))


def searchable(raw: bytes, rec: Mapping[str, Any] | None) -> bytes:
    """The text a quote or a value is searched in. Captured memory bytes of a dynamic observation are runtime data, not
    observed output: they can feed `compute`, but a substring of them never backs a quote or a value."""
    return _blank_dyn_bytes(raw) if is_dynamic(rec) else raw


def _quote_in_raw(quote: str, raw: bytes, asm: bool = False, dump: bool = False, dyn: bool = False) -> bool:
    if _HEX_FULL.fullmatch(quote):  # a hex-literal quote is token-bounded and numeric
        cls, key = value_class(quote)
        if cls == "hexstr":   # version 21: > 16 digits is a byte string: the exact whole token
            return key in _hex_tokens(raw, asm, dump, dyn)
        return key in _raw_numbers(raw, asm, dump, dyn)[0]
    return quote.encode("utf-8") in raw


def _quote_in_trace(quote: str, rec: Mapping[str, Any], raw: bytes) -> bool:
    """Dynamic observation: is the quote a substring of ONE rendered trace line (a pure function of the document)?
    A quote never spans two lines (that would assert the events are adjacent); a `0x` quote is token-bounded and numeric
    like everywhere else. Version 14: or a substring of the observed execution's own output (stdout, the stderr
    separator, stderr; rendered like a run_controlled blob), when the document carries it."""
    if not is_dynamic(rec):
        return False
    try:
        obs = load_observation(raw)
    except ObservationError:  # pragma: no cover  (validate_record rejects an unparsable document first)
        return False
    out = output_text(obs)
    if out is not None and _quote_in_raw(quote, out.encode("utf-8")):
        return True
    if "\n" in quote:
        return False
    text = trace_text(obs)
    if _HEX_FULL.fullmatch(quote):
        return _quote_in_raw(quote, text.encode("utf-8"))
    return quote in text


def _quote_hint(rec: Mapping[str, Any], raw: bytes, quote: str) -> str:
    """Explains a failed quote on dynamic observation evidence: what to copy (the trace lines the reply printed)."""
    if not is_dynamic(rec):
        return ""
    try:
        lines = suggest_lines(load_observation(raw), quote)
    except ObservationError:  # pragma: no cover
        return ""
    return ("; quote text copied exactly from one trace line of this observation (a whole line or a part of it, >= 4 "
            "characters; the lines are printed in the run_controlled reply as observation.trace), not a field name. "
            "Lines closest to your quote: " + " | ".join(ln[:160] for ln in lines)
            + ". To claim an order of calls use an api_sequence atom instead")


def verify_claim(claim: Mapping[str, Any], evidence: Mapping[str, Mapping[str, Any]],
                 invalidated: Mapping[str, Any], cas: Cas, target_sha256: str,
                 allowed_isolations: frozenset[str] = ISOLATED, scope_sha256: str | None = None,
                 fixed_sha256: str | None = None) -> Verdict:
    """claim: text, kind, polarity, requested, evidence_ids, atoms. evidence: id -> record (from the ledger)."""
    requested = ClaimStatus(claim["requested"])
    if requested is ClaimStatus.REJECTED:
        raise ValueError("REJECTED cannot be requested; only the verifier grants it")
    if requested is ClaimStatus.UNVERIFIED:
        return Verdict(ClaimStatus.UNVERIFIED)  # without evidence it is a hypothesis (model.is_hypothesis)

    issues: list[dict] = []
    checks: list[dict] = []

    def reject(code: str, detail: str = "") -> None:
        issues.append({"code": code, "severity": "REJECT", "detail": detail})

    def check(code: str, ok: bool) -> None:
        checks.append({"code": code, "ok": ok})

    ev_ids = list(dict.fromkeys(claim.get("evidence_ids") or []))
    if not ev_ids:
        reject("NO_EVIDENCE")
        return Verdict(ClaimStatus.REJECTED, checks, issues)

    polarity, kind = claim["polarity"], claim["kind"]
    recs: dict[str, Mapping[str, Any]] = {}
    raws: dict[str, bytes] = {}
    for eid in ev_ids:
        rec = evidence.get(eid)
        if rec is None:
            reject("UNKNOWN_EVIDENCE_ID", eid)
            continue
        if eid in invalidated:
            reject("EVIDENCE_INVALIDATED", eid)
            continue
        if not evidence_id_ok(rec) or rec.get("evidence_id") != eid:
            reject("EVIDENCE_ID_MISMATCH", eid)
            continue
        if rec.get("untrusted_content") is not True:
            reject("EVIDENCE_NOT_MARKED_UNTRUSTED", eid)
            continue
        subj = rec.get("subject") or {}
        fixed_run = (bool(fixed_sha256) and subj.get("sha256") == fixed_sha256
                     and rec.get("authority") == "controlled-replay")
        if target_sha256 not in (subj.get("sha256"), subj.get("derived_from_sha256")) and not fixed_run:
            reject("SUBJECT_SHA_MISMATCH", eid)
            continue
        try:
            raw = cas.get(rec["raw"]["blob_sha256"])
        except (CasError, KeyError, TypeError):
            reject("RAW_BLOB_HASH_MISMATCH", eid)
            continue
        if rec["raw"].get("bytes") != len(raw):
            reject("RAW_BLOB_HASH_MISMATCH", f"{eid} size")
            continue
        strength = derive_strength(rec.get("capture") or {})  # the field stored in the record is not trusted
        if strength == "failed":
            reject("EVIDENCE_FAILED", eid)
            continue
        if rec.get("authority") == DYNAMIC_AUTHORITY:  # dynamic observation: raw document + identity/scope consistency
            bad = validate_dynamic(rec, raw, scope_sha256=scope_sha256)
            if (rec.get("environment") or {}).get("isolation") not in allowed_isolations:
                bad.append(("DYNAMIC_NOT_ISOLATED", "dynamic observation was not taken in an isolated environment"))
            for code, detail in bad:
                reject(code, f"{eid}: {detail}")
            if bad:
                continue
        if rec.get("authority") == COMPUTE_AUTHORITY:  # compute: inputs re-derived from evidence, code/output digest
            bad = compute_ev.validate_record(rec, raw, evidence, cas, allowed_isolations)
            for code, detail in bad:
                reject(code, f"{eid}: {detail}")
            if bad:
                continue
        if rec.get("authority") == EMULATION_AUTHORITY:  # emulate: a deterministic, returned, non-native emulation
            bad = emulation_ev.validate_record(rec, cas)
            for code, detail in bad:
                reject(code, f"{eid}: {detail}")
            if bad:
                continue
        if rec.get("authority") == REGION_VIEW_AUTHORITY:  # captured_region: tied to an intact observation, never stronger
            bad = region_view_ev.validate_record(rec, evidence, invalidated)
            for code, detail in bad:
                reject(code, f"{eid}: {detail}")
            if bad:
                continue
        recs[eid], raws[eid] = rec, raw
    for eid, rec in recs.items():   # a view is cited together with its observation (lineage and coverage stay visible)
        if rec.get("authority") == REGION_VIEW_AUTHORITY and region_view_ev.parent_id(rec) not in ev_ids:
            reject(region_view_ev.PARENT_NOT_CITED, f"{eid}: also cite its observation {region_view_ev.parent_id(rec)}")
    check("EVIDENCE_INTEGRITY", not issues)
    if issues:
        return Verdict(ClaimStatus.REJECTED, checks, issues)

    strengths = {eid: derive_strength(r["capture"]) for eid, r in recs.items()}

    comp = {eid for eid, r in recs.items() if r["authority"] == COMPUTE_AUTHORITY}
    if not any(r["confidence"] in ("observed", "derived") and r["authority"] != "analyst-inference"
               for eid, r in recs.items() if eid not in comp):
        if comp:  # a computation is not evidence about the target: the static evidence its inputs came from must be cited too
            reject("COMPUTE_ONLY", "cite the static evidence the computation inputs came from")
        else:
            reject("INFERRED_ONLY")
    check("NOT_INFERRED_ONLY", "INFERRED_ONLY" not in [i["code"] for i in issues])
    # compute evidence that can support a value: bound + full + only in an observation/present claim (same cap as derivation)
    comp_ok = {eid for eid in comp if strengths[eid] == "full" and compute_ev.is_bound(recs[eid], recs)}         if (not is_behavior(kind) and polarity == "present") else set()
    if comp:  # added only when compute evidence is cited: the `checks` list of version 6 claims does not change
        check("COMPUTE", not any(i["code"] in COMPUTE_REJECTS for i in issues))
    # emulation evidence (version 19): its output backs a value only in an observation/present claim; never behavior,
    # absence or PROVEN. Like compute output, it is kept out of the generic raw-output value paths below.
    emu = {eid for eid, r in recs.items() if r["authority"] == EMULATION_AUTHORITY}
    emu_ok = {eid for eid in emu if strengths[eid] == "full"} \
        if (not is_behavior(kind) and polarity == "present") else set()
    if emu:  # added only when emulation evidence is cited: the `checks` list of version 17 claims does not change
        check("EMULATION", emu_ok == emu)
    aux, aux_ok = comp | emu, comp_ok | emu_ok   # evidence whose numbers count only when allowed for this claim

    if polarity == "absent":
        for eid, r in recs.items():
            if strengths[eid] != "full" or (r.get("coverage") or {}).get("relationship") != "complete":
                reject("ABSENCE_WITHOUT_COMPLETE_COVERAGE", eid)
        check("ABSENCE_COVERAGE", "ABSENCE_WITHOUT_COMPLETE_COVERAGE" not in [i["code"] for i in issues])

    # atomlar
    nums = {eid: numbers_of(raws[eid], recs[eid]) for eid in recs}
    # version 23: what each cited evidence backs UNCONDITIONALLY (conditional dataflow_slice lines blanked)
    slices = {eid for eid, r in recs.items() if r.get("operation") == SLICE_OPERATION}
    uraws = {eid: unconditional_raw(raws[eid], recs[eid]) for eid in slices}
    unums = {eid: numbers_of(uraws[eid], recs[eid]) for eid in slices}
    cond_issues: list[dict] = []   # backed only by conditional slice lines (UNVERIFIED, not a reject)

    def uncond_number(n: int) -> bool:
        return any(n in unums.get(e, nums[e])[0] or n in unums.get(e, nums[e])[1] for e in recs
                   if e not in aux or e in aux_ok)

    def uncond_token(t: str) -> bool:
        return any(t in hex_tokens_of(uraws.get(e, raws[e]), recs[e]) for e in recs if e not in aux or e in aux_ok)

    def uncond_quote(q: str) -> bool:
        return any(_quote_in_raw(q, searchable(uraws.get(e, raws[e]), recs[e]), is_asm(recs[e]), is_dump(recs[e]),
                                 is_dynamic(recs[e])) or (e not in slices and _quote_in_trace(q, recs[e], raws[e]))
                   for e in recs)
    verified_values: set[int] = set()  # constant atoms: the number is in the raw output
    verified_addrs: set[int] = set()  # address atoms: the number is declared an address inside an evidence location
    seq_unknown: list[dict] = []  # api_sequence: coverage incomplete, not verifiable (UNVERIFIED, not a reject)
    n_seq = 0
    derivations: list[int | bytes] = []  # verified derivation results (value support only in observation)
    n_deriv = 0
    fix_unknown: list[dict] = []  # fix_pair: a run is incomplete, or only one build was cited (UNVERIFIED, not a reject)
    n_fix, fix_paired = 0, set()
    exit_unknown: list[dict] = []  # exit_code: the run recorded no exit code / is not complete (UNVERIFIED, not a reject)
    n_exit = 0
    exit_allowed: set[int] = set()  # numbers a verified exit_code atom may back, in an exit-code phrase of the text only
    pair_unknown: list[dict] = []   # control_pair: missing / incomplete / same outcome / unstable (UNVERIFIED, not a reject)
    n_pair = 0
    for i, atom in enumerate(claim.get("atoms") or []):
        typ = atom.get("type")
        if typ == control_pair_ev.ATOM:   # carries its own evidence ids (both sides), like fix_pair
            n_pair += 1
            claim_vals = {str(v["value"]) for v in effective_values(claim.get("text") or "", claim.get("values") or [])}
            res = control_pair_ev.check(atom, recs, raws, set(_complete_replays(recs, strengths, allowed_isolations)),
                                        target_sha256, kind, claim_vals, claim.get("text") or "")
            if res is not None and res[0] == "REJECT":
                reject(res[1], f"atom[{i}]: {res[2]}")
            elif res is not None:
                pair_unknown.append({"code": res[1], "severity": "UNVERIFY", "detail": f"atom[{i}]: {res[2]}"})
            continue
        if typ == "fix_pair":  # carries its own evidence ids (original + fixed), like derivation leaves
            n_fix += 1
            res = _check_fix_pair(atom, recs, raws, strengths, allowed_isolations, target_sha256, fixed_sha256, kind)
            if res is not None and res[0] == "REJECT":
                reject(res[1], f"atom[{i}]: {res[2]}")
            else:
                if res is not None:
                    fix_unknown.append({"code": res[1], "severity": "UNVERIFY", "detail": f"atom[{i}]: {res[2]}"})
                fix_paired.add(str((atom.get("fixed") or {}).get("evidence_id")))
            continue
        if typ == "derivation":  # leaves carry their own evidence_id; the atom has no top-level id
            n_deriv += 1
            res = _check_derivation_atom(atom, recs, raws, nums)
            if isinstance(res, tuple):
                reject(res[0], f"atom[{i}]: {res[1]}")
            else:
                derivations.append(res)
            continue
        a_ev = atom.get("evidence_id")
        if a_ev not in recs:
            reject("ATOM_EVIDENCE_NOT_LISTED", f"atom[{i}]")
            continue
        if typ == "quote":
            q = atom.get("text")
            if not isinstance(q, str) or len(q) < MIN_QUOTE_LEN:
                reject("QUOTE_TOO_SHORT", f"atom[{i}]")
            elif not _quote_in_raw(q, searchable(raws[a_ev], recs[a_ev]), is_asm(recs[a_ev]), is_dump(recs[a_ev]),
                                   is_dynamic(recs[a_ev])) and not _quote_in_trace(q, recs[a_ev], raws[a_ev]):
                reject("QUOTE_NOT_IN_RAW", f"atom[{i}]{_quote_hint(recs[a_ev], raws[a_ev], q)}")
            elif a_ev in slices and not uncond_quote(q):
                cond_issues.append({"code": QUOTE_ONLY_CONDITIONAL, "severity": "UNVERIFY", "detail":
                                    f"atom[{i}]: the quote is only on conditional dataflow_slice lines (candidate / "
                                    "assumes= / last=); cite evidence that shows it unconditionally"})
        elif typ == "address":
            space = str(atom.get("space") or "auto").lower()
            if space not in ("auto", "va", "rva", "file_offset"):
                reject("ADDRESS_UNRESOLVABLE", f"atom[{i}]: space must be va, rva or omitted")
                continue
            if isinstance(atom.get("value"), str) and value_class(atom["value"])[0] == "hexstr":
                reject("ADDRESS_UNRESOLVABLE", f"atom[{i}]: an address has at most {MAX_NUMBER_HEX_DIGITS} hex digits "
                       "(a longer or zero-padded decimal token is a byte string, version 21)")
                continue
            try:
                n = normalize_address(atom.get("value"), "va" if space == "auto" else space, strict=True)
            except AddressError as e:
                reject("ADDRESS_UNRESOLVABLE", f"atom[{i}]: {e}")
                continue
            locs = recs[a_ev].get("locations") or []
            spaces = ("va", "rva", "file_offset") if space == "auto" else (space,)
            if any(location_contains(loc, sp, n) for loc in locs for sp in spaces):
                verified_addrs.add(n)
            else:
                other = [sp for sp in ("va", "rva", "file_offset") if sp != space
                         and any(location_contains(loc, sp, n) for loc in locs)]
                hint = f"; value is in the {other[0]} locations: use space='{other[0]}' or omit space" if other else ""
                reject("ADDRESS_NOT_IN_LOCATIONS", f"atom[{i}]: {hex(n)} not in evidence locations{hint}")
        elif typ == "constant":
            if isinstance(atom.get("value"), str) and value_class(atom["value"])[0] == "hexstr":
                # version 21: a byte string / digest constant is its exact whole token, never a number
                if value_class(atom["value"])[1] not in hex_tokens_of(raws[a_ev], recs[a_ev]):
                    reject("CONSTANT_NOT_IN_RAW", f"atom[{i}]")
                elif a_ev in slices and not uncond_token(value_class(atom["value"])[1]):
                    cond_issues.append({"code": VALUE_ONLY_CONDITIONAL, "severity": "UNVERIFY",
                                        "detail": f"atom[{i}]: only on conditional dataflow_slice lines"})
                continue
            try:
                n = normalize_address(atom.get("value"), "file_offset", strict=True)
            except AddressError as e:
                reject("CONSTANT_UNRESOLVABLE", f"atom[{i}]: {e}")
                continue
            hexes, decs = nums[a_ev]
            if n in hexes or n in decs:
                if a_ev not in aux or a_ev in aux_ok:  # an unbound compute / misused emulation output verifies no value
                    if a_ev in slices and not uncond_number(n):
                        cond_issues.append({"code": VALUE_ONLY_CONDITIONAL, "severity": "UNVERIFY",
                                            "detail": f"atom[{i}]: {hex(n)} only on conditional dataflow_slice lines"})
                    else:
                        verified_values.add(n)
            else:
                reject("CONSTANT_NOT_IN_RAW", f"atom[{i}]")
        elif typ == "api_sequence":
            n_seq += 1
            code, detail = _check_api_sequence_atom(atom, recs[a_ev], raws[a_ev], polarity)
            if code == API_SEQ_INCOMPLETE:
                seq_unknown.append({"code": code, "severity": "UNVERIFY", "detail": f"atom[{i}]: {detail}"})
            elif code:
                reject(code, f"atom[{i}]: {detail}")
        elif typ == "exit_code":
            n_exit += 1
            res = _check_exit_code_atom(atom, recs[a_ev], strengths[a_ev], allowed_isolations, polarity)
            if res is None:   # holds: the code (and its 32-bit pattern) now backs the same number written in the text
                exit_allowed |= _exit_code_numbers(atom["code"])
            elif res[0] == "REJECT":
                reject(res[1], f"atom[{i}]: {res[2]}")
            else:
                exit_unknown.append({"code": res[1], "severity": "UNVERIFY", "detail": f"atom[{i}]: {res[2]}"})
        else:
            reject("ATOM_TYPE_UNKNOWN", f"atom[{i}]")
    check("ATOMS", not any(c in ("QUOTE_TOO_SHORT", "QUOTE_NOT_IN_RAW", "ADDRESS_UNRESOLVABLE",
                                 "ADDRESS_NOT_IN_LOCATIONS", "CONSTANT_UNRESOLVABLE",
                                 "CONSTANT_NOT_IN_RAW", "ATOM_EVIDENCE_NOT_LISTED",
                                 "ATOM_TYPE_UNKNOWN", *_API_SEQ_REJECTS, *DERIVATION_REJECTS, *_FIX_REJECTS,
                                 *EXIT_CODE_REJECTS, control_pair_ev.INVALID)
                         for c in [i["code"] for i in issues]))
    if n_seq:  # added only when there is an atom: the `checks` list of atom-less (version 4) claims does not change
        check("API_SEQUENCE", not seq_unknown and not any(i["code"] in _API_SEQ_REJECTS for i in issues))
    if n_exit:  # added only when there is an atom: the `checks` list of exit-code-less (version 16) claims does not change
        check("EXIT_CODE", not exit_unknown and not any(i["code"] in EXIT_CODE_REJECTS for i in issues))
    pair_needed = control_pair_ev.needs_pair(kind, claim.get("text") or "", claim.get("behavior_class"))
    if pair_needed and not n_pair:
        pair_unknown.append({"code": control_pair_ev.MISSING, "severity": "UNVERIFY", "detail":
                             "a validation claim (accepted/rejected, valid/invalid, correct input) needs a control_pair "
                             "atom: one run_controlled case the program accepts and one it rejects, same build and "
                             "inputs equal except the discriminator"})
    if n_pair or pair_needed:   # added only for validation claims / pair atoms: other claims keep the version 23 checks
        check("CONTROL_PAIR", not pair_unknown and control_pair_ev.INVALID not in [i["code"] for i in issues])
    if control_pair_ev.class_missing(kind, claim.get("behavior_class")):   # structural: no word list decides it
        pair_unknown.append({"code": control_pair_ev.CLASS_MISSING, "severity": "UNVERIFY", "detail":
                             "a behavior claim declares behavior_class: 'acceptance_validation' (an input is accepted "
                             "or rejected, a key is valid, a password correct; needs a control_pair) or 'ordinary'"})
        check("BEHAVIOR_CLASS", False)
    if n_deriv:  # same principle: the `checks` list of derivation-less (version 5) claims does not change
        check("DERIVATIONS", not any(i["code"] in DERIVATION_REJECTS for i in issues))
    if fixed_sha256:   # a fixed-build run is valid only as the fixed side of a fix_pair; nothing else may lean on it
        for eid, r in recs.items():
            if (r.get("subject") or {}).get("sha256") == fixed_sha256 and eid not in fix_paired:
                reject("FIX_BUILD_EVIDENCE_NEEDS_PAIR", f"{eid}: evidence of the fixed build backs a claim only inside "
                       "a fix_pair together with the original build's run of the same input")
    if kind == FIX_KIND and not n_fix:
        fix_unknown.append({"code": FIX_NEEDS_BOTH, "severity": "UNVERIFY", "detail":
                            "a fix_verification claim needs a fix_pair atom: run_controlled on the original AND on the fixed build"})
    if n_fix or kind == FIX_KIND:   # added only for fix claims: the `checks` list of other claims does not change
        check("FIX_PAIR", not fix_unknown and not any(i["code"] in _FIX_REJECTS for i in issues))

    # 0x literals in the text: numeric match; no substring
    # Version 17: occurrences of a verified exit code inside an explicit exit-code phrase are backed by the atom and left
    # out of the value / hex-literal checks below; every other occurrence of the same number is checked as before.
    text_rest, exit_ctx = _blank_exit_context(claim.get("text") or "", exit_allowed)
    good, bad = hex_literals(text_rest)
    for tok in bad:
        reject("HEX_LITERAL_MALFORMED", tok)
    raw_hexes = set().union(*(h for e, (h, _) in nums.items() if e not in aux or e in aux_ok)) if nums else set()
    for n in good:
        # Version 8: a location RANGE never backs a bare literal (a header read spans small numbers); only an `address`
        # atom declares an address inside a range. A POINT location is an address the tool itself reported (function,
        # xref, string), so a literal equal to it ("main (0x140001070)") is still an address mention.
        supported = (n in verified_values or n in verified_addrs or n in raw_hexes
                     or any(loc.get("kind") in POINT_LOCATIONS and location_contains_any_space(loc, n)
                            for r in recs.values() for loc in r.get("locations") or []))
        if not supported:
            reject("HEX_LITERAL_UNSUPPORTED", hex(n))
        elif slices and not (n in verified_values or n in verified_addrs or uncond_number(n)
                             or any(loc.get("kind") in POINT_LOCATIONS and location_contains_any_space(loc, n)
                                    for r in recs.values() for loc in r.get("locations") or [])):
            cond_issues.append({"code": VALUE_ONLY_CONDITIONAL, "severity": "UNVERIFY",
                                "detail": f"{hex(n)} only on conditional dataflow_slice lines"})
    # Version 21: a 0x literal of more than 16 digits is a byte string (digest, key): its exact canonical text must be a
    # whole hex token of an evidence that may back numbers for this claim (no numeric collapse: 0x000..0 is not 0).
    long_lits = long_hex_literals(text_rest)
    if long_lits:
        allowed_toks = set().union(*(hex_tokens_of(raws[e], recs[e]) for e in recs if e not in aux or e in aux_ok))
        for s in long_lits:
            if s not in allowed_toks:
                reject("HEX_LITERAL_UNSUPPORTED", _shown("0x" + s))
            elif slices and not uncond_token(s):
                cond_issues.append({"code": VALUE_ONLY_CONDITIONAL, "severity": "UNVERIFY",
                                    "detail": f"{_shown('0x' + s)} only on conditional dataflow_slice lines"})
    check("HEX_LITERALS", not any(i["code"].startswith("HEX_LITERAL") for i in issues))

    if issues:
        return Verdict(ClaimStatus.REJECTED, checks, issues)

    # result values: if absent from the evidence (or from execution evidence) the claim cannot be SUPPORTED
    # A derivation supports a value only in an observation (observation, present) claim: "this computation over these
    # constants gives X" is a static fact; "X is accepted" is behavior and needs execution (derivation supports nothing there).
    deriv_ok = derivations if (not is_behavior(kind) and polarity == "present") else []
    if exit_ctx:   # a declared value equal to a context-backed exit code is that same occurrence, not an extra claim
        claim = {**claim, "values": [d for d in claim.get("values") or [] if numeric(str(d.get("value"))) not in exit_ctx
                                     and not _is_signed_in(str(d.get("value")), exit_ctx)]}
    claim = {**claim, "text": text_rest}   # _check_values reads only the text and the declared values
    checked = _check_values(claim, recs, raws, strengths, verified_values, allowed_isolations, nums,
                            deriv_ok, derivations, comp, comp_ok, verified_addrs, emu, emu_ok, uraws, unums)
    unbacked = [v for v in checked if not v["supported"]]
    for v in unbacked:
        issues.append({"code": v["code"], "severity": "UNVERIFY", "detail": _shown(v["value"])})
    check("VALUES_IN_EVIDENCE", not unbacked)
    if slices:   # added only when dataflow_slice evidence is cited: the `checks` list of version 22 claims does not change
        issues += cond_issues
        check("UNCONDITIONAL_BACKING", not cond_issues
              and not any(v["code"] == VALUE_ONLY_CONDITIONAL for v in unbacked))
    # Version 16: the technical terms of the text must be in the cited evidence too (the status covers the whole
    # statement's terms, not only its atoms). An absence claim names what is NOT in the evidence: not applied there.
    bad_terms = unbacked_terms(claim.get("text") or "", recs, raws, comp) if polarity == "present" else []
    for t in bad_terms:
        issues.append({"code": TERM_ISSUE_CODE, "severity": "UNVERIFY", "detail": _shown(t)})
    if bad_terms:  # written only when it fails: records whose terms are all backed keep the version 15 `checks`
        check("TERMS_IN_EVIDENCE", False)

    # A behavior claim ("this input is accepted", "the key is valid", "the branch is taken under this condition") is
    # supported only by execution evidence: a value APPEARING in static evidence does not show it is the accepted input.
    behavior = is_behavior(kind)
    why: list[tuple[str, str]] = []
    if behavior or requested is ClaimStatus.PROVEN:
        why = _proven_blockers(kind, polarity, recs, strengths, allowed_isolations,
                               claim.get("atoms") or [], checked, claim.get("text") or "", nums)
    # A dynamic observation is an execution observation: if the claim is tied to its output a behavior claim reaches
    # SUPPORTED; the PROVEN blockers (no matching run outcome, etc.) are then only a cap (they do not make it UNVERIFIED).
    dyn_backing = _dynamic_backs_claim(recs, claim.get("atoms") or [], checked, claim.get("text") or "", nums)
    exec_why = [w for w in why if behavior and not dyn_backing and w[0] not in _CAP_ONLY_BLOCKERS]
    if exec_why:
        issues.append({"code": BEHAVIOR_ISSUE_CODE, "severity": "UNVERIFY", "detail":
                       "behavior claim (what the program does when run) needs controlled-run evidence"})
        issues += [{"code": c, "severity": "UNVERIFY", "detail": d} for c, d in exec_why]
    if behavior:
        check("BEHAVIOR_NEEDS_EXECUTION", not exec_why)
    if seq_unknown:
        issues += seq_unknown
    if fix_unknown:
        issues += fix_unknown
    if exit_unknown:
        issues += exit_unknown
    if pair_unknown:
        issues += pair_unknown
    if unbacked or bad_terms or exec_why or seq_unknown or fix_unknown or exit_unknown or cond_issues or pair_unknown:
        return Verdict(ClaimStatus.UNVERIFIED, checks, issues, _public(checked))

    # SUPPORTED conditions met
    granted = ClaimStatus.SUPPORTED
    if dyn_backing and why and behavior and requested is not ClaimStatus.PROVEN:  # SUPPORTED via dynamic observation: why it is not PROVEN is not silent
        issues += [{"code": c, "severity": "CAP", "detail": d} for c, d in why if c not in _CAP_ONLY_BLOCKERS]
    if behavior or requested is ClaimStatus.PROVEN:
        check("PROVEN_CONDITIONS", not why)
        if not why:
            granted = ClaimStatus.PROVEN  # behavior: execution evidence + result tied to the output -> PROVEN
        elif requested is ClaimStatus.PROVEN:
            for code, detail in why:
                issues.append({"code": code, "severity": "DOWNGRADE", "detail": detail})
    # partial evidence supports only present + SUPPORTED
    return Verdict(granted, checks, issues, _public(checked))


def unbacked_terms(text: str, recs: Mapping[str, Mapping[str, Any]], raws: Mapping[str, bytes],
                   comp: set[str] | frozenset[str] = frozenset()) -> list[str]:
    """Technical terms of the claim text (terms.py) that no cited evidence backs. The haystack is the searchable raw
    output of every cited evidence except compute (the model's own code and output are not evidence about the target)
    and analyst inference, plus the stdin/argv given to a cited run and a dynamic observation's own output. An IDA
    auto-name (`sub_<hex>`) is also backed by a cited decompile/disassembly of that address or a point location."""
    terms = extract_terms(text)
    if not terms:
        return []
    parts: list[str] = []
    addrs: set[int] = set()
    for eid, rec in recs.items():
        if eid in comp or rec.get("authority") == "analyst-inference":
            continue
        parts.append(searchable(raws[eid], rec).decode("utf-8", "replace"))
        p = rec.get("parameters") or {}
        if isinstance(p.get("stdin"), str):
            parts.append(p["stdin"])
        parts += [a for a in p.get("argv") or [] if isinstance(a, str)]
        if is_dynamic(rec):
            try:
                out = output_text(load_observation(raws[eid]))
            except ObservationError:  # pragma: no cover  (validate_record rejects an unparsable document first)
                out = None
            if out:
                parts.append(out)
        for k in ("function", "address"):
            v = p.get(k)
            if isinstance(v, int) and not isinstance(v, bool):
                addrs.add(v)
            elif isinstance(v, str) and _HEX_FULL.fullmatch(v.strip()):
                addrs.add(int(v.strip(), 16))
        for loc in rec.get("locations") or []:  # an address the tool itself reported (function, xref, string)
            if loc.get("kind") == "address" and isinstance(loc.get("start"), int):
                addrs.add(loc["start"])
    hay = normalize_hay("\n".join(parts))
    return [t["term"] for t in terms if not term_backed(t, hay, addrs)]


def _shown(value: str) -> str:
    return value if len(value) <= 80 else value[:77] + "..."


def _public(checked: list[dict]) -> list[dict]:
    # `support` is written only for a derivation-supported value: `values` of derivation-less (version 5) records does not change
    return [{"value": _shown(v["value"]), "derived": v["derived"], "source": v["source"],
             "supported": v["supported"], **({} if v["supported"] else {"code": v["code"]}),
             **({"support": v["_via"]} if v.get("_via") in ("derivation", "computation", "emulation") else {})}
            for v in checked]


def _check_values(claim: Mapping[str, Any], recs: Mapping[str, Mapping[str, Any]],
                  raws: Mapping[str, bytes], strengths: Mapping[str, str], verified: set[int],
                  allowed: frozenset[str], nums: Mapping[str, tuple[set[int], set[int]]],
                  deriv_ok: list | None = None, deriv_all: list | None = None,
                  comp: set[str] | frozenset[str] = frozenset(), comp_ok: set[str] | frozenset[str] = frozenset(),
                  addrs: set[int] | frozenset[int] = frozenset(),
                  emu: set[str] | frozenset[str] = frozenset(), emu_ok: set[str] | frozenset[str] = frozenset(),
                  uraws: Mapping[str, bytes] | None = None,
                  unums: Mapping[str, tuple[set[int], set[int]]] | None = None) -> list[dict]:
    """For each result value: {value, derived, source, supported, code}. 0x literals are not repeated here
    (those in the text are HEX_LITERAL_*; declared 0x values are checked numerically). deriv_ok: verified derivation
    results that can support a value (observation+present only); deriv_all: all verified derivation results.
    addrs: numbers verified by an `address` atom (they support a hex-form value only). emu / emu_ok: cited emulation
    evidence / the part that may back a value in this claim (observation + present)."""
    values = effective_values(claim.get("text") or "", claim.get("values") or [])
    replays = _complete_replays(recs, strengths, allowed)
    behavior = is_behavior(claim.get("kind") or "behavior")
    out = []
    toks: dict[tuple[str, bool], set[str]] = {}   # hex tokens per evidence, computed only when a hex string needs them
    uraws, unums = uraws or {}, unums or {}

    def tokens(eid: str, uncond: bool = False) -> set[str]:
        if (eid, uncond) not in toks:
            toks[(eid, uncond)] = hex_tokens_of(uraws.get(eid, raws[eid]) if uncond else raws[eid], recs[eid])
        return toks[(eid, uncond)]

    for v in values:
        val = v["value"]
        cls, key = value_class(val)   # version 21: classified before comparing (values.py)
        n = key if cls == "number" else None

        def hits(eids: Any, uncond: bool = False) -> list[str]:
            res = []
            for eid in eids:
                raw = uraws.get(eid, raws[eid]) if uncond else raws[eid]
                if n is not None:
                    hexes, decs = unums.get(eid, nums[eid]) if uncond else nums[eid]
                    if n in hexes or n in decs:  # raw output only: a location range is not a value (version 8)
                        res.append(eid)
                elif cls == "hexstr":   # a byte string / digest: the exact whole token, never a number or a part
                    if key in tokens(eid, uncond):
                        res.append(eid)
                elif cls == "fraction":   # a decimal fraction: the exact token (`3.14` is not inside `13.145`)
                    if re.search(r"(?<![0-9A-Za-z_.])" + re.escape(val) + r"(?![0-9A-Za-z_])(?!\.[0-9])",
                                 searchable(raw, recs[eid]).decode("utf-8", "replace")):
                        res.append(eid)
                elif val.encode("utf-8") in searchable(raw, recs[eid]):
                    res.append(eid)
            return res

        code, ok = "VALUE_NOT_IN_EVIDENCE", False
        raw_hits = hits([e for e in raws if e not in comp and e not in emu])  # compute/emulation: own rules (below)
        comp_hits = hits(sorted(comp)) if comp else []
        emu_hits = hits(sorted(emu)) if emu else []
        if v["derived"]:
            # computed value: must appear in the execution output OR have been given to the execution as input
            # (execution evidence carries the input in `parameters`; the result is tied separately by quote/value, see PROVEN).
            # The input path (version 6) is for behavior claims only: an input the model itself supplied can show what the
            # program does only via behavior + execution result (PROVEN_NEEDS_OBSERVED_OUTPUT); it never supports an
            # observation claim (what is in code/data).
            ok = any(e in replays for e in raw_hits) or (
                behavior and any(_fed_to_run(recs[e], val) for e in replays))
            if not ok and raw_hits:
                code = "VALUE_DERIVED_NEEDS_EXECUTION"  # even if it appears in static evidence, a computed value is verified by execution
        else:
            # an address atom backs the hex form of the address only, never a decimal result value (version 8)
            by_atom = n is not None and (n in verified or (n in addrs and _HEX_FULL.fullmatch(val) is not None))
            ok = by_atom or bool(raw_hits)
            # version 23: backed only by conditional dataflow_slice lines (candidate / assumes= / last=) is not enough
            if not by_atom and raw_hits and uraws and not hits(raw_hits, uncond=True):
                ok, code = False, VALUE_ONLY_CONDITIONAL
        via = None
        if not ok and deriv_all and any(result_matches(r, val) for r in deriv_all):
            if deriv_ok and any(result_matches(r, val) for r in deriv_ok):
                ok, via = True, "derivation"  # recomputed from static constants (observation; not executed)
            else:
                code = "VALUE_DERIVED_NEEDS_EXECUTION"  # in a behavior claim derivation does not replace execution
        if not ok and comp_hits:
            if any(e in comp_ok for e in comp_hits):
                ok, via = True, "computation"  # bound, deterministic, isolated computation (observation; target not executed)
            elif behavior:
                code = "VALUE_DERIVED_NEEDS_EXECUTION"  # a computation does not show what the program does
            else:
                code = "VALUE_COMPUTE_NOT_BOUND"  # inputs are not from the cited static evidence
        if not ok and emu_hits:
            if any(e in emu_ok for e in emu_hits):
                ok, via = True, "emulation"  # CPU emulation of the target's code (observation; the program was not run)
            elif behavior:
                code = "VALUE_DERIVED_NEEDS_EXECUTION"  # an emulated value does not show what the program does
        out.append({**v, "supported": ok, "code": code, "_raw_hits": raw_hits, **({"_via": via} if via else {})})
    return out


def _check_derivation_atom(atom: Mapping[str, Any], recs: Mapping[str, Mapping[str, Any]],
                           raws: Mapping[str, bytes], nums: Mapping[str, tuple[set[int], set[int]]]
                           ) -> int | bytes | tuple[str, str]:
    """Derivation atom: (code, detail) reject reason or the verified result. Leaves must be found in the cited
    `shipped-artifact` evidence's raw output verbatim (quote) or by exact numeric equality (constant)."""
    if set(atom) - {"type", "value", "expr"} or "expr" not in atom or "value" not in atom:
        return "DERIVATION_MALFORMED", "atom must be {type, value, expr}"
    claimed = atom["value"]
    if isinstance(claimed, bool) or not isinstance(claimed, (str, int)) or claimed == "":
        return "DERIVATION_MALFORMED", "value must be a string or an integer"

    def leaf(kind: str, node: dict) -> int | bytes:
        eid = node.get("evidence_id")
        if eid not in recs:
            raise DerivationError("DERIVATION_LEAF_NOT_STATIC", "the leaf's evidence is not in evidence_ids")
        if recs[eid].get("authority") != STATIC_AUTHORITY:  # execution input/output, dynamic observation: never
            raise DerivationError("DERIVATION_LEAF_NOT_STATIC", f"{eid}: a leaf may come only from static target evidence")
        if kind == "quote":
            q = node["quote"]
            if not isinstance(q, str) or len(q) < MIN_QUOTE_LEN:
                raise DerivationError("DERIVATION_MALFORMED", f"quote leaf must be a string of >= {MIN_QUOTE_LEN} characters")
            b = q.encode("utf-8")
            if b not in raws[eid]:
                raise DerivationError("DERIVATION_LEAF_NOT_IN_RAW", f"quote is not in the raw output of {eid}")
            return b
        c = node["const"]
        n = c if (isinstance(c, int) and not isinstance(c, bool)) else (claim_number(c) if isinstance(c, str) else None)
        if n is None or n < 0:
            raise DerivationError("DERIVATION_MALFORMED", "constant leaf must be a non-negative integer or a 0x (<= 16 "
                                  "digits) / decimal (no leading zero) string")
        hexes, decs = nums[eid]
        if n not in hexes and n not in decs:
            raise DerivationError("DERIVATION_LEAF_NOT_IN_RAW", f"constant {hex(n)} is not in the raw output of {eid}")
        return n

    try:
        result = evaluate_derivation(atom["expr"], leaf)
    except DerivationError as e:
        return e.code, e.detail
    if not result_matches(result, claimed):
        return "DERIVATION_MISMATCH", "the recomputed result is not exactly equal to value"
    return result


def _fed_to_run(rec: Mapping[str, Any], val: str) -> bool:
    """Was the value given to the run as input (stdin line/word or argv item)? No substring match."""
    p = rec.get("parameters") or {}
    stdin = p.get("stdin")
    if isinstance(stdin, str):
        if val == stdin.strip() or val in stdin.split() or val in [ln.strip() for ln in stdin.splitlines()]:
            return True
    argv = p.get("argv")
    return isinstance(argv, list) and val in [a for a in argv if isinstance(a, str)]


def _complete_replays(recs: Mapping[str, Mapping[str, Any]], strengths: Mapping[str, str],
                      allowed: frozenset[str]) -> list[str]:
    """Complete, untruncated, exit-coded, sufficiently isolated `controlled-replay` observation evidence."""
    out = []
    for eid, r in recs.items():
        cap = r["capture"]
        if (r["authority"] == "controlled-replay" and r["confidence"] == "observed"
                and cap.get("status") == "OK" and cap.get("truncated") is False
                and cap.get("timed_out") is False and cap.get("exit_code") is not None
                and strengths[eid] == "full"
                and (r.get("environment") or {}).get("isolation") in allowed):
            out.append(eid)
    return out


def _proven_blockers(kind: str, polarity: str, recs: Mapping[str, Mapping[str, Any]],
                     strengths: Mapping[str, str], allowed: frozenset[str],
                     atoms: list | None = None, checked: list | None = None, text: str = "",
                     nums: Mapping[str, tuple[set[int], set[int]]] | None = None) -> list[tuple[str, str]]:
    why: list[tuple[str, str]] = []
    if not is_behavior(kind):
        why.append(("PROVEN_STATIC_CLAIM", "an observation is SUPPORTED at most"))
    if any(r["authority"] == REGION_VIEW_AUTHORITY for r in recs.values()):
        why.append((region_view_ev.PROVEN_CAP, "a view of captured memory is derived from one observation: SUPPORTED at most"))
    if polarity == "absent":
        why.append(("PROVEN_ABSENCE", "an absence claim is SUPPORTED at most"))
    replays = {eid: r for eid, r in recs.items()
               if r["authority"] == "controlled-replay" and r["confidence"] == "observed"}
    dyn_ids = {eid for eid, r in recs.items() if r["authority"] == DYNAMIC_AUTHORITY}
    paired = _dynamic_pairs(recs, strengths, allowed)
    if dyn_ids - paired:  # a dynamic observation without a matching run outcome cannot back PROVEN (alone or leaning on another)
        why.append((DYNAMIC_PAIR_CODE, "a dynamic observation alone never proves a claim: cite a complete "
                    "run_controlled outcome of the same case (argv, stdin, exit code) and a full-coverage observation"))
    if not replays:
        why.append(("PROVEN_NEEDS_CONTROLLED_REPLAY", "no isolated run evidence"))
        return why
    good = {}
    for eid, r in replays.items():
        cap = r["capture"]
        if (cap.get("status") == "OK" and cap.get("truncated") is False
                and cap.get("timed_out") is False and cap.get("exit_code") is not None
                and strengths[eid] == "full"):
            good[eid] = r
    if not good:
        why.append(("PROVEN_EVIDENCE_NOT_COMPLETE",
                    "run evidence is not OK/untruncated/without timeout/with exit code"))
        return why
    if not any((r.get("environment") or {}).get("isolation") in allowed for r in good.values()):
        why.append(("ENV_ISOLATION_BELOW_SCOPE", "environment isolation is insufficient"))
    # The result must be tied to the execution output: supplying the input is not enough. A quote/constant atom from the output or
    # a result value that appears in the output is required (otherwise a "key is valid" claim never looks at the output).
    good_isolated = {e for e, r in good.items() if (r.get("environment") or {}).get("isolation") in allowed}
    good_isolated |= paired  # the output of a paired dynamic observation also counts as "observed output"
    literals = hex_literals(text)[0]
    observed = any(a.get("type") in ("quote", "constant", "api_sequence", "exit_code") and a.get("evidence_id") in good_isolated
                   for a in atoms or []) or any(a.get("type") in ("fix_pair", control_pair_ev.ATOM)
                                                for a in atoms or []) or any(
        v["supported"] and any(e in good_isolated for e in v.get("_raw_hits", ())) for v in checked or []) or any(
        n in nums[e][0] for e in good_isolated for n in literals if nums and e in nums)
    if good_isolated and not observed:
        why.append(("PROVEN_NEEDS_OBSERVED_OUTPUT",
                    "cite a quote atom from the run output (e.g. 'License valid') or a value that appears in it"))
    return why


def _check_fix_pair(atom: Mapping[str, Any], recs: Mapping[str, Mapping[str, Any]], raws: Mapping[str, bytes],
                    strengths: Mapping[str, str], allowed: frozenset[str], target_sha: str, fixed_sha: str | None,
                    kind: str) -> tuple[str, str, str] | None:
    """The fix-verification rule(evidence-schema 4.11). None = the pair holds; else (severity, code, detail),
    severity REJECT (the pair is wrong or contradicted) or UNVERIFY (a run is not complete: re-run, nothing is false)."""
    if kind != FIX_KIND:
        return "REJECT", "FIX_PAIR_WRONG_KIND", f"a fix_pair atom belongs to a claim of kind {FIX_KIND!r}"
    if not fixed_sha:
        return "REJECT", "FIX_NO_FIXED_BUILD", "no fixed build is bound in the scope manifest (fixed_target_sha256)"
    o, f = atom.get("original"), atom.get("fixed")
    if (not isinstance(o, dict) or not isinstance(f, dict) or not isinstance(o.get("evidence_id"), str)
            or not isinstance(f.get("evidence_id"), str) or not isinstance(o.get("quote"), str)
            or not isinstance(f.get("quote"), str)):
        return "REJECT", "FIX_PAIR_MALFORMED", ('fix_pair is {"type":"fix_pair","original":{"evidence_id":..,"quote":..},'
                                                '"fixed":{"evidence_id":..,"quote":..}}')
    oe, fe, oq, fq = o["evidence_id"], f["evidence_id"], o["quote"], f["quote"]
    if oe not in recs or fe not in recs:
        return "REJECT", "FIX_PAIR_EVIDENCE_NOT_LISTED", "both run evidence ids must be in the claim's evidence_ids"
    ro, rf = recs[oe], recs[fe]
    if ((ro.get("subject") or {}).get("sha256") != target_sha or (rf.get("subject") or {}).get("sha256") != fixed_sha
            or ro.get("authority") != "controlled-replay" or rf.get("authority") != "controlled-replay"):
        return "REJECT", "FIX_PAIR_BUILD_MISMATCH", ("original must be a run of the job's target (SHA-256 in the scope "
                                                    "manifest), fixed a run of fixed_target_sha256; both controlled-replay")
    if len(oq) < MIN_QUOTE_LEN or len(fq) < MIN_QUOTE_LEN or oq == fq:
        return "REJECT", "FIX_PAIR_MALFORMED", "the two quotes must be different and at least 4 characters each"
    po, pf = ro.get("parameters") or {}, rf.get("parameters") or {}
    if po.get("argv") != pf.get("argv") or po.get("stdin_sha256") != pf.get("stdin_sha256"):
        return "REJECT", "FIX_INPUTS_DIFFER", "the two runs must use the same argv and the same stdin (same input on both builds)"
    bo, bf = oq.encode("utf-8"), fq.encode("utf-8")
    if bo not in raws[oe]:
        return "REJECT", "FIX_QUOTE_NOT_IN_RAW", "the reproduce quote is not in the original build's output"
    if bf not in raws[fe]:
        return "REJECT", "FIX_QUOTE_NOT_IN_RAW", "the fixed-build quote is not in the fixed build's output"
    if bo in raws[fe]:
        return "REJECT", "FIX_STILL_REPRODUCES", "the original build's reproduce quote also appears in the fixed build's output"
    complete = set(_complete_replays(recs, strengths, allowed))
    bad = [e for e in (oe, fe) if e not in complete]
    if bad:
        return "UNVERIFY", FIX_RUN_INCOMPLETE, (f"{', '.join(bad)} is not a complete isolated run (OK, untruncated, no "
                                               "timeout, exit code): re-run that build")
    return None


_EXIT_MIN, _EXIT_MAX = -(1 << 31), (1 << 32) - 1


def _exit_pattern(n: int) -> int:
    """A Windows exit code is a 32-bit DWORD: -1073741819 and 0xC0000005 are the same code. Outside 32 bits: itself."""
    return n & 0xFFFFFFFF if _EXIT_MIN <= n <= _EXIT_MAX else n


def _exit_code_numbers(code: int) -> set[int]:
    """Integers that denote the same 32-bit exit code: the code, its unsigned pattern and its signed reading."""
    pat = _exit_pattern(code)
    out = {code, pat}
    if _EXIT_MIN <= code <= _EXIT_MAX and pat >= (1 << 31):
        out.add(pat - (1 << 32))
    return out


# Explicit exit-code phrases (case-insensitive); group 1 is the number. Small on purpose: anything else is not an
# exit-code context and the number is checked like any other value.
_EXIT_NUM = r"(-?(?:0[xX][0-9a-fA-F]+|[0-9]+))(?![0-9A-Za-z_])"
_EXIT_CONTEXT = tuple(re.compile(p, re.I) for p in (
    r"\bexit\s+(?:code|status)\s*(?:is\s+|was\s+|of\s+|equals\s+|=\s*|:\s*)?" + _EXIT_NUM,
    r"\bexit(?:s|ed)?\s+with\s+(?:(?:exit\s+)?(?:code|status)\s+)?" + _EXIT_NUM,
    r"\breturns?\s+" + _EXIT_NUM + r"\s+to\s+the\s+(?:OS|operating\s+system)\b",
))


def _blank_exit_context(text: str, allowed: set[int]) -> tuple[str, set[int]]:
    """(text with the verified exit-code numbers in exit-code phrases blanked, the integers blanked). Nothing is
    blanked when no exit_code atom holds."""
    if not allowed or not text:
        return text, set()
    spans: list[tuple[int, int]] = []
    hit: set[int] = set()
    for rx in _EXIT_CONTEXT:
        for m in rx.finditer(text):
            tok = m.group(1)
            neg = tok.startswith("-")
            body = tok[1:] if neg else tok
            val = int(body, 16) if body[:2].lower() == "0x" else int(body, 10)
            val = -val if neg else val
            if val in allowed:
                spans.append((m.start(1), m.end(1)))
                hit.add(val)
    chars = list(text)
    for a, b in spans:
        chars[a:b] = " " * (b - a)
    return "".join(chars), hit


def _is_signed_in(value: str, ints: set[int]) -> bool:
    try:
        return int(value, 0) in ints
    except ValueError:
        return False


def _check_exit_code_atom(atom: Mapping[str, Any], rec: Mapping[str, Any], strength: str, allowed: frozenset[str],
                          polarity: str) -> tuple[str, str, str] | None:
    """`exit_code` atom {evidence_id, code}: None = the recorded exit code of that run equals `code`; else
    (severity, code, detail), severity REJECT (malformed, wrong evidence, contradicted) or UNVERIFY (the run has no
    usable exit code: nothing is false, re-run). Only a `run_controlled` observation can prove an exit code."""
    code = atom.get("code")
    if set(atom) - {"type", "evidence_id", "code"} or isinstance(code, bool) or not isinstance(code, int):
        return "REJECT", "EXIT_CODE_MALFORMED", 'exit_code is {"type":"exit_code","evidence_id":<run ev_>,"code":<integer>}'
    if not _EXIT_MIN <= code <= _EXIT_MAX:
        return "REJECT", "EXIT_CODE_MALFORMED", "code must fit a 32-bit exit code (-2147483648..4294967295)"
    if polarity != "present":
        return "REJECT", "EXIT_CODE_MALFORMED", "the atom binds only a present observed exit code"
    if rec.get("authority") != "controlled-replay" or rec.get("operation") != "run_controlled":
        return "REJECT", "EXIT_CODE_NEEDS_RUN_EVIDENCE", (
            f"the cited evidence is {rec.get('operation')!r} ({rec.get('authority')}), not a run_controlled observation: "
            "static, compute and dynamic-observation evidence cannot prove an exit code")
    cap, res = rec.get("capture") or {}, rec.get("result")
    seen = cap.get("exit_code")
    if isinstance(res, dict) and "exit_code" in res and res["exit_code"] != seen:
        return "REJECT", "EXIT_CODE_MISMATCH", "the run record is inconsistent (capture and result disagree on the exit code)"
    if isinstance(seen, bool) or not isinstance(seen, int):
        return "UNVERIFY", EXIT_CODE_NOT_RECORDED, ("that run recorded no exit code (the process did not finish normally): "
                                                    "an exit code cannot be claimed from it")
    if _exit_pattern(seen) != _exit_pattern(code):
        return "REJECT", "EXIT_CODE_MISMATCH", f"the run observed exit code {seen}, the atom says {code}"
    if not (cap.get("status") == "OK" and cap.get("truncated") is False and cap.get("timed_out") is False
            and strength == "full" and (rec.get("environment") or {}).get("isolation") in allowed):
        return "UNVERIFY", EXIT_CODE_RUN_INCOMPLETE, ("that run is not a complete isolated run (OK, untruncated, no "
                                                      "timeout, sufficient isolation): re-run it")
    return None


def _dynamic_pairs(recs: Mapping[str, Mapping[str, Any]], strengths: Mapping[str, str],
                   allowed: frozenset[str]) -> set[str]:
    """Dynamic observations that can back PROVEN: full coverage (strength=full), sufficiently isolated, exit-coded
    AND matching a complete `controlled-replay` run outcome of the same case (argv + stdin SHA-256 + exit code).
    Matching is by case, not run_id: the run_controlled evidence id carries no run_id (resume idempotency)."""
    replays = [recs[e] for e in _complete_replays(recs, strengths, allowed)]
    out = set()
    for eid, d in recs.items():
        if d["authority"] != DYNAMIC_AUTHORITY or strengths[eid] != "full":
            continue
        dp, cap = d.get("parameters") or {}, d["capture"]
        if (d.get("environment") or {}).get("isolation") not in allowed or cap.get("exit_code") is None:
            continue
        if any((r.get("parameters") or {}).get("argv") == dp.get("argv")
               and (r.get("parameters") or {}).get("stdin_sha256") == dp.get("stdin_sha256")
               and r["capture"].get("exit_code") == cap.get("exit_code") for r in replays):
            out.add(eid)
    return out


def _dynamic_backs_claim(recs: Mapping[str, Mapping[str, Any]], atoms: list, checked: list, text: str,
                         nums: Mapping[str, tuple[set[int], set[int]]]) -> bool:
    """Is the claim tied to the raw document of a cited dynamic observation (quote/constant atom, a value that appears in
    that document, or a 0x literal)? Merely adding dynamic evidence does not make a static value 'executed' (decoy-value pattern)."""
    dyn = {eid for eid, r in recs.items() if r["authority"] == DYNAMIC_AUTHORITY}
    if not dyn:
        return False
    literals = hex_literals(text)[0]
    return (any(a.get("type") in ("quote", "constant", "api_sequence") and a.get("evidence_id") in dyn
                for a in atoms or [])
            or any(v["supported"] and any(e in dyn for e in v.get("_raw_hits", ())) for v in checked or [])
            or any(n in nums[e][0] for e in dyn for n in literals if e in nums))


def _check_api_sequence_atom(atom: Mapping[str, Any], rec: Mapping[str, Any], raw: bytes,
                             polarity: str) -> tuple[str | None, str]:
    """`api_sequence` atom: (code, detail) or (None, ""). The code is a REJECT (`_API_SEQ_REJECTS`) or an UNVERIFIED
    (`API_SEQUENCE_COVERAGE_INCOMPLETE`) reason. The decision lives in the pure `dynamic.match` functions (same rule as the scorer)."""
    calls, mode, module, caller = atom.get("calls"), atom.get("mode", "exact"), atom.get("module"), atom.get("caller")
    if mode not in API_SEQ_MODES:
        return "API_SEQUENCE_MALFORMED", f"mode must be {'|'.join(API_SEQ_MODES)}"
    if not (isinstance(calls, list) and 0 < len(calls) <= API_SEQ_MAX_CALLS
            and all(isinstance(c, str) and 0 < len(c) <= 256 for c in calls)):
        return "API_SEQUENCE_MALFORMED", f"calls must be a list of 1..{API_SEQ_MAX_CALLS} API names"
    if module is not None and not (isinstance(module, str) and 0 < len(module) <= 260):
        return "API_SEQUENCE_MALFORMED", "module must be a string"
    if caller is not None and caller not in TARGET_CALLERS:
        return "API_SEQUENCE_MALFORMED", f"caller must be {'|'.join(TARGET_CALLERS)}"
    if set(atom) - {"type", "evidence_id", "calls", "mode", "module", "caller"}:
        return "API_SEQUENCE_MALFORMED", "unknown field"
    if polarity != "present":
        return "API_SEQUENCE_MALFORMED", "the atom binds only a present call sequence"
    if rec.get("authority") != DYNAMIC_AUTHORITY:
        return "API_SEQUENCE_NEEDS_DYNAMIC_EVIDENCE", "the atom binds only to dynamic observation evidence"
    try:
        obs = load_observation(raw)  # validate_record already parsed it; here we only take the events
    except ObservationError as e:  # pragma: no cover  (validate_record rejects first)
        return "API_SEQUENCE_MALFORMED", str(e)
    if caller is not None and obs.schema != SCHEMA_V2:
        return "API_SEQUENCE_MALFORMED", "caller needs an rh.dynamic/2 observation (it records the call origin)"
    check = (check_api_sequence if mode == "exact" else check_api_subsequence)(obs, calls, module=module,
                                                                                 caller=caller)
    if check.verdict == "match":
        return None, ""
    if check.verdict == "unknown":
        return API_SEQ_INCOMPLETE, check.reason
    return "API_SEQUENCE_MISMATCH", f"{check.reason} (observed {len(check.observed)} calls, "                                     f"first divergence {check.first_divergence})"
