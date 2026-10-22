"""The `control_pair` atom and the acceptance-validation rule (verifier version 24; docs/design/evidence-schema.md 4.17).

A control pair binds contrasting observations of ONE build under one scope: at least one complete `run_controlled`
case per side ("accepted" / "rejected"), all on the job's target SHA-256, whose declared inputs are equal except for a
named discriminator (a stdin line, the whole stdin, or one argv item). Each side binds an observed outcome of its own
case(s): an exact stdout/stderr quote or the recorded exit code. The accepted outcome must hold in every accepted case
and in no rejected case, and the rejected outcome the other way round.

A quote alone proves only that bytes appeared, not what they mean; the pair proves the contrast the claim declares.

Direction binding: the atom says which side the claim is about (`asserts`: "accepted" | "rejected"). The claim must
name that side's discriminator input as a value (declared or written in the text) and must not name the other side's
input; otherwise the binding is wrong and the claim is REJECTED (`CONTROL_PAIR_INVALID`): the model wrote both the claim
and the pair, so this is a malformed binding, nothing is pending a re-run. "BAD is accepted" over a pair whose accepted
side ran GOOD therefore fails. A backstop also compares the verdict words of the text with `asserts` (accept/valid/
correct vs reject/invalid/wrong, a preceding "not"/"never" flips them): a text whose only verdict is the opposite side's
is REJECTED too, and so is a side whose quoted outcome reads only as the other verdict (an "accepted" side bound to
"License invalid"). Exit codes carry no verdict meaning here. Beyond these word checks, which label each side carries
stays the model's declaration, checked against that side's own outcome.

Which claims need a pair (structural, not a word list): every behavior claim must declare `behavior_class`
("acceptance_validation" | "ordinary"; `bypass_poc` is acceptance_validation by kind, `fix_verification` has its own
two-build `fix_pair`). Missing: UNVERIFIED (`BEHAVIOR_CLASS_MISSING`). "acceptance_validation" needs a pair. The text
check (`kinds.STRONG` plus verdict phrases, quoted output text excluded) is only a backstop that turns an "ordinary"
claim with validation wording into one that needs a pair. Ordinary behavior claims ("prints its version", "exits with
code 3") need none.

Side effects are not an outcome kind: `run_controlled` records them per session (`parameters.side_effects` is the same
list for every case of a run), so a file cannot be attributed to one case.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from .kinds import _QUOTED, _strong_hit, is_behavior

ATOM = "control_pair"
BEHAVIOR_CLASSES = ("acceptance_validation", "ordinary")
CLASS_MISSING = "BEHAVIOR_CLASS_MISSING"
MISSING = "CONTROL_PAIR_MISSING"
INVALID = "CONTROL_PAIR_INVALID"
INCOMPLETE = "CONTROL_PAIR_INCOMPLETE"
SAME_OUTCOME = "CONTROL_PAIR_SAME_OUTCOME"
UNSTABLE = "CONTROL_PAIR_UNSTABLE"
UNVERIFY_CODES = (MISSING, INCOMPLETE, SAME_OUTCOME, UNSTABLE)
SIDES = ("accepted", "rejected")
SOURCES = ("stdin", "argv")
MAX_CASES_PER_SIDE = 16
MIN_QUOTE_LEN = 4
STDERR_MARK = b"\n--- stderr ---\n"   # sandbox/evidence.py: raw = stdout + mark + stderr
_FIX_KIND = "fix_verification"
_EXIT_MIN, _EXIT_MAX = -(1 << 31), (1 << 32) - 1

# Verdict phrases (outside quoted output text), whole words only: "correctly", "validates the header", "doğrudan" are
# not verdicts. Only a backstop since version 24: the rule itself is the declared behavior_class.
_ACCEPT_WORDS = (r"accept(?:s|ed|ance)?|valid|correct|authenticat(?:es|ed)|unlock(?:s|ed)?|grants?\s+access|"
                 r"logs?\s+(?:you\s+)?in|succeeds|succeeded|pass(?:es|ed)?\s+(?:the\s+)?(?:check|validation|verification)|"
                 r"kabul\s+edil(?:ir|di|ecek|iyor)|geçerli(?:dir)?|gecerli(?:dir)?|doğru(?:dur)?|dogru(?:dur)?")
_REJECT_WORDS = (r"reject(?:s|ed|ion)?|invalid|incorrect|wrong|denie[sd]|refuse[sd]|fails\s+(?:the\s+)?(?:check|validation)|"
                 r"reddedil(?:ir|di|ecek|iyor)|kabul\s+edil(?:mez|medi)|geçersiz(?:dir)?|gecersiz(?:dir)?|"
                 r"yanlış(?:tır)?|yanlis(?:tir)?")
_ACCEPT = re.compile(rf"\b(?:{_ACCEPT_WORDS})\b", re.I | re.U)
_REJECT = re.compile(rf"\b(?:{_REJECT_WORDS})\b", re.I | re.U)
_NEGATION = re.compile(r"\b(?:not|never|no|cannot|can't|isn't|is\s+not|wasn't|won't|doesn't)\s+(?:\w+\s+){0,2}$", re.I)


def _bare(text: str) -> str:
    return _QUOTED.sub(" ", text or "")


def is_validation_text(text: str) -> bool:
    """Does the claim text read like an acceptance/validation verdict? Quoted output text does not count."""
    bare = _bare(text)
    return bool(_strong_hit(text or "") or _ACCEPT.search(bare) or _REJECT.search(bare))


def verdict_sides(text: str) -> set[str]:
    """The sides ("accepted" / "rejected") the verdict words of the text assert; a negation in the three words before a
    verdict flips it ("is not accepted" -> rejected). Empty when the text has no verdict word."""
    bare, out = _bare(text), set()
    for rx, side, other in ((_ACCEPT, "accepted", "rejected"), (_REJECT, "rejected", "accepted")):
        for m in rx.finditer(bare):
            out.add(other if _NEGATION.search(bare[:m.start()]) else side)
    return out


def class_missing(kind: str, behavior_class: str | None) -> bool:
    """A behavior claim must declare its class (bypass_poc is acceptance_validation by kind; a fix claim has none)."""
    return is_behavior(kind) and kind not in (_FIX_KIND, "bypass_poc") and behavior_class is None


def needs_pair(kind: str, text: str, behavior_class: str | None) -> bool:
    if kind == _FIX_KIND or not is_behavior(kind):
        return False
    return kind == "bypass_poc" or behavior_class == "acceptance_validation" or is_validation_text(text)


def _exit_pattern(n: int) -> int:
    return n & 0xFFFFFFFF if _EXIT_MIN <= n <= _EXIT_MAX else n


def _side(raw: Any) -> tuple[list[str], dict] | str:
    """(case evidence ids, outcome) of one side, or the reason it is malformed."""
    if not isinstance(raw, dict) or set(raw) - {"evidence_id", "evidence_ids", "outcome"}:
        return 'a side is {"evidence_id": <run ev_>, "outcome": {...}} (or "evidence_ids": [...] for repeated cases)'
    if ("evidence_id" in raw) == ("evidence_ids" in raw):
        return "give exactly one of evidence_id / evidence_ids per side"
    ids = [raw["evidence_id"]] if "evidence_id" in raw else raw["evidence_ids"]
    if (not isinstance(ids, list) or not 0 < len(ids) <= MAX_CASES_PER_SIDE
            or not all(isinstance(e, str) and e for e in ids) or len(set(ids)) != len(ids)):
        return f"evidence_ids: 1..{MAX_CASES_PER_SIDE} distinct ev_ ids"
    out = raw.get("outcome")
    if not isinstance(out, dict):
        return 'outcome is {"type":"quote","quote":".."} or {"type":"exit_code","code":N}'
    if out.get("type") == "quote":
        if set(out) - {"type", "quote"} or not isinstance(out.get("quote"), str) or len(out["quote"]) < MIN_QUOTE_LEN:
            return f"a quote outcome is {{\"type\":\"quote\",\"quote\":<exact output text, >= {MIN_QUOTE_LEN} chars>}}"
        if STDERR_MARK.decode() in out["quote"]:
            return "a quote lies inside stdout or inside stderr, never across the separator"
    elif out.get("type") == "exit_code":
        c = out.get("code")
        if set(out) - {"type", "code"} or isinstance(c, bool) or not isinstance(c, int) or not _EXIT_MIN <= c <= _EXIT_MAX:
            return "an exit_code outcome is {\"type\":\"exit_code\",\"code\":<32-bit integer>}"
    else:
        return "outcome type must be quote or exit_code (side effects are per session, not per case)"
    return list(ids), dict(out)


def _streams(rec: Mapping[str, Any], raw: bytes) -> tuple[bytes, ...]:
    """stdout and stderr of a run_controlled blob, split at the recorded stdout length (never ambiguous)."""
    k = (rec.get("result") or {}).get("stdout_kept_bytes")
    if isinstance(k, int) and not isinstance(k, bool) and raw[k:k + len(STDERR_MARK)] == STDERR_MARK:
        return raw[:k], raw[k + len(STDERR_MARK):]
    return (raw,)   # older record without the split point: the whole blob


def _holds(out: Mapping[str, Any], rec: Mapping[str, Any], raw: bytes) -> bool:
    if out["type"] == "quote":
        q = out["quote"].encode("utf-8")
        return any(q in s for s in _streams(rec, raw))
    seen = (rec.get("capture") or {}).get("exit_code")
    return isinstance(seen, int) and not isinstance(seen, bool) and _exit_pattern(seen) == _exit_pattern(out["code"])


def _inputs(rec: Mapping[str, Any]) -> tuple:
    p = rec.get("parameters") or {}
    return (p.get("argv"), p.get("stdin_sha256"), p.get("support_files"))


def _stdin_lines(rec: Mapping[str, Any]) -> list[str] | None:
    s = (rec.get("parameters") or {}).get("stdin")
    return s.splitlines() if isinstance(s, str) else None


def _differ_only_in(a: Mapping[str, Any], b: Mapping[str, Any], source: str, index: int | None) -> str | bool:
    """True: inputs equal except the discriminator, which differs; False: identical inputs; str: the mismatch."""
    pa, pb = a.get("parameters") or {}, b.get("parameters") or {}
    if pa.get("support_files") != pb.get("support_files"):
        return "the cases ran with different support files"
    if source == "argv":
        va, vb = pa.get("argv"), pb.get("argv")
        if not (isinstance(va, list) and isinstance(vb, list)) or len(va) != len(vb) or not 0 <= index < len(va):
            return f"argv lists differ in length or have no item {index}"
        if pa.get("stdin_sha256") != pb.get("stdin_sha256"):
            return "stdin differs, but the discriminator is argv"
        if any(x != y for i, (x, y) in enumerate(zip(va, vb)) if i != index):
            return f"argv differs outside item {index}"
        return va[index] != vb[index]
    if pa.get("argv") != pb.get("argv"):
        return "argv differs, but the discriminator is stdin"
    if index is None:
        return pa.get("stdin_sha256") != pb.get("stdin_sha256")
    la, lb = _stdin_lines(a), _stdin_lines(b)
    if la is None or lb is None:
        return "stdin is not recorded inline (over 1024 characters): name no line index, the whole stdin is compared"
    if len(la) != len(lb) or not 0 <= index < len(la):
        return f"stdin line counts differ or there is no line {index}"
    if any(x != y for i, (x, y) in enumerate(zip(la, lb)) if i != index):
        return f"stdin differs outside line {index}"
    return la[index] != lb[index]


def _side_input(rec: Mapping[str, Any], source: str, index: int | None) -> tuple[str, str] | None:
    """(raw, normalized) discriminator input of one case: the raw recorded value (the stdin line, the whole stdin as
    recorded, the argv item) and the same with surrounding whitespace removed, which is how a claim can write it (a
    claim value never carries the trailing newline of stdin). None when it is not recorded (stdin over 1024 chars)."""
    p = rec.get("parameters") or {}
    raw: str | None = None
    if source == "argv":
        argv = p.get("argv")
        if isinstance(argv, list) and 0 <= index < len(argv) and isinstance(argv[index], str):
            raw = argv[index]
    elif index is None:
        raw = p["stdin"] if isinstance(p.get("stdin"), str) else None
    else:
        lines = _stdin_lines(rec)
        raw = lines[index] if lines is not None and 0 <= index < len(lines) else None
    return None if raw is None else (raw, raw.strip())


def _bind(asserts: str, a_in: tuple[str, str] | None, o_in: tuple[str, str] | None, values: set[str],
          text: str) -> str | None:
    """Why the claim is not about the asserted side's input (None: it is). A claim value matches a side when it equals
    that side's raw recorded value OR its normalized form (surrounding whitespace removed); the caller has already
    rejected sides whose normalized forms are equal, so the two sides' accepted spellings never overlap."""
    other = SIDES[1 - SIDES.index(asserts)]
    if a_in is None:
        return f"the {asserts} side's discriminator input is not recorded inline: it cannot be bound to the claim"
    if o_in is not None and o_in != a_in and set(o_in) & values:
        return (f"the claim names {o_in[1][:60]!r}, the input of the {other} side, but asserts the {asserts} side; one "
                "claim per side")
    if not set(a_in) & values:
        return (f"the claim must name the input it is about: the {asserts} side ran {a_in[1][:60]!r}; write it in "
                "the text or declare it in values (as {\"value\":..,\"derived\":true} if you chose it)")
    if verdict_sides(text) == {other}:
        return f"the text states a {other} verdict but the atom asserts the {asserts} side"
    return None


def check(atom: Mapping[str, Any], recs: Mapping[str, Mapping[str, Any]], raws: Mapping[str, bytes],
          complete: set[str] | frozenset[str], target_sha: str, kind: str, values: set[str] | frozenset[str] = frozenset(),
          text: str = "") -> tuple[str, str, str] | None:
    """None = the pair holds; else (severity, code, detail): REJECT (`CONTROL_PAIR_INVALID`: malformed, mismatched
    binding, a claim not about the asserted side's input, or an outcome its own case does not show) or UNVERIFY
    (incomplete run, same outcome, unstable). `complete`: the cited complete isolated controlled-replay evidence (OK,
    untruncated, no timeout, exit code). `values`: the claim's result values (declared + read from the text)."""
    def bad(detail: str) -> tuple[str, str, str]:
        return "REJECT", INVALID, detail

    if kind == _FIX_KIND or not is_behavior(kind):
        return bad("a control_pair belongs to a behavior claim (two builds: kind='fix_verification' with fix_pair)")
    if set(atom) - {"type", "discriminator", "asserts", *SIDES} or not all(s in atom for s in SIDES):
        return bad('control_pair is {"type":"control_pair","asserts":"accepted"|"rejected","discriminator":{"source":'
                   '"stdin"|"argv","index":N},"accepted":{"evidence_id":..,"outcome":{..}},"rejected":{"evidence_id":..,'
                   '"outcome":{..}}}')
    asserts = atom.get("asserts")
    if asserts not in SIDES:
        return bad('asserts names the side the claim is about: "accepted" or "rejected"')
    d = atom.get("discriminator")
    if not isinstance(d, dict) or set(d) - {"source", "index"} or d.get("source") not in SOURCES:
        return bad('discriminator is {"source":"stdin"|"argv","index":N} (stdin: index is optional, the line number)')
    source, index = d["source"], d.get("index")
    if index is not None and (isinstance(index, bool) or not isinstance(index, int) or index < 0):
        return bad("discriminator index must be a non-negative integer")
    if source == "argv" and index is None:
        return bad("an argv discriminator names the argv item (index)")
    sides: dict[str, tuple[list[str], dict]] = {}
    for name in SIDES:
        res = _side(atom[name])
        if isinstance(res, str):
            return bad(f"{name}: {res}")
        sides[name] = res
    for name, (_ids, out) in sides.items():   # backstop: a side's quoted output must not read as the other verdict
        other = SIDES[1 - SIDES.index(name)]
        if out["type"] == "quote" and verdict_sides(out["quote"]) == {other}:
            return bad(f"the {name} outcome {out['quote'][:60]!r} reads as a {other} verdict (sides swapped?)")
    acc_ids, acc_out = sides["accepted"]
    rej_ids, rej_out = sides["rejected"]
    if set(acc_ids) & set(rej_ids):
        return bad("one case cannot be on both sides")
    # every case comes from `recs`, the evidence map of this job's own ledger, which is bound to one scope manifest:
    # a pair can never mix scopes or jobs (verify_claim's integrity checks already ran on each case)
    for eid in acc_ids + rej_ids:
        if eid not in recs:
            return bad(f"{eid} is not in the claim's evidence_ids")
        r = recs[eid]
        if r.get("authority") != "controlled-replay" or r.get("operation") != "run_controlled":
            return bad(f"{eid} is not a run_controlled observation")
        if (r.get("subject") or {}).get("sha256") != target_sha or (r.get("parameters") or {}).get("build"):
            return bad(f"{eid} is not a run of the job's target build (one build only; two builds: fix_pair)")
        res = r.get("result")
        if isinstance(res, dict) and "exit_code" in res and res["exit_code"] != (r.get("capture") or {}).get("exit_code"):
            return bad(f"{eid}: the run record is inconsistent (capture and result disagree on the exit code)")
    for name, (ids, _o) in sides.items():
        if any(_inputs(recs[e]) != _inputs(recs[ids[0]]) for e in ids[1:]):
            return bad(f"{name}: repeated cases of one side must have the same input")
    differs = _differ_only_in(recs[acc_ids[0]], recs[rej_ids[0]], source, index)
    if isinstance(differs, str):
        return bad(f"inputs must be equal except the discriminator: {differs}")
    a_ids, o_ids = sides[asserts][0], sides[SIDES[1 - SIDES.index(asserts)]][0]
    a_in, o_in = _side_input(recs[a_ids[0]], source, index), _side_input(recs[o_ids[0]], source, index)
    if differs and a_in is not None and o_in is not None and a_in[1] == o_in[1]:
        # the recorded inputs differ, but only in surrounding whitespace: a claim value could name either side
        return bad("the two sides' discriminator inputs differ only in surrounding whitespace; the discriminator must "
                   "differ after whitespace is removed")
    why = _bind(asserts, a_in, o_in, set(values), text)
    if why:
        return bad(why)
    not_done = [e for e in acc_ids + rej_ids if e not in complete]
    if not_done:
        return ("UNVERIFY", INCOMPLETE, f"{', '.join(not_done)} is not a complete isolated run (OK, untruncated, no "
                "timeout, exit code, clean session): re-run that input")
    for name, (ids, out) in sides.items():
        n = sum(_holds(out, recs[e], raws[e]) for e in ids)
        if n == 0:
            return bad(f"the {name} outcome is not observed in its own case(s)")
        if n < len(ids):
            return "UNVERIFY", UNSTABLE, f"the {name} outcome holds in {n} of {len(ids)} repeated cases of the same input"
    cross = (any(_holds(acc_out, recs[e], raws[e]) for e in rej_ids)
             or any(_holds(rej_out, recs[e], raws[e]) for e in acc_ids))
    if acc_out == rej_out or cross:
        return "UNVERIFY", SAME_OUTCOME, ("the two sides do not contrast: an outcome also holds on the other side "
                                          "(pick outcomes that differ, e.g. the two different messages)")
    if not differs:
        return "UNVERIFY", UNSTABLE, "both sides ran the same input yet show different outcomes (nondeterministic)"
    for eid in complete:   # another cited complete run of a side's input must agree with that side's outcome
        if eid in acc_ids or eid in rej_ids or (recs[eid].get("parameters") or {}).get("build"):
            continue
        for name, (ids, out) in sides.items():
            if _inputs(recs[eid]) == _inputs(recs[ids[0]]) and not _holds(out, recs[eid], raws[eid]):
                return "UNVERIFY", UNSTABLE, f"{eid} ran the {name} input but does not show the {name} outcome"
    return None
