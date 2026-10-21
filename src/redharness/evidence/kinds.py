"""Claim kind: `observation` (what the code/data is) and `behavior` (what happens when the program runs).

Why: a value APPEARING in static evidence does not prove it is an input the program accepts (an eval decoy: `qwerty`
appeared in decompile output, the claim "correct password is `qwerty`" became SUPPORTED, yet `qwerty` was a decoy).
Behavior claims are supported only by execution evidence (controlled replay).

Kinds: `observation`, `behavior`; legacy names are accepted (`static_fact` -> observation, `runtime_behavior` ->
behavior); `bypass_poc` is in the behavior class and stays separate.

If the model gives no `kind`, it is inferred from the text. Fail-closed: a behavior pattern means `behavior`; with no
positive sign of an observation (address, symbol, "function/string/calls...") it is also `behavior`.
Even when the model says `observation`, a STRONG behavior pattern ("correct password", "valid key", "is accepted",
"doğru parola", "kabul edilir"...) turns the kind into `behavior` and `issues` says so (not silent). Weak patterns
("accepts", "prints"...) matter only when no `kind` is given (ledger called directly); MCP `claim_add` now REQUIRES
`kind`.

Triggers are bilingual on purpose: models may write either English or Turkish claim text, so every Turkish phrase has
an English equivalent and both are kept.
"""

from __future__ import annotations

import re

# fix_verification: behavior class; "finding F reproduces on the original build and not on the fixed build"
CLAIM_KINDS = ("observation", "behavior", "static_fact", "runtime_behavior", "bypass_poc", "fix_verification")
_ALIASES = {"static_fact": "observation", "runtime_behavior": "behavior"}
_BEHAVIOR_KINDS = frozenset({"behavior", "bypass_poc", "fix_verification"})

_F = re.I | re.U
_CRED = (r"(?:pass(?:word|code|phrase)?|key|serial(?:\s+number)?|licen[cs]e(?:\s+key)?|pin|code|answer|flag|"
         r"secret|credentials?|input|user(?:name)?|login|token|"
         r"parola|şifre|sifre|anahtar|seri(?:\s+no|\s+numarası)?|lisans|girdi|cevap|bayrak|kod)")

# STRONG: means "this input/password/key/serial is correct/valid/accepted". Counts as behavior even if the model says
# `observation`. Kept narrow: accepts/prints/success/valid/be valid alone do not trigger (they produce false alarms).
_CS = (r"(?:pass(?:word|code|phrase)?|key|serial(?:\s+number)?|licen[cs]e(?:\s+key)?|pin|secret|credentials?|"
       r"answer|input|parola|şifre|sifre|anahtar|seri(?:\s+no|\s+numarası)?|lisans|girdi|cevap)")
_Q = r"""[`"'“‘][^`"'”’\n]{1,80}[`"'”’]"""
_VERDICT = r"(?:accepted|valid|correct|rejected|invalid)"
STRONG = tuple(re.compile(p, _F) for p in (
    rf"\b(?:correct|right|valid|working|winning|magic|accepted)\s+{_CS}\b",
    rf"\b(?:doğru|dogru|geçerli|gecerli|kabul\s+edilen)\s+{_CS}\b",
    rf"\b{_CS}\s+(?:\S{{1,60}}\s+)?(?:is|are|will\s+be|would\s+be)\s+{_VERDICT}\b",
    rf"{_Q}\s+(?:is|are|will\s+be|would\s+be)\s+{_VERDICT}\b",
    r"\b(?:accepted|rejected)\s+(?:as|by)\s+(?:the\s+)?(?:program|binary|check|validator|application|app)\b",
    r"\b(?:unlocks?|authenticates?|grants?\s+access|logs?\s+(?:you\s+)?in)\b",
    rf"\b{_CS}\b[^.\n]{{0,40}}\b(?:kabul\s+edil(?:ir|ecek|iyor|di|miş|mis)|reddedil(?:ir|ecek|iyor|di|miş|mis)|"
    r"geçerlidir|gecerlidir|geçersizdir|gecersizdir)\b",
    rf"{_Q}[^.\n]{{0,30}}\b(?:kabul\s+edil(?:ir|ecek|iyor|di)|geçerlidir|gecerlidir|doğrudur|dogrudur)\b",
    r"""\b(?:password|passcode|passphrase|serial|licen[cs]e|pin|parola|şifre|sifre)\s+(?:is|=|:|olarak|-)\s*[`"'“‘]""",
    rf"\b(?:accepts?|accepted)\s+(?:the\s+)?(?:{_CS}\s+)?{_Q}",
    # English equivalents of the Turkish finite-verb patterns above (kabul edilir / reddedilir / geçerlidir / doğrudur)
    rf"\b{_CS}\b[^.\n]{{0,40}}\b(?:gets?|got|is|are|was|were|will\s+be|would\s+be)\s+(?:accepted|rejected|valid|"
    r"invalid|correct)\b",
    rf"{_Q}[^.\n]{{0,30}}\b(?:is|are|gets?|got|was|will\s+be)\s+(?:accepted|valid|correct)\b",
))

# WEAK: runtime heuristics; effective only when no `kind` is given.
WEAK = tuple(re.compile(p, _F) for p in (
    r"\b(?:accepts?|accepted|rejects?|rejected|valid|invalid|succe(?:ed|eds|ss|ssful(?:ly)?)|fails?|failed)\b",
    r"\b(?:prints?|displays?|outputs?|exits?|crash(?:es)?|returns\s+(?:success|failure|true|false))\b",
    r"\b(?:when|if|once|after)\b[^.]{0,60}\b(?:entered|typed|supplied|provided|given|passed|run|executed|launched)\b",
    r"\b(?:at\s+run\s?time|upon\s+execution|when\s+(?:run|executed|running))\b",
    r"\b(?:çalıştır\w*|calistir\w*|girildiğinde|girildiginde|kabul|geçerli|gecerli|başarılı|basarili)\b",
    # English equivalents of the Turkish words above (run it / when entered / accept / valid / successful)
    r"\b(?:run\s+(?:it|the\s+(?:program|binary|target|sample))|(?:upon|on)\s+(?:entry|input)|when\s+entered|"
    r"accept(?:ance)?|successfully)\b",
))

# Positive signs of an observation (needed when no behavior pattern matched and no `kind` was given; else behavior).
OBSERVATION_SIGNS = tuple(re.compile(p, _F) for p in (
    r"\b0x[0-9a-f]+\b",
    r"\b(?:sub|loc|func|fn|off|dword|byte|word|qword|unk|nullsub)_[0-9A-Fa-f]{3,}\b",
    r"\b(?:function|routine|subroutine|symbol|string|constant|address|offset|import|export|section|segment|"
    r"struct|structure|variable|global|buffer|branch|jump|loop|compar\w+|decompil\w+|disassembl\w+|"
    r"instruction|opcode|table|array|calls?|called|references?|xrefs?|stores?|reads?|writes?|defined|"
    r"located|contains?|declares?|allocates?|entry\s+point|main|xor|hash|strcmp|scanf|gets|fgets)\b",
    r"\b(?:fonksiyon|rutin|dizge|sabit|adres|ofset|çağırır|cagirir|başvurur|basvurur|içerir|icerir|"
    r"bölüm|bolum|tablo|döngü|dongu|karşılaştırır|karsilastirir|tanımlı|tanimli)\b",
))


def kind_class(kind: str) -> str:
    """`observation` | `behavior` (bypass_poc and legacy names are classified; unknown -> behavior, fail-closed)."""
    if kind in _ALIASES:
        return _ALIASES[kind]
    if kind == "observation":
        return "observation"
    return "behavior"


def is_behavior(kind: str) -> bool:
    return kind_class(kind) == "behavior"


def canonical_kind(kind: str) -> str:
    """Map legacy names to the new names; `bypass_poc` stays separate."""
    if kind not in CLAIM_KINDS:
        raise ValueError(f"kind must be one of {list(CLAIM_KINDS)}")
    return _ALIASES.get(kind, kind)


_QUOTED = re.compile(_Q)


def _strong_hit(text: str) -> str | None:
    """STRONG scan. Quoted literals (the program's output text, "Correct Password!") count only in the quoted-value
    patterns; the other patterns run on the text with quoted parts removed."""
    bare = _QUOTED.sub(" ", text)
    for rx in STRONG:
        m = rx.search(text if "[`" in rx.pattern or "{1,80}" in rx.pattern else bare)
        if m:
            return m.group(0)
    return None


def _first(patterns: tuple[re.Pattern[str], ...], text: str) -> str | None:
    for rx in patterns:
        m = rx.search(text)
        if m:
            return m.group(0)
    return None


def resolve_kind(declared: str | None, text: str) -> tuple[str, str, str | None]:
    """(kind, source, matched). source: declared | inferred | overridden. matched: the triggering phrase or None."""
    if declared is not None:
        kind = canonical_kind(declared)
        if kind_class(kind) == "observation":
            hit = _strong_hit(text)
            if hit:
                return "behavior", "overridden", hit
        return kind, "declared", None
    hit = _strong_hit(text) or _first(WEAK, text)
    if hit:
        return "behavior", "inferred", hit
    if _first(OBSERVATION_SIGNS, text):
        return "observation", "inferred", None
    return "behavior", "inferred", None  # unclear: fail-closed
