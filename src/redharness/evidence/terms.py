"""Technical terms of a claim text and their binding to cited evidence (verifier version 18).

Gap: the verifier checks atoms, values and 0x literals, but without this rule the rest of the text would pass
unchecked, so "sub_401000 CRC-32 hashes the username ... invertible op chain" could be SUPPORTED although neither
"CRC-32" nor "invertible" is in the cited evidence. Rule: every TECHNICAL TERM of the claim text must be found in a
cited evidence record (its raw output, or the input given to a run); otherwise the claim cannot be SUPPORTED/PROVEN
(UNVERIFIED, `TERM_NOT_IN_EVIDENCE`). The model's reading of the code goes into the separate `interpretation` field,
which the status never covers (docs/design/evidence-schema.md section 4.12).

Deterministic, no LLM, no dictionary of English. A term is (after quoted/backticked spans, 0x literals and, from
verifier version 21, bare hex runs of more than 16 characters (digests) are removed; those are values and are checked
by values.py / hex_literals):
- identifier: a token with `_` (`sub_401920`, `_main`, `valid_key`), letters mixed with digits (`Str1`, `v22`,
  `base64`), an inner lower->upper case change (`hiddenKey`, `VirtualAlloc`), a dotted/`::` name (`kernel32.dll`), or
  a word written as a call (`rot(`);
- template: a `::`-qualified name or a name whose argument list contains a known C/C++ type token (`int`, `char`,
  `size_t`, `uint8_t`..`uint64_t`, `std::...`, a pointer/reference, or a nested template) followed directly by `<...>`
  (`std::vector<int>`, `QList<int>`, `List<char *>`); the FULL name including the argument list is the term (so
  `std::vector<float>` does not back `std::vector<int>`). Plain `Name<T>` in prose is not a template. Whitespace and
  printing keywords (`class `, `struct `, `enum `, `union `) inside the angle brackets are not significant,
  whitespace outside them is;
- section: a dot-leading known PE section name after whitespace or at the start of the text (`.text`, `.rdata`,
  `.pdata`, `.rsrc$01`, case-insensitive); a sentence-final dot (`.`, `sentence.`), a decimal (`.5`), a file extension
  glued to its stem (`foo.dll`) or another dot-leading word (`.NET`, `.This`) is not one;
- compound: a hyphenated token with a digit (`FNV-1a`, `SHA-256`, `UTF-16`, `abcde-2026-xyz`); a number with a
  lowercase unit (`64-bit`, `14-char`) and all-digit compounds (dates) are not terms (numbers are values.py's job);
- acronym: an upper-case token with >= 2 capitals (`XOR`, `PRNG`, `IOCTL`; an inflection such as `XORs`, `XORed` is
  dropped), except a closed set of notation words (EXEMPT_ACRONYMS);
- lexicon: a closed list of algorithm, representation, randomness, mathematical-property and cryptographic-purpose
  words (LEXICON; e.g. `hex`, `lowercase`, `invertible`, `pseudorandomly`, `encrypted`, `hash`).
Plain English (verbs such as compares/reads/sums, nouns such as username/buffer) is NOT a term and is NOT verified:
the status covers the anchored terms, values, literals and atoms, not the relations the prose states between them.

Binding (case-insensitive, `-` and `_` are the same separator, token-bounded): the term occurs in the searchable
raw output of a cited non-compute evidence, in the stdin/argv given to a cited run, or in a dynamic observation's
own output. Closed aliases: `XOR` is also backed by a `^` that is a binary operator between two code-like operands
(`a ^ b`, `x^=y`, `v1 ^ 0x5A`, `(a)^(b)`), never by a `^` inside a `[^...]` character class or a string, and never by
the caret of prose (`The ^ is a caret`); the `xor` mnemonic/text is the term itself, `hex` by a printf hex conversion
(`%x`, `%02X`). An IDA auto-name `sub_<hex>`/`loc_<hex>` is also backed when the cited evidence is a decompile/
disassembly of that address or reports it as a point location. A lexicon word is matched by its stem plus an optional
inflection or digit/separator tail (`decrypted` is backed by `decrypt_block`, `crc` by `crc32`, `sha` not by `shadow`).
"""

from __future__ import annotations

import re
from typing import Iterable

# Notation words that describe how a value is written, not what the code does (closed, a priori list).
EXEMPT_ACRONYMS = frozenset({"API", "ASCII", "NUL", "NULL", "EOF", "DLL", "EXE", "ID", "VA", "RVA"})

# Closed lexicon (stems; a word matches a stem plus an optional inflection). Upper-case spellings (FNV, CRC, AES,
# PRNG...) are acronyms and digit-bearing ones (md5, base64, rot13) are identifiers; the lexicon catches the
# lower-case words of these classes.
LEXICON_STEMS = (
    # named algorithms (hash/checksum/cipher/PRNG)
    "fnv", "crc", "sha", "hmac", "murmur", "adler", "fletcher", "siphash", "xxhash", "djb", "blowfish", "twofish",
    "serpent", "chacha", "salsa", "caesar", "vigenere", "mersenne", "xorshift", "lcg",
    # representation / format
    "hex", "hexadecimal", "lowercase", "uppercase", "endian", "little-endian", "big-endian", "unicode",
    # randomness
    "random", "pseudorandom", "pseudo-random", "prng", "rng",
    # mathematical properties
    "invertible", "reversible", "irreversible", "bijective", "injective", "surjective", "one-way",
    # cryptographic purpose
    "encrypt", "decrypt", "cipher", "ciphertext", "plaintext", "obfuscat", "hash", "checksum", "compress",
    "decompress",
)
_INFLECTION = r"(?:s|es|ed|d|ing|ion|ions|ly|ally|er|ers|ic|ically|ness)?"
_STEMS_LONGEST_FIRST = tuple(sorted(LEXICON_STEMS, key=len, reverse=True))
_LEX = re.compile(r"(?:%s)%s" % ("|".join(re.escape(s) for s in _STEMS_LONGEST_FIRST), _INFLECTION))

_QUOTED = (re.compile(r"`[^`\n]+`"), re.compile(r'"[^"\n]+"'), re.compile("“[^”\n]+”"),
           re.compile(r"(?<![0-9A-Za-z])'[^'\n]+'(?![0-9A-Za-z])"), re.compile("(?<![0-9A-Za-z])‘[^’\n]+’(?![0-9A-Za-z])"))
_HEX = re.compile(r"(?<![0-9A-Za-z_])0[xX][0-9a-fA-F]+[A-Za-z0-9]*")
# verifier version 21: a bare hex run of > 16 characters with a letter (a digest) is a hex-string VALUE (values.py)
_HEX_STRING = re.compile(r"(?<![0-9A-Za-z_])(?=[0-9]*[a-fA-F])[0-9a-fA-F]{17,}(?![0-9A-Za-z_])")
_HYPH = re.compile(r"(?<![0-9A-Za-z_\-])[0-9A-Za-z]+(?:-[0-9A-Za-z]+)+(?![0-9A-Za-z_\-])")
_UNIT = re.compile(r"[0-9]+-[a-z]+")
_DIGITS = re.compile(r"[0-9]+(?:-[0-9]+)+")
_WORD = re.compile(r"(?<![0-9A-Za-z_$])[A-Za-z_$][A-Za-z0-9_$]*(?:(?:\.|::)[A-Za-z_$][A-Za-z0-9_$]*)*(\()?")
# PE section names: dot-leading, after whitespace or at the start of the text (`.text`, `.pdata`, `.rsrc$01`). The
# list is closed and case-insensitive: a sentence dot, `.5`, `foo.dll`, `.NET`, `.exe` or `.This` is not a section.
_SECTION_NAMES = ("textbss", "rdata", "reloc", "pdata", "xdata", "idata", "edata", "debug", "didat", "gfids", "00cfg",
                  "orpc", "rsrc", "text", "data", "tls", "bss", "crt")
_SECTION = re.compile(r"(?<!\S)\.(?:%s)(?:\$[0-9A-Za-z]+)?(?![A-Za-z0-9_$])"
                      % "|".join(sorted(_SECTION_NAMES, key=len, reverse=True)), re.IGNORECASE)
# Template argument text: types, separators and qualifiers only (no control characters/operators that would make prose
# look like a template); at least one letter or digit is required.
_TEMPLATE_ARGS = re.compile(r"[A-Za-z0-9_:,.$*&\[\]<>\s]+")
# A known C/C++ type token in an argument list: `Name<T>` alone is prose, `QList<int>`/`std::vector<T>` are templates.
_TEMPLATE_TYPE = re.compile(r"(?<![A-Za-z0-9_])(?:int|char|short|long|float|double|bool|void|unsigned|signed|"
                            r"size_t|wchar_t|u?int(?:8|16|32|64)_t)(?![A-Za-z0-9_])")
_PRINT_KEYWORD = re.compile(r"(?:class|struct|enum|union)(?=\s)")
_ACRONYM = re.compile(r"([A-Z][A-Z0-9]*[A-Z][A-Z0-9]*)(?:'?[a-zçğıöşü]+)?")
_CAMEL = re.compile(r"[a-z][A-Z]")
_IDA_NAME = re.compile(r"(?:sub|loc)_([0-9A-Fa-f]+)")
_PRINTF_HEX = re.compile(r"%[-+ #0]*[0-9]*(?:hh|h|ll|l|I64|I32)?[xX]")


def _is_identifier(tok: str, call: bool) -> bool:
    if call or "_" in tok or "::" in tok or _CAMEL.search(tok):
        return True
    if re.search(r"[A-Za-z]", tok) and re.search(r"[0-9]", tok):
        return True
    if "." in tok:  # dotted name: every part >= 2 characters (not "e.g")
        return all(len(p) >= 2 for p in tok.split("."))
    return False


def _classify_word(tok: str, call: bool) -> tuple[str, str] | None:
    """(term, class) for one word token or None."""
    if _is_identifier(tok, call):
        return tok, "identifier"
    m = _ACRONYM.fullmatch(tok)
    if m and sum(c.isupper() for c in m.group(1)) >= 2:
        head = m.group(1)
        return (None if head in EXEMPT_ACRONYMS else (head, "acronym"))
    if _LEX.fullmatch(tok.lower()):
        return tok, "lexicon"
    return None


def _template_close(t: str, start: int) -> int | None:
    """Index just past the `>` matching the `<` at t[start] (one level of nesting is common: vector<pair<int,int>>);
    None if the list is not closed on the same line."""
    depth = 0
    for i in range(start, len(t)):
        c = t[i]
        if c == "<":
            depth += 1
        elif c == ">":
            depth -= 1
            if depth == 0:
                return i + 1
        elif c == "\n":
            return None
    return None


def _template_base(tok: str) -> bool:
    """Is `tok` a name a template argument list may belong to (`std::vector`, `List`, `My_Map`)? A bare lower-case
    prose word (`count<10`) is not: that would turn a comparison into a technical term."""
    return "::" in tok or _is_identifier(tok, False) or any(c.isupper() for c in tok)


def _template_is_term(base: str, args: str) -> bool:
    """Strong template context: a `::`-qualified name, or an argument list with a known type/pointer/reference or a
    nested template. `Vector<T>` in prose is not a term; `std::vector<int>` and `QList<int>` are."""
    if "::" in base:
        return True
    if "std::" in args or _TEMPLATE_TYPE.search(args):
        return True
    if "*" in args or "&" in args:
        return True
    return "<" in args and ">" in args  # nested template


def _squash_templates(s: str) -> str:
    """Canonical template text: inside matched `<...>` spans whitespace and the printing keywords (`class `,
    `struct `, `enum `, `union `) are not significant, so `std::vector<int,class std::allocator<int> >` becomes
    `std::vector<int,std::allocator<int>>`. Everything outside the angle brackets is untouched. One nesting-aware
    pass (a stack matches the pairs), so any nesting depth collapses without repeated rescans."""
    if "<" not in s:
        return s
    n = len(s)
    stack: list[int] = []
    depth = [0] * (n + 1)
    for i, c in enumerate(s):
        if c == "<":
            stack.append(i)
        elif c == ">" and stack:
            start = stack.pop()
            depth[start + 1] += 1
            depth[i] -= 1
    out: list[str] = []
    level = 0
    i = 0
    while i < n:
        level += depth[i]
        c = s[i]
        if level > 0 and c not in "<>":
            if c.isspace():
                i += 1
                continue
            if c.isalpha() and (i == 0 or not (s[i - 1].isalnum() or s[i - 1] in "_$")):
                m = _PRINT_KEYWORD.match(s, i)
                if m:
                    i = m.end()
                    while i < n and s[i].isspace():
                        i += 1
                    continue
        out.append(c)
        i += 1
    return "".join(out)


# Code-like operands around `^`: an identifier/number/closing bracket on the left, an identifier/number (possibly
# parenthesised or with a unary/pointer prefix) on the right.
_NUM = r"(?:0[xX][0-9A-Fa-f]+[uUlL]*|\d+(?:\.\d+)?[uUlLfF]*)"
_IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"
_NUM_RX = re.compile(_NUM)
_IDENT_RX = re.compile(_IDENT)
_CODE_PUNCT = frozenset(";=(){}")
_UNARY = "~!+-*&("


def _left_operand(line: str, end: int) -> str | None:
    """The operand token ending just before `end` (whitespace skipped), or None."""
    i = end
    while i > 0 and line[i - 1].isspace():
        i -= 1
    if i == 0:
        return None
    c = line[i - 1]
    if c in ")]":
        return c
    if c.isalnum() or c in "_$":
        start = i
        while start > 0 and (line[start - 1].isalnum() or line[start - 1] in "_$."):
            start -= 1
        return line[start:i]
    return None


def _right_operand(line: str, start: int) -> str | None:
    """The operand token starting at `start` (whitespace, `^=`'s `=` and unary prefixes skipped), or None."""
    n = len(line)
    i = start
    if i < n and line[i] == "=":  # `^=`
        i += 1
    while i < n and line[i].isspace():
        i += 1
    while i < n and line[i] in _UNARY:
        i += 1
    if i < n and (line[i].isalnum() or line[i] in "_$"):
        tok_start = i
        while i < n and (line[i].isalnum() or line[i] in "_$."):
            i += 1
        return line[tok_start:i]
    if i < n and line[i] in ")]":
        return line[i]
    return None


def _code_like_operand(tok: str) -> bool:
    """A number/hex literal, a single-letter local, or a decompiler-style variable (`v12`, `a1`, `_key`, `*p`)."""
    core = tok.strip("()[]").lstrip("~!+-*&")
    if not core:
        return False
    if _NUM_RX.fullmatch(core):
        return True
    if not _IDENT_RX.fullmatch(core):
        return False
    return len(core) == 1 or any(c.isdigit() for c in core) or "_" in core or "$" in core


def _caret_backs_xor(hay: str) -> bool:
    """`^` as a binary operator between two code-like operands (`a ^ b`, `x^=y`, `v1 ^ 0x5A`, `(a)^(b)`): not a
    `[^...]` negation, not a caret inside a literal string, and not the caret of prose (`The ^ is a caret`). Each line
    is scanned once while the quote/character-class state is tracked, so a line with many carets stays linear."""
    for line in hay.split("\n"):
        line_code = any(c in line for c in _CODE_PUNCT)
        quote = ""
        in_class = False
        escaped = False
        last_nonspace = -1
        for i, c in enumerate(line):
            if escaped:
                escaped = False
            elif quote:
                if c == "\\":
                    escaped = True
                elif c == quote:
                    quote = ""
            elif in_class:
                if c == "]":
                    in_class = False
            elif c in "'\"":
                quote = c
            elif c == "[":
                in_class = True
            elif c == "^":
                left = _left_operand(line, last_nonspace + 1 if last_nonspace >= 0 else 0)
                right = _right_operand(line, i + 1)
                if left and right and (line_code or _code_like_operand(left) or _code_like_operand(right)):
                    return True
            if not c.isspace():
                last_nonspace = i
    return False


def extract_terms(text: str) -> list[dict]:
    """[{term, cls}] in text order, unique by term. Deterministic."""
    t = text
    for rx in _QUOTED:
        t = rx.sub(lambda m: " " * len(m.group(0)), t)
    t = _HEX.sub(lambda m: " " * len(m.group(0)), t)
    t = _HEX_STRING.sub(lambda m: " " * len(m.group(0)), t)   # a digest is a value (values.py, version 21), not a term
    found: list[tuple[int, str, str]] = []

    def hyph(m: re.Match[str]) -> str:
        tok = m.group(0)
        if _UNIT.fullmatch(tok) or _DIGITS.fullmatch(tok):
            return tok if _UNIT.fullmatch(tok) else " " * len(tok)  # a unit word stays plain text; numbers are values
        if _LEX.fullmatch(tok.lower()):
            found.append((m.start(), tok, "lexicon"))
        elif any(c.isdigit() for c in tok):
            found.append((m.start(), tok, "compound"))
        else:  # word-only compound (XOR-decodes, PRNG-selected): each part on its own
            pos = m.start()
            for part in tok.split("-"):
                c = _classify_word(part, False)
                if c:
                    found.append((pos, *c))
                pos += len(part) + 1
        return " " * len(tok)

    t = _HYPH.sub(hyph, t)
    for m in _SECTION.finditer(t):
        found.append((m.start(), m.group(0), "section"))
    pos = 0
    while True:   # word tokens, extended to the full name when a template argument list follows
        m = _WORD.search(t, pos)
        if not m:
            break
        tok = m.group(0).rstrip("(")
        base_end = m.start() + len(tok)
        if base_end < len(t) and t[base_end] == "<" and _template_base(tok):
            close = _template_close(t, base_end)
            args = t[base_end + 1:close - 1] if close else ""
            if (close and _TEMPLATE_ARGS.fullmatch(args) and re.search(r"[A-Za-z0-9]", args)
                    and _template_is_term(tok, args)):
                found.append((m.start(), tok + "<" + re.sub(r"\s+", " ", args).strip() + ">", "template"))
                pos = close
                continue
        c = _classify_word(tok, m.group(1) is not None)
        if c:
            found.append((m.start(), *c))
        pos = m.end()
    out: list[dict] = []
    seen: set[str] = set()
    for _, term, cls in sorted(found, key=lambda x: x[0]):
        if term not in seen:
            seen.add(term)
            out.append({"term": term, "cls": cls})
    return out


def normalize_hay(text: str) -> str:
    """The haystack terms are searched in: lower case, `-` is `_` (whitespace stays: `valid key` in an output line
    does not back the identifier `valid_key`)."""
    return text.lower().replace("-", "_")


def _variants(term: str) -> list[str]:
    v = re.sub(r"[-_]+", "_", term.lower()).strip("_")
    out = [v] if v else []
    if "_" in v:
        out.append(v.replace("_", ""))
    return out


def _found(variant: str, hay: str, stem: bool) -> bool:
    """Token-bounded search; a lexicon stem may carry an inflection or a digit/separator tail (`decryption`,
    `crc32`, `decrypt_block`) but not more letters (`sha` is not found in `shadow`)."""
    tail = (_INFLECTION + r"(?![a-z])") if stem else r"(?![0-9a-z])"
    return re.search(r"(?<![0-9a-z])" + re.escape(variant) + tail, hay) is not None


def term_backed(term: dict, hay: str, addresses: Iterable[int] = ()) -> bool:
    """Is the term found in the normalized haystack (normalize_hay) or, for an IDA auto-name, at a cited address?"""
    word, cls = term["term"], term["cls"]
    if cls == "template":   # whitespace/keywords inside <...> are not significant (outside it is; the name stays token-bounded)
        return any(_found(v, _squash_templates(hay), False) for v in _variants(_squash_templates(word)))
    if cls == "lexicon":
        w = word.lower()
        base = next((s for s in _STEMS_LONGEST_FIRST if w.startswith(s)), w)
        if any(_found(v, hay, True) for v in _variants(base)):
            return True
        if base in ("hex", "hexadecimal") and _PRINTF_HEX.search(hay.replace("_", " ")):
            return True
        return False
    if any(_found(v, hay, False) for v in _variants(word)):
        return True
    if cls == "acronym" and word == "XOR":  # version 18: only a binary `^` between operands (not `[^...]`, not a string)
        return _caret_backs_xor(hay)
    m = _IDA_NAME.fullmatch(word)
    if m:
        n = int(m.group(1), 16)
        return n in set(addresses)
    return False
