"""Readable encoding label for a string record of an engine (`enc=ascii|utf-16le|utf-32le|utf-8|8bit|unknown`).

IDA reports the numeric strtype (low two bits = character width: 0 = 1 byte, 1 = 2 bytes, 2 = 4 bytes); Ghidra
reports the data-type name ("string", "unicode", "unicode32", "utf8", ...). The raw kind is always kept next to the label.
"""
from __future__ import annotations


def encoding_tag(kind: str, value: str = "") -> str:
    """`enc=<label>` for a strings line. The wide encodings add their family in upper case, `enc=utf-16le (UTF-16)`:
    the claim verifier matches a term token-bounded, so `UTF-16` is not found inside `utf-16le`."""
    return enc_label(string_encoding(kind, value))


def enc_label(enc: str) -> str:
    """`enc=<enc>` plus the upper-case family for the wide encodings."""
    family = {"utf-16le": " (UTF-16)", "utf-32le": " (UTF-32)"}.get(enc, "")
    return f"enc={enc}{family}"


def string_encoding(kind: str, value: str = "") -> str:
    k = (kind or "").strip().lower()
    if k.lstrip("-").isdigit():                     # IDA strtype
        width = int(k) & 0x3
        if width == 1:
            return "utf-16le"
        if width == 2:
            return "utf-32le"
        if width == 0:
            return "ascii" if value.isascii() else "8bit"
        return "unknown"
    if "unicode32" in k or "utf32" in k or "utf-32" in k:
        return "utf-32le"
    if "unicode" in k or "utf16" in k or "utf-16" in k:
        return "utf-16le"
    if "utf8" in k or "utf-8" in k:
        return "utf-8"
    if "string" in k or "char" in k:
        return "ascii" if value.isascii() else "8bit"
    return "unknown"
