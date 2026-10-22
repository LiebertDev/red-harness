"""Verifier golden corpus: pins that records produced under version 5 verify bit-for-bit the same under version 6+.

Uses only the public API present in both versions (Cas, Journal, Ledger, build_evidence); so the same corpus was run
against the old code to produce `tests/fixtures/verifier_v5_golden.json` (evidence ids are content-addressed, the
timestamp does not enter the verification record). The corpus has NO version 6 new forms (0x..LL/u suffix, IDA ..h)
and no `derivation` atom; those are checked in separate tests (test_verifier_v6.py).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from redharness.core.cas import Cas
from redharness.core.journal import Journal
from redharness.core.result import Status
from redharness.evidence.ledger import Ledger
from redharness.evidence.model import build_evidence

TARGET = hashlib.sha256(b"golden-corpus.exe").hexdigest()
SANDBOX = {"id": "wsb-1", "platform": "windows", "architecture": "x64", "isolation": "windows-sandbox"}

DECOMPILE = (b"int __cdecl main(int argc, const char **argv)\n{\n"
             b"  char Str1[16]; // [esp+20h] [ebp-60h] BYREF\n"
             b"  if ( strlen(Buffer) == 32 && (v16 ^ 0x1337) + 42 == v3 )\n"
             b"    puts(\"Correct Password!\");\n"
             b"  strcmp(Str1, \"qwerty\");\n  return 0x10462;\n}\n")
DISASM = (b"0x401460: 55 push ebp\n0x401461: 89e5 mov ebp, esp\n0x401464: 83ec24 sub esp, 0x24\n"
          b"0x401467: 8b4508 mov eax, [ebp+Str]\n0x40149d: 3c60 cmp al, 0x60\n"
          b"0x4014a0: e8 call sub_401600 ; high byte\n")
STRINGS = b"0x1a40: IRP_MJ_DEVICE_CONTROL\ndispatch at 0x104620 ioctl 0x15e000\nAccess granted!\n"


class Corpus:
    def __init__(self, root: Path):
        self.cas = Cas(root / "cas")
        self.journal = Journal(root / "events.jsonl")
        self.ledger = Ledger(self.journal, self.cas, TARGET)

    def ev(self, raw: bytes, operation: str = "decompile", authority: str = "shipped-artifact", **kw) -> str:
        base = dict(subject_sha256=TARGET, tool=operation, operation=operation, raw=raw, status=Status.OK,
                    confidence="observed", authority=authority,
                    locations=[{"kind": "address-range", "space": "va", "start": 0x401000, "end": 0x401700}],
                    coverage={"scope": "function", "relationship": "complete"})
        base.update(kw)
        return self.ledger.record_evidence(build_evidence(self.cas, **base))["evidence_id"]

    def replay(self, raw: bytes, stdin: str) -> str:
        return self.ev(raw, operation="run_controlled", authority="controlled-replay", environment=SANDBOX,
                       exit_code=0, locations=(), parameters={"argv": [], "stdin": stdin})


def build(root: Path) -> dict[str, dict]:
    """Name -> {status, checks, issues, values} (with the verifier's current version)."""
    c = Corpus(root)
    dec = c.ev(DECOMPILE)
    asm = c.ev(DISASM, operation="disassemble")
    st = c.ev(STRINGS, operation="strings", locations=[{"kind": "file-offset-range", "start": 6720, "end": 6741}])
    ok_run = c.replay(b"Enter password: Access granted!\n--- stderr ---\n", "secret\n")
    bad_run = c.replay(b"Enter password: Access denied!\n--- stderr ---\n", "qwerty\n")
    q = lambda e, t: {"type": "quote", "evidence_id": e, "text": t}  # noqa: E731
    cases = {
        "obs_quote_ok": ("main compares `qwerty` using strcmp.", "observation", [dec], [q(dec, "strcmp(Str1")], None),
        "obs_quote_missing": ("main calls strcmp.", "observation", [dec], [q(dec, "strncmp(Str1")], None),
        "obs_hex_literal_raw": ("main returns 0x10462.", "observation", [dec], [], None),
        "obs_hex_literal_substring_trap": ("dispatch is at address 0x10462.", "observation", [st], [], None),
        "obs_hex_literal_malformed": ("the constant 0x12zz is used.", "observation", [dec], [], None),
        "obs_hex_quote_token": ("the return value is a constant.", "observation", [dec], [q(dec, "0x1046")], None),
        "obs_constant_atom": ("The XOR key is a constant.", "observation", [dec],
                              [{"type": "constant", "evidence_id": dec, "value": "0x1337"}], None),
        "obs_constant_missing": ("The XOR key is a constant.", "observation", [dec],
                                 [{"type": "constant", "evidence_id": dec, "value": "0x1338"}], None),
        "obs_address_atom": ("main starts at address 0x401460.", "observation", [asm],
                             [{"type": "address", "evidence_id": asm, "value": "0x401460"}], None),
        "obs_address_outside": ("the function is at address 0x402000.", "observation", [asm],
                                [{"type": "address", "evidence_id": asm, "value": "0x402000"}], None),
        "obs_decimal_value_ok": ("the length must be 32; the result is found by adding 42.", "observation", [dec], [], None),
        "obs_decimal_value_missing": ("the length must be 33.", "observation", [dec], [], None),
        "obs_asm_word_not_number": ("sub_401600 is called; 0x24 bytes are reserved.", "observation", [asm], [], None),
        "obs_derived_static_only": ("example pair 17 and 4944.", "observation", [dec], [],
                                    [17, {"value": 4944, "derived": True}]),
        "obs_atom_not_listed": ("main calls strcmp.", "observation", [dec], [q(asm, "push ebp")], None),
        "beh_static_only": ("The correct password is `qwerty`.", "behavior", [dec], [q(dec, "qwerty")], None),
        "beh_run_fed_and_output": ("When the password `secret` is entered the program prints Access granted!", "behavior",
                                   [ok_run], [q(ok_run, "Access granted!")],
                                   [{"value": "secret", "derived": True}]),
        "beh_run_no_output_atom": ("The password `secret` is accepted.", "behavior", [ok_run], [],
                                   [{"value": "secret", "derived": True}]),
        "beh_run_wrong_input": ("When `qwerty` is entered the output is Access denied!", "behavior", [bad_run],
                                [q(bad_run, "Access denied!")], None),
        "absent_complete": ("No network API is called.", "observation", [dec], [], None),
        "inferred_kind": ("main is the function at 0x401460 and calls strcmp.", None, [asm, dec], [], None),
    }
    out = {}
    for name, (text, kind, evs, atoms, values) in cases.items():
        polarity = "absent" if name.startswith("absent") else "present"
        # verifier 24: a behavior claim declares its class; "ordinary" keeps the version 5 meaning (validation wording
        # still asks for a control pair through the text backstop, see test_verifier_v6.V24_PAIR_CASES)
        res = c.ledger.add_claim(text, kind, polarity, evs, atoms, "SUPPORTED", values=values,
                                 behavior_class="ordinary" if kind == "behavior" else None)
        if res.claim is not None:
            v = res.claim["verification"]
            out[name] = {"status": res.status.value, "checks": v["checks"], "issues": v["issues"],
                         "values": v["values"]}
        else:
            out[name] = {"status": res.status.value, "issues": res.issues}
    return out
