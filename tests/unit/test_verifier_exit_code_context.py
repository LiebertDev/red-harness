"""The `exit_code` atom backs a number written in the claim text ONLY where it stands in an explicit exit-code phrase.

Every other occurrence of the same number (an address, a count) is governed by the normal value / hex-literal rules.
Fakes only (ledger level, Env fixture of test_dynamic.py).
"""
import pytest

from redharness.evidence.model import ClaimStatus

from .test_dynamic import env as env  # noqa: F401
from .test_verifier_exit_code import atom, claim, codes, run_ev

NTSTATUS = -1073741819   # 0xC0000005 as the signed 32-bit exit code run_controlled records


def test_same_number_used_as_an_address_elsewhere_is_not_backed_by_the_atom(env):
    ev = run_ev(env, code=NTSTATUS)
    text = "The program exits with code 0xC0000005 when given `token_a`; the faulting address is 0xC0000005."
    res = claim(env, [ev], [atom(ev, NTSTATUS)], text=text)
    assert res.status is ClaimStatus.REJECTED and "HEX_LITERAL_UNSUPPORTED" in codes(res)
    only_exit = claim(env, [ev], [atom(ev, NTSTATUS)], text="The program exits with code 0xC0000005 when given `token_a`.")
    assert only_exit.status is ClaimStatus.PROVEN, only_exit.issues


def test_address_only_mention_of_the_code_is_not_backed(env):
    ev = run_ev(env, code=NTSTATUS)
    res = claim(env, [ev], [atom(ev, NTSTATUS)], text="The handler at 0xC0000005 runs when given `token_a`.")
    assert res.status is ClaimStatus.REJECTED and "HEX_LITERAL_UNSUPPORTED" in codes(res)


def test_same_decimal_used_as_a_count_elsewhere_is_not_backed_by_the_atom(env):
    ev = run_ev(env, code=3)
    res = claim(env, [ev], [atom(ev, 3)], text="The program exits with code 3 when given `token_a`; the table has 3 entries.")
    assert res.status is ClaimStatus.UNVERIFIED and "VALUE_NOT_IN_EVIDENCE" in codes(res)


def test_number_without_an_exit_code_phrase_is_not_backed(env):
    ev = run_ev(env, code=3)
    res = claim(env, [ev], [atom(ev, 3)], text="The program prints 3 lines when given `token_a`.")
    assert res.status is ClaimStatus.UNVERIFIED and "VALUE_NOT_IN_EVIDENCE" in codes(res)


@pytest.mark.parametrize("phrase", ["exit code 3", "exit code is 3", "exit code = 3", "exit status 3", "exits with 3",
                                    "exits with code 3", "exits with exit status 3", "exited with code 3",
                                    "returns 3 to the operating system", "Exit Code: 3"])
def test_documented_exit_code_phrases_back_the_number(env, phrase):
    ev = run_ev(env, code=3)
    res = claim(env, [ev], [atom(ev, 3)], text=f"With `token_a` the program ends: {phrase}.")
    assert res.status is ClaimStatus.PROVEN, (phrase, res.issues)


@pytest.mark.parametrize("phrase", ["exit code 0xC0000005", "exit code 3221225477", "exit status -1073741819",
                                    "exits with code 0xc0000005", "returns 3221225477 to the operating system"])
def test_ntstatus_forms_in_an_exit_phrase_are_backed(env, phrase):
    ev = run_ev(env, code=NTSTATUS)
    for code in (NTSTATUS, 3221225477):
        res = claim(env, [ev], [atom(ev, code)], text=f"With `token_a` the program ends with {phrase}.")
        assert res.status is ClaimStatus.PROVEN, (phrase, code, res.issues)


def test_unsigned_code_above_2_pow_31_normalizes_both_ways(env):
    ev = run_ev(env, code=3221225477)      # an unsigned record of the same code
    for code in (3221225477, NTSTATUS):
        for text in ("exit code 3221225477", "exit code 0xC0000005", "exit code -1073741819"):
            res = claim(env, [ev], [atom(ev, code)], text=f"With `token_a` the program ends: {text}.")
            assert res.status is ClaimStatus.PROVEN, (code, text, res.issues)
    wrong = claim(env, [ev], [atom(ev, 3221225477)], text="With `token_a` the program ends: exit code 3221225478.")
    assert wrong.status is ClaimStatus.UNVERIFIED and "VALUE_NOT_IN_EVIDENCE" in codes(wrong)


def test_declared_value_equal_to_the_context_backed_code_is_the_same_occurrence(env):
    ev = run_ev(env, code=NTSTATUS)
    res = env.ledger.add_claim("With `token_a` the program ends with exit code 0xC0000005.", "behavior", "present", [ev],
                               [atom(ev, NTSTATUS)], "PROVEN",
                               values=[{"value": "token_a", "derived": True}, {"value": "0xC0000005", "derived": False}])
    assert res.status is ClaimStatus.PROVEN, res.issues
