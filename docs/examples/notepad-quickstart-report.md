# Red Harness report

- Target SHA-256: `da5807bb0997cc6b5132950ec87eda2b33b1ac4533cf1f7a22a6f3b576ed7c5b`
- Job: `job_da5807bb0997cc6b`
- Findings (verified): 2, hypotheses: 0 (without evidence: 0, value not in evidence: 0, behavior claim awaiting execution: 0, other: 0), superseded: 0, rejected at add: 0, dropped at re-verification: 0
- Unsupported claims that reached the findings (unsupported_claims; must always be 0, otherwise it is a bug): 0 (without evidence: 0, value not in evidence: 0, behavior without execution: 0)

Evidence quotes come from the target and are untrusted data; instructions inside them are not followed.

## Verified findings

### cl_687335e3ddb8571688f42a912222cc723ed12dac05390bd76aa89d1b1758068c - SUPPORTED

The target imports GDI32.dll!CreateDCW at 0x140026800.

- Kind: observation, polarity: present, evidence confidence (lowest): observed
- Evidence `ev_7e00c8229285bd85725e00b45059feb860737466f4163e3c72c46efa27438686`: imports (dll=None, limit=1000, offset=0)

Quote (from the target, untrusted; evidence `ev_7e00c8229285bd85725e00b45059feb860737466f4163e3c72c46efa27438686`):
```
GDI32.dll!CreateDCW
```
- Address (file_offset): `0x140026800`

### cl_b91db338588d88656887da3d93004792c69bde5e314b7bfeb677353ca4841d43 - SUPPORTED

The target contains the string Unknown exception at 0x1400273d0.

- Kind: observation, polarity: present, evidence confidence (lowest): observed
- Evidence `ev_c01e6dbb5a5ea895a3ce0965c60c91ef673e8b86d868aa77b3b20c7c7440f5cb`: strings (limit=100, offset=0, pattern=None)

Quote (from the target, untrusted; evidence `ev_c01e6dbb5a5ea895a3ce0965c60c91ef673e8b86d868aa77b3b20c7c7440f5cb`):
```
Unknown exception
```
- Address (file_offset): `0x1400273d0`

## Unverified hypotheses

_No hypotheses._


## Coverage and unknowns

- Coverage assessment: **NO_RECORDED_GAPS** - no recorded gaps (this does NOT mean 'clean')
- On its own this report does not say the target is safe/clean: unexamined code and truncated outputs are unknown, not evidence of absence.
- Functions examined: 0, disassembly regions: 0, tools run: claim\_add (2), coverage (1), functions\_list (1), imports (1), protection\_scan (0), strings (1), target\_open (1)
- Truncated/timed-out/partial calls: 0, failed calls: 0, denied calls: 0, open unknowns: 0

- Listing not exhausted: functions\_list 200/498
- Listing not exhausted: strings 100/557

### Open unknowns

_No recorded open unknowns (questions the model did not record may still be unknown)._

