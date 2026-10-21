"""`emulate`: runs ONE function of the target in a CPU emulator (Unicorn) to recover values the static view cannot show
(decoded strings, computed constants, checksum outputs, unpacked buffers). Nothing runs natively; the result is an
observation of emulation, never of a program run. Design: docs/design/emulation.md.

The emulator package is optional (`pip install "redharness[emulate]"`); without it the tool answers EMULATOR_MISSING.
"""

from .spec import SpecError, build_request

__all__ = ["SpecError", "build_request"]
