"""Static analysis engines (common interface: base.py)."""

# Heavy engine work holds the machine-wide `heavy.lock` (the sandbox returns BUSY meanwhile; core/heavy.py).
# Backends do `from .._common import HEAVY`, so the swap happens here in the package initializer, which runs BEFORE them.
from . import _common as _c
from ..core.heavy import HeavyGate as _Gate

if not isinstance(_c.HEAVY, _Gate):
    _c.HEAVY = _Gate()
