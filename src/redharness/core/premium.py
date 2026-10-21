"""Open-core seam: premium modules are absent from the public build. Code that reaches one imports it lazily and, when
it is missing, degrades with a clear message instead of failing at import time."""
from __future__ import annotations

NOT_INCLUDED = "premium feature not included in this build"


def is_missing(err: ImportError, module: str) -> bool:
    """True when `err` says that `module` (a dotted absolute name) or one of its parent packages is not installed.
    Any other ImportError (a real defect inside a premium module that IS present) is not masked."""
    name = err.name or ""
    return bool(name) and (module == name or module.startswith(name + "."))
