"""Pinned portable interpreter for `compute`: the CPython embeddable package.

Windows Sandbox is a clean Windows with no Python in it (guest.ps1 uses only PowerShell/.NET). So the
interpreter is placed from the host into the read-only input folder, like the target's VC++ DLLs (sandbox/support.py). Rules:
- The package SHA-256 is pinned in code (`PINNED`). Installation (`install_runtime`) accepts only a zip matching this digest;
  only the files in the `files` list are extracted from the zip and EVERY file's SHA-256 is pinned too.
- On every `compute` call the installed files are re-hashed (`load_runtime`); a single byte of difference = `RuntimeError`,
  no run is made (no silent fallback).
- The file set is deliberately narrow: `_socket`, `_ssl`, `select`, `_ctypes`, `_multiprocessing`, `_overlapped`, `_hashlib`
  (OpenSSL), `_sqlite3` etc. are NOT included. This is NOT a security boundary (the boundary is Windows Sandbox: network off,
  separate user, Low IL); it only shrinks the attack surface. hashlib md5/sha1/sha2/sha3/blake2 work with built-in modules.

Provenance of the pinned package: the MD5 of python-3.12.10-embed-amd64.zip downloaded from python.org equals
`fe8ef205f2e9c3ba44d0cf9954e1abd3` published by the python.org API; the Authenticode signatures of python.exe and
python312.dll are valid (Python Software Foundation); with this narrow file set the interpreter starts, `socket` and
`ctypes` cannot be imported and hashlib works. The pinned SHA-256 values were computed locally (python.org does not
publish SHA-256 for this release).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Config

BOOT_NAME = "rh_boot.py"
BOOT_SOURCE = Path(__file__).with_name(BOOT_NAME)


class RuntimeMissing(RuntimeError):
    """Interpreter not installed, or the installed files do not match the pinned digests: no run is made."""


@dataclass(frozen=True)
class RuntimeSpec:
    runtime_id: str                     # visible in the evidence, e.g. "cpython-3.12.10-embed-amd64"
    zip_name: str
    zip_sha256: str
    url: str
    exe: str                            # the file run inside the sandbox
    files: dict[str, str] = field(default_factory=dict)   # name -> SHA-256 (only these are extracted and staged)


PINNED = RuntimeSpec(
    runtime_id="cpython-3.12.10-embed-amd64",
    zip_name="python-3.12.10-embed-amd64.zip",
    zip_sha256="4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3",
    url="https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip",
    exe="python.exe",
    files={
        "python.exe": "4d6f5f81a4bca11191c4c7c6b43632694d0a4ce74e068619d8fdc161d469859a",
        "python312.dll": "9a0e3435aaa680d868150f87ab3e388ad2eebc22f87e036155c7b4eda8cd2120",
        "python3.dll": "fb975a606e7fbf74f64260e3f60c3490b4f74a183c0926fd6ed1ac4c52ac7b1c",
        "python312.zip": "fb131c0ef7e35cc5250a74c8cd18744bf4115fb8163710711f3758d7df3d1f88",
        "python312._pth": "2820f241bc9d6810d4db21c21cca3845799367fbdf0199620fb37c86a74b945c",
        "vcruntime140.dll": "052ad6a20d375957e82aa6a3c441ea548d89be0981516ca7eb306e063d5027f4",
        "vcruntime140_1.dll": "6a99bc0128e0c7d6cbbf615fcc26909565e17d4ca3451b97f8987f9c6acbc6c8",
        "unicodedata.pyd": "208ee1cd3cbad0828433ca7246b05be2b1ff5569983d27d296c0b38888585488",
        "_decimal.pyd": "aeacfead2befcc0768063a037bb64bd32109ae09cb144e5f571b04dd7965db9d",
        "_bz2.pyd": "65f610646d10d5babea080e060d244b546ec52c54012e5e937dc72dcc2e2e7bc",
        "_lzma.pyd": "e3deecc1f59a3b811c608861decd84de1e8df8bafd5e2b39188861318c5a38cf",
    })


@dataclass(frozen=True)
class Runtime:
    spec: RuntimeSpec
    root: Path
    files: tuple[Path, ...]             # files to stage (including the exe) + rh_boot.py
    exe_path: Path
    exe_sha256: str
    boot_sha256: str

    def describe(self) -> dict:
        """Interpreter identity that enters the evidence (no floats in the identity projection)."""
        return {"id": self.spec.runtime_id, "zip_sha256": self.spec.zip_sha256, "exe_sha256": self.exe_sha256,
                "boot_sha256": self.boot_sha256}


def runtime_dir(cfg: Config, spec: RuntimeSpec = PINNED) -> Path:
    return cfg.data_root / "runtimes" / spec.runtime_id


def _sha_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def install_runtime(cfg: Config, zip_path: str | os.PathLike, spec: RuntimeSpec = PINNED) -> Path:
    """Installs the file set from the pinned-digest zip under `<data_root>/runtimes/<id>/`. Uses no network: the operator
    downloads the zip (`spec.url`). If the digest does not match, nothing is written."""
    zp = Path(zip_path)
    actual = _sha_file(zp)
    if actual != spec.zip_sha256:
        raise RuntimeMissing(f"{zp.name}: SHA-256 {actual} does not match the pinned digest ({spec.zip_sha256}); not installed")
    dest = runtime_dir(cfg, spec)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=".install-", dir=dest.parent))
    try:
        with zipfile.ZipFile(zp) as z:
            names = set(z.namelist())
            for name, want in spec.files.items():
                if name not in names:
                    raise RuntimeMissing(f"{name} not in zip")
                data = z.read(name)
                if hashlib.sha256(data).hexdigest() != want:
                    raise RuntimeMissing(f"{name}: SHA-256 does not match the pinned digest")
                (tmp / name).write_bytes(data)
        if dest.exists():
            shutil.rmtree(dest)
        os.replace(tmp, dest)
    finally:
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)
    load_runtime(cfg, spec)  # re-verify the installation immediately
    return dest


def load_runtime(cfg: Config, spec: RuntimeSpec = PINNED) -> Runtime:
    """Verifies the installed interpreter (every file is re-hashed, no extra file is staged)."""
    root = runtime_dir(cfg, spec)
    if not root.is_dir():
        raise RuntimeMissing(f"compute interpreter not installed ({spec.runtime_id}); the operator must download {spec.url} "
                             f"and install it with `rh compute-runtime install <zip>`")
    files: list[Path] = []
    for name, want in spec.files.items():
        p = root / name
        if not p.is_file() or p.is_symlink():
            raise RuntimeMissing(f"compute interpreter incomplete: {name}")
        if _sha_file(p) != want:
            raise RuntimeMissing(f"compute interpreter altered: {name} SHA-256 does not match the pinned digest")
        files.append(p)
    boot = BOOT_SOURCE
    return Runtime(spec, root, tuple(files) + (boot,), root / spec.exe, spec.files[spec.exe], _sha_file(boot))


def main(argv: list[str]) -> int:
    """`rh compute-runtime install <zip>` | `rh compute-runtime status`."""
    cfg = Config.load()
    if len(argv) == 2 and argv[0] == "install":
        try:
            print(f"installed: {install_runtime(cfg, argv[1])}")
            return 0
        except (RuntimeMissing, OSError, zipfile.BadZipFile) as e:
            print(f"error: {e}")
            return 2
    if argv == ["status"]:
        try:
            rt = load_runtime(cfg)
            print(f"ok: {rt.spec.runtime_id} ({rt.root})")
            return 0
        except RuntimeMissing as e:
            print(f"missing: {e}")
            return 1
    print(f"usage: rh compute-runtime install <{PINNED.zip_name}> | rh compute-runtime status\n"
          f"download: {PINNED.url}\nSHA-256: {PINNED.zip_sha256}")
    return 2
