# Third-party notices

Red Harness's own source code is licensed under [Apache-2.0](LICENSE). Every component listed here is a **separate
product with its own licence**. None of them is part of Red Harness, none is covered by Red Harness's Apache-2.0
licence, and **Red Harness bundles and redistributes none of them**: this repository and the `redharness` package
contain no binary, source or data of any component below. You obtain each one yourself, from its own publisher, and
you accept its licence when you do. Product names identify integrations only; they do not imply affiliation or
endorsement.

`rh deps list` shows each component below, whether it is present on your machine, its licence and its upstream link.
`rh deps install <id>` installs the pip components (Unicorn, Capstone) after printing the notice and asking you to
confirm; it installs nothing else. The upstream licence texts of the tools below are in [licenses/](licenses/README.md).

Licence facts below were checked against PyPI metadata and the upstream repositories on 2026-10-21. They are summaries,
not legal advice, and the upstream licence always controls.

## Optional pip components (installed by you, on request)

### Unicorn (CPU emulator)

- **Used for:** the `emulate` tool (bounded emulation of target code in a restricted host process). Off by default.
- **Bundled:** no. **Obtained:** `rh deps install emulate`, or `pip install "redharness[emulate]"`. Both install the
  pinned release `unicorn==2.1.4` from PyPI.
- **Licence:** the Unicorn engine is licensed upstream under **GPL-2.0**
  ([licenses/unicorn-2.1.4-COPYING.txt](licenses/unicorn-2.1.4-COPYING.txt)). The PyPI metadata of the Python package
  `unicorn` declares the BSD licence classifier, but the wheel contains the compiled engine and carries no licence file
  of its own (checked for 2.1.4). Treat the engine's GPL-2.0 terms as the ones that matter if you redistribute an
  environment that contains it: you would have to supply the licence text and the corresponding source yourself.
- **Upstream:** <https://www.unicorn-engine.org/> and <https://github.com/unicorn-engine/unicorn>.
- Not part of Red Harness, not covered by Red Harness's Apache-2.0 licence.

### Capstone (disassembler)

- **Used for:** the Pro `captured_region` disassembly view and some optional tests. The Core edition does not need it.
- **Bundled:** no. **Obtained:** `rh deps install capstone`, which installs the pinned release `capstone==5.0.6` from PyPI.
- **Licence:** **BSD-3-Clause**
  ([licenses/capstone-5.0.6-LICENSE.TXT](licenses/capstone-5.0.6-LICENSE.TXT)); the PyPI package declares the BSD
  licence classifier. The wheel (checked for 5.0.6) carries `LICENSE.TXT`, which pip stores in the package's
  `.dist-info` folder.
- **Upstream:** <https://www.capstone-engine.org/> and <https://github.com/capstone-engine/capstone>.
- Not part of Red Harness, not covered by Red Harness's Apache-2.0 licence.

### Python packages that Red Harness depends on

The MCP Python SDK (`mcp==1.30.0`) is the only direct runtime dependency. pip installs it, with its own dependencies,
under their own licences; none is embedded. `pytest` (MIT) is a development extra. Licences as resolved on 2026-10-21;
the texts are in each package's `.dist-info` folder and at the links below.

| Package | Licence | Upstream |
|---|---|---|
| mcp 1.30.0 | MIT | <https://github.com/modelcontextprotocol/python-sdk> |
| pydantic 2.14.1, pydantic-core, pydantic-settings | MIT | <https://github.com/pydantic/pydantic> |
| starlette 1.9.0, sse-starlette 3.5.0, uvicorn 0.54.0 | BSD-3-Clause | <https://github.com/Kludex/starlette> |
| httpx 0.28.1, httpcore 1.0.9 | BSD-3-Clause | <https://github.com/encode/httpx> |
| anyio 4.15.1 | MIT | <https://github.com/agronholm/anyio> |
| jsonschema 4.26.0 (with referencing, rpds-py) | MIT | <https://github.com/python-jsonschema/jsonschema> |
| python-multipart 0.0.32 | Apache-2.0 | <https://github.com/Kludex/python-multipart> |
| certifi 2026.10.18 | MPL-2.0 | <https://github.com/certifi/python-certifi> |
| other transitive packages (h11, idna, click, attrs, pyjwt, ...) | MIT, BSD-3-Clause or PSF | see each package's PyPI page |

## Bring-your-own analysis engines

An analysis engine is required for the MCP tools. Red Harness ships none, downloads none, and never installs one. It
looks for the engine you installed and uses it as a separate program.

### Ghidra

- **Used for:** analysis engine (`rh mcp --engine ghidra`); tested with 12.1.3. Needs a JDK 21 (see "Runtimes" below).
- **Bundled:** no. **Obtained:** download the release from <https://github.com/NationalSecurityAgency/ghidra/releases>,
  extract it, and set `RH_GHIDRA_DIR` to the folder that contains `support/analyzeHeadless.bat` (`GHIDRA_INSTALL_DIR` is
  also read; common locations such as `~/ghidra*` are searched).
- **Licence:** **Apache-2.0** ([licenses/ghidra-12.1.3-LICENSE.txt](licenses/ghidra-12.1.3-LICENSE.txt)), with component qualifications in Ghidra's own
  [NOTICE](https://github.com/NationalSecurityAgency/ghidra/blob/master/NOTICE); the Ghidra distribution carries
  additional third-party licences. Ghidra's notice credits software developed at the US National Security Agency and
  explains that US-government-created portions are not subject to US copyright. Red Harness is not affiliated with or
  endorsed by the NSA.
- Not part of Red Harness, not covered by Red Harness's Apache-2.0 licence.

### IDA Pro / IDA Home (Hex-Rays)

- **Used for:** analysis engine (`rh mcp --engine ida`) through the `idapro` (idalib) Python package.
- **Bundled:** no, and it cannot be: it is commercial software. **Obtained:** from Hex-Rays, under a licence you hold.
  Set `RH_IDA_DIR` (or `IDADIR`) to the folder that contains `idalib.dll`; set `RH_IDA_PYTHON` if the `idapro` package
  is installed in a different Python. Install `idapro` from the wheel inside your IDA installation, not from PyPI
  (the PyPI publisher is unverified). Red Harness never runs IDA's licence activation script.
- **Licence:** proprietary, governed by the Hex-Rays [EULA](https://hex-rays.com/eula) and your purchase agreement. You
  must obtain the rights your use needs (product, user, machine, decompiler, automation interface). Red Harness grants
  none, and a working integration is not a statement that your licence permits it.
- **Upstream:** <https://hex-rays.com/ida-pro>.
- Not part of Red Harness, not covered by Red Harness's Apache-2.0 licence.

## Runtimes and operating-system features

### CPython embeddable package (the `compute` runtime)

- **Used for:** the Python interpreter that the `compute` tool runs inside Windows Sandbox.
- **Bundled:** no. **Obtained:** you download `python-3.12.10-embed-amd64.zip` from python.org yourself; `rh compute-runtime`
  prints the address and the pinned SHA-256, and `rh compute-runtime install <zip>` verifies the digest and unpacks only
  a narrow, hash-checked file set.
- **Licence:** PSF License Agreement and component licences
  ([licenses/cpython-3.12.10-LICENSE.txt](licenses/cpython-3.12.10-LICENSE.txt);
  [overview](https://docs.python.org/3/license.html)).
- **Upstream:** <https://www.python.org/downloads/release/python-31210/>.
- Not part of Red Harness, not covered by Red Harness's Apache-2.0 licence.

### JDK 21 (for Ghidra)

A JDK 21 of your choice (for example Eclipse Temurin 21) must be on `PATH` or in `JAVA_HOME` when you use Ghidra. It is
installed and licensed separately (OpenJDK builds are typically GPL-2.0 with the Classpath Exception; see your
vendor's terms). Red Harness neither includes nor installs it.

### Windows Sandbox

- **Used for:** isolating the two tools that execute a target natively or run model code (`run_controlled`, `compute`).
- **Bundled:** no. It is an optional feature of Windows 10/11 Pro, Enterprise and Education (not Home) that you switch
  on yourself; Red Harness does not install or modify it. Without it those tools report `SANDBOX_UNAVAILABLE` and the
  other tools keep working.
- **Licence:** part of Windows, under the Microsoft licence terms of your Windows edition.
- **Documentation:** <https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview>.
- Not part of Red Harness, not covered by Red Harness's Apache-2.0 licence.

## Your obligations

The vendor's applicable licence controls, and these summaries do not interpret your individual contract. Obtain every
component lawfully, follow its terms (including any terms on publishing analysis output), and keep the licence notices
that come with the software you actually install or redistribute. Only analyse binaries you own or are authorized to
test.
