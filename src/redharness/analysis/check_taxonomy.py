"""Closed taxonomy of protection / licensing check CANDIDATES: the data behind `check_inventory.py`.

Eight categories, C1..C8, one primary code per candidate. Every signal row says WHERE it is looked for (an imported
API, a string, or an instruction pattern), HOW STRONG a hit is, and WHY the hit may be innocent (`fp`). A hit is an
observation that a signal is present in the file; it is never proof that a check exists, runs, or decides anything.

The taxonomy is data: a new observation is a new row, not a new branch. Import and string signals of the existing
anti-analysis catalogue (`antianalysis.py`) are REUSED through the `FROM_CATALOGUE` map (technique name -> code), not
copied; only signals that catalogue does not carry (licence, trial, signature, network) live here.
"""

from __future__ import annotations

from dataclasses import dataclass

CATEGORIES: dict[str, str] = {
    "C1": "licence/key validation",
    "C2": "anti-debug",
    "C3": "anti-VM/sandbox",
    "C4": "self-integrity/hash",
    "C5": "machine/hardware id",
    "C6": "signature/crypto verification",
    "C7": "time/trial",
    "C8": "network activation",
}
STRENGTH_ORDER = {"strong": 0, "moderate": 1, "weak": 2}
KINDS = ("import", "string", "pattern")


@dataclass(frozen=True)
class Signal:
    """One taxonomy row. `match`: for `import` canonical "dll!function" (lower case, A/W suffix optional), for `string`
    the needles (case-insensitive; an identifier-like needle must not sit inside a longer identifier), for `pattern`
    the pattern id implemented in check_inventory.PATTERNS."""
    code: str
    kind: str
    name: str
    strength: str
    match: tuple[str, ...]
    why: str
    fp: str


# ------------------------------------------------------------------------------ reused catalogue rows
# antianalysis technique -> (code, strength cap, false-positive note). The effective strength is the weaker of the
# catalogue strength and the cap. Techniques that are NOT listed are deliberately not checks: process enumeration,
# OpenProcess, window enumeration, DuplicateHandle, memory protection changes, the exception filters (all common in
# ordinary software and in the C runtime) are anti-analysis HINTS in the catalogue, not check candidates here.
FROM_CATALOGUE: dict[str, tuple[str, str, str]] = {
    # -- C2 anti-debug (imports)
    "debugger-present": ("C2", "strong", "the C runtime's startup also calls IsDebuggerPresent (suppressed in a CRT "
                                         "startup cluster); a crash handler or logger may call it too"),
    "ntqueryinformationprocess": ("C2", "moderate", "also used for process / command-line / parent queries"),
    "debug-object-query": ("C2", "moderate", "NtQueryObject / NtQueryInformationThread serve many non-debug queries"),
    "hide-thread-from-debugger": ("C2", "strong", "NtSetInformationThread has other information classes; only the "
                                                  "hide-from-debugger class is anti-debug"),
    "kernel-debugger-query": ("C2", "weak", "NtQuerySystemInformation is a general system-information call"),
    "output-debug-string": ("C2", "weak", "logging and trace code uses OutputDebugString"),
    "debug-break": ("C2", "weak", "assertion / crash handling code raises breakpoints"),
    "thread-context": ("C2", "moderate", "debuggers, profilers, coroutine libraries and crash dumpers use thread "
                                         "contexts; only a read of the debug registers is anti-debug"),
    "debug-attach": ("C2", "moderate", "debugger tooling and self-debugging helpers use these calls"),
    # -- C2 anti-debug (strings naming debuggers / debug-output capture)
    "debugger-tool": ("C2", "weak", "a string naming a debugger can sit in help text, a process blacklist, or a "
                                    "security tool's own database"),
    "dump-tool": ("C2", "weak", "a dumper name can sit in a security tool's detection list"),
    "instrumentation-framework": ("C2", "weak", "instrumentation framework name; can be documentation text"),
    "debugger-capture": ("C2", "weak", "OutputDebugString capture window name; logging tools mention it"),
    # -- C3 anti-VM / sandbox
    "firmware-table": ("C3", "strong", "inventory and driver-installer software also reads SMBIOS tables"),
    "device-enumeration": ("C3", "weak", "installers, drivers and hardware inventory legitimately enumerate devices"),
    "vm-artifact": ("C3", "moderate", "the name of a hypervisor can appear in virtualization management or "
                                  "compatibility code"),
    "sandbox-artifact": ("C3", "moderate", "sandbox product names appear in security tools' own lists"),
    "emulator-artifact": ("C3", "moderate", "Wine detection is also used for compatibility workarounds"),
    # -- C4 self-integrity
    "memory-map-query": ("C4", "weak", "VirtualQuery is used by allocators, GC, stack probing and crash handlers"),
    "module-path-query": ("C4", "weak", "GetModuleHandle / GetModuleFileName are used by nearly every program (and "
                                        "by the CRT startup: suppressed in a CRT startup cluster)"),
    "self-memory-read": ("C4", "weak", "ReadProcessMemory is used by debuggers, profilers and tools; reading ones own "
                                       "image is the integrity case"),
    # -- C5 machine / hardware id
    "machine-identity": ("C5", "weak", "computer and user names are read by telemetry, installers and UI code"),
    "mac-address": ("C5", "moderate", "network tools, telemetry and installers read adapter addresses"),
    "volume-serial": ("C5", "moderate", "GetVolumeInformation also returns file system flags and labels; installers "
                                        "and drive pickers call it (a C3 sandbox check reads the same data)"),
    "wmi-query": ("C5", "weak", "COM initialization / CoCreateInstance is used by any COM or WMI client"),
}

# Signals that are only CONTEXT for a self-integrity check: reading ones own module path, memory map or memory is
# ordinary program behaviour. They become C4 candidates only when a hash / checksum partner signal is present in the
# same file (the integrity check needs something to compare); otherwise they are listed under `suppressed`.
CONTEXT_ONLY = frozenset({"module-path-query", "memory-map-query", "self-memory-read"})
HASH_PARTNERS = frozenset({"hash-api", "image-checksum", "crc32-table"})

# --------------------------------------------------------------------------------- own import signals
# dll!function, lower case; a trailing A/W is matched either way.
IMPORT_SIGNALS: tuple[Signal, ...] = (
    Signal("C1", "import", "key-entry-text", "weak", ("user32!getdlgitemtext", "user32!getwindowtext"),
           "reads text from a dialog / window control (where a licence key is often entered)",
           "every GUI program reads control text; only a decision on the text makes it a key check"),
    Signal("C2", "import", "process-debug-info", "moderate", ("ntdll!rtlqueryprocessdebuginformation",),
           "queries debug information of a process",
           "diagnostic tools use it; legitimate crash analysis"),
    Signal("C4", "import", "image-checksum", "moderate", ("imagehlp!mapfileandchecksum", "imagehlp!checksummappedfile"),
           "computes the PE image checksum (used to detect a modified file)",
           "build, signing and installer tools compute checksums for other reasons"),
    Signal("C4", "import", "hash-api", "weak",
           ("bcrypt!bcryptcreatehash", "bcrypt!bcrypthashdata", "bcrypt!bcryptfinishhash",
            "advapi32!cryptcreatehash", "advapi32!crypthashdata"),
           "hashing API (an integrity or key hash may be built on it)",
           "hashing is universal (storage, networking, caches); it is self-integrity only if the input is the "
           "program's own image"),
    Signal("C5", "import", "hardware-profile", "moderate", ("advapi32!getcurrenthwprofile",),
           "reads the hardware profile GUID", "rare outside machine binding and inventory code"),
    Signal("C5", "import", "computer-name", "weak", ("kernel32!getcomputernameex",),
           "reads the computer name (a machine binding input)",
           "telemetry, installers and UI code read the name"),
    Signal("C6", "import", "verify-trust", "strong", ("wintrust!winverifytrust",),
           "verifies a code signature / trust chain",
           "update, installer and plugin loaders verify signatures routinely; it is licence-related only if it "
           "guards a licence or entitlement file"),
    Signal("C6", "import", "verify-signature", "strong",
           ("bcrypt!bcryptverifysignature", "ncrypt!ncryptverifysignature", "advapi32!cryptverifysignature"),
           "verifies a digital signature with a public key",
           "TLS stacks and updaters verify signatures; check what is signed"),
    Signal("C6", "import", "certificate-chain", "moderate",
           ("crypt32!certgetcertificatechain", "crypt32!certverifycertificatechainpolicy",
            "crypt32!cryptqueryobject", "crypt32!certverifysignature"),
           "builds or validates a certificate chain",
           "TLS and update stacks do this for networking, not licensing"),
    Signal("C6", "import", "public-key-import", "weak", ("bcrypt!bcryptimportkeypair", "ncrypt!ncryptimportkey"),
           "imports a public key (the verify half of a signed licence)",
           "any crypto client imports keys"),
    Signal("C7", "import", "wall-clock", "weak",
           ("kernel32!getsystemtime", "kernel32!getlocaltime", "kernel32!getsystemtimepreciseasfiletime",
            "kernel32!getsystemtimeasfiletime"),
           "reads the wall-clock date and time (a trial / expiry check compares it with a stored date)",
           "logging, timestamps and random seeds read the clock; the C runtime startup imports "
           "GetSystemTimeAsFileTime (suppressed in a CRT startup cluster); a compare against a date is what makes "
           "it a trial check"),
    Signal("C7", "import", "crt-time", "weak",
           ("msvcrt!time", "msvcrt!_time64", "msvcrt!_time32", "msvcrt!localtime", "msvcrt!_localtime64",
            "api-ms-win-crt-time-l1-1-0!time", "api-ms-win-crt-time-l1-1-0!_time64",
            "api-ms-win-crt-time-l1-1-0!_localtime64", "api-ms-win-crt-time-l1-1-0!_localtime64_s",
            "api-ms-win-crt-time-l1-1-0!localtime"),
           "C runtime calendar time", "timestamps and srand(time(0)) seeds are common"),
    Signal("C8", "import", "http-client", "moderate",
           ("wininet!internetopen", "wininet!internetopenurl", "wininet!internetconnect", "wininet!httpopenrequest",
            "wininet!httpsendrequest", "winhttp!winhttpopen", "winhttp!winhttpconnect", "winhttp!winhttpopenrequest",
            "winhttp!winhttpsendrequest", "urlmon!urldownloadtofile"),
           "HTTP client API (an online activation or licence server call may use it)",
           "updaters, crash reporters and telemetry use the same APIs"),
    Signal("C8", "import", "socket-client", "weak",
           ("ws2_32!wsastartup", "ws2_32!connect", "ws2_32!getaddrinfo", "ws2_32!gethostbyname"),
           "raw socket client API", "any networked program imports Winsock"),
)

# ------------------------------------------------------------------------------------- string signals
# Needles are matched case-insensitively as ASCII and UTF-16LE anywhere in the file. A needle made of identifier
# characters must be a whole word (so "licensed" is not "license"); a needle with punctuation matches as written.
STRING_SIGNALS: tuple[Signal, ...] = (
    Signal("C1", "string", "licence-phrase", "moderate",
           ("license key", "licence key", "serial key", "product key", "activation code",
            "activation key", "registration code", "registration key", "unlock code", "invalid license",
            "invalid licence", "license invalid", "licence invalid", "license valid", "licence valid", "valid license",
            "valid licence", "license expired", "enter key", "enter serial", "enter license", "enter licence"),
           "text naming a licence / serial / activation key",
           "a UI string or help text proves a licence feature exists, not that this code validates anything"),
    Signal("C1", "string", "licence-word", "weak", ("license", "licence", "licensing", "keygen", "serial number"),
           "the word licence or serial number",
           "licence texts (GPL/MIT notices) and 'licensed to' banners contain it; 'serial number' also names "
           "volume and device serials"),
    Signal("C2", "string", "debugger-message", "moderate",
           ("debugger detected", "debugger found", "being debugged", "debugger present", "isdebuggerpresent",
            "checkremotedebuggerpresent", "ntqueryinformationprocess", "ntsetinformationthread",
            "zwqueryinformationprocess", "ntqueryinformationthread"),
           "a debugger-detection message or an API name resolved by string (GetProcAddress)",
           "documentation text and security tools' API lists contain these names; the import table's own name "
           "strings are excluded"),
    Signal("C3", "string", "vm-registry-path", "weak", ("disk\\enum", "scsi\\disk&ven_vmware", "vmware virtual",
                                                        "virtual hd", "vbox harddisk"),
           "registry / device path used to recognise virtual disks",
           "installers and security software read the same paths"),
    Signal("C5", "string", "hardware-query", "moderate",
           ("machineguid", "win32_baseboard", "win32_bios", "win32_processor", "win32_diskdrive",
            "win32_networkadapter", "win32_computersystemproduct", "win32_physicalmemory"),
           "WMI class / registry value that holds a hardware identity",
           "inventory, telemetry and installer code query the same classes"),
    Signal("C5", "string", "hardware-id-word", "weak", ("hwid", "hardware id", "hardware-id", "machine id",
                                                        "machine-id", "machine code"),
           "text naming a hardware / machine id", "UI or documentation text"),
    Signal("C6", "string", "pem-key", "moderate",
           ("-----begin public key-----", "-----begin rsa public key-----", "-----begin ec public key-----",
            "-----begin certificate-----"),
           "an embedded PEM public key or certificate (the verify half of a signed licence / update)",
           "TLS roots and updaters embed certificates; check what the key is used for"),
    Signal("C6", "string", "signature-message", "moderate",
           ("signature verification failed", "invalid signature", "bad signature", "signature mismatch",
            "signature check failed"),
           "text of a failed signature check", "crypto libraries carry the same messages"),
    Signal("C7", "string", "trial-word", "moderate",
           ("trial", "trial expired", "trial period", "trial version", "evaluation copy", "evaluation period",
            "days left", "days remaining", "license has expired", "licence has expired", "license expires",
            "licence expires", "license expired"),
           "text about a trial / evaluation period or an expiry",
           "UI text only; certificate or cookie expiry text uses 'expired' too"),
    Signal("C7", "string", "expiry-word", "weak", ("expired", "expiry", "expiration", "has expired", "expires on"),
           "the word expired / expiry", "certificate, cookie, session and password expiry code"),
    Signal("C8", "string", "activation-phrase", "moderate",
           ("activation server", "online activation", "activate online", "license server", "licence server",
            "/activate", "api/license", "api/activate", "license/verify", "licensing server"),
           "text or URL path of an activation / licence server",
           "documentation text; a server name alone does not show this binary talks to it"),
    Signal("C8", "string", "activate-word", "weak", ("activate", "activation"),
           "the word activate", "window activation, product activation UI and OS APIs use the word"),
)

# Hosts whose http(s) URLs are namespaces, schemas or certificate infrastructure, not an activation endpoint.
BENIGN_URL_HOSTS = (
    "schemas.microsoft.com", "schemas.openxmlformats.org", "www.w3.org", "ns.adobe.com", "purl.org",
    "www.microsoft.com", "go.microsoft.com", "aka.ms", "crl.microsoft.com", "www.verisign.com", "ocsp.verisign.com",
    "crl.verisign.com", "www.symauth.com", "ocsp.digicert.com", "crl3.digicert.com", "crl4.digicert.com",
    "www.digicert.com", "ocsp.sectigo.com", "crl.sectigo.com", "ocsp.comodoca.com", "crl.comodoca.com",
    "ocsp.globalsign.com", "crl.globalsign.com", "ts.verisign.com", "timestamp.digicert.com",
    "timestamp.verisign.com", "timestamp.comodoca.com", "xml.org", "docs.oasis-open.org", "relaxng.org",
    "manifests.microsoft.com", "www.example.com", "example.com", "localhost",
)
URL_SIGNAL = Signal("C8", "string", "url", "weak", ("http://", "https://"),
                    "an http(s) URL string",
                    "updaters, telemetry, help links and certificate endpoints are URLs too; only a URL that is "
                    "sent a licence or machine id is activation")

# --------------------------------------------------------------------------------- pattern signals
# Implemented in check_inventory.PATTERNS (byte patterns over executable sections, or over the whole file where the
# constant is data). The rows here carry the taxonomy facts.
PATTERN_SIGNALS: tuple[Signal, ...] = (
    Signal("C1", "pattern", "fnv-1a-prime", "weak", ("fnv-1a-prime",),
           "multiplication by the FNV prime 0x01000193 (a hash loop; FNV-1a hashes are common in key checks)",
           "FNV is a general hash for tables and checksums; it counts for licensing only when the result reaches "
           "a compare and a decision branch"),
    Signal("C2", "pattern", "peb-beingdebugged", "strong", ("peb-beingdebugged",),
           "reads the process environment block and then the byte at offset 2 (BeingDebugged)",
           "none known in compiled C/C++ runtime code; hand-written PEB walkers for other fields may be near"),
    Signal("C2", "pattern", "rdtsc-pair", "weak", ("rdtsc-pair",),
           "two RDTSC reads close together (elapsed-time anti-debug)",
           "benchmarks, seeds and profilers read the time stamp counter twice"),
    Signal("C3", "pattern", "cpuid-hypervisor", "moderate", ("cpuid-hypervisor",),
           "CPUID leaf 0x40000000, or leaf 1 followed by a test of the hypervisor bit",
           "feature-dispatch code reads CPUID leaf 1 for other bits; this pattern needs the hypervisor leaf / bit 31"),
    Signal("C4", "pattern", "crc32-table", "weak", ("crc32-table",),
           "the CRC-32 table (polynomial 0xEDB88320) is present",
           "zlib, PNG, ZIP and network code embed the same table; it is self-integrity only if it checks the "
           "program's own bytes"),
)


def all_codes() -> tuple[str, ...]:
    return tuple(CATEGORIES)
