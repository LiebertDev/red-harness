"""Genel anti-analiz / anti-cheat yetenek taraması (statik, motordan bağımsız).

Amaç: korumalı bir PE'de (paketçi, lisans koruması, Ring3 anti-cheat, sürücü arayüzü) hangi
anti-analiz TEKNİKLERİNİN kullanılabileceğini gösteren kanıt-konumlu bir yetenek haritası çıkarmak.
Tek bir ürüne/crackme'ye özel değildir: kurallar aile + teknik + API/işaret tablosudur ve yeni
gözlemler tabloya satır eklemekle kazanılır, kod dallanmaz.

Neden API importları: paketlenmemiş korumalı yazılımlarda anti-debug/anti-VM/anti-dump kararları
neredeyse her zaman belirli Win32/NT API'lerinden geçer. İçe aktarma tablosu bunu dosyada gösterir.

Kurallar (fail-closed, kanıt-öncelikli):
- Yalnız statik okuma: hiçbir şey yürütülmez, ağ kullanılmaz, hedef değiştirilmez.
- Import tablosu kesilirse sonuç PARTIAL olur ve `unknowns` nedenini söyler; "sembol yok" ile
  "ölçemedim" ASLA karıştırılmaz. Import dizini hiç yoksa API tabanlı tespit "girdisiz"dir; bu,
  anti-analiz kodu olmadığının kanıtı değildir (not olarak yazılır).
- Bir API'nin veya dizgenin varlığı KANIT DEĞİL, İPUCUDUR: kod o API'yi hiç çağırmayabilir,
  dizge bir kütüphaneden/overlay'den/rastgele bayttan gelebilir. Güç alanı bunu ayırır
  (`weak` < `moderate` < `strong`) ve hiçbir bulgu tek başına davranış iddiasını PROVEN yapamaz.
- Dinamik çözümleme (GetProcAddress/LoadLibrary) varsa statik import görünümü yetenekleri
  gizleyebilir: bu bir kapsam boşluğudur, not olarak taşınır.
- Bulgular deterministiktir: (aile, teknik, kaynak, DLL, fonksiyon, ofset) sırasına göre.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from .pe_dirs import ImportProfile, scan_imports_image
from .pe_image import PeError, PeImage, parse_pe

STRENGTH_ORDER = {"weak": 0, "moderate": 1, "strong": 2}
FAMILIES = ("anti-debug", "timing", "anti-dump", "vm-detection", "injection", "input-monitoring",
            "fingerprint", "kernel-interface", "kernel-internals", "instrumentation", "protection-vendor",
            "protection")
MAX_MARKER_OFFSETS = 4       # raporda gösterilen ilk konumlar (tümü `offsets` alanında sınırlı)
MAX_MARKER_COUNT = 256       # sayım üst sınırı ("256+" olarak raporlanır)


@dataclass(frozen=True)
class ApiTechnique:
    """Bir anti-analiz tekniğinin API parmak izi. `apis` kanonik "dll!fonksiyon" (küçük harf)."""
    technique: str
    family: str
    strength: str
    apis: tuple[str, ...]
    why: str


@dataclass(frozen=True)
class MarkerTechnique:
    """Dosya içinde aranan ASCII/UTF-16LE dizge işareti (araç, VM, ürün ya da çekirdek yolu)."""
    technique: str
    family: str
    strength: str
    needle: str
    why: str


# ---------------------------------------------------------------------------------------- katalog
# API tablosu: her satır bir tekniktir; aynı API birden çok teknikte görünebilir (ör. OpenProcess
# hem enjeksiyon hem sürücü/süreç arayüzü için ipucudur). Yeni ürün geldiğinde kod değil TABLO büyür.

API_TECHNIQUES: tuple[ApiTechnique, ...] = (
    # -- anti-debug -------------------------------------------------------------------------
    ApiTechnique("debugger-present", "anti-debug", "strong",
                 ("kernel32!isdebuggerpresent", "kernel32!checkremotedebuggerpresent"),
                 "direct debugger presence check"),
    ApiTechnique("ntqueryinformationprocess", "anti-debug", "moderate",
                 ("ntdll!ntqueryinformationprocess",),
                 "process debug port/flags/object-handle queries"),
    ApiTechnique("debug-object-query", "anti-debug", "moderate",
                 ("ntdll!ntqueryobject", "ntdll!ntqueryinformationthread"),
                 "debug-object / thread information probing"),
    ApiTechnique("hide-thread-from-debugger", "anti-debug", "strong",
                 ("ntdll!ntsetinformationthread", "ntdll!ntsetinformationprocess"),
                 "hide-from-debugger thread/process information"),
    ApiTechnique("kernel-debugger-query", "anti-debug", "moderate",
                 ("ntdll!ntquerysysteminformation",),
                 "system/kernel debugger state queries"),
    ApiTechnique("output-debug-string", "anti-debug", "weak",
                 ("kernel32!outputdebugstringa", "kernel32!outputdebugstringw"),
                 "debugger capture via OutputDebugString"),
    ApiTechnique("debug-break", "anti-debug", "moderate",
                 ("kernel32!debugbreak", "ntdll!dbgbreakpoint", "ntdll!dbguserbreakpoint"),
                 "int3/breakpoint based debugger detection"),
    ApiTechnique("exception-filter", "anti-debug", "weak",
                 ("kernel32!setunhandledexceptionfilter", "kernel32!addvectoredexceptionhandler",
                  "kernel32!unhandledexceptionfilter"),
                 "exception-based control flow / debugger hiding"),
    ApiTechnique("thread-context", "anti-debug", "strong",
                 ("kernel32!getthreadcontext", "kernel32!setthreadcontext",
                  "ntdll!ntgetcontextthread", "ntdll!ntsetcontextthread"),
                 "hardware-breakpoint (Dr0-Dr7) inspection through thread context"),
    ApiTechnique("window-class-scan", "anti-debug", "weak",
                 ("user32!findwindowa", "user32!findwindoww", "user32!findwindowexa",
                  "user32!findwindowexw", "user32!enumwindows", "user32!getforegroundwindow"),
                 "debugger window/class enumeration"),
    ApiTechnique("input-block", "anti-debug", "weak",
                 ("user32!blockinput",), "input blocking during analysis"),
    ApiTechnique("debug-attach", "anti-debug", "moderate",
                 ("kernel32!debugactiveprocess", "kernel32!debugactiveprocessstop",
                  "kernel32!waitfordebugevent"),
                 "self-debugging / debugger API use"),
    ApiTechnique("process-enumeration", "anti-debug", "moderate",
                 ("kernel32!createtoolhelp32snapshot", "kernel32!process32firstw", "kernel32!process32nextw",
                  "kernel32!module32firstw", "kernel32!module32nextw", "kernel32!enumprocesses",
                  "kernel32!enumprocessmodules", "kernel32!enumprocessmodulesex",
                  "psapi!enumprocesses", "psapi!enumprocessmodules", "psapi!enumprocessmodulesex"),
                 "process/module enumeration (debugger/tool/cheat detection)"),
    ApiTechnique("wow64-context", "anti-debug", "moderate",
                 ("kernel32!wow64getthreadcontext", "kernel32!wow64setthreadcontext",
                  "ntdll!ntwow64readvirtualmemory", "ntdll!ntwow64writevirtualmemory"),
                 "WOW64 context/memory access (32-bit process inspection)"),

    # -- timing -----------------------------------------------------------------------------
    ApiTechnique("timing-query", "timing", "moderate",
                 ("kernel32!queryperformancecounter", "kernel32!gettickcount", "kernel32!gettickcount64",
                  "winmm!timegettime", "ntdll!ntqueryperformancecounter", "ntdll!ntquerysystemtime",
                  "kernel32!getsystemtimeasfiletime"),
                 "elapsed-time checks (single-step / breakpoint detection)"),

    # -- anti-dump / self-inspection --------------------------------------------------------
    ApiTechnique("memory-map-query", "anti-dump", "moderate",
                 ("kernel32!virtualquery", "kernel32!virtualqueryex", "ntdll!ntqueryvirtualmemory"),
                 "own address-space inspection (dump/hook detection)"),
    ApiTechnique("module-path-query", "anti-dump", "weak",
                 ("kernel32!getmodulefilenamea", "kernel32!getmodulefilenamew", "kernel32!getmodulehandlea",
                  "kernel32!getmodulehandlew", "kernel32!getmodulehandleexa", "kernel32!getmodulehandleexw"),
                 "module base/path checks (image integrity)"),
    ApiTechnique("executable-memory-write", "anti-dump", "moderate",
                 ("kernel32!virtualprotect", "kernel32!virtualprotectex", "ntdll!ntprotectvirtualmemory",
                  "kernel32!flushinstructioncache"),
                 "memory protection changes / self-modifying code"),
    ApiTechnique("self-memory-read", "anti-dump", "weak",
                 ("kernel32!readprocessmemory", "ntdll!ntreadvirtualmemory"),
                 "reading own/foreign memory (integrity checks, dumping)"),
    ApiTechnique("exception-flow", "anti-dump", "weak",
                 ("kernel32!raiseexception", "ntdll!rtlraiseexception"),
                 "exception-driven control flow"),

    # -- VM / sandbox detection -------------------------------------------------------------
    ApiTechnique("firmware-table", "vm-detection", "strong",
                 ("kernel32!getsystemfirmwaretable", "kernel32!enumsystemfirmwaretables"),
                 "SMBIOS/firmware table inspection (hypervisor discovery)"),
    ApiTechnique("registry-query", "vm-detection", "weak",
                 ("advapi32!regopenkeyexa", "advapi32!regopenkeyexw", "advapi32!regqueryvalueexa",
                  "advapi32!regqueryvalueexw", "advapi32!reggetvaluea", "advapi32!reggetvaluew"),
                 "registry-based environment/VM checks"),
    ApiTechnique("device-enumeration", "vm-detection", "moderate",
                 ("setupapi!setupdigetdeviceregistrypropertya", "setupapi!setupdigetdeviceregistrypropertyw",
                  "setupapi!setupdienumdeviceinfo", "setupapi!setupdigetclassdevsa", "setupapi!setupdigetclassdevsw"),
                 "device/driver enumeration (VM artifacts, anti-cheat device discovery)"),
    ApiTechnique("mac-address", "vm-detection", "weak",
                 ("iphlpapi!getadaptersinfo", "iphlpapi!getadaptersaddresses"),
                 "network adapter fingerprinting"),
    ApiTechnique("volume-serial", "vm-detection", "weak",
                 ("kernel32!getvolumeinformationa", "kernel32!getvolumeinformationw"),
                 "volume serial / filesystem fingerprinting"),

    # -- injection / dynamic code -----------------------------------------------------------
    ApiTechnique("remote-thread", "injection", "strong",
                 ("kernel32!createremotethread", "kernel32!createremotethreadex", "ntdll!ntcreatethreadex",
                  "kernel32!queueuserapc", "ntdll!ntqueueapcthread"),
                 "remote/APC thread execution"),
    ApiTechnique("remote-write", "injection", "strong",
                 ("kernel32!writeprocessmemory", "ntdll!ntwritevirtualmemory"),
                 "writing into another process"),
    ApiTechnique("section-mapping", "injection", "weak",
                 ("kernel32!mapviewoffile", "kernel32!createfilemappinga", "kernel32!createfilemappingw",
                  "ntdll!ntmapviewofsection", "ntdll!ntcreatesection"),
                 "file/section mapping (manual mapping, unpacking)"),
    ApiTechnique("dynamic-resolve", "injection", "weak",
                 ("kernel32!getprocaddress", "ntdll!ldrgetprocedureaddress"),
                 "runtime API resolution (hides imports from static analysis)"),
    ApiTechnique("module-load", "injection", "weak",
                 ("kernel32!loadlibrarya", "kernel32!loadlibraryw", "kernel32!loadlibraryexa",
                  "kernel32!loadlibraryexw", "ntdll!ldrloaddll"),
                 "runtime module loading"),
    ApiTechnique("process-hollowing", "injection", "strong",
                 ("ntdll!ntunmapviewofsection", "ntdll!zwunmapviewofsection"),
                 "section unmapping (process hollowing / image replacement)"),
    ApiTechnique("thread-control", "injection", "moderate",
                 ("kernel32!suspendthread", "kernel32!resumethread", "ntdll!ntsuspendprocess",
                  "ntdll!ntresumeprocess", "ntdll!ntsuspendthread"),
                 "thread/process suspension (freeze windows, anti-debug)"),
    ApiTechnique("process-open", "injection", "moderate",
                 ("kernel32!openprocess", "ntdll!ntopenprocess"),
                 "opening process handles (scanning/injection/anti-cheat)"),
    ApiTechnique("handle-duplication", "injection", "weak",
                 ("kernel32!duplicatehandle", "ntdll!ntduplicateobject"),
                 "handle duplication/inheritance tricks"),

    # -- input monitoring / anti-cheat ------------------------------------------------------
    ApiTechnique("input-monitoring", "input-monitoring", "moderate",
                 ("user32!getasynckeystate", "user32!getkeystate", "user32!getkeyboardstate",
                  "user32!setwindowshookexa", "user32!setwindowshookexw", "user32!registerrawinputdevices",
                  "user32!getrawinputdata", "user32!getrawinputbuffer"),
                 "keyboard/raw-input monitoring (anti-cheat input checks)"),

    # -- fingerprint / licensing ------------------------------------------------------------
    ApiTechnique("machine-identity", "fingerprint", "weak",
                 ("kernel32!getcomputernamea", "kernel32!getcomputernamew", "kernel32!getusernamea",
                  "kernel32!getusernamew", "advapi32!getusernamea", "advapi32!getusernamew"),
                 "machine/user identity collection (HWID, licensing)"),
    ApiTechnique("system-fingerprint", "fingerprint", "weak",
                 ("kernel32!getsysteminfo", "kernel32!getnativesysteminfo", "kernel32!globalmemorystatusex",
                  "kernel32!isprocessorfeaturepresent"),
                 "hardware/system fingerprint"),
    ApiTechnique("wmi-query", "fingerprint", "moderate",
                 ("ole32!cocreateinstance", "ole32!cogetclassobject", "ole32!coinitializeex",
                  "ole32!coinitializesecurity"),
                 "WMI/COM based hardware or environment queries"),
    ApiTechnique("disk-identity", "fingerprint", "weak",
                 ("kernel32!getdiskfreespaceexa", "kernel32!getdiskfreespaceexw", "kernel32!getdrivetypea",
                  "kernel32!getdrivetypew", "kernel32!getlogicaldrivestringsa", "kernel32!getlogicaldrivestringsw"),
                 "disk/drive enumeration"),

    # -- kernel interface / anti-cheat ------------------------------------------------------
    ApiTechnique("driver-ioctl", "kernel-interface", "strong",
                 ("kernel32!deviceiocontrol", "ntdll!ntdeviceiocontrolfile", "ntdll!zwdeviceiocontrolfile"),
                 "user-mode <-> kernel driver IOCTL channel"),
    ApiTechnique("service-control", "kernel-interface", "moderate",
                 ("advapi32!openscmanagera", "advapi32!openscmanagerw", "advapi32!openservicea",
                  "advapi32!openservicew", "advapi32!createservicea", "advapi32!createservicew",
                  "advapi32!startservicea", "advapi32!startservicew", "advapi32!controlservice"),
                 "service manager use (driver/service install or control)"),
    ApiTechnique("driver-load", "kernel-interface", "strong",
                 ("ntdll!ntloaddriver", "ntdll!zwloaddriver"),
                 "kernel driver loading"),
    ApiTechnique("thread-handle", "kernel-interface", "weak",
                 ("kernel32!openthread", "ntdll!ntopenthread"),
                 "opening thread handles"),
    ApiTechnique("named-pipe", "kernel-interface", "weak",
                 ("kernel32!createnamedpipea", "kernel32!createnamedpipew", "kernel32!connectnamedpipe",
                  "kernel32!callnamedpipea", "kernel32!callnamedpipew"),
                 "named-pipe IPC (driver/service/user-mode agent channel)"),
    ApiTechnique("registry-write", "kernel-interface", "weak",
                 ("advapi32!regsetvalueexa", "advapi32!regsetvalueexw", "advapi32!regcreatekeyexa",
                  "advapi32!regcreatekeyexw"),
                 "registry persistence/configuration"),

    # -- kernel internals (anti-cheat drivers: vgk.sys, BEDaisy.sys, ...) --------------------
    ApiTechnique("process-notify", "kernel-internals", "strong",
                 ("ntoskrnl!pssetcreateprocessnotifyroutine", "ntoskrnl!pssetcreateprocessnotifyroutineex"),
                 "process creation notification callback (anti-cheat process policing)"),
    ApiTechnique("thread-notify", "kernel-internals", "strong",
                 ("ntoskrnl!pssetcreatethreadnotifyroutine", "ntoskrnl!pssetcreatethreadnotifyroutineex"),
                 "thread creation notification callback"),
    ApiTechnique("image-notify", "kernel-internals", "strong",
                 ("ntoskrnl!pssetloadimagenotifyroutine", "ntoskrnl!pssetloadimagenotifyroutineex"),
                 "image load notification callback (manual-map / unsigned module detection)"),
    ApiTechnique("object-callback", "kernel-internals", "strong",
                 ("ntoskrnl!obregistercallbacks", "ntoskrnl!obunregistercallbacks"),
                 "object (process/thread handle) callback registration (handle stripping)"),
    ApiTechnique("registry-callback", "kernel-internals", "moderate",
                 ("ntoskrnl!cmregistercallback", "ntoskrnl!cmregistercallbackex",
                  "ntoskrnl!cmunregistercallback"),
                 "registry callback (protected key/configuration monitoring)"),
    ApiTechnique("minifilter", "kernel-internals", "strong",
                 ("fltmgr!fltregisterfilter", "fltmgr!fltstartfiltering", "fltmgr!fltunregisterfilter"),
                 "file-system minifilter (file/load enforcement)"),
    ApiTechnique("kernel-process-memory", "kernel-internals", "strong",
                 ("ntoskrnl!mmcopyvirtualmemory",
                  "ntoskrnl!kestackattachprocess", "ntoskrnl!pslookupprocessbyprocessid",
                  "ntoskrnl!psgetprocessimagefilename", "ntoskrnl!zwopenprocess"),
                 "read/write/attach to another process from kernel (scanner/integrity checks)"),
    ApiTechnique("dpc-timer", "kernel-internals", "weak",
                 ("ntoskrnl!keinitializetimer", "ntoskrnl!kesettimerex", "ntoskrnl!keinitializedpc",
                  "ntoskrnl!keinsertqueuedpc"),
                 "timer/DPC usage (periodic scans, watchdog)"),
    ApiTechnique("kernel-etw", "kernel-internals", "weak",
                 ("ntoskrnl!etwregister", "ntoskrnl!etwwrite", "ntoskrnl!etwunregister"),
                 "ETW provider/callback (telemetry, detection events)"),
    ApiTechnique("kernel-device-interface", "kernel-internals", "moderate",
                 ("ntoskrnl!iocreatedevice", "ntoskrnl!iocreatesymboliclink"),
                 "device/symbolic-link creation (user-mode IOCTL channel)"),
    ApiTechnique("kernel-dynamic-resolve", "kernel-internals", "moderate",
                 ("ntoskrnl!mmgetsystemroutineaddress",),
                 "runtime resolution of unimported kernel APIs (hides capabilities)"),
)

MARKER_TECHNIQUES: tuple[MarkerTechnique, ...] = (
    # -- araç/dump/debugger izleri ----------------------------------------------------------
    MarkerTechnique("debugger-tool", "instrumentation", "moderate", "ollydbg",
                    "OllyDbg debugger reference"),
    MarkerTechnique("debugger-tool", "instrumentation", "moderate", "x64dbg", "x64dbg debugger reference"),
    MarkerTechnique("debugger-tool", "instrumentation", "moderate", "x32dbg", "x32dbg debugger reference"),
    MarkerTechnique("debugger-tool", "instrumentation", "moderate", "windbg", "WinDbg reference"),
    MarkerTechnique("debugger-tool", "instrumentation", "moderate", "immunity debugger",
                    "Immunity Debugger reference"),
    MarkerTechnique("debugger-tool", "instrumentation", "moderate", "idaq", "IDA reference"),
    MarkerTechnique("debugger-tool", "instrumentation", "moderate", "scylla", "Scylla import rebuilder reference"),
    MarkerTechnique("debugger-tool", "instrumentation", "moderate", "cheat engine",
                    "Cheat Engine reference"),
    MarkerTechnique("debugger-tool", "instrumentation", "moderate", "process hacker",
                    "Process Hacker reference"),
    MarkerTechnique("debugger-tool", "instrumentation", "moderate", "api monitor", "API Monitor reference"),
    MarkerTechnique("dump-tool", "instrumentation", "strong", "pe-sieve", "PE-sieve dumper reference"),
    MarkerTechnique("dump-tool", "instrumentation", "strong", "hollows_hunter",
                    "hollows_hunter dumper reference"),
    MarkerTechnique("debugger-capture", "instrumentation", "moderate", "dbwin_buffer",
                    "OutputDebugString capture window"),
    MarkerTechnique("instrumentation-framework", "instrumentation", "strong", "frida",
                    "Frida instrumentation reference"),
    # -- sanal makine / kum havuzu ----------------------------------------------------------
    MarkerTechnique("vm-artifact", "vm-detection", "moderate", "vmware", "VMware artifact"),
    MarkerTechnique("vm-artifact", "vm-detection", "moderate", "virtualbox", "VirtualBox artifact"),
    MarkerTechnique("vm-artifact", "vm-detection", "moderate", "vboxservice", "VirtualBox guest service"),
    MarkerTechnique("vm-artifact", "vm-detection", "moderate", "vmtoolsd", "VMware Tools service"),
    MarkerTechnique("vm-artifact", "vm-detection", "weak", "vmhgfs", "VMware shared-folder driver"),
    MarkerTechnique("vm-artifact", "vm-detection", "weak", "vmmouse", "VMware mouse driver"),
    MarkerTechnique("vm-artifact", "vm-detection", "weak", "vmci", "VMware VMCI device"),
    MarkerTechnique("vm-artifact", "vm-detection", "moderate", "qemu", "QEMU artifact"),
    MarkerTechnique("vm-artifact", "vm-detection", "moderate", "xenstore", "Xen artifact"),
    MarkerTechnique("vm-artifact", "vm-detection", "moderate", "hyper-v", "Hyper-V artifact"),
    MarkerTechnique("sandbox-artifact", "vm-detection", "moderate", "sandboxie", "Sandboxie artifact"),
    MarkerTechnique("sandbox-artifact", "vm-detection", "moderate", "sbiedll", "Sandboxie hook DLL"),
    MarkerTechnique("sandbox-artifact", "vm-detection", "moderate", "cuckoomon", "Cuckoo sandbox monitor"),
    MarkerTechnique("emulator-artifact", "vm-detection", "moderate", "wine_get_unix_file_name",
                    "Wine emulator API"),
    # -- koruma/anti-cheat ürün izleri (bağlam; tek başına kanıt değil) ----------------------
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "nprotect", "nProtect product marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "gameguard", "GameGuard product marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "gamemon", "GameMon module marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "winlicense", "WinLicense marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "themida", "Themida marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "winlice", "WinLicense section marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "easyanticheat",
                    "EasyAntiCheat marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "easyanticheat.sys",
                    "EasyAntiCheat kernel driver"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "battleye", "BattlEye marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "beservice", "BattlEye service marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "vanguard", "Riot Vanguard marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "vgk.sys", "Vanguard kernel driver"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "denuvo", "Denuvo marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "denuvo64", "Denuvo64 marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "xigncode", "XignCode marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "mhyprot", "mhyprot anti-cheat marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "ace-game", "ACE anti-cheat marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "tenprotect", "TenProtect marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "hackshield", "HackShield marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "npgg", "nProtect NPGG module"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "npkc", "nProtect NPKC module"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "npggnt", "nProtect NPGGNT module"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "npkcrypt", "nProtect NPKCrypt driver"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "dump_wmimmc", "nProtect dump driver"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "inca.dll", "nProtect INCA module"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "easy anti-cheat", "EasyAntiCheat name"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "eossdk", "EasyAntiCheat EOS SDK"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "bedaisy", "BattlEye kernel driver"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "vgc.sys", "Vanguard vgc driver"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "riot vanguard", "Riot Vanguard name"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "wellbia", "XignCode vendor"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "xhunter", "XignCode kernel driver"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "ace-base", "ACE base module"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "tenpatch", "TenProtect patch module"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "tp3helper", "TenProtect helper"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "ehsvc", "AhnLab HackShield service"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "ahnlab", "AhnLab vendor"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "oreans", "Oreans (WinLicense/Themida)"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "vmprotect", "VMProtect marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "weak", "enigma", "Enigma protector name"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "safedisc", "SafeDisc marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "securom", "SecuROM marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "starforce", "StarForce marker"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "punkbuster", "PunkBuster name"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "pnkbstr", "PunkBuster module"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "pbsvc", "PunkBuster service"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "faceit", "FACEIT name"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "faceitac", "FACEIT AC module"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "faceitac.sys", "FACEIT AC driver"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "faceitclient", "FACEIT client"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "eseaclient", "ESEA client"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "eseaac", "ESEA anti-cheat"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "esea anti-cheat", "ESEA name"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "ricochet", "Ricochet name"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "ricochet.sys", "Ricochet driver"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "wardenclient", "Warden client"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "blizzard warden", "Warden name"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "neac.sys", "NEAC driver"),
    MarkerTechnique("vendor-marker", "protection-vendor", "moderate", "netease anti-cheat", "NEAC name"),
    # -- çekirdek/sürücü arayüzü ------------------------------------------------------------
    MarkerTechnique("device-path", "kernel-interface", "moderate", "\\device\\",
                    "NT device path (driver communication)"),
    MarkerTechnique("device-path", "kernel-interface", "moderate", "\\dosdevices\\",
                    "DOS device path (driver communication)"),
    MarkerTechnique("device-path", "kernel-interface", "moderate", "\\\\.\\",
                    "Win32 device namespace path (IOCTL target)"),
    MarkerTechnique("device-path", "kernel-interface", "moderate", "\\??\\",
                    "NT object-manager path"),
    MarkerTechnique("kernel-callback", "kernel-interface", "strong", "obregistercallbacks",
                    "kernel object callback registration"),
    MarkerTechnique("kernel-callback", "kernel-interface", "strong", "psprotectedprocess",
                    "protected-process (anti-cheat) marker"),
    # -- donanım/kimlik sorguları -----------------------------------------------------------
    MarkerTechnique("wmi-hwid", "fingerprint", "moderate", "win32_computersystemproduct",
                    "WMI system-product query"),
    MarkerTechnique("wmi-hwid", "fingerprint", "moderate", "win32_baseboard", "WMI baseboard query"),
    MarkerTechnique("wmi-hwid", "fingerprint", "moderate", "win32_diskdrive", "WMI disk query"),
    MarkerTechnique("wmi-hwid", "fingerprint", "moderate", "win32_networkadapter", "WMI network query"),
    MarkerTechnique("wmi-hwid", "fingerprint", "moderate", "win32_processor", "WMI processor query"),
    MarkerTechnique("firmware-string", "fingerprint", "weak", "systembiosversion", "BIOS version query"),
    MarkerTechnique("firmware-string", "fingerprint", "weak", "videobiosversion", "video BIOS version query"),
    MarkerTechnique("vm-registry-key", "vm-detection", "moderate", "software\\vmware", "VMware registry key"),
    MarkerTechnique("vm-registry-key", "vm-detection", "moderate", "software\\virtualbox",
                    "VirtualBox registry key"),
)

# API anahtarı -> onu kullanan teknikler (import başına tek sözlük araması).
_API_INDEX: dict[str, tuple[ApiTechnique, ...]] = {}
for _t in API_TECHNIQUES:
    for _api in _t.apis:
        _API_INDEX[_api] = _API_INDEX.get(_api, ()) + (_t,)


# ----------------------------------------------------------------------------------------- model

@dataclass(frozen=True)
class Hit:
    """Tek bir kanıt konumu: içe aktarılan sembol, dizge işareti ya da TLS callback.
    `source`: import | delay-import | string | tls. `file_offset`/`rva`/`iat_rva` yalnız gerçekten
    bilinen konumlarda doludur. `needle` yalnız dizge işaretlerinde eşleşen ham iğnedir."""
    family: str
    technique: str
    strength: str
    source: str
    detail: str
    needle: str | None = None
    dll: str | None = None
    function: str | None = None
    iat_rva: int | None = None
    rva: int | None = None
    file_offset: int | None = None
    occurrences: int = 1
    offsets: tuple[int, ...] = ()


@dataclass(frozen=True)
class FamilySummary:
    """Aile bazında özet: kaç bulgu, kaç ayrı teknik, en güçlü sinyal."""
    family: str
    hits: int
    techniques: tuple[str, ...]
    strongest: str


@dataclass(frozen=True)
class CapabilityCoverage:
    """Neyin ölçüldüğü/ölçülemediği. `imports_complete=False` ise API tabanlı tespit EKSİK."""
    imports_complete: bool
    import_table_declared: bool
    dlls: int
    imported_functions: int
    delay_imports: int
    tls_callbacks: int
    dynamic_resolution: bool
    api_set_imports: bool
    unknowns: tuple[str, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class AntiAnalysisProfile:
    """Bir PE'nin deterministik statik anti-analiz yetenek profili."""
    sha256: str
    file_size: int
    arch: str
    image_base: int
    sections: tuple[str, ...]
    layout: str                      # memory | file | mixed | unknown
    hits: tuple[Hit, ...]
    families: tuple[FamilySummary, ...]
    coverage: CapabilityCoverage
    notes: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return self.coverage.imports_complete


# -------------------------------------------------------------------------------------- eşleştirme

_DLL_ALIASES = {"kernelbase": "kernel32"}


def _dll_key(name: str) -> str:
    """Import DLL adını kural anahtarına indirger: yol yok, küçük harf, '.dll' son eki yok.
    `kernelbase`, `kernel32`'nin çoğu API'sini ihraç eder; aynı kurallarla eşlenir."""
    n = name.strip().lower().replace("\\", "/").rsplit("/", 1)[-1]
    for suffix in (".dll", ".exe", ".sys"):
        if n.endswith(suffix):
            n = n[:-len(suffix)]
            break
    return _DLL_ALIASES.get(n, n)


def _function_keys(name: str) -> tuple[str, ...]:
    """Fonksiyon adı + varsa A/W son eki atılmış biçimi (kernel32!CreateFileA -> createfile)."""
    n = name.strip().lower()
    keys = [n]
    if len(n) > 1 and n[-1] in "aw":
        keys.append(n[:-1])
    return tuple(keys)


def _api_hits(table: ImportProfile) -> list[Hit]:
    out: list[Hit] = []
    for fact in table.all_tables:
        source = "delay-import" if fact.delay else "import"
        for fn in fact.functions:
            if fn.name is None:
                continue
            dll_key = _dll_key(fact.dll)
            keys = [f"{dll_key}!{k}" for k in _function_keys(fn.name)]
            seen: set[str] = set()
            for key in keys:
                for tech in _API_INDEX.get(key, ()):
                    if tech.technique in seen:
                        continue
                    seen.add(tech.technique)
                    out.append(Hit(
                        family=tech.family, technique=tech.technique, strength=tech.strength,
                        source=source,
                        detail=f"{fact.dll}!{fn.name} is imported ({source}); {tech.why}",
                        dll=fact.dll, function=fn.name, iat_rva=fn.thunk_rva, rva=fn.name_rva,
                        file_offset=fn.file_offset))
    return out


def _ident_unit(value: int) -> bool:
    """ASCII tanımlayıcı karakteri mi ([A-Za-z0-9_])? Sözcük sınırı denetimi için."""
    return (48 <= value <= 57) or (65 <= value <= 90) or (97 <= value <= 122) or value == 95


def _bounded(low: bytes, idx: int, encoding: str, length: int) -> bool:
    """Tanımlayıcı benzeri iğneler bir sözcüğün ORTASINDA başlayamaz VE bitemez: 'CredUnprotectA'
    içindeki 'nprotect', 'SubscribeService...' içindeki 'beservice' ve 'DpmStreamOpenToUnprotect'
    içindeki 'nprotect' ürün işareti SAYILMAZ; aynı şekilde 'securomx_helper' içindeki 'securom'
    da sayılmaz (iğne daha uzun bir tanımlayıcının ön eki). Sınır, tamponun ucu ya da
    [A-Za-z0-9_] OLMAYAN bir karakterdir; bu yüzden 'securom.dll', 'SecuROM ' ve 'vgk.sys'
    eşleşmeye devam eder ('.' ve boşluk sınır sayılır). Yol/nokta içeren iğnelerde
    (ör. '\\\\device\\\\') ham eşleşme yeterlidir (`identifier=False`, bu denetim uygulanmaz)."""
    if encoding == "ascii":
        before = low[idx - 1] if idx > 0 else 0
        after = low[idx + length] if idx + length < len(low) else 0
        return not _ident_unit(before) and not _ident_unit(after)
    def unit(pos: int) -> int:
        if pos < 0 or pos + 1 >= len(low):
            return 0
        return low[pos] | (low[pos + 1] << 8)
    return not _ident_unit(unit(idx - 2)) and not _ident_unit(unit(idx + length))


def _marker_hits(data: bytes, low: bytes) -> list[Hit]:
    """İşaretleri ASCII ve UTF-16LE olarak arar; her kural için en çok bir bulgu üretir.
    Sayım `MAX_MARKER_COUNT` ile sınırlıdır (fazlası '256+' diye raporlanır)."""
    out: list[Hit] = []
    for rule in MARKER_TECHNIQUES:
        patterns = ((rule.needle.encode("ascii").lower(), "ascii"),
                    (rule.needle.encode("utf-16-le").lower(), "utf-16le"))
        identifier = all(ch.isalnum() or ch == "_" for ch in rule.needle)
        offsets: list[int] = []
        encodings: list[str] = []
        total = 0
        for needle, enc in patterns:
            start = 0
            found = 0
            while total < MAX_MARKER_COUNT:
                idx = low.find(needle, start)
                if idx < 0:
                    break
                if identifier and not _bounded(low, idx, enc, len(needle)):
                    start = idx + max(1, len(needle))
                    continue
                total += 1
                found += 1
                if len(offsets) < MAX_MARKER_OFFSETS:
                    offsets.append(idx)
                start = idx + max(1, len(needle))
            if found:
                encodings.append(enc)
        if not total:
            continue
        count = f"{total}+" if total >= MAX_MARKER_COUNT else str(total)
        out.append(Hit(
            family=rule.family, technique=rule.technique, strength=rule.strength, source="string",
            detail=f"string {rule.needle!r} occurs {count} time(s) ({', '.join(encodings)}); {rule.why}",
            needle=rule.needle, file_offset=offsets[0], occurrences=total, offsets=tuple(sorted(offsets))))
    return out


def _tls_hits(table: ImportProfile) -> list[Hit]:
    out: list[Hit] = []
    for cb in table.tls_callbacks:
        out.append(Hit(
            family="protection", technique="tls-callback", strength="strong", source="tls",
            detail=(f"TLS callback #{cb.index} at VA 0x{cb.va:x} runs before the entry point "
                    f"(pre-main code, common in packers and anti-debug)"),
            rva=cb.rva, file_offset=cb.file_offset))
    return out


def _sort_key(h: Hit) -> tuple:
    return (h.family, h.technique, h.source, h.dll or "", h.function or "",
            h.file_offset if h.file_offset is not None else -1,
            h.iat_rva if h.iat_rva is not None else -1)


def _layout_of_sections(img: PeImage) -> str:
    """Bölüm ham işaretçisi RVA'ya eşitse bellek-yerleşimi (dump), değilse dosya düzeni."""
    mem = file_ = 0
    for s in img.sections:
        if not s.raw_size or not (s.vsize or s.raw_size):
            continue
        if s.raw_ptr == s.rva:
            mem += 1
        else:
            file_ += 1
    if mem and not file_:
        return "memory"
    if file_ and not mem:
        return "file"
    if mem and file_:
        return "mixed"
    return "unknown"


def _summaries(hits: tuple[Hit, ...]) -> tuple[FamilySummary, ...]:
    by_family: dict[str, list[Hit]] = {}
    for h in hits:
        by_family.setdefault(h.family, []).append(h)
    out = []
    for family in FAMILIES:
        group = by_family.get(family)
        if not group:
            continue
        strongest = max((h.strength for h in group), key=lambda s: STRENGTH_ORDER.get(s, -1))
        out.append(FamilySummary(family, len(group),
                                 tuple(sorted({h.technique for h in group})), strongest))
    return tuple(out)


# --------------------------------------------------------------------------------------- tarama

def scan_antianalysis(data: bytes) -> AntiAnalysisProfile:
    """Bir PE dosyasının statik anti-analiz yetenek profilini çıkarır.

    - Import/delay-import/TLS tabloları `pe_dirs` ile okunur; tablo kesilirse sonuç `complete=False`
      ve `coverage.unknowns` doludur (kısmi sonuç OK sayılmaz).
    - Dizge işaretleri dosyanın TAMAMINDA (başlıklar + bölümler + overlay) ASCII ve UTF-16LE aranır;
      eşleşme rastlantısal olabilir, `notes` bunu söyler.
    - PE değilse `PeError`, bildirilen dizin okunamıyorsa `PeDirectoryError` yükselir.
    """
    img = parse_pe(lambda off, n: data[off:off + n], len(data))
    read = lambda off, n: data[off:off + n]
    table = scan_imports_image(img, read)
    hits = _api_hits(table) + _marker_hits(data, data.lower()) + _tls_hits(table)
    hits.sort(key=_sort_key)

    imported = [fn for fact in table.all_tables for fn in fact.functions if fn.name]
    names = {f"{_dll_key(fn.dll)}!{k}" for fn in imported for k in _function_keys(fn.name)}
    dynamic = bool(names & {"kernel32!getprocaddress", "ntdll!ldrgetprocedureaddress"})
    api_sets = any(_dll_key(fact.dll).startswith(("api-ms-win-", "ext-ms-win-")) for fact in table.all_tables)

    notes = ["static only: an imported API or a string marker shows a technique is AVAILABLE in the "
             "binary, not that it runs; runtime confirmation needs controlled runs or dynamic observation",
             "string markers are byte matches anywhere in the file (headers, overlay, compressed data): "
             "a match can be a coincidence and is never proof"]
    if not table.complete:
        notes.append("import tables were cut short: API-based detection is INCOMPLETE (see unknowns); "
                     "missing entries mean 'not measured', not 'absent'")
    if dynamic:
        notes.append("runtime API resolution (GetProcAddress/LoadLibrary) is imported: capabilities can be "
                     "resolved at run time and stay invisible to the static import table")
    if api_sets:
        notes.append("API-set forwarder DLLs are imported: some capabilities may be forwarded and missed")
    if not imported and table.complete:
        notes.append("no named imports were read: API-based capability detection has NO INPUT here "
                     "(packed, stubbed or statically linked?); this is NOT evidence that no anti-analysis "
                     "code exists")
    if table.delay_imports:
        notes.append("delay-load imports are resolved on first use: their presence does not mean the DLLs "
                     "are loaded at process start")
    if table.tls_callbacks:
        notes.append("TLS callbacks execute before the entry point; they are a strong indicator of "
                     "pre-main protection/anti-debug logic")

    coverage = CapabilityCoverage(
        imports_complete=table.complete,
        import_table_declared=bool(table.imports or table.delay_imports),
        dlls=len(table.all_tables),
        imported_functions=table.function_count,
        delay_imports=len(table.delay_imports),
        tls_callbacks=len(table.tls_callbacks),
        dynamic_resolution=dynamic,
        api_set_imports=api_sets,
        unknowns=table.unknowns,
        notes=table.notes,
    )
    return AntiAnalysisProfile(hashlib.sha256(data).hexdigest(), img.file_size, img.arch, img.image_base,
                               tuple(s.name for s in img.sections), _layout_of_sections(img),
                               tuple(hits), _summaries(tuple(hits)), coverage, tuple(notes))


def scan_antianalysis_file(path: str | Path) -> AntiAnalysisProfile:
    """Kolaylık: dosyayı okur ve `scan_antianalysis` çağırır (okuma hatası `PeError`)."""
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise PeError(f"dosya okunamadı: {p}") from exc
    return scan_antianalysis(data)


# ------------------------------------------------------------------------------------- metin

def render_profile(p: AntiAnalysisProfile) -> str:
    """Kanıt metni (modele/rapora giden deterministik döküm). Konumlar hex'tir."""
    cov = p.coverage
    lines = [
        f"sha256 {p.sha256}",
        f"file_size {p.file_size} bytes arch {p.arch} image_base 0x{p.image_base:x} layout {p.layout}",
        f"sections ({len(p.sections)}): {','.join(s or '-' for s in p.sections)}",
        f"status {'OK' if p.complete else 'PARTIAL'} imports_complete {cov.imports_complete}",
        f"imports: dlls {cov.dlls} functions {cov.imported_functions} delay_tables {cov.delay_imports} "
        f"tls_callbacks {cov.tls_callbacks} dynamic_resolution {cov.dynamic_resolution} "
        f"api_sets {cov.api_set_imports}",
        f"families ({len(p.families)}):",
    ]
    for f in p.families:
        lines.append(f"  {f.family} hits={f.hits} strongest={f.strongest} "
                     f"techniques={','.join(f.techniques)}")
    lines.append(f"hits ({len(p.hits)}):")
    for h in p.hits:
        where = []
        if h.dll:
            where.append(f"dll {h.dll}")
        if h.function:
            where.append(f"function {h.function}")
        if h.iat_rva is not None:
            where.append(f"iat_rva 0x{h.iat_rva:x}")
        if h.rva is not None:
            where.append(f"rva 0x{h.rva:x}")
        if h.file_offset is not None:
            where.append(f"file_offset 0x{h.file_offset:x}")
        if h.occurrences > 1:
            where.append(f"occurrences {h.occurrences}")
        if h.offsets:
            where.append("offsets " + ",".join(f"0x{o:x}" for o in h.offsets))
        lines.append(f"  [{h.family}] {h.technique} strength={h.strength} source={h.source} "
                     f"{' '.join(where)} :: {h.detail}")
    lines.append(f"unknowns ({len(cov.unknowns)}):")
    for u in cov.unknowns:
        lines.append(f"  {u}")
    lines.append("notes:")
    for n in p.notes:
        lines.append(f"  {n}")
    return "\n".join(lines) + "\n"
