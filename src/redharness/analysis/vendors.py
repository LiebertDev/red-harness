"""Protection product attribution (vendor attribution): links markers to known anti-cheat/protection families.

Purpose: turn the question "what is this?" on a protected target into an **evidence-backed candidate list**. The input is the
`antianalysis.scan_antianalysis` profile (string markers + section names); the output is attribution candidates
carrying the matched indicators, a score and a confidence.

Kurallar:
- An attribution is a **hypothesis**, not proof that the product runs: a string marker can also appear
  in another product's detection list, and a section name can be imitated. So a single marker never goes
  above "moderate"; "strong" needs at least two independent indicator groups and a score >= 6.
- The markers come from the `antianalysis.MARKER_TECHNIQUES` table; this module does no new scanning.
- Candidates are sorted deterministically: (-score, vendor id).
"""

from __future__ import annotations

from dataclasses import dataclass

from .antianalysis import AntiAnalysisProfile


@dataclass(frozen=True)
class VendorIndicator:
    """An indicator of a product. `kind`: string | section. `group`: independence group
    (name variants of the same product count as one group)."""
    kind: str
    value: str
    weight: int          # 1 weak, 2 medium, 3 strong
    group: str
    why: str


@dataclass(frozen=True)
class VendorRule:
    id: str
    name: str
    kind: str            # anti-cheat | protector | drm
    indicators: tuple[VendorIndicator, ...]
    min_score: int = 3
    note: str = ""


@dataclass(frozen=True)
class VendorMatch:
    kind: str
    value: str
    weight: int
    group: str
    why: str
    file_offset: int | None = None
    occurrences: int = 1


@dataclass(frozen=True)
class VendorAttribution:
    vendor_id: str
    name: str
    kind: str
    score: int
    confidence: str      # moderate | strong
    groups: tuple[str, ...]
    matches: tuple[VendorMatch, ...]
    note: str


def _i(kind: str, value: str, weight: int, group: str, why: str) -> VendorIndicator:
    return VendorIndicator(kind, value.lower(), weight, group, why)


# Catalog: new product = new row. Values must equal the needles in the `antianalysis` marker table
# (a consistency test checks this); section names come from the section table.
VENDOR_RULES: tuple[VendorRule, ...] = (
    VendorRule("nprotect-gameguard", "nProtect GameGuard", "anti-cheat", (
        _i("string", "gameguard", 3, "name", "GameGuard product name"),
        _i("string", "gamemon", 3, "module", "GameMon module"),
        _i("string", "nprotect", 2, "name", "nProtect name"),
        _i("string", "npgg", 3, "module", "NPGG module"),
        _i("string", "npkc", 2, "module", "NPKC module"),
        _i("string", "npggnt", 3, "driver", "NPGGNT driver/module"),
        _i("string", "npkcrypt", 3, "driver", "NPKCrypt driver"),
        _i("string", "dump_wmimmc", 2, "driver", "dump driver"),
        _i("string", "inca.dll", 2, "module", "INCA module"),
    ), note="user-mode GameGuard client and/or its kernel components"),
    VendorRule("winlicense-themida", "WinLicense / Themida (Oreans)", "protector", (
        _i("string", "winlicense", 3, "name", "WinLicense name"),
        _i("string", "winlice", 3, "name", "WinLicense section/name marker"),
        _i("string", "themida", 3, "themida", "Themida name"),
        _i("string", "oreans", 2, "vendor", "Oreans vendor name"),
        _i("section", ".winlice", 3, "section", "WinLicense section"),
        _i("section", ".themida", 3, "section", "Themida section"),
        _i("section", ".tmd", 3, "section", "Themida section"),
    ), note="packer/license protector; unpack and license checks are separate steps"),
    VendorRule("vmprotect", "VMProtect", "protector", (
        _i("string", "vmprotect", 3, "name", "VMProtect name"),
        _i("section", ".vmp0", 3, "section", "VMProtect section"),
        _i("section", ".vmp1", 3, "section", "VMProtect section"),
    )),
    VendorRule("easyanticheat", "EasyAntiCheat", "anti-cheat", (
        _i("string", "easyanticheat", 3, "name", "EasyAntiCheat name"),
        _i("string", "easy anti-cheat", 3, "name", "EasyAntiCheat name (spaced)"),
        _i("string", "easyanticheat.sys", 3, "driver", "EasyAntiCheat kernel driver"),
        _i("string", "eossdk", 2, "sdk", "EOS SDK"),
    ), note="user-mode client; kernel driver (EasyAntiCheat.sys) may be separate"),
    VendorRule("battleye", "BattlEye", "anti-cheat", (
        _i("string", "battleye", 3, "name", "BattlEye name"),
        _i("string", "beservice", 3, "service", "BEService"),
        _i("string", "bedaisy", 3, "driver", "BEDaisy kernel driver"),
    )),
    VendorRule("vanguard", "Riot Vanguard", "anti-cheat", (
        _i("string", "vanguard", 2, "name", "Vanguard name"),
        _i("string", "riot vanguard", 3, "name", "Riot Vanguard name"),
        _i("string", "vgk.sys", 3, "driver", "VGK kernel driver"),
        _i("string", "vgc.sys", 3, "service", "VGC service/driver"),
    ), note="kernel-mode anti-cheat; dynamic work needs an isolated VM (W10)"),
    VendorRule("xigncode", "XignCode3 (Wellbia)", "anti-cheat", (
        _i("string", "xigncode", 3, "name", "XignCode name"),
        _i("string", "wellbia", 3, "vendor", "Wellbia vendor"),
        _i("string", "xhunter", 2, "driver", "XignCode kernel driver"),
    )),
    VendorRule("mhyprot", "miHoYo mhyprot", "anti-cheat", (
        _i("string", "mhyprot", 3, "driver", "mhyprot kernel driver"),
    )),
    VendorRule("ace-tencent", "ACE / TenProtect (Tencent)", "anti-cheat", (
        _i("string", "ace-game", 3, "name", "ACE game module"),
        _i("string", "ace-base", 3, "driver", "ACE base module/driver"),
        _i("string", "tenprotect", 3, "name", "TenProtect name"),
        _i("string", "tenpatch", 3, "driver", "TenProtect patch module/driver"),
        _i("string", "tp3helper", 2, "helper", "TenProtect helper"),
    )),
    VendorRule("hackshield", "AhnLab HackShield", "anti-cheat", (
        _i("string", "hackshield", 3, "name", "HackShield name"),
        _i("string", "ahnlab", 2, "vendor", "AhnLab vendor"),
        _i("string", "ehsvc", 3, "driver", "HackShield service/driver"),
    )),
    VendorRule("denuvo", "Denuvo", "drm", (
        _i("string", "denuvo", 3, "name", "Denuvo name"),
        _i("string", "denuvo64", 3, "name", "Denuvo64 marker"),
    ), min_score=4, note="DRM; license/activation analysis is separate from anti-debug"),
    # These three DRM rules carry a single weight-3 name marker, so they use the default threshold 3 (as other
    # single-strong-marker rules such as mhyprot do); a min_score above the only marker's weight would make the rule
    # unreachable. The "at least one weight>=2 marker" gate and the fact that a single marker cannot reach "strong"
    # bound the false positives.
    VendorRule("safedisc", "SafeDisc", "drm", (
        _i("string", "safedisc", 3, "name", "SafeDisc name"),
    ), min_score=3),
    VendorRule("securom", "SecuROM", "drm", (
        _i("string", "securom", 3, "name", "SecuROM name"),
    ), min_score=3),
    VendorRule("starforce", "StarForce", "drm", (
        _i("string", "starforce", 3, "name", "StarForce name"),
    ), min_score=3),
    VendorRule("enigma", "Enigma Protector", "protector", (
        _i("string", "enigma", 2, "name", "Enigma name"),
        _i("section", ".enigma1", 3, "section", "Enigma section"),
        _i("section", ".enigma2", 3, "section", "Enigma section"),
    )),
    VendorRule("punkbuster", "PunkBuster (Even Balance)", "anti-cheat", (
        _i("string", "punkbuster", 3, "name", "PunkBuster name"),
        _i("string", "pnkbstr", 3, "module", "PunkBuster module"),
        _i("string", "pbsvc", 3, "service", "PunkBuster service"),
    )),
    VendorRule("faceit", "FACEIT Anti-Cheat", "anti-cheat", (
        _i("string", "faceit", 3, "name", "FACEIT name"),
        _i("string", "faceitac", 3, "name", "FACEIT AC module"),
        _i("string", "faceitac.sys", 3, "driver", "FACEIT AC driver"),
        _i("string", "faceitclient", 2, "client", "FACEIT client"),
    )),
    VendorRule("esea", "ESEA Anti-Cheat", "anti-cheat", (
        _i("string", "eseaclient", 3, "name", "ESEA client"),
        _i("string", "eseaac", 3, "name", "ESEA anti-cheat module"),
        _i("string", "esea anti-cheat", 3, "name", "ESEA name"),
    )),
    VendorRule("ricochet", "Ricochet (Activision)", "anti-cheat", (
        _i("string", "ricochet", 3, "name", "Ricochet name"),
        _i("string", "ricochet.sys", 3, "driver", "Ricochet kernel driver"),
    )),
    VendorRule("warden", "Warden (Blizzard)", "anti-cheat", (
        _i("string", "wardenclient", 3, "name", "Warden client"),
        _i("string", "blizzard warden", 3, "name", "Warden name"),
    )),
    VendorRule("neac", "NEAC (NetEase)", "anti-cheat", (
        _i("string", "neac.sys", 3, "driver", "NEAC kernel driver"),
        _i("string", "netease anti-cheat", 3, "name", "NEAC name"),
    )),
)


def attribute_vendors(anti: AntiAnalysisProfile, rules: tuple[VendorRule, ...] = VENDOR_RULES
                      ) -> tuple[VendorAttribution, ...]:
    """Links the markers/sections of the profile to the product rules. Candidates below the threshold are not returned."""
    strings = {h.needle.lower(): h for h in anti.hits if h.source == "string" and h.needle}
    sections = {s.strip().lower() for s in anti.sections if s.strip()}
    out: list[VendorAttribution] = []
    for rule in rules:
        matches: list[VendorMatch] = []
        seen: set[str] = set()
        for ind in rule.indicators:
            if ind.value in seen:
                continue
            if ind.kind == "string" and ind.value in strings:
                hit = strings[ind.value]
                matches.append(VendorMatch("string", ind.value, ind.weight, ind.group, ind.why,
                                           hit.file_offset, hit.occurrences))
                seen.add(ind.value)
            elif ind.kind == "section" and ind.value in sections:
                matches.append(VendorMatch("section", ind.value, ind.weight, ind.group, ind.why))
                seen.add(ind.value)
        score = sum(m.weight for m in matches)
        groups = tuple(sorted({m.group for m in matches}))
        if score < rule.min_score or not any(m.weight >= 2 for m in matches):
            continue
        confidence = "strong" if score >= 6 and len(groups) >= 2 else "moderate"
        out.append(VendorAttribution(rule.id, rule.name, rule.kind, score, confidence, groups,
                                     tuple(matches), rule.note))
    return tuple(sorted(out, key=lambda v: (-v.score, v.vendor_id)))


def render_vendors(vendors: tuple[VendorAttribution, ...]) -> str:
    """Evidence text: attribution candidates and matched indicators (deterministic)."""
    lines = [f"vendors ({len(vendors)}):"]
    for v in vendors:
        lines.append(f"  {v.vendor_id} [{v.kind}] confidence={v.confidence} score={v.score} "
                     f"groups={','.join(v.groups)}")
        for m in v.matches:
            where = f" file_offset 0x{m.file_offset:x}" if m.file_offset is not None else ""
            times = f" occurrences={m.occurrences}" if m.occurrences > 1 else ""
            lines.append(f"    {m.kind}:{m.value} weight={m.weight}{where}{times} :: {m.why}")
        if v.note:
            lines.append(f"    note: {v.note}")
    lines.append("  attribution is heuristic: a marker may be another product's detection list or a "
                 "leftover; it is not proof that the product is active")
    return "\n".join(lines) + "\n"
