"""Rule catalog R01-R14 and static evaluator (Section 5).

Each rule fires at most once per file and produces a RuleFinding linking the flag
to an exact file offset / RVA, observed evidence, plain explanation, and known
benign example.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Optional

from coalscan.core.banding import BandingConfig, DEFAULT_BANDING_CONFIG
from coalscan.core.limits import (
    ENTROPY_MIN_SECTION_BYTES,
    MIN_IMPORTS_NATIVE_PE,
)
from coalscan.core.models import (
    ImportInfo,
    PEInspectionResult,
    RouteDecision,
    RuleFinding,
    RuleSeverity,
)


@dataclass(frozen=True)
class RuleSpec:
    """Static metadata for a rule in the R01-R14 catalog."""

    rule_id: str
    title: str
    severity: RuleSeverity
    points: int
    group: Optional[str]  # "A", "B", or None
    explanation: str
    benign_example: str


RULE_CATALOG: Final[dict[str, RuleSpec]] = {
    "R01": RuleSpec(
        rule_id="R01",
        title="VirtualAlloc import",
        severity=RuleSeverity.MEDIUM,
        points=2,
        group="A",
        explanation="Allocates virtual memory pages directly, which can be used for dynamic code or buffers.",
        benign_example="JIT compilers, custom allocators, and standard C/C++ runtime startup.",
    ),
    "R02": RuleSpec(
        rule_id="R02",
        title="VirtualProtect import",
        severity=RuleSeverity.MEDIUM,
        points=2,
        group="A",
        explanation="Changes memory protection flags on allocated pages (for example, marking pages executable).",
        benign_example="JIT engines, debuggers, and standard runtime guard-page management.",
    ),
    "R03": RuleSpec(
        rule_id="R03",
        title="WriteProcessMemory import",
        severity=RuleSeverity.HIGH,
        points=4,
        group=None,
        explanation="Writes data into the virtual address space of another process.",
        benign_example="Debuggers, diagnostic profilers, and endpoint instrumentation tools.",
    ),
    "R04": RuleSpec(
        rule_id="R04",
        title="CreateRemoteThread import",
        severity=RuleSeverity.HIGH,
        points=4,
        group=None,
        explanation="Starts a thread of execution inside another process's address space.",
        benign_example="Administrative utilities, debuggers, and performance monitoring tools.",
    ),
    "R05": RuleSpec(
        rule_id="R05",
        title="LoadLibrary* and GetProcAddress both imported",
        severity=RuleSeverity.MEDIUM,
        points=2,
        group="A",
        explanation="Resolves DLLs and function pointers dynamically at runtime rather than solely via static imports.",
        benign_example="Plugin frameworks, delay-loaded DLLs, and many normal desktop applications.",
    ),
    "R06": RuleSpec(
        rule_id="R06",
        title="CreateProcess / ShellExecute import",
        severity=RuleSeverity.LOW,
        points=1,
        group="B",
        explanation="Launches an external program or shell command.",
        benign_example="Installers, application launchers, IDEs, and helper utilities.",
    ),
    "R07": RuleSpec(
        rule_id="R07",
        title="WinINet / WinHTTP imports",
        severity=RuleSeverity.LOW,
        points=1,
        group="B",
        explanation="Provides HTTP/HTTPS or internet client networking capability.",
        benign_example="Browsers, software updaters, cloud sync clients, and license checkers.",
    ),
    "R08": RuleSpec(
        rule_id="R08",
        title="Fewer than 5 imported functions in total (native PE only)",
        severity=RuleSeverity.LOW,
        points=1,
        group="B",
        explanation="Very small import tables can indicate packed binaries or manual dynamic API resolution.",
        benign_example="Statically linked Go/Rust programs, resource DLLs, or minimal system utilities.",
    ),
    "R09": RuleSpec(
        rule_id="R09",
        title="Section entropy at least 7.0 (section 1 KB or more)",
        severity=RuleSeverity.MEDIUM,
        points=2,
        group=None,
        explanation="High byte randomness suggests compressed, packed, or encrypted section content.",
        benign_example="Compressed icons, embedded media/archives, or installer payloads.",
    ),
    "R10": RuleSpec(
        rule_id="R10",
        title="Section both writable and executable",
        severity=RuleSeverity.HIGH,
        points=4,
        group=None,
        explanation="Memory in this section can be modified at runtime and then executed directly.",
        benign_example="JIT runtimes, legacy linkers, or self-modifying simulation code.",
    ),
    "R11": RuleSpec(
        rule_id="R11",
        title="Entry point outside an executable section",
        severity=RuleSeverity.MEDIUM,
        points=2,
        group=None,
        explanation="AddressOfEntryPoint does not lie inside a section marked IMAGE_SCN_MEM_EXECUTE.",
        benign_example="Custom packers, specialized protectors, or non-standard linker scripts.",
    ),
    "R12": RuleSpec(
        rule_id="R12",
        title="Overlay after mapped sections",
        severity=RuleSeverity.LOW,
        points=1,
        group="B",
        explanation="Trailing data is appended after the end of the last section mapped by the PE header.",
        benign_example="Self-extracting installers, setup archives, and bundled configuration data.",
    ),
    "R13": RuleSpec(
        rule_id="R13",
        title="TLS callback present",
        severity=RuleSeverity.LOW,
        points=1,
        group="B",
        explanation="Thread Local Storage (TLS) callbacks execute code before the main entry point runs.",
        benign_example="C/C++ thread-local variable initialization and security/runtime libraries.",
    ),
    "R14": RuleSpec(
        rule_id="R14",
        title="Signature data present or absent",
        severity=RuleSeverity.LOW,
        points=1,
        group="B",
        explanation="No Authenticode certificate table is present in the Security Data Directory (presence clue only).",
        benign_example="Unsigned independent utilities, student-compiled binaries, and open-source tools.",
    ),
}


def normalize_import_name(fn_name: str) -> str:
    """Normalize an imported function name for case-insensitive matching with A/W/Ex suffixes.

    Examples:
    - 'VirtualAllocEx' -> 'virtualallocex', base 'virtualalloc'
    - 'CreateProcessW' -> 'createprocessw', base 'createprocess'
    - 'LoadLibraryExA' -> 'loadlibraryexa', base 'loadlibrary'
    """
    low = fn_name.strip().lower()
    # Strip trailing A or W when preceded by an alphabetic name of length >= 4
    if len(low) > 4 and low[-1] in ("a", "w"):
        stem = low[:-1]
        if stem.endswith("ex") and len(stem) > 4:
            return stem[:-2]
        return stem
    if len(low) > 4 and low.endswith("ex"):
        return low[:-2]
    return low


def _format_loc(file_offset: Optional[int], rva: Optional[int], detail: str = "") -> str:
    parts: list[str] = []
    if file_offset is not None:
        parts.append(f"Offset 0x{file_offset:X}")
    if rva is not None and rva > 0:
        parts.append(f"RVA 0x{rva:X}")
    base = " / ".join(parts) if parts else "PE Header"
    if detail:
        return f"{base} ({detail})"
    return base


def _make_finding(
    rule_id: str,
    observed: str,
    file_offset: Optional[int],
    rva: Optional[int],
    detail: str = "",
) -> RuleFinding:
    spec = RULE_CATALOG[rule_id]
    return RuleFinding(
        rule_id=spec.rule_id,
        title=spec.title,
        severity=spec.severity,
        points=spec.points,
        group=spec.group,
        observed=observed,
        file_offset=file_offset,
        rva=rva,
        location_label=_format_loc(file_offset, rva, detail),
        explanation=spec.explanation,
        benign_example=spec.benign_example,
    )


def evaluate_rules(
    inspection: PEInspectionResult,
    route: RouteDecision,
    config: BandingConfig = DEFAULT_BANDING_CONFIG,
) -> list[RuleFinding]:
    """Evaluate applicable rules from R01-R14 on an inspected PE file.

    - If neither `route.run_full_rules` nor `route.run_structural_rules_only` is True,
      returns an empty list (e.g. unsupported architecture, not a PE, malformed).
    - If `route.run_structural_rules_only` is True (.NET or confirmed NATIVE driver),
      evaluates only structural rules R09-R14 (suppressing R01-R08).
    - If `route.skip_r11` is True (e.g. DLL with AddressOfEntryPoint == 0), skips R11.
    """
    if not route.run_full_rules and not route.run_structural_rules_only:
        return []

    findings: list[RuleFinding] = []

    # ------------------------------------------------------------------
    # Import-based rules R01-R08 (only when run_full_rules is True)
    # ------------------------------------------------------------------
    if route.run_full_rules:
        r01_match: Optional[ImportInfo] = None
        r02_match: Optional[ImportInfo] = None
        r03_match: Optional[ImportInfo] = None
        r04_match: Optional[ImportInfo] = None
        loadlib_match: Optional[ImportInfo] = None
        getproc_match: Optional[ImportInfo] = None
        r06_match: Optional[ImportInfo] = None
        r07_match: Optional[ImportInfo] = None

        wininet_apis = {
            "internetopen",
            "internetconnect",
            "httpopenrequest",
            "httpsendrequest",
            "internetreadfile",
            "internetopenurl",
            "winhttpopen",
            "winhttpconnect",
            "winhttpopenrequest",
            "winhttpsendrequest",
            "winhttpreceiveresponse",
            "urldownloadtofile",
        }

        for imp in inspection.imports:
            fn_low = imp.function_name.lower()
            fn_norm = normalize_import_name(imp.function_name)
            dll_low = imp.dll_name.lower()

            if r01_match is None and (
                fn_norm == "virtualalloc" or fn_low.startswith("virtualalloc")
            ):
                r01_match = imp

            if r02_match is None and (
                fn_norm == "virtualprotect" or fn_low.startswith("virtualprotect")
            ):
                r02_match = imp

            if r03_match is None and fn_norm == "writeprocessmemory":
                r03_match = imp

            if r04_match is None and (
                fn_norm == "createremotethread" or fn_low.startswith("createremotethread")
            ):
                r04_match = imp

            if loadlib_match is None and (
                fn_norm == "loadlibrary" or fn_low.startswith("loadlibrary")
            ):
                loadlib_match = imp

            if getproc_match is None and fn_low == "getprocaddress":
                getproc_match = imp

            if r06_match is None and (
                fn_norm in ("createprocess", "shellexecute")
                or fn_low.startswith("createprocess")
                or fn_low.startswith("shellexecute")
            ):
                r06_match = imp

            if r07_match is None and (
                "wininet" in dll_low
                or "winhttp" in dll_low
                or fn_norm in wininet_apis
            ):
                r07_match = imp

        if r01_match is not None:
            findings.append(
                _make_finding(
                    "R01",
                    observed=f"Imported {r01_match.dll_name}!{r01_match.function_name}",
                    file_offset=r01_match.file_offset,
                    rva=r01_match.iat_rva,
                    detail="IAT entry",
                )
            )

        if r02_match is not None:
            findings.append(
                _make_finding(
                    "R02",
                    observed=f"Imported {r02_match.dll_name}!{r02_match.function_name}",
                    file_offset=r02_match.file_offset,
                    rva=r02_match.iat_rva,
                    detail="IAT entry",
                )
            )

        if r03_match is not None:
            findings.append(
                _make_finding(
                    "R03",
                    observed=f"Imported {r03_match.dll_name}!{r03_match.function_name}",
                    file_offset=r03_match.file_offset,
                    rva=r03_match.iat_rva,
                    detail="IAT entry",
                )
            )

        if r04_match is not None:
            findings.append(
                _make_finding(
                    "R04",
                    observed=f"Imported {r04_match.dll_name}!{r04_match.function_name}",
                    file_offset=r04_match.file_offset,
                    rva=r04_match.iat_rva,
                    detail="IAT entry",
                )
            )

        if loadlib_match is not None and getproc_match is not None:
            findings.append(
                _make_finding(
                    "R05",
                    observed=(
                        f"Both {loadlib_match.function_name} and {getproc_match.function_name} "
                        f"are imported ({loadlib_match.dll_name})"
                    ),
                    file_offset=loadlib_match.file_offset or getproc_match.file_offset,
                    rva=loadlib_match.iat_rva or getproc_match.iat_rva,
                    detail="IAT entry",
                )
            )

        if r06_match is not None:
            findings.append(
                _make_finding(
                    "R06",
                    observed=f"Imported {r06_match.dll_name}!{r06_match.function_name}",
                    file_offset=r06_match.file_offset,
                    rva=r06_match.iat_rva,
                    detail="IAT entry",
                )
            )

        if r07_match is not None:
            findings.append(
                _make_finding(
                    "R07",
                    observed=f"Imported {r07_match.dll_name}!{r07_match.function_name}",
                    file_offset=r07_match.file_offset,
                    rva=r07_match.iat_rva,
                    detail="IAT entry",
                )
            )

        if not route.suppress_r08 and inspection.total_import_count < MIN_IMPORTS_NATIVE_PE:
            findings.append(
                _make_finding(
                    "R08",
                    observed=(
                        f"Total imported functions = {inspection.total_import_count} "
                        f"(threshold is {MIN_IMPORTS_NATIVE_PE} for native PE)"
                    ),
                    file_offset=None,
                    rva=None,
                    detail="Import Directory",
                )
            )

    # ------------------------------------------------------------------
    # Structural rules R09-R14 (run for both full and structural-only routes)
    # ------------------------------------------------------------------
    # R09: Section entropy >= 7.0 for section >= 1 KB (1024 bytes)
    for sec in inspection.sections:
        if sec.raw_size >= ENTROPY_MIN_SECTION_BYTES and sec.entropy >= config.entropy_threshold:
            findings.append(
                _make_finding(
                    "R09",
                    observed=(
                        f"Section '{sec.name}' ({sec.raw_size} bytes) has entropy "
                        f"{sec.entropy:.2f} bits/byte (>= {config.entropy_threshold:.1f})"
                    ),
                    file_offset=sec.raw_offset,
                    rva=sec.virtual_address,
                    detail=f"{sec.name} start",
                )
            )
            break

    # R10: Section both writable and executable
    for sec in inspection.sections:
        if sec.is_writable and sec.is_executable:
            flag_names = []
            if sec.is_readable:
                flag_names.append("read")
            if sec.is_writable:
                flag_names.append("write")
            if sec.is_executable:
                flag_names.append("execute")
            findings.append(
                _make_finding(
                    "R10",
                    observed=f"Section '{sec.name}' flags = {' + '.join(flag_names)}",
                    file_offset=sec.raw_offset,
                    rva=sec.virtual_address,
                    detail=f"{sec.name} start",
                )
            )
            break

    # R11: Entry point outside an executable section (skipped when route.skip_r11 is True)
    if not route.skip_r11 and inspection.entry_point_rva != 0:
        if not inspection.entry_point_in_exec_section:
            sec_desc = (
                f"section '{inspection.entry_point_section_name}' (non-executable)"
                if inspection.entry_point_section_name
                else "unmapped or header region outside executable sections"
            )
            findings.append(
                _make_finding(
                    "R11",
                    observed=(
                        f"AddressOfEntryPoint (RVA 0x{inspection.entry_point_rva:X}) "
                        f"points to {sec_desc}"
                    ),
                    file_offset=inspection.entry_point_offset,
                    rva=inspection.entry_point_rva,
                    detail="Entry point",
                )
            )

    # R12: Overlay after mapped sections
    if inspection.has_overlay and inspection.overlay_size > 0:
        findings.append(
            _make_finding(
                "R12",
                observed=(
                    f"Overlay of {inspection.overlay_size} bytes appended at "
                    f"file offset 0x{(inspection.overlay_offset or 0):X}"
                ),
                file_offset=inspection.overlay_offset,
                rva=None,
                detail="Overlay start",
            )
        )

    # R13: TLS callback present
    if inspection.has_tls_callbacks:
        findings.append(
            _make_finding(
                "R13",
                observed=(
                    f"TLS callback registered at RVA 0x{(inspection.tls_callback_rva or 0):X}"
                ),
                file_offset=inspection.tls_callback_offset,
                rva=inspection.tls_callback_rva,
                detail="TLS callback",
            )
        )

    # R14: Signature/certificate data presence check (fires when absent)
    if not inspection.has_signature:
        findings.append(
            _make_finding(
                "R14",
                observed="Security Data Directory (certificate table) is absent (0 bytes)",
                file_offset=None,
                rva=None,
                detail="Security Directory",
            )
        )

    return findings
