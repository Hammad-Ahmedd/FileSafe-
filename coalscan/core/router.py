"""Content-based file type router and status classifier (Section 2).

Never routes by extension alone once candidate extensions (.exe, .dll, .sys, .ocx)
pass the initial filter. Every file ends with one exact FileStatus and reason.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from coalscan.core.limits import (
    CANDIDATE_EXTENSIONS,
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_I386,
    MAX_FILE_SIZE_BYTES,
    SUPPORTED_X86_MACHINES,
)
from coalscan.core.models import FileStatus, PEInspectionResult, RouteDecision


def is_candidate_extension(file_name: str) -> bool:
    """Return True if file_name has one of the candidate extensions (.exe, .dll, .sys, .ocx)."""
    ext = Path(file_name).suffix.lower()
    return ext in CANDIDATE_EXTENSIONS


def route_file(
    file_name: str,
    file_size: int,
    inspection: Optional[PEInspectionResult] = None,
    check_extension: bool = True,
) -> RouteDecision:
    """Determine the triage route and status for a file from its size and content inspection.

    Order of evaluation:
    1. Candidate extension filter (.exe, .dll, .sys, .ocx) -> 'skipped (extension or limit)'
    2. File size limit (50 MB) -> 'too large' (not parsed, not hashed)
    3. Parser sanity / corruption -> 'malformed'
    4. MZ / PE signature check -> 'not a PE file'
    5. CPU machine field (must be 0x014C or 0x8664) -> 'unsupported architecture'
    6. Managed .NET (CLR directory index 14 non-empty) -> 'analyzed (managed .NET, limited)'
    7. Native driver (Subsystem NATIVE) -> 'analyzed (driver, limited)'
    8. Unconfirmed .sys extension (non-NATIVE subsystem) -> 'driver candidate'
    9. Native PE32/PE32+ executable or DLL -> 'analyzed'
    """
    ext = Path(file_name).suffix.lower()

    if check_extension and ext not in CANDIDATE_EXTENSIONS:
        ext_display = ext if ext else "<no extension>"
        return RouteDecision(
            status=FileStatus.SKIPPED,
            reason=f"Skipped non-candidate extension '{ext_display}' (allowed: .exe, .dll, .sys, .ocx)",
            file_kind="Skipped file",
        )

    if file_size > MAX_FILE_SIZE_BYTES:
        return RouteDecision(
            status=FileStatus.TOO_LARGE,
            reason=f"File size ({file_size} bytes) exceeds 50 MB limit ({MAX_FILE_SIZE_BYTES} bytes)",
            file_kind="Too large",
        )

    if inspection is None:
        return RouteDecision(
            status=FileStatus.FAILED,
            reason="Internal error: missing PE inspection result",
            file_kind="Failed",
        )

    if inspection.is_malformed:
        return RouteDecision(
            status=FileStatus.MALFORMED,
            reason=inspection.malformed_reason or "Malformed PE structure",
            file_kind="Malformed PE",
        )

    if not inspection.is_pe:
        return RouteDecision(
            status=FileStatus.NOT_A_PE,
            reason=inspection.not_pe_reason or "No MZ or valid PE signature",
            file_kind="Not a PE file",
        )

    # Machine check (only 0x014C x86 and 0x8664 x64 are supported for rules/disassembly)
    if inspection.machine not in SUPPORTED_X86_MACHINES:
        return RouteDecision(
            status=FileStatus.UNSUPPORTED_ARCH,
            reason=(
                f"Machine field 0x{inspection.machine:04X} ({inspection.architecture}) "
                "is not x86 (0x014C) or x64 (0x8664); hash and header metadata only"
            ),
            file_kind="ARM, ARM64 or other CPU",
            run_full_rules=False,
            run_structural_rules_only=False,
            run_disassembly=False,
        )

    arch_bits = 64 if inspection.machine == IMAGE_FILE_MACHINE_AMD64 else 32
    no_entry_point = inspection.entry_point_rva == 0
    dll_skip_r11 = inspection.is_dll and no_entry_point
    dll_skip_r11_reason = (
        "DLL has no entry point (AddressOfEntryPoint is 0); R11 is skipped"
        if dll_skip_r11
        else (
            "No entry point (AddressOfEntryPoint is 0); R11 is skipped"
            if no_entry_point
            else None
        )
    )

    # Managed .NET check (COM descriptor data directory index 14 is non-empty)
    if inspection.has_clr_header:
        return RouteDecision(
            status=FileStatus.ANALYZED_DOTNET_LIMITED,
            reason=(
                "COM descriptor (CLR) data directory 14 is non-empty; "
                "hash, metadata and structural rules R09-R14 only (R08 suppressed, no x86 disassembly)"
            ),
            file_kind="Managed .NET",
            run_full_rules=False,
            run_structural_rules_only=True,
            suppress_r08=True,
            skip_r11=no_entry_point,
            skip_r11_reason=dll_skip_r11_reason,
            run_disassembly=False,
            capstone_arch_bits=None,
        )

    # Native driver check (Subsystem NATIVE in optional header)
    if inspection.is_native_subsystem:
        return RouteDecision(
            status=FileStatus.ANALYZED_DRIVER_LIMITED,
            reason=(
                "Subsystem NATIVE confirmed in optional header; "
                "hash, metadata and structural rules R09-R14 only"
            ),
            file_kind="Native driver",
            run_full_rules=False,
            run_structural_rules_only=True,
            suppress_r08=True,
            skip_r11=no_entry_point,
            skip_r11_reason=dll_skip_r11_reason,
            run_disassembly=False,
            capstone_arch_bits=None,
        )

    # Unconfirmed .sys file: has .sys extension but Subsystem != NATIVE
    if ext == ".sys":
        return RouteDecision(
            status=FileStatus.DRIVER_CANDIDATE,
            reason=(
                "File has .sys extension without NATIVE subsystem; "
                "analyzed as ordinary PE and labeled 'driver candidate'"
            ),
            file_kind=f"Driver candidate ({inspection.pe_format} {inspection.architecture})",
            run_full_rules=True,
            run_structural_rules_only=False,
            suppress_r08=False,
            skip_r11=no_entry_point,
            skip_r11_reason=dll_skip_r11_reason,
            run_disassembly=True,
            capstone_arch_bits=arch_bits,
        )

    # Native DLL (IMAGE_FILE_DLL flag in characteristics)
    if inspection.is_dll:
        reason = (
            f"Native {inspection.pe_format} {inspection.architecture} DLL analyzed; "
            "no entry point (AddressOfEntryPoint is 0) so R11 is skipped"
            if dll_skip_r11
            else f"Native {inspection.pe_format} {inspection.architecture} DLL analyzed (rules R01-R14 and bounded disassembly)"
        )
        return RouteDecision(
            status=FileStatus.ANALYZED,
            reason=reason,
            file_kind=f"DLL ({inspection.architecture})",
            run_full_rules=True,
            run_structural_rules_only=False,
            suppress_r08=False,
            skip_r11=no_entry_point,
            skip_r11_reason=dll_skip_r11_reason,
            run_disassembly=True,
            capstone_arch_bits=arch_bits,
        )

    # Native PE32 / PE32+ executable
    return RouteDecision(
        status=FileStatus.ANALYZED,
        reason=(
            f"Native {inspection.pe_format} {inspection.architecture} executable analyzed "
            "(rules R01-R14 and bounded disassembly)"
        ),
        file_kind=f"Native {inspection.pe_format} executable ({inspection.architecture})",
        run_full_rules=True,
        run_structural_rules_only=False,
        suppress_r08=False,
        skip_r11=no_entry_point,
        skip_r11_reason=dll_skip_r11_reason,
        run_disassembly=True,
        capstone_arch_bits=arch_bits,
    )
