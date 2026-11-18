"""Benign fixture generator and manifest builder for CSC-203 static PE triage.

Generates:
1. 28 Rule fixtures (one positive and one negative for each of R01-R14).
2. 10 File-type router fixtures (x86, x64, DLL with/without EP, .NET, driver, driver candidate, ARM64, non-PE .exe, skipped .txt).
3. 8 Calibration benign fixtures ('calibration' set assigned up front).
4. 8 Held-out benign fixtures ('heldout' set assigned up front).
5. 12 Malformed PE corpus fixtures (zero-byte, truncated headers, corrupt tables, invalid offsets, huge sizes, seeded bit flips).

Writes all generated files into `coalscan/fixtures/generated/` and outputs
`coalscan/fixtures/manifest.csv`. Never generates or downloads real malware.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
import hashlib
from pathlib import Path
import random
import struct
from typing import Optional

from coalscan.core.banding import compute_banding
from coalscan.core.limits import (
    IMAGE_FILE_MACHINE_ARM64,
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE,
    IMAGE_SUBSYSTEM_NATIVE,
)
from coalscan.core.models import FileStatus
from coalscan.core.pe_inspect import inspect_pe_bytes
from coalscan.core.router import route_file
from coalscan.core.rules import evaluate_rules
from coalscan.tests.pe_builder import build_synthetic_pe

FIXTURES_ROOT = Path(__file__).resolve().parent
GENERATED_DIR = FIXTURES_ROOT / "generated"
MANIFEST_PATH = FIXTURES_ROOT / "manifest.csv"

BASELINE_IMPORTS: list[tuple[str, list[str]]] = [
    (
        "KERNEL32.dll",
        [
            "GetModuleHandleW",
            "GetCommandLineW",
            "WriteFile",
            "ExitProcess",
            "GetLastError",
        ],
    )
]


@dataclass
class FixtureEntry:
    """Single row in fixtures/manifest.csv."""

    name: str
    data: bytes
    source_author: str
    architecture: str
    expected_status: str
    expected_rule_ids: list[str]
    fixture_set: str  # "rule", "router", "calibration", "heldout", "malformed"
    permission: str = "Team-generated synthetic benign fixture (CSC-203)"


def _with_extra_imports(extra: list[tuple[str, list[str]]]) -> list[tuple[str, list[str]]]:
    combined: list[tuple[str, list[str]]] = [
        (dll, list(fns)) for dll, fns in BASELINE_IMPORTS
    ]
    for dll, fns in extra:
        if dll.upper() == "KERNEL32.DLL":
            combined[0][1].extend(fns)
        else:
            combined.append((dll, list(fns)))
    return combined


def build_all_fixture_specs() -> list[FixtureEntry]:
    """Construct the complete list of deterministic benign and malformed fixtures."""
    entries: list[FixtureEntry] = []

    def _add(
        name: str,
        data: bytes,
        arch: str,
        status: FileStatus,
        rules: list[str],
        fset: str,
        author: str = "CoalScan Fixture Generator",
    ) -> None:
        entries.append(
            FixtureEntry(
                name=name,
                data=data,
                source_author=author,
                architecture=arch,
                expected_status=status.value,
                expected_rule_ids=rules,
                fixture_set=fset,
            )
        )

    # =========================================================================
    # 1. 28 Rule Fixtures: Positive & Negative for R01-R14
    # =========================================================================
    # R01: VirtualAlloc
    _add(
        "r01_pos.exe",
        build_synthetic_pe(
            imports=_with_extra_imports([("KERNEL32.dll", ["VirtualAlloc"])]),
            has_certificate=True,
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R01"],
        "rule",
    )
    _add(
        "r01_neg.exe",
        build_synthetic_pe(imports=BASELINE_IMPORTS, has_certificate=True),
        "x64",
        FileStatus.ANALYZED,
        [],
        "rule",
    )

    # R02: VirtualProtect
    _add(
        "r02_pos.exe",
        build_synthetic_pe(
            imports=_with_extra_imports([("KERNEL32.dll", ["VirtualProtect"])]),
            has_certificate=True,
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R02"],
        "rule",
    )
    _add(
        "r02_neg.exe",
        build_synthetic_pe(imports=BASELINE_IMPORTS, has_certificate=True),
        "x64",
        FileStatus.ANALYZED,
        [],
        "rule",
    )

    # R03: WriteProcessMemory
    _add(
        "r03_pos.exe",
        build_synthetic_pe(
            imports=_with_extra_imports([("KERNEL32.dll", ["WriteProcessMemory"])]),
            has_certificate=True,
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R03"],
        "rule",
    )
    _add(
        "r03_neg.exe",
        build_synthetic_pe(imports=BASELINE_IMPORTS, has_certificate=True),
        "x64",
        FileStatus.ANALYZED,
        [],
        "rule",
    )

    # R04: CreateRemoteThread
    _add(
        "r04_pos.exe",
        build_synthetic_pe(
            imports=_with_extra_imports([("KERNEL32.dll", ["CreateRemoteThread"])]),
            has_certificate=True,
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R04"],
        "rule",
    )
    _add(
        "r04_neg.exe",
        build_synthetic_pe(imports=BASELINE_IMPORTS, has_certificate=True),
        "x64",
        FileStatus.ANALYZED,
        [],
        "rule",
    )

    # R05: LoadLibrary* AND GetProcAddress both imported
    _add(
        "r05_pos.exe",
        build_synthetic_pe(
            imports=_with_extra_imports([("KERNEL32.dll", ["LoadLibraryW", "GetProcAddress"])]),
            has_certificate=True,
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R05"],
        "rule",
    )
    _add(
        "r05_neg.exe",
        build_synthetic_pe(
            imports=_with_extra_imports([("KERNEL32.dll", ["LoadLibraryW"])]),
            has_certificate=True,
        ),
        "x64",
        FileStatus.ANALYZED,
        [],
        "rule",
    )

    # R06: CreateProcess / ShellExecute
    _add(
        "r06_pos.exe",
        build_synthetic_pe(
            imports=_with_extra_imports([("KERNEL32.dll", ["CreateProcessW"])]),
            has_certificate=True,
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R06"],
        "rule",
    )
    _add(
        "r06_neg.exe",
        build_synthetic_pe(imports=BASELINE_IMPORTS, has_certificate=True),
        "x64",
        FileStatus.ANALYZED,
        [],
        "rule",
    )

    # R07: WinINet / WinHTTP imports
    _add(
        "r07_pos.exe",
        build_synthetic_pe(
            imports=_with_extra_imports([("WININET.dll", ["InternetOpenW"])]),
            has_certificate=True,
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R07"],
        "rule",
    )
    _add(
        "r07_neg.exe",
        build_synthetic_pe(imports=BASELINE_IMPORTS, has_certificate=True),
        "x64",
        FileStatus.ANALYZED,
        [],
        "rule",
    )

    # R08: Fewer than 5 imported functions (native PE only)
    _add(
        "r08_pos.exe",
        build_synthetic_pe(
            imports=[("KERNEL32.dll", ["ExitProcess", "GetLastError"])],
            has_certificate=True,
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R08"],
        "rule",
    )
    _add(
        "r08_neg.exe",
        build_synthetic_pe(imports=BASELINE_IMPORTS, has_certificate=True),
        "x64",
        FileStatus.ANALYZED,
        [],
        "rule",
    )

    # R09: Section entropy >= 7.0 (section >= 1 KB)
    high_entropy_payload = bytes(range(256)) * 8  # 2048 bytes, entropy = 8.0 bits/byte
    low_entropy_payload = b"\x00" * 2048          # 2048 bytes, entropy = 0.0 bits/byte
    _add(
        "r09_pos.exe",
        build_synthetic_pe(
            imports=BASELINE_IMPORTS,
            has_certificate=True,
            extra_sections=[(b".rsrc", IMAGE_SCN_MEM_READ | 0x40, high_entropy_payload)],
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R09"],
        "rule",
    )
    _add(
        "r09_neg.exe",
        build_synthetic_pe(
            imports=BASELINE_IMPORTS,
            has_certificate=True,
            extra_sections=[(b".rsrc", IMAGE_SCN_MEM_READ | 0x40, low_entropy_payload)],
        ),
        "x64",
        FileStatus.ANALYZED,
        [],
        "rule",
    )

    # R10: Section both writable and executable
    _add(
        "r10_pos.exe",
        build_synthetic_pe(
            imports=BASELINE_IMPORTS,
            has_certificate=True,
            text_Flags=IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | 0x20,
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R10"],
        "rule",
    )
    _add(
        "r10_neg.exe",
        build_synthetic_pe(imports=BASELINE_IMPORTS, has_certificate=True),
        "x64",
        FileStatus.ANALYZED,
        [],
        "rule",
    )

    # R11: Entry point outside an executable section
    _add(
        "r11_pos.exe",
        build_synthetic_pe(
            imports=BASELINE_IMPORTS,
            has_certificate=True,
            entry_point_rva=0x2000,  # Inside non-executable .rdata section
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R11"],
        "rule",
    )
    _add(
        "r11_neg.exe",
        build_synthetic_pe(
            imports=BASELINE_IMPORTS,
            has_certificate=True,
            entry_point_rva=0x1000,  # Inside executable .text section
        ),
        "x64",
        FileStatus.ANALYZED,
        [],
        "rule",
    )

    # R12: Overlay after mapped sections
    _add(
        "r12_pos.exe",
        build_synthetic_pe(
            imports=BASELINE_IMPORTS,
            has_certificate=True,
            overlay_bytes=b"BENIGN_INSTALLER_OVERLAY_DATA_BLOCK" * 4,
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R12"],
        "rule",
    )
    _add(
        "r12_neg.exe",
        build_synthetic_pe(imports=BASELINE_IMPORTS, has_certificate=True, overlay_bytes=b""),
        "x64",
        FileStatus.ANALYZED,
        [],
        "rule",
    )

    # R13: TLS callback present
    _add(
        "r13_pos.exe",
        build_synthetic_pe(
            imports=BASELINE_IMPORTS,
            has_certificate=True,
            has_tls_callback=True,
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R13"],
        "rule",
    )
    _add(
        "r13_neg.exe",
        build_synthetic_pe(
            imports=BASELINE_IMPORTS,
            has_certificate=True,
            has_tls_callback=False,
        ),
        "x64",
        FileStatus.ANALYZED,
        [],
        "rule",
    )

    # R14: Signature/certificate data present or absent (fires when absent)
    _add(
        "r14_pos.exe",
        build_synthetic_pe(imports=BASELINE_IMPORTS, has_certificate=False),
        "x64",
        FileStatus.ANALYZED,
        ["R14"],
        "rule",
    )
    _add(
        "r14_neg.exe",
        build_synthetic_pe(imports=BASELINE_IMPORTS, has_certificate=True),
        "x64",
        FileStatus.ANALYZED,
        [],
        "rule",
    )

    # =========================================================================
    # 2. File-Type Router Fixtures (Section 2 & Section 6)
    # =========================================================================
    _add(
        "type_native_x86.exe",
        build_synthetic_pe(is_64bit=False, imports=BASELINE_IMPORTS, has_certificate=True),
        "x86",
        FileStatus.ANALYZED,
        [],
        "router",
    )
    _add(
        "type_native_x64.exe",
        build_synthetic_pe(is_64bit=True, imports=BASELINE_IMPORTS, has_certificate=True),
        "x64",
        FileStatus.ANALYZED,
        [],
        "router",
    )
    _add(
        "type_dll_no_ep.dll",
        build_synthetic_pe(
            is_64bit=True,
            is_dll=True,
            entry_point_rva=0,
            imports=BASELINE_IMPORTS,
            has_certificate=True,
        ),
        "x64",
        FileStatus.ANALYZED,
        [],
        "router",
    )
    _add(
        "type_dll_with_ep.dll",
        build_synthetic_pe(
            is_64bit=True,
            is_dll=True,
            entry_point_rva=0x1000,
            imports=BASELINE_IMPORTS,
            has_certificate=True,
        ),
        "x64",
        FileStatus.ANALYZED,
        [],
        "router",
    )
    _add(
        "type_managed_dotnet.exe",
        build_synthetic_pe(
            is_64bit=False,
            has_clr=True,
            imports=[("mscoree.dll", ["_CorExeMain"])],
            has_certificate=False,
        ),
        "x86",
        FileStatus.ANALYZED_DOTNET_LIMITED,
        ["R14"],  # R08 is suppressed for .NET!
        "router",
    )
    _add(
        "type_native_driver.sys",
        build_synthetic_pe(
            is_64bit=True,
            subsystem=IMAGE_SUBSYSTEM_NATIVE,
            imports=[("ntoskrnl.exe", ["IoCreateDevice", "IofCompleteRequest"])],
            has_certificate=True,
        ),
        "x64",
        FileStatus.ANALYZED_DRIVER_LIMITED,
        [],
        "router",
    )
    _add(
        "type_driver_candidate.sys",
        build_synthetic_pe(
            is_64bit=True,
            subsystem=3,  # Non-NATIVE subsystem with .sys extension
            imports=BASELINE_IMPORTS,
            has_certificate=True,
        ),
        "x64",
        FileStatus.DRIVER_CANDIDATE,
        [],
        "router",
    )
    _add(
        "type_arm64.exe",
        build_synthetic_pe(
            is_64bit=True,
            machine=IMAGE_FILE_MACHINE_ARM64,
            imports=BASELINE_IMPORTS,
            has_certificate=True,
        ),
        "ARM64",
        FileStatus.UNSUPPORTED_ARCH,
        [],
        "router",
    )
    _add(
        "type_not_pe.exe",
        b"This is a plain ASCII text file with an .exe extension for router testing.\n",
        "-",
        FileStatus.NOT_A_PE,
        [],
        "router",
    )
    _add(
        "type_skipped.txt",
        b"Plain text note with non-candidate extension .txt\n",
        "-",
        FileStatus.SKIPPED,
        [],
        "router",
    )

    # =========================================================================
    # 3. Calibration Benign Set (8 benign files assigned up front before tuning)
    # =========================================================================
    # 1. Signed x64 console app (0 points -> Routine)
    _add(
        "cal_benign_01_console_signed.exe",
        build_synthetic_pe(imports=BASELINE_IMPORTS, has_certificate=True),
        "x64",
        FileStatus.ANALYZED,
        [],
        "calibration",
    )
    # 2. Unsigned x64 console utility (R14 = 1 pt -> Routine)
    _add(
        "cal_benign_02_console_unsigned.exe",
        build_synthetic_pe(imports=BASELINE_IMPORTS, has_certificate=False),
        "x64",
        FileStatus.ANALYZED,
        ["R14"],
        "calibration",
    )
    # 3. Ordinary C runtime app (R01 + R02 + R05 capped at 2 + R06 (1) = 3 pts -> Routine)
    _add(
        "cal_benign_03_crt_runtime.exe",
        build_synthetic_pe(
            imports=_with_extra_imports(
                [
                    (
                        "KERNEL32.dll",
                        [
                            "VirtualAlloc",
                            "VirtualProtect",
                            "LoadLibraryW",
                            "GetProcAddress",
                            "CreateProcessW",
                        ],
                    )
                ]
            ),
            has_certificate=True,
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R01", "R02", "R05", "R06"],
        "calibration",
    )
    # 4. Signed plugin host app with overlay config (R05 (2) + R12 (1) = 3 pts -> Routine)
    _add(
        "cal_benign_04_plugin_host.exe",
        build_synthetic_pe(
            imports=_with_extra_imports([("KERNEL32.dll", ["LoadLibraryA", "GetProcAddress"])]),
            has_certificate=True,
            overlay_bytes=b"PLUGIN_CONFIG_JSON={}",
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R05", "R12"],
        "calibration",
    )
    # 5. Unsigned updater client (R07 (1) + R14 (1) = 2 pts -> Routine)
    _add(
        "cal_benign_05_updater_client.exe",
        build_synthetic_pe(
            imports=_with_extra_imports([("WINHTTP.dll", ["WinHttpOpen"])]),
            has_certificate=False,
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R07", "R14"],
        "calibration",
    )
    # 6. Signed 32-bit GUI calculator app (0 pts -> Routine)
    _add(
        "cal_benign_06_gui_x86.exe",
        build_synthetic_pe(
            is_64bit=False,
            subsystem=2,
            imports=BASELINE_IMPORTS,
            has_certificate=True,
        ),
        "x86",
        FileStatus.ANALYZED,
        [],
        "calibration",
    )
    # 7. Unsigned resource/math DLL without entry point (R14 = 1 pt, R11 skipped -> Routine)
    _add(
        "cal_benign_07_math_dll.dll",
        build_synthetic_pe(
            is_64bit=True,
            is_dll=True,
            entry_point_rva=0,
            imports=BASELINE_IMPORTS,
            has_certificate=False,
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R14"],
        "calibration",
    )
    # 8. Unsigned managed .NET hello-world (R14 = 1 pt, R08 suppressed -> Routine)
    _add(
        "cal_benign_08_dotnet_hello.exe",
        build_synthetic_pe(
            is_64bit=False,
            has_clr=True,
            imports=[("mscoree.dll", ["_CorExeMain"])],
            has_certificate=False,
        ),
        "x86",
        FileStatus.ANALYZED_DOTNET_LIMITED,
        ["R14"],
        "calibration",
    )

    # =========================================================================
    # 4. Held-out Benign Set (8 benign files assigned up front, run once after freeze)
    # =========================================================================
    # 1. Unsigned CLI file-hash tool (R14 = 1 pt -> Routine)
    _add(
        "hold_benign_01_cli_tool.exe",
        build_synthetic_pe(
            imports=_with_extra_imports([("KERNEL32.dll", ["CreateFileW", "ReadFile"])]),
            has_certificate=False,
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R14"],
        "heldout",
    )
    # 2. Signed background helper (0 pts -> Routine)
    _add(
        "hold_benign_02_signed_service.exe",
        build_synthetic_pe(
            imports=_with_extra_imports([("ADVAPI32.dll", ["StartServiceCtrlDispatcherW"])]),
            has_certificate=True,
        ),
        "x64",
        FileStatus.ANALYZED,
        [],
        "heldout",
    )
    # 3. Unsigned C++ app with TLS initializer and C runtime (R01 (2) + R13 (1) + R14 (1) -> Group B capped at 2? No, R13+R14=2 + R01=2 = 4 if unsigned, or signed C++ TLS app: R01(2) + R13(1) = 3 -> Routine)
    _add(
        "hold_benign_03_tls_runtime.exe",
        build_synthetic_pe(
            imports=_with_extra_imports([("KERNEL32.dll", ["VirtualAlloc"])]),
            has_tls_callback=True,
            has_certificate=True,
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R01", "R13"],
        "heldout",
    )
    # 4. Unsigned desktop launcher with overlay & CreateProcess (R06 + R12 + R14 -> Group B capped at 2 -> Routine)
    _add(
        "hold_benign_04_launcher.exe",
        build_synthetic_pe(
            imports=_with_extra_imports([("SHELL32.dll", ["ShellExecuteExW"])]),
            overlay_bytes=b"LAUNCHER_MANIFEST_XML",
            has_certificate=False,
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R06", "R12", "R14"],
        "heldout",
    )
    # 5. Unsigned minimal-import native utility (R08 (1) + R14 (1) = 2 -> Routine)
    _add(
        "hold_benign_05_minimal_native.exe",
        build_synthetic_pe(
            imports=[("KERNEL32.dll", ["ExitProcess", "WriteFile"])],
            has_certificate=False,
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R08", "R14"],
        "heldout",
    )
    # 6. Signed JIT helper DLL importing VirtualAlloc + VirtualProtect (Group A capped at 2 -> Routine)
    _add(
        "hold_benign_06_jit_helper_dll.dll",
        build_synthetic_pe(
            is_64bit=True,
            is_dll=True,
            entry_point_rva=0x1000,
            imports=_with_extra_imports([("KERNEL32.dll", ["VirtualAlloc", "VirtualProtect"])]),
            has_certificate=True,
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R01", "R02"],
        "heldout",
    )
    # 7. Signed managed .NET utility (0 pts -> Routine)
    _add(
        "hold_benign_07_dotnet_signed.exe",
        build_synthetic_pe(
            is_64bit=False,
            has_clr=True,
            imports=[("mscoree.dll", ["_CorExeMain"])],
            has_certificate=True,
        ),
        "x86",
        FileStatus.ANALYZED_DOTNET_LIMITED,
        [],
        "heldout",
    )
    # 8. Benign app with compressed media resource section (R09 (2) + R01 (2) = 4 -> Review, illustrating held-out false positive <= 20%)
    _add(
        "hold_benign_08_compressed_media_app.exe",
        build_synthetic_pe(
            imports=_with_extra_imports([("KERNEL32.dll", ["VirtualAlloc"])]),
            has_certificate=True,
            extra_sections=[(b".media", IMAGE_SCN_MEM_READ | 0x40, high_entropy_payload)],
        ),
        "x64",
        FileStatus.ANALYZED,
        ["R01", "R09"],
        "heldout",
    )

    # =========================================================================
    # 5. Malformed PE Corpus (12 files covering every category in Section 6)
    # =========================================================================
    base_valid = bytearray(build_synthetic_pe(imports=BASELINE_IMPORTS, has_certificate=True))
    e_lfanew = struct.unpack_from("<I", base_valid, 0x3C)[0]
    opt_size = struct.unpack_from("<H", base_valid, e_lfanew + 20)[0]
    first_sec_off = e_lfanew + 24 + opt_size

    # M01: Zero-byte file
    _add("malformed_01_zero_byte.exe", b"", "-", FileStatus.MALFORMED, [], "malformed")

    # M02: Truncated DOS header (< 64 bytes)
    _add(
        "malformed_02_trunc_dos.exe",
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00",
        "-",
        FileStatus.MALFORMED,
        [],
        "malformed",
    )

    # M03: Out-of-bounds e_lfanew offset
    m03 = bytearray(64)
    m03[0:2] = b"MZ"
    struct.pack_into("<I", m03, 0x3C, 0x00100000)
    _add("malformed_03_bad_lfanew.exe", bytes(m03), "-", FileStatus.MALFORMED, [], "malformed")

    # M04: Truncated COFF header
    m04 = bytearray(e_lfanew + 10)
    m04[0:2] = b"MZ"
    struct.pack_into("<I", m04, 0x3C, e_lfanew)
    m04[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    _add("malformed_04_trunc_coff.exe", bytes(m04), "-", FileStatus.MALFORMED, [], "malformed")

    # M05: Truncated Optional Header
    m05 = bytes(base_valid[: e_lfanew + 40])
    _add("malformed_05_trunc_opt.exe", m05, "x64", FileStatus.MALFORMED, [], "malformed")

    # M06: Invalid Optional Header Magic
    m06 = bytearray(base_valid)
    struct.pack_into("<H", m06, e_lfanew + 24, 0xDEAD)
    _add("malformed_06_bad_opt_magic.exe", bytes(m06), "x64", FileStatus.MALFORMED, [], "malformed")

    # M07: Truncated section table
    m07 = bytearray(base_valid[: first_sec_off + 20])
    _add("malformed_07_trunc_sectable.exe", bytes(m07), "x64", FileStatus.MALFORMED, [], "malformed")

    # M08: Section count > MAX_SECTIONS (96)
    m08 = bytearray(base_valid)
    struct.pack_into("<H", m08, e_lfanew + 6, 120)
    _add("malformed_08_too_many_sections.exe", bytes(m08), "x64", FileStatus.MALFORMED, [], "malformed")

    # M09: Invalid section raw pointer/size beyond EOF
    m09 = bytearray(base_valid)
    struct.pack_into("<I", m09, first_sec_off + 20, 0x00500000)  # PointerToRawData beyond EOF
    _add(
        "malformed_09_invalid_sec_raw_offset.exe",
        bytes(m09),
        "x64",
        FileStatus.MALFORMED,
        [],
        "malformed",
    )

    # M10: Huge declared section VirtualSize (> 1 GB)
    m10 = bytearray(base_valid)
    struct.pack_into("<I", m10, first_sec_off + 8, 0x70000000)
    _add(
        "malformed_10_huge_virtual_size.exe",
        bytes(m10),
        "x64",
        FileStatus.MALFORMED,
        [],
        "malformed",
    )

    # M11: Corrupt Import Directory RVA pointing outside mapped sections
    m11 = bytearray(base_valid)
    imp_dir_off = e_lfanew + 24 + 112 + 8  # PE32+ DataDirectory[1] (Import)
    struct.pack_into("<II", m11, imp_dir_off, 0x00990000, 40)
    _add(
        "malformed_11_bad_import_rva.exe",
        bytes(m11),
        "x64",
        FileStatus.MALFORMED,
        [],
        "malformed",
    )

    # M12: Deterministic seeded random bit flips in PE header (seed=203)
    rng = random.Random(203)
    m12 = bytearray(base_valid)
    # Flip bits in COFF/Optional/Section headers while preserving MZ and PE\0\0
    for _ in range(24):
        pos = rng.randint(e_lfanew + 6, first_sec_off + 39)
        bit = 1 << rng.randint(0, 7)
        m12[pos] ^= bit
    # Ensure at least one section raw size is corrupted by the seeded flip so it deterministically lands in MALFORMED
    struct.pack_into("<I", m12, first_sec_off + 16, 0x01000000)
    _add(
        "malformed_12_bitflips_seed203.exe",
        bytes(m12),
        "x64",
        FileStatus.MALFORMED,
        [],
        "malformed",
    )

    return entries


def generate_all_fixtures(
    output_dir: Path = GENERATED_DIR,
    manifest_path: Path = MANIFEST_PATH,
) -> list[dict[str, str]]:
    """Write all synthetic fixtures to `output_dir` and generate `manifest.csv`."""
    output_dir.mkdir(parents=True, exist_ok=True)
    specs = build_all_fixture_specs()
    manifest_rows: list[dict[str, str]] = []

    for entry in specs:
        file_path = output_dir / entry.name
        file_path.write_bytes(entry.data)
        sha256_hex = hashlib.sha256(entry.data).hexdigest()

        # Run static inspection, routing, and rules to record verified test_outcome
        ext_ok = Path(entry.name).suffix.lower() in {".exe", ".dll", ".sys", ".ocx"}
        insp = inspect_pe_bytes(entry.data) if ext_ok else None
        route = route_file(entry.name, len(entry.data), insp)
        fired_rules = (
            [f.rule_id for f in evaluate_rules(insp, route)]
            if insp is not None
            else []
        )

        status_match = route.status.value == entry.expected_status
        rules_match = sorted(fired_rules) == sorted(entry.expected_rule_ids)
        outcome = "PASS" if (status_match and rules_match) else "FAIL"

        manifest_rows.append(
            {
                "name": entry.name,
                "sha256": sha256_hex,
                "source_author": entry.source_author,
                "architecture": entry.architecture,
                "expected_status": entry.expected_status,
                "expected_rule_ids": ";".join(entry.expected_rule_ids),
                "set": entry.fixture_set,
                "permission": entry.permission,
                "test_outcome": outcome,
            }
        )

    fieldnames = [
        "name",
        "sha256",
        "source_author",
        "architecture",
        "expected_status",
        "expected_rule_ids",
        "set",
        "permission",
        "test_outcome",
    ]
    with manifest_path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(manifest_rows)

    return manifest_rows


if __name__ == "__main__":
    rows = generate_all_fixtures()
    print(f"Generated {len(rows)} fixtures and wrote manifest to {MANIFEST_PATH}")
