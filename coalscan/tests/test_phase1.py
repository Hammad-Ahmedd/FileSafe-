"""Phase 1 unit tests: limits, models, hashing, PE inspection, and content router."""

from __future__ import annotations

import hashlib
from pathlib import Path
import struct

import pytest

from coalscan.core import limits
from coalscan.core.hashing import (
    FileTooLargeError,
    compute_sha256_bytes,
    compute_sha256_file,
)
from coalscan.core.models import (
    FileStatus,
    RiskBand,
    escape_untrusted_text,
    escape_xml_markup,
)
from coalscan.core.pe_inspect import (
    compute_shannon_entropy,
    inspect_pe_bytes,
    inspect_pe_file,
)
from coalscan.core.router import is_candidate_extension, route_file
from coalscan.tests.pe_builder import build_synthetic_pe


def test_limits_named_constants() -> None:
    """Verify all numeric limits match Revision 5 Section 2."""
    assert limits.MAX_FILE_SIZE_BYTES == 50 * 1024 * 1024
    assert limits.MAX_FILES_PER_SCAN == 500
    assert limits.PER_FILE_TIMEOUT_SECONDS == 20
    assert limits.TOP_LEVEL_FOLDER_ONLY is True
    assert limits.MAX_DISASM_INSTRUCTIONS_PER_FILE == 2000
    assert limits.MAX_ENTRY_DISASM_BYTES == 256
    assert limits.MAX_EVIDENCE_DISASM_BYTES == 128
    assert limits.MAX_EVIDENCE_LOCATIONS_PER_FILE == 3
    assert limits.MAX_SECTIONS == 96
    assert limits.MAX_IMPORT_ENTRIES == 20_000
    assert limits.CANDIDATE_EXTENSIONS == frozenset({".exe", ".dll", ".sys", ".ocx"})


def test_escape_untrusted_text() -> None:
    """Ensure control characters and em-dashes are sanitized while plain-text characters
    ('<', '>', '&', "'") are not double-escaped, and escape_xml_markup escapes XML for PDF."""
    dirty = "bad<script>&'\"name\x00\n\u2014test"
    plain_sanitized = escape_untrusted_text(dirty)
    assert "<script>&'\"name" in plain_sanitized
    assert "&#x27;" not in plain_sanitized
    assert "&amp;" not in plain_sanitized
    assert "\\x00" in plain_sanitized
    assert "\\x0a" in plain_sanitized
    assert "\u2014" not in plain_sanitized
    assert "-test" in plain_sanitized

    xml_escaped = escape_xml_markup(dirty)
    assert "&lt;script&gt;" in xml_escaped
    assert "&amp;" in xml_escaped
    assert "&#x27;" in xml_escaped


def test_hashing_bytes_and_file(tmp_path: Path) -> None:
    """Verify SHA-256 hashing on bytes and files, and rejection of oversized files."""
    sample = b"CSC-203 static triage sample bytes"
    expected = hashlib.sha256(sample).hexdigest()
    assert compute_sha256_bytes(sample) == expected

    f = tmp_path / "sample.exe"
    f.write_bytes(sample)
    assert compute_sha256_file(f) == expected

    # Enforce max_bytes limit without hashing oversized files
    with pytest.raises(FileTooLargeError):
        compute_sha256_file(f, max_bytes=10)


def test_entropy_calculation() -> None:
    """Verify Shannon entropy bounds (0.0 for uniform bytes, 8.0 for full byte distribution)."""
    assert compute_shannon_entropy(b"") == 0.0
    assert compute_shannon_entropy(b"\x00" * 1024) == 0.0
    all_bytes = bytes(range(256)) * 8
    assert compute_shannon_entropy(all_bytes) == 8.0


def test_pe_inspect_and_route_native_x64_exe() -> None:
    """Inspect and route a native PE32+ x64 executable."""
    pe_bytes = build_synthetic_pe(
        is_64bit=True,
        imports=[("KERNEL32.dll", ["VirtualAlloc", "GetLastError"])],
    )
    insp = inspect_pe_bytes(pe_bytes)
    assert insp.is_pe is True
    assert insp.is_malformed is False
    assert insp.pe_format == "PE32+"
    assert insp.architecture == "x64"
    assert insp.is_dll is False
    assert insp.total_import_count == 2
    assert insp.entry_point_in_exec_section is True

    decision = route_file("sample.exe", len(pe_bytes), insp)
    assert decision.status == FileStatus.ANALYZED
    assert decision.run_full_rules is True
    assert decision.run_disassembly is True
    assert decision.capstone_arch_bits == 64
    assert decision.skip_r11 is False


def test_pe_inspect_and_route_native_x86_exe() -> None:
    """Inspect and route a native PE32 x86 executable."""
    pe_bytes = build_synthetic_pe(is_64bit=False)
    insp = inspect_pe_bytes(pe_bytes)
    assert insp.is_pe is True
    assert insp.is_malformed is False
    assert insp.pe_format == "PE32"
    assert insp.architecture == "x86"

    decision = route_file("app32.exe", len(pe_bytes), insp)
    assert decision.status == FileStatus.ANALYZED
    assert decision.capstone_arch_bits == 32


def test_pe_inspect_and_route_dll_with_and_without_entry_point() -> None:
    """Verify DLL handling: AddressOfEntryPoint=0 skips R11 and states why."""
    dll_no_ep = build_synthetic_pe(is_64bit=True, is_dll=True, entry_point_rva=0)
    insp_no_ep = inspect_pe_bytes(dll_no_ep)
    assert insp_no_ep.is_dll is True
    assert insp_no_ep.entry_point_rva == 0

    dec_no_ep = route_file("resource.dll", len(dll_no_ep), insp_no_ep)
    assert dec_no_ep.status == FileStatus.ANALYZED
    assert dec_no_ep.skip_r11 is True
    assert dec_no_ep.skip_r11_reason is not None
    assert "R11 is skipped" in dec_no_ep.skip_r11_reason

    dll_with_ep = build_synthetic_pe(is_64bit=True, is_dll=True, entry_point_rva=0x1000)
    insp_with_ep = inspect_pe_bytes(dll_with_ep)
    dec_with_ep = route_file("plugin.dll", len(dll_with_ep), insp_with_ep)
    assert dec_with_ep.status == FileStatus.ANALYZED
    assert dec_with_ep.skip_r11 is False


def test_pe_inspect_and_route_managed_dotnet() -> None:
    """Verify Managed .NET routing via CLR data directory 14."""
    dotnet_pe = build_synthetic_pe(
        is_64bit=False,
        has_clr=True,
        imports=[("mscoree.dll", ["_CorExeMain"])],
    )
    insp = inspect_pe_bytes(dotnet_pe)
    assert insp.has_clr_header is True

    decision = route_file("viewer.exe", len(dotnet_pe), insp)
    assert decision.status == FileStatus.ANALYZED_DOTNET_LIMITED
    assert decision.run_full_rules is False
    assert decision.run_structural_rules_only is True
    assert decision.suppress_r08 is True
    assert decision.run_disassembly is False


def test_pe_inspect_and_route_driver_and_driver_candidate() -> None:
    """Verify NATIVE subsystem driver vs unconfirmed .sys driver candidate."""
    # Confirmed native driver (Subsystem == 1)
    native_drv = build_synthetic_pe(
        is_64bit=True,
        subsystem=limits.IMAGE_SUBSYSTEM_NATIVE,
    )
    insp_drv = inspect_pe_bytes(native_drv)
    assert insp_drv.is_native_subsystem is True
    dec_drv = route_file("diskflt.sys", len(native_drv), insp_drv)
    assert dec_drv.status == FileStatus.ANALYZED_DRIVER_LIMITED
    assert dec_drv.run_structural_rules_only is True
    assert dec_drv.run_disassembly is False

    # Unconfirmed .sys (Subsystem == 3 WINDOWS_CUI) -> 'driver candidate'
    unconfirmed_sys = build_synthetic_pe(is_64bit=True, subsystem=3)
    insp_cand = inspect_pe_bytes(unconfirmed_sys)
    assert insp_cand.is_native_subsystem is False
    dec_cand = route_file(" fake_driver.sys", len(unconfirmed_sys), insp_cand)
    assert dec_cand.status == FileStatus.DRIVER_CANDIDATE
    assert dec_cand.run_full_rules is True
    assert dec_cand.run_disassembly is True


def test_pe_inspect_and_route_unsupported_architecture() -> None:
    """Verify ARM64 PE is routed as 'unsupported architecture'."""
    arm64_pe = build_synthetic_pe(
        is_64bit=True,
        machine=limits.IMAGE_FILE_MACHINE_ARM64,
    )
    insp = inspect_pe_bytes(arm64_pe)
    assert insp.architecture == "ARM64"
    decision = route_file("arm_app.exe", len(arm64_pe), insp)
    assert decision.status == FileStatus.UNSUPPORTED_ARCH
    assert decision.run_full_rules is False
    assert decision.run_disassembly is False


def test_pe_inspect_and_route_not_a_pe_file() -> None:
    """Verify a non-PE file with .exe extension gets 'not a PE file'."""
    raw = b"This is a plain text document renamed to .exe\n"
    insp = inspect_pe_bytes(raw)
    assert insp.is_pe is False
    assert insp.is_malformed is False

    decision = route_file("fake.exe", len(raw), insp)
    assert decision.status == FileStatus.NOT_A_PE


def test_route_skipped_extension_and_too_large() -> None:
    """Verify non-candidate extensions are skipped and >50MB files are marked too large."""
    assert is_candidate_extension("app.exe") is True
    assert is_candidate_extension("lib.DLL") is True
    assert is_candidate_extension("drv.sys") is True
    assert is_candidate_extension("ctrl.ocx") is True
    assert is_candidate_extension("readme.txt") is False

    skip_dec = route_file("notes.txt", 120, None)
    assert skip_dec.status == FileStatus.SKIPPED

    large_dec = route_file("giant.exe", limits.MAX_FILE_SIZE_BYTES + 1, None)
    assert large_dec.status == FileStatus.TOO_LARGE


def test_pe_inspect_malformed_cases() -> None:
    """Verify malformed PE structures are caught cleanly without unhandled exceptions."""
    # 1. Zero-byte file
    insp_zero = inspect_pe_bytes(b"")
    assert insp_zero.is_malformed is True
    assert route_file("empty.exe", 0, insp_zero).status == FileStatus.MALFORMED

    # 2. Truncated DOS header
    insp_short_dos = inspect_pe_bytes(b"MZ" + b"\x00" * 10)
    assert insp_short_dos.is_malformed is True

    # 3. Out-of-bounds e_lfanew
    bad_lfanew = bytearray(64)
    bad_lfanew[0:2] = b"MZ"
    struct.pack_into("<I", bad_lfanew, 0x3C, 0x9999)
    insp_lfanew = inspect_pe_bytes(bytes(bad_lfanew))
    assert insp_lfanew.is_malformed is True

    # 4. Section count > MAX_SECTIONS (96)
    valid_pe = bytearray(build_synthetic_pe())
    e_lfanew = struct.unpack_from("<I", valid_pe, 0x3C)[0]
    struct.pack_into("<H", valid_pe, e_lfanew + 6, 120)  # NumberOfSections = 120
    insp_many_sec = inspect_pe_bytes(bytes(valid_pe))
    assert insp_many_sec.is_malformed is True
    assert "exceeds parser sanity limit" in insp_many_sec.malformed_reason

    # 5. Corrupt section raw size exceeding file size
    corrupt_sec = bytearray(build_synthetic_pe())
    opt_size = struct.unpack_from("<H", corrupt_sec, e_lfanew + 20)[0]
    first_sec_off = e_lfanew + 24 + opt_size
    struct.pack_into("<I", corrupt_sec, first_sec_off + 16, 0x05000000)  # Huge SizeOfRawData
    insp_corrupt_sec = inspect_pe_bytes(bytes(corrupt_sec))
    assert insp_corrupt_sec.is_malformed is True
    assert route_file("corrupt.exe", len(corrupt_sec), insp_corrupt_sec).status == FileStatus.MALFORMED


def test_pe_inspect_overlay_tls_and_certificate(tmp_path: Path) -> None:
    """Verify overlay, TLS callbacks, and certificate presence extraction."""
    pe_bytes = build_synthetic_pe(
        is_64bit=True,
        has_tls_callback=True,
        has_certificate=True,
        overlay_bytes=b"EXTRA_OVERLAY_DATA_12345",
    )
    f = tmp_path / "featured.exe"
    f.write_bytes(pe_bytes)
    insp = inspect_pe_file(f)
    assert insp.is_malformed is False
    assert insp.has_tls_callbacks is True
    assert insp.tls_callback_rva is not None
    assert insp.has_signature is True
    assert insp.signature_offset is not None
    assert insp.has_overlay is True
    assert insp.overlay_size > 0
