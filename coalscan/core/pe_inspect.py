"""Static PE header, section, import, overlay, TLS, and certificate inspection.

Reads raw bytes using pefile and structural checks without ever launching,
importing, or loading the binary into the OS loader.
"""

from __future__ import annotations

from collections import Counter
import math
from pathlib import Path
import struct
from typing import Optional, Union

import pefile

from coalscan.core.limits import (
    CLR_DATA_DIRECTORY_INDEX,
    DOS_HEADER_MIN_SIZE,
    IMAGE_FILE_DLL,
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_ARM,
    IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_ARMNT,
    IMAGE_FILE_MACHINE_I386,
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE,
    IMAGE_SUBSYSTEM_NATIVE,
    LFANEW_OFFSET,
    MAX_FILE_SIZE_BYTES,
    MAX_IMPORT_ENTRIES,
    MAX_SECTIONS,
    MZ_SIGNATURE,
    PE32_MAGIC,
    PE32_PLUS_MAGIC,
    PE_SIGNATURE,
    SECURITY_DATA_DIRECTORY_INDEX,
    TLS_DATA_DIRECTORY_INDEX,
)
from coalscan.core.models import (
     ImportInfo,
    PEInspectionResult,
    SectionInfo,
    escape_untrusted_text,
)


def compute_shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits per byte (range 0.0 to 8.0)."""
    length = len(data)
    if length == 0:
        return 0.0
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def map_Machine_to_arch(machine: int) -> str:
    """Return a human-readable architecture label for IMAGE_FILE_HEADER.Machine."""
    if machine == IMAGE_FILE_MACHINE_I386:
        return "x86"
    if machine == IMAGE_FILE_MACHINE_AMD64:
        return "x64"
    if machine == IMAGE_FILE_MACHINE_ARM64:
        return "ARM64"
    if machine in (IMAGE_FILE_MACHINE_ARM, IMAGE_FILE_MACHINE_ARMNT):
        return "ARM"
    return f"Other (0x{machine:04X})"


def rva_to_file_offset(rva: int, sections: list[SectionInfo]) -> Optional[int]:
    """Map an RVA to a raw file offset using the validated section table."""
    if rva <= 0:
        return None
    for sec in sections:
        sec_span = max(sec.virtual_size, sec.raw_size)
        if sec.virtual_address <= rva < sec.virtual_address + sec_span:
            delta = rva - sec.virtual_address
            if delta < sec.raw_size:
                return sec.raw_offset + delta
            return None
    return None


def inspect_pe_bytes(data: bytes) -> PEInspectionResult:
    """Statically inspect raw file bytes and return a PEInspectionResult.

    Distinguishes between:
    - Not a PE file (missing MZ or non-PE signature)
    - Malformed PE file (zero-byte, truncated headers, corrupt section table,
      invalid offsets, huge declared sizes, or exceeding parser sanity limits)
    - Valid PE file with extracted headers, sections, imports, overlay, TLS, and cert presence
    """
    result = PEInspectionResult()
    file_len = len(data)

    if file_len > MAX_FILE_SIZE_BYTES:
        result.is_malformed = True
        result.malformed_reason = (
            f"Buffer size ({file_len} bytes) exceeds limit ({MAX_FILE_SIZE_BYTES} bytes)"
        )
        return result

    # 1. Zero-byte check
    if file_len == 0:
        result.is_malformed = True
        result.malformed_reason = "Zero-byte file"
        return result

    # 2. Check MZ signature
    if len(data) < 2 or data[:2] != MZ_SIGNATURE:
        result.is_pe = False
        result.not_pe_reason = "Missing MZ header signature"
        return result

    # 3. Minimum DOS header size to read e_lfanew at 0x3C
    if file_len < DOS_HEADER_MIN_SIZE:
        result.is_malformed = True
        result.malformed_reason = (
            f"Truncated DOS header ({file_len} bytes, need at least {DOS_HEADER_MIN_SIZE} bytes)"
        )
        return result

    e_lfanew = struct.unpack_from("<I", data, LFANEW_OFFSET)[0]
    if e_lfanew == 0:
        result.is_pe = False
        result.not_pe_reason = "Invalid e_lfanew offset (0)"
        return result

    if e_lfanew + 4 > file_len:
        result.is_malformed = True
        result.malformed_reason = (
            f"Invalid e_lfanew offset (0x{e_lfanew:X}) points beyond file size ({file_len} bytes)"
        )
        return result

    # 4. Check PE\0\0 signature
    pe_sig = data[e_lfanew : e_lfanew + 4]
    if pe_sig != PE_SIGNATURE:
        result.is_pe = False
        result.not_pe_reason = "Missing valid PE\\0\\0 signature"
        return result

    # Once MZ and PE\0\0 are present, the file claims to be a PE file.
    result.is_pe = True

    # 5. Pre-validate COFF File Header (20 bytes after PE\0\0)
    coff_offset = e_lfanew + 4
    if coff_offset + 20 > file_len:
        result.is_malformed = True
        result.malformed_reason = "Truncated COFF file header"
        return result

    machine, num_sections, _, _, _, size_of_opt_header, characteristics = struct.unpack_from(
        "<HHIIIHH", data, coff_offset
    )
    result.machine = machine
    result.architecture = map_Machine_to_arch(machine)
    result.characteristics = characteristics
    result.is_dll = bool(characteristics & IMAGE_FILE_DLL)
    result.num_sections = num_sections

    if num_sections > MAX_SECTIONS:
        result.is_malformed = True
        result.malformed_reason = (
            f"Section count ({num_sections}) exceeds parser sanity limit ({MAX_SECTIONS})"
        )
        return result

    if size_of_opt_header < 24:
        result.is_malformed = True
        result.malformed_reason = (
            f"Optional header size ({size_of_opt_header} bytes) is too small"
        )
        return result

    opt_offset = coff_offset + 20
    if opt_offset + size_of_opt_header > file_len:
        result.is_malformed = True
        result.malformed_reason = "Truncated Optional Header"
        return result

    opt_magic = struct.unpack_from("<H", data, opt_offset)[0]
    if opt_magic == PE32_MAGIC:
        result.pe_format = "PE32"
        result.is_64bit = False
    elif opt_magic == PE32_PLUS_MAGIC:
        result.pe_format = "PE32+"
        result.is_64bit = True
    else:
        result.is_malformed = True
        result.malformed_reason = f"Invalid Optional Header Magic (0x{opt_magic:04X})"
        return result

    # 6. Pre-validate Section Table bounds (40 bytes per section header)
    sec_table_offset = opt_offset + size_of_opt_header
    sec_table_end = sec_table_offset + (num_sections * 40)
    if sec_table_end > file_len:
        result.is_malformed = True
        result.malformed_reason = (
            f"Truncated section table (needs {sec_table_end} bytes, file is {file_len} bytes)"
        )
        return result

    # Validate each section's raw offset/size before full pefile parsing
    for idx in range(num_sections):
        entry_off = sec_table_offset + idx * 40
        raw_name = data[entry_off : entry_off + 8].split(b"\x00", 1)[0]
        sec_name = escape_untrusted_text(raw_name.decode("latin-1", errors="replace"), max_len=32)
        v_size, v_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, entry_off + 8)

        # Check huge or out-of-bounds raw offsets/sizes
        if raw_size > 0:
            if raw_ptr > file_len or raw_ptr + raw_size > file_len:
                result.is_malformed = True
                result.malformed_reason = (
                    f"Section '{sec_name}' raw bounds (offset 0x{raw_ptr:X}, size 0x{raw_size:X}) "
                    f"exceed file size ({file_len} bytes)"
                )
                return result
        elif raw_ptr > file_len:
            result.is_malformed = True
            result.malformed_reason = (
                f"Section '{sec_name}' raw pointer (0x{raw_ptr:X}) exceeds file size ({file_len} bytes)"
            )
            return result

        # Check absurd virtual size (> 1 GB)
        if v_size > 0x40000000:
            result.is_malformed = True
            result.malformed_reason = (
                f"Section '{sec_name}' declares excessive virtual size (0x{v_size:X})"
            )
            return result

    # 7. Parse with pefile (fast_load=True first so we control directory parsing safely)
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        result.is_malformed = True
        result.malformed_reason = f"PEFormatError: {escape_untrusted_text(str(exc), max_len=160)}"
        return result
    except Exception as exc:
        result.is_malformed = True
        result.malformed_reason = (
            f"Unexpected parser error: {escape_untrusted_text(str(exc), max_len=160)}"
        )
        return result

    try:
        opt = pe.OPTIONAL_HEADER
        result.subsystem = int(getattr(opt, "Subsystem", 0))
        result.is_native_subsystem = result.subsystem == IMAGE_SUBSYSTEM_NATIVE
        result.image_base = int(getattr(opt, "ImageBase", 0))
        result.entry_point_rva = int(getattr(opt, "AddressOfEntryPoint", 0))

        # Validate SizeOfImage sanity
        size_of_image = int(getattr(opt, "SizeOfImage", 0))
        if size_of_image == 0 or size_of_image > 0x80000000:
            result.is_malformed = True
            result.malformed_reason = f"Invalid SizeOfImage (0x{size_of_image:X}) in Optional Header"
            return result

        # Extract sections
        sections: list[SectionInfo] = []
        max_section_raw_end = sec_table_end
        for sec in pe.sections:
            raw_name = sec.Name.split(b"\x00", 1)[0].decode("latin-1", errors="replace")
            safe_name = escape_untrusted_text(raw_name, max_len=32)
            v_addr = int(sec.VirtualAddress)
            v_size = int(sec.Misc_VirtualSize)
            r_off = int(sec.PointerToRawData)
            r_size = int(sec.SizeOfRawData)
            chars = int(sec.Characteristics)

            sec_bytes = data[r_off : r_off + r_size] if r_size > 0 else b""
            entropy = compute_shannon_entropy(sec_bytes)
            is_exec = bool(chars & IMAGE_SCN_MEM_EXECUTE)
            is_write = bool(chars & IMAGE_SCN_MEM_WRITE)
            is_read = bool(chars & IMAGE_SCN_MEM_READ)

            if r_size > 0 and r_off + r_size > max_section_raw_end:
                max_section_raw_end = r_off + r_size

            sections.append(
                SectionInfo(
                    name=safe_name,
                    virtual_address=v_addr,
                    virtual_size=v_size,
                    raw_offset=r_off,
                    raw_size=r_size,
                    characteristics=chars,
                    entropy=entropy,
                    is_executable=is_exec,
                    is_writable=is_write,
                    is_readable=is_read,
                )
            )
        result.sections = sections

        # Check entry point location against sections
        if result.entry_point_rva != 0:
            result.entry_point_offset = rva_to_file_offset(result.entry_point_rva, sections)
            for sec in sections:
                sec_span = max(sec.virtual_size, sec.raw_size)
                if sec.virtual_address <= result.entry_point_rva < sec.virtual_address + sec_span:
                    result.entry_point_section_name = sec.name
                    if sec.is_executable:
                        result.entry_point_in_exec_section = True
                    break

        # Inspect Data Directories
        data_dirs = list(getattr(opt, "DATA_DIRECTORY", []))

        # Helper to validate RVA-based data directories
        def _is_rva_valid(rva: int) -> bool:
            if rva == 0:
                return True
            if rva_to_file_offset(rva, sections) is not None:
                return True
            # Allow header-resident RVAs if within SizeOfHeaders
            size_of_headers = int(getattr(opt, "SizeOfHeaders", sec_table_end))
            return 0 < rva < min(size_of_headers, file_len)

        # Check Import Directory (index 1) validity before parsing
        if len(data_dirs) > 1:
            imp_dir = data_dirs[1]
            if imp_dir.VirtualAddress != 0 and imp_dir.Size != 0:
                if not _is_rva_valid(int(imp_dir.VirtualAddress)):
                    result.is_malformed = True
                    result.malformed_reason = (
                        f"Import directory RVA (0x{imp_dir.VirtualAddress:X}) does not map to file data"
                    )
                    return result

        # Check Security / Certificate Directory (index 4 - file offset, not RVA!)
        if len(data_dirs) > SECURITY_DATA_DIRECTORY_INDEX:
            sec_dir = data_dirs[SECURITY_DATA_DIRECTORY_INDEX]
            cert_off = int(sec_dir.VirtualAddress)
            cert_size = int(sec_dir.Size)
            if cert_off != 0 or cert_size != 0:
                if cert_off <= 0 or cert_size <= 0 or cert_off + cert_size > file_len:
                    result.is_malformed = True
                    result.malformed_reason = (
                        f"Security directory bounds (offset 0x{cert_off:X}, size 0x{cert_size:X}) "
                        f"are invalid for file size ({file_len} bytes)"
                    )
                    return result
                result.has_signature = True
                result.signature_offset = cert_off
                result.signature_size = cert_size

        # Check TLS Directory (index 9)
        if len(data_dirs) > TLS_DATA_DIRECTORY_INDEX:
            tls_dir = data_dirs[TLS_DATA_DIRECTORY_INDEX]
            if tls_dir.VirtualAddress != 0 and tls_dir.Size != 0:
                if not _is_rva_valid(int(tls_dir.VirtualAddress)):
                    result.is_malformed = True
                    result.malformed_reason = (
                        f"TLS directory RVA (0x{tls_dir.VirtualAddress:X}) does not map to file data"
                    )
                    return result

        # Check CLR / .NET Directory (index 14)
        if len(data_dirs) > CLR_DATA_DIRECTORY_INDEX:
            clr_dir = data_dirs[CLR_DATA_DIRECTORY_INDEX]
            if clr_dir.VirtualAddress != 0 and clr_dir.Size != 0:
                if not _is_rva_valid(int(clr_dir.VirtualAddress)):
                    result.is_malformed = True
                    result.malformed_reason = (
                        f"CLR directory RVA (0x{clr_dir.VirtualAddress:X}) does not map to file data"
                    )
                    return result
                result.has_clr_header = True
                result.clr_rva = int(clr_dir.VirtualAddress)
                result.clr_size = int(clr_dir.Size)

        # Parse Import and TLS directories via pefile
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
            ]
        )

        # Extract imports and enforce MAX_IMPORT_ENTRIES
        imports: list[ImportInfo] = []
        total_imports = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                raw_dll = entry.dll.decode("latin-1", errors="replace") if entry.dll else ""
                dll_name = escape_untrusted_text(raw_dll, max_len=128)
                for imp in entry.imports:
                    total_imports += 1
                    if total_imports > MAX_IMPORT_ENTRIES:
                        result.is_malformed = True
                        result.malformed_reason = (
                            f"Import entry count exceeds parser sanity limit ({MAX_IMPORT_ENTRIES})"
                        )
                        return result
                    if imp.name:
                        raw_fn = imp.name.decode("latin-1", errors="replace")
                    elif imp.ordinal is not None:
                        raw_fn = f"ordinal_{imp.ordinal}"
                    else:
                        raw_fn = "unknown"
                    fn_name = escape_untrusted_text(raw_fn, max_len=128)
                    iat_addr = int(imp.address) if imp.address else 0
                    iat_rva = (
                        iat_addr - result.image_base
                        if iat_addr >= result.image_base > 0
                        else iat_addr
                    )
                    imp_offset = rva_to_file_offset(iat_rva, sections)
                    imports.append(
                        ImportInfo(
                            dll_name=dll_name,
                            function_name=fn_name,
                            iat_rva=iat_rva,
                            file_offset=imp_offset,
                        )
                    )
        result.imports = imports
        result.total_import_count = total_imports

        # Extract TLS callback presence
        if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS is not None:
            tls_struct = pe.DIRECTORY_ENTRY_TLS.struct
            callbacks_va = int(getattr(tls_struct, "AddressOfCallBacks", 0))
            if callbacks_va != 0:
                callbacks_rva = (
                    callbacks_va - result.image_base
                    if callbacks_va >= result.image_base > 0
                    else callbacks_va
                )
                cb_offset = rva_to_file_offset(callbacks_rva, sections)
                ptr_size = 8 if result.is_64bit else 4
                ptr_fmt = "<Q" if result.is_64bit else "<I"
                if cb_offset is not None and cb_offset + ptr_size <= file_len:
                    first_cb = struct.unpack_from(ptr_fmt, data, cb_offset)[0]
                    if first_cb != 0:
                        result.has_tls_callbacks = True
                        first_cb_rva = (
                            first_cb - result.image_base
                            if first_cb >= result.image_base > 0
                            else first_cb
                        )
                        result.tls_callback_rva = first_cb_rva
                        result.tls_callback_offset = (
                            rva_to_file_offset(first_cb_rva, sections) or cb_offset
                        )
                        result.tls_callbacks_count = 1

        # Overlay detection: bytes after the end of the last mapped section
        # Note: if a file has sections and file_len > max_section_raw_end, check if it exceeds mapped data
        if num_sections > 0 and file_len > max_section_raw_end:
            # Exclude security certificate bytes if the overlay is solely the certificate table,
            # or report overlay if non-certificate appended bytes exist (or if no cert covers it).
            overlay_start = max_section_raw_end
            overlay_len = file_len - overlay_start
            if result.has_signature and result.signature_offset == overlay_start and result.signature_size == overlay_len:
                # Appended bytes are exclusively the certificate table (R14)
                pass
            elif overlay_len > 0:
                result.has_overlay = True
                result.overlay_offset = overlay_start
                result.overlay_size = overlay_len
    finally:
        pe.close()

    return result


def inspect_pe_file(file_path: Union[str, Path]) -> PEInspectionResult:
    """Read a file safely within MAX_FILE_SIZE_BYTES and inspect its PE structure."""
    path = Path(file_path)
    file_size = path.stat().st_size
    if file_size > MAX_FILE_SIZE_BYTES:
        res = PEInspectionResult()
        res.is_malformed = True
        res.malformed_reason = (
            f"File size ({file_size} bytes) exceeds limit ({MAX_FILE_SIZE_BYTES} bytes)"
        )
        return res
    data = path.read_bytes()
    return inspect_pe_bytes(data)
