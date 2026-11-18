"""Deterministic synthetic PE32/PE32+ byte builder for unit tests and benign fixtures.

Constructs valid, minimal PE structures in memory without executing or compiling
any external code. Used by Phase 1-6 tests and fixtures/generate_fixtures.py.
"""

from __future__ import annotations

import struct
from typing import Optional

from coalscan.core.limits import (
    IMAGE_FILE_DLL,
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_I386,
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE,
    PE32_MAGIC,
    PE32_PLUS_MAGIC,
)


def build_synthetic_pe(
    *,
    is_64bit: bool = True,
    machine: Optional[int] = None,
    is_dll: bool = False,
    subsystem: int = 3,  # IMAGE_SUBSYSTEM_WINDOWS_CUI
    entry_point_rva: int = 0x1000,
    text_Flags: int = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | 0x00000020,
    text_data: bytes = b"\x48\x83\xEC\x28\x31\xC0\x48\x83\xC4\x28\xC3",
    extra_sections: Optional[list[tuple[bytes, int, bytes]]] = None,
    imports: Optional[list[tuple[str, list[str]]]] = None,
    has_clr: bool = False,
    has_tls_callback: bool = False,
    has_certificate: bool = False,
    overlay_bytes: bytes = b"",
) -> bytes:
    """Build a synthetic, structurally valid PE32 or PE32+ image in memory.

    Layout (file alignment 0x200, section alignment 0x1000):
    - 0x0000..0x0200: DOS header + PE signature + COFF header + Optional header + Section table
    - Section 1 (.text): RVA 0x1000, raw offset 0x0200
    - Section 2 (.rdata): RVA 0x2000, raw offset after .text (contains Import Table, CLR header, TLS dir if requested)
    - Extra sections: subsequent RVAs and raw offsets
    - Optional certificate table and/or trailing overlay bytes
    """
    if machine is None:
        machine = IMAGE_FILE_MACHINE_AMD64 if is_64bit else IMAGE_FILE_MACHINE_I386

    file_alignment = 0x200
    section_alignment = 0x1000
    image_base = 0x140000000 if is_64bit else 0x00400000

    def _align(val: int, alignment: int) -> int:
        rem = val % alignment
        return val if rem == 0 else val + (alignment - rem)

    # Prepare .text section
    text_raw_size = _align(max(len(text_data), 16), file_alignment)
    text_padded = text_data.ljust(text_raw_size, b"\x90")
    text_vsize = max(len(text_data), 0x100)

    # Prepare .rdata section for imports, CLR descriptor, and TLS directory
    rdata_vaddr = 0x2000
    rdata_buf = bytearray(0x1000)
    cursor = 0

    imp_dir_rva = 0
    imp_dir_size = 0
    clr_dir_rva = 0
    clr_dir_size = 0
    tls_dir_rva = 0
    tls_dir_size = 0

    ptr_size = 8 if is_64bit else 4
    ptr_fmt = "<Q" if is_64bit else "<I"

    if imports:
        num_dlls = len(imports)
        imp_dir_rva = rdata_vaddr + cursor
        # Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes + 1 null terminator descriptor
        imp_desc_table_size = (num_dlls + 1) * 20
        imp_dir_size = imp_desc_table_size
        desc_offset = cursor
        cursor += imp_desc_table_size

        for dll_idx, (dll_name, fn_names) in enumerate(imports):
            # Align cursor to 8 bytes
            cursor = _align(cursor, 8)
            ilt_rva = rdata_vaddr + cursor
            num_fns = len(fn_names)
            ilt_offset = cursor
            cursor += (num_fns + 1) * ptr_size

            iat_rva = rdata_vaddr + cursor
            iat_offset = cursor
            cursor += (num_fns + 1) * ptr_size

            for fn_idx, fn_name in enumerate(fn_names):
                hint_name_rva = rdata_vaddr + cursor
                fn_bytes = fn_name.encode("ascii") + b"\x00"
                # 2-byte hint (0) + ASCII function name + null byte
                struct.pack_into("<H", rdata_buf, cursor, 0)
                rdata_buf[cursor + 2 : cursor + 2 + len(fn_bytes)] = fn_bytes
                cursor += 2 + len(fn_bytes)
                if cursor % 2 != 0:
                    cursor += 1
                struct.pack_into(ptr_fmt, rdata_buf, ilt_offset + fn_idx * ptr_size, hint_name_rva)
                struct.pack_into(ptr_fmt, rdata_buf, iat_offset + fn_idx * ptr_size, hint_name_rva)

            dll_bytes = dll_name.encode("ascii") + b"\x00"
            dll_rva = rdata_vaddr + cursor
            rdata_buf[cursor : cursor + len(dll_bytes)] = dll_bytes
            cursor += len(dll_bytes)

            # Write IMAGE_IMPORT_DESCRIPTOR: OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk
            struct.pack_into(
                "<IIIII",
                rdata_buf,
                desc_offset + dll_idx * 20,
                ilt_rva,
                0,
                0,
                dll_rva,
                iat_rva,
            )

    if has_clr:
        cursor = _align(cursor, 8)
        clr_dir_rva = rdata_vaddr + cursor
        clr_dir_size = 72  # IMAGE_COR20_HEADER size
        struct.pack_into("<IIHHII", rdata_buf, cursor, 72, 2, 5, 0, 0x1000, 0x20)
        cursor += clr_dir_size

    if has_tls_callback:
        cursor = _align(cursor, 8)
        cb_array_rva = rdata_vaddr + cursor
        # Callback pointing to .text start (image_base + 0x1000) followed by null terminator
        struct.pack_into(ptr_fmt, rdata_buf, cursor, image_base + 0x1000)
        struct.pack_into(ptr_fmt, rdata_buf, cursor + ptr_size, 0)
        cursor += ptr_size * 2

        tls_dir_rva = rdata_vaddr + cursor
        if is_64bit:
            tls_dir_size = 40
            struct.pack_into(
                "<QQQQII",
                rdata_buf,
                cursor,
                image_base + rdata_vaddr,
                image_base + rdata_vaddr + 8,
                image_base + rdata_vaddr + 16,
                image_base + cb_array_rva,
                0,
                0,
            )
        else:
            tls_dir_size = 24
            struct.pack_into(
                "<IIIIII",
                rdata_buf,
                cursor,
                image_base + rdata_vaddr,
                image_base + rdata_vaddr + 4,
                image_base + rdata_vaddr + 8,
                image_base + cb_array_rva,
                0,
                0,
            )
        cursor += tls_dir_size

    sections_to_build: list[tuple[bytes, int, int, bytes, int]] = []
    # (name_8b, vaddr, vsize, raw_bytes, characteristics)
    sections_to_build.append((b".text\x00\x00\x00", 0x1000, text_vsize, text_padded, text_Flags))

    if cursor > 0:
        rdata_raw_size = _align(cursor, file_alignment)
        rdata_bytes = bytes(rdata_buf[:rdata_raw_size])
        sections_to_build.append(
            (
                b".rdata\x00\x00",
                rdata_vaddr,
                max(cursor, 0x100),
                rdata_bytes,
                IMAGE_SCN_MEM_READ | 0x00000040,
            )
        )

    next_vaddr = 0x3000 if cursor > 0 else 0x2000
    if extra_sections:
        for sec_name, sec_chars, sec_payload in extra_sections:
            name_padded = sec_name[:8].ljust(8, b"\x00")
            raw_sz = _align(max(len(sec_payload), 1), file_alignment)
            raw_bytes = sec_payload.ljust(raw_sz, b"\x00")
            v_sz = max(len(sec_payload), 0x100)
            sections_to_build.append((name_padded, next_vaddr, v_sz, raw_bytes, sec_chars))
            next_vaddr += _align(v_sz, section_alignment)

    num_sections = len(sections_to_build)
    opt_header_size = 240 if is_64bit else 224
    e_lfanew = 0x80
    headers_end = e_lfanew + 4 + 20 + opt_header_size + (num_sections * 40)
    size_of_headers = _align(headers_end, file_alignment)

    # Compute raw offsets for all sections
    raw_cursor = size_of_headers
    section_headers = bytearray()
    section_bodies = bytearray()
    for name_8b, vaddr, vsize, raw_bytes, chars in sections_to_build:
        raw_sz = len(raw_bytes)
        sec_hdr = struct.pack(
            "<8sIIIIIIHHI",
            name_8b,
            vsize,
            vaddr,
            raw_sz,
            raw_cursor,
            0,
            0,
            0,
            0,
            chars,
        )
        section_headers.extend(sec_hdr)
        section_bodies.extend(raw_bytes)
        raw_cursor += raw_sz

    size_of_image = next_vaddr

    # Optional certificate table after mapped sections
    cert_offset = 0
    cert_size = 0
    cert_blob = b""
    if has_certificate:
        cert_offset = raw_cursor
        # WIN_CERTIFICATE header (dwLength=16, wRevision=0x0200, wCertificateType=2, 8 dummy bytes)
        cert_blob = struct.pack("<IHH8s", 16, 0x0200, 0x0002, b"TESTCERT")
        cert_size = len(cert_blob)
        raw_cursor += cert_size

    # Build DOS Header
    dos_header = bytearray(e_lfanew)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, e_lfanew)

    # Build COFF File Header
    characteristics = 0x0002 | (0x0020 if is_64bit else 0x0100)
    if is_dll:
        characteristics |= IMAGE_FILE_DLL
    coff_header = struct.pack(
        "<HHIIIHH",
        machine,
        num_sections,
        0x65000000,
        0,
        0,
        opt_header_size,
        characteristics,
    )

    # Build Optional Header
    data_dirs = [(0, 0)] * 16
    if imp_dir_rva:
        data_dirs[1] = (imp_dir_rva, imp_dir_size)
    if cert_offset:
        data_dirs[4] = (cert_offset, cert_size)
    if tls_dir_rva:
        data_dirs[9] = (tls_dir_rva, tls_dir_size)
    if clr_dir_rva:
        data_dirs[14] = (clr_dir_rva, clr_dir_size)

    if is_64bit:
        opt_fixed = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            PE32_PLUS_MAGIC,
            14,
            0,
            len(text_padded),
            0,
            0,
            entry_point_rva,
            0x1000,
            image_base,
            section_alignment,
            file_alignment,
            6,
            0,
            0,
            0,
            6,
            0,
            0,
            size_of_image,
            size_of_headers,
            0,
            subsystem,
            0x8160,
            0x100000,
            0x1000,
            0x100000,
            0x1000,
            0,
            16,
        )
    else:
        opt_fixed = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            PE32_MAGIC,
            14,
            0,
            len(text_padded),
            0,
            0,
            entry_point_rva,
            0x1000,
            rdata_vaddr,
            image_base,
            section_alignment,
            file_alignment,
            6,
            0,
            0,
            0,
            6,
            0,
            0,
            size_of_image,
            size_of_headers,
            0,
            subsystem,
            0x8140,
            0x100000,
            0x1000,
            0x100000,
            0x1000,
            0,
            16,
        )

    dir_bytes = b"".join(struct.pack("<II", rva, sz) for rva, sz in data_dirs)
    opt_header = opt_fixed + dir_bytes

    full_headers = bytes(dos_header) + b"PE\x00\x00" + coff_header + opt_header + bytes(section_headers)
    padded_headers = full_headers.ljust(size_of_headers, b"\x00")

    return padded_headers + bytes(section_bodies) + cert_blob + overlay_bytes
