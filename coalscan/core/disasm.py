"""Bounded disassembly engine using Capstone and student x86-64 subset decoder.

Implements Section 1 ('Disassembly is bounded, not whole-file'):
1. Up to 256 bytes at the entry point (skipped if no entry point).
2. Up to 128 bytes around each evidence location inside an executable section,
   at most 3 locations per file.
3. Never more than 2,000 instructions per file across all regions combined.
Maps RVAs to file offsets through the validated section table and notes truncation.
"""

from __future__ import annotations

from typing import Optional

import capstone

from coalscan.core.limits import (
    MAX_DISASM_INSTRUCTIONS_PER_FILE,
    MAX_ENTRY_DISASM_BYTES,
    MAX_EVIDENCE_DISASM_BYTES,
    MAX_EVIDENCE_LOCATIONS_PER_FILE,
)
from coalscan.core.models import (
    DisasmInstruction,
    DisasmRegion,
    PEInspectionResult,
    RouteDecision,
    RuleFinding,
    SectionInfo,
)
from coalscan.decoder.x64_subset import decode_instruction


def _find_executable_section_for_rva(
    rva: int, sections: list[SectionInfo]
) -> Optional[SectionInfo]:
    """Return the executable SectionInfo containing `rva`, or None."""
    if rva <= 0:
        return None
    for sec in sections:
        if not sec.is_executable:
            continue
        span = max(sec.virtual_size, sec.raw_size)
        if sec.virtual_address <= rva < sec.virtual_address + span:
            delta = rva - sec.virtual_address
            if delta < sec.raw_size:
                return sec
    return None


def _find_executable_section_for_offset(
    file_offset: int, sections: list[SectionInfo]
) -> Optional[SectionInfo]:
    """Return the executable SectionInfo containing `file_offset`, or None."""
    if file_offset < 0:
        return None
    for sec in sections:
        if not sec.is_executable:
            continue
        if sec.raw_offset <= file_offset < sec.raw_offset + sec.raw_size:
            return sec
    return None


def disassemble_bounded_regions(
    data: bytes,
    inspection: PEInspectionResult,
    route: RouteDecision,
    findings: list[RuleFinding],
    max_entry_bytes: int = MAX_ENTRY_DISASM_BYTES,
    max_evidence_bytes: int = MAX_EVIDENCE_DISASM_BYTES,
    max_evidence_locations: int = MAX_EVIDENCE_LOCATIONS_PER_FILE,
    max_total_instructions: int = MAX_DISASM_INSTRUCTIONS_PER_FILE,
) -> tuple[list[DisasmRegion], bool, str]:
    """Disassemble bounded regions of a PE image and return (regions, truncated, reason).

    Never disassembles whole files.
    """
    if not route.run_disassembly or route.capstone_arch_bits not in (32, 64):
        return [], False, ""

    mode = capstone.CS_MODE_64 if route.capstone_arch_bits == 64 else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)

    regions: list[DisasmRegion] = []
    total_instructions = 0
    overall_truncated = False
    overall_trunc_reason = ""
    seen_offsets: set[int] = set()

    def _disasm_slice(
        label: str,
        rva: int,
        file_offset: int,
        max_bytes: int,
        sec: SectionInfo,
    ) -> None:
        nonlocal total_instructions, overall_truncated, overall_trunc_reason

        if total_instructions >= max_total_instructions:
            overall_truncated = True
            overall_trunc_reason = (
                f"Reached per-file cap of {max_total_instructions} disassembled instructions"
            )
            return

        sec_end = min(sec.raw_offset + sec.raw_size, len(data))
        if file_offset < sec.raw_offset or file_offset >= sec_end:
            return

        slice_end = min(file_offset + max_bytes, sec_end)
        raw_slice = data[file_offset:slice_end]
        if not raw_slice:
            return

        va = inspection.image_base + rva
        region = DisasmRegion(
            label=label,
            rva=rva,
            file_offset=file_offset,
            virtual_address=va,
        )

        remaining_budget = max_total_instructions - total_instructions
        cs_insns = list(md.disasm(raw_slice, va))

        if len(cs_insns) > remaining_budget:
            cs_insns = cs_insns[:remaining_budget]
            region.truncated = True
            region.truncation_note = (
                f"Truncated at {max_total_instructions} instructions per-file limit"
            )
            overall_truncated = True
            overall_trunc_reason = region.truncation_note

        for insn in cs_insns:
            rel = insn.address - va
            insn_file_off = file_offset + rel
            raw_insn_bytes = bytes(insn.bytes)
            comment = ""
            if route.capstone_arch_bits == 64:
                student = decode_instruction(raw_insn_bytes, address=insn.address)
                if student.supported and student.memory_address is not None:
                    comment = f"reads 0x{student.memory_address:X}"
                elif student.supported and student.branch_target is not None:
                    comment = f"target 0x{student.branch_target:X}"

            region.instructions.append(
                DisasmInstruction(
                    address=insn.address,
                    file_offset=insn_file_off,
                    size=insn.size,
                    bytes_hex=raw_insn_bytes.hex(" "),
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                    comment=comment,
                )
            )
            total_instructions += 1

        if region.instructions:
            regions.append(region)
            seen_offsets.add(file_offset)

    # 1. Up to 256 bytes at the entry point (if present and inside an executable section)
    if inspection.entry_point_rva != 0 and inspection.entry_point_offset is not None:
        ep_sec = _find_executable_section_for_rva(
            inspection.entry_point_rva, inspection.sections
        )
        if ep_sec is not None:
            _disasm_slice(
                label=f"Entry point (RVA 0x{inspection.entry_point_rva:X}, {ep_sec.name})",
                rva=inspection.entry_point_rva,
                file_offset=inspection.entry_point_offset,
                max_bytes=max_entry_bytes,
                sec=ep_sec,
            )

    # 2. Up to 128 bytes around each evidence location inside an executable section (at most 3)
    evidence_count = 0
    for finding in findings:
        if evidence_count >= max_evidence_locations:
            break

        target_sec: Optional[SectionInfo] = None
        target_off: Optional[int] = None
        target_rva: Optional[int] = None

        if finding.rva is not None and finding.rva > 0:
            target_sec = _find_executable_section_for_rva(finding.rva, inspection.sections)
            if target_sec is not None:
                target_rva = finding.rva
                target_off = target_sec.raw_offset + (finding.rva - target_sec.virtual_address)

        if target_sec is None and finding.file_offset is not None:
            target_sec = _find_executable_section_for_offset(
                finding.file_offset, inspection.sections
            )
            if target_sec is not None:
                target_off = finding.file_offset
                target_rva = target_sec.virtual_address + (
                    finding.file_offset - target_sec.raw_offset
                )

        if target_sec is not None and target_off is not None and target_rva is not None:
            if target_off not in seen_offsets:
                _disasm_slice(
                    label=f"Evidence {finding.rule_id} ({finding.location_label})",
                    rva=target_rva,
                    file_offset=target_off,
                    max_bytes=max_evidence_bytes,
                    sec=target_sec,
                )
                evidence_count += 1

    return regions, overall_truncated, overall_trunc_reason
