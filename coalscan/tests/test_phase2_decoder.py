"""Phase 2 tests: student x86-64 subset decoder, worked examples, and 100-vector Capstone oracle."""

from __future__ import annotations

from collections import Counter

import capstone
import pytest

from coalscan.decoder.vectors import DECODER_VECTORS_100, DecoderVector
from coalscan.decoder.x64_subset import (
    compare_function_with_capstone,
    decode_instruction,
    normalize_capstone_family,
)


def test_required_worked_examples() -> None:
    """Verify the 4 required worked examples from Section 4 of the specification."""
    # Example 1: FF 15 10 00 00 00 at 0x140001000 -> call qword ptr [rip+0x10], len 6, next 0x140001006, addr 0x140001016
    ex1 = decode_instruction(bytes.fromhex("FF 15 10 00 00 00"), address=0x140001000)
    assert ex1.supported is True
    assert ex1.length == 6
    assert ex1.mnemonic == "call"
    assert ex1.mnemonic_family == "CALL"
    assert ex1.text == "call qword ptr [rip+0x10]"
    assert ex1.next_rip == 0x140001006
    assert ex1.memory_address == 0x140001016

    # Example 2: 48 89 5C 24 08 -> mov qword ptr [rsp+8], rbx, length 5
    ex2 = decode_instruction(bytes.fromhex("48 89 5C 24 08"), address=0x140001000)
    assert ex2.supported is True
    assert ex2.length == 5
    assert ex2.mnemonic == "mov"
    assert ex2.mnemonic_family == "MOV"
    assert ex2.text == "mov qword ptr [rsp+8], rbx"

    # Example 3: 8B 04 25 78 56 34 12 -> mov eax, dword ptr [0x12345678], length 7
    ex3 = decode_instruction(bytes.fromhex("8B 04 25 78 56 34 12"), address=0x140001000)
    assert ex3.supported is True
    assert ex3.length == 7
    assert ex3.mnemonic == "mov"
    assert ex3.mnemonic_family == "MOV"
    assert ex3.text == "mov eax, dword ptr [0x12345678]"

    # Example 4: 74 05 at 0x140001000 -> je 0x140001007, length 2
    ex4 = decode_instruction(bytes.fromhex("74 05"), address=0x140001000)
    assert ex4.supported is True
    assert ex4.length == 2
    assert ex4.mnemonic == "je"
    assert ex4.mnemonic_family == "Jcc"
    assert ex4.text == "je 0x140001007"
    assert ex4.branch_target == 0x140001007


def test_100_vectors_category_distribution() -> None:
    """Verify the 100 test vectors match the exact distribution in Section 6."""
    assert len(DECODER_VECTORS_100) == 100
    counts = Counter(v.category for v in DECODER_VECTORS_100)
    assert counts["reg_direct"] == 12
    assert counts["mem_modrm"] == 14
    assert counts["sib"] == 14
    assert counts["rip_relative"] == 10
    assert counts["rex"] == 12
    assert counts["immediate"] == 12
    assert counts["branch"] == 12
    assert counts["stack_ret"] == 6
    assert counts["unsupported"] == 4
    assert counts["truncated"] == 4


@pytest.mark.parametrize("vec", DECODER_VECTORS_100, ids=lambda v: f"{v.vec_id}_{v.category}")
def test_100_vectors_against_capstone(vec: DecoderVector) -> None:
    """Verify 100% length and mnemonic-family agreement with Capstone on all 92 supported vectors
    and explicit rejection on all 8 reject vectors."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    res = decode_instruction(vec.raw_bytes, address=vec.address)

    if vec.expected_supported:
        assert res.supported is True, f"{vec.vec_id} failed: {res.rejection_reason}"
        assert res.length == vec.expected_length
        assert res.mnemonic_family == vec.expected_family

        # Compare against Capstone 64-bit oracle
        cs_insns = list(md.disasm(vec.raw_bytes, vec.address, count=1))
        assert len(cs_insns) == 1, f"Capstone failed to disassemble {vec.vec_id}"
        cs_insn = cs_insns[0]

        assert res.length == cs_insn.size, (
            f"{vec.vec_id} length mismatch: student={res.length} vs capstone={cs_insn.size}"
        )
        cs_family = normalize_capstone_family(cs_insn.mnemonic)
        assert res.mnemonic_family == cs_family, (
            f"{vec.vec_id} family mismatch: student={res.mnemonic_family} vs capstone={cs_family}"
        )
    else:
        assert res.supported is False, f"{vec.vec_id} should have been rejected"
        assert res.length == 0
        assert res.rejection_reason is not None and len(res.rejection_reason) > 0


def test_additional_stack_and_alu_forms() -> None:
    """Test PUSH imm8/imm32, POP r/m64 (8F /0), JMP r/m64 (FF /4), and rejected subopcodes."""
    # 68 id: push imm32
    p32 = decode_instruction(bytes.fromhex("68 00 10 00 00"))
    assert p32.supported and p32.length == 5 and p32.mnemonic_family == "PUSH"

    # 6A ib: push imm8
    p8 = decode_instruction(bytes.fromhex("6A 08"))
    assert p8.supported and p8.length == 2 and p8.mnemonic_family == "PUSH"

    # 8F /0: pop r/m64
    pop_mem = decode_instruction(bytes.fromhex("8F 00"))
    assert pop_mem.supported and pop_mem.length == 2 and pop_mem.mnemonic_family == "POP"

    # 8F /1: invalid POP subopcode -> rejected
    bad_pop = decode_instruction(bytes.fromhex("8F 08"))
    assert not bad_pop.supported and "only /0 is POP" in (bad_pop.rejection_reason or "")

    # FF /4: jmp r/m64
    jmp_reg = decode_instruction(bytes.fromhex("FF E0"))
    assert jmp_reg.supported and jmp_reg.length == 2 and jmp_reg.mnemonic_family == "JMP"

    # FF /0 (INC) is outside subset -> rejected
    bad_ff = decode_instruction(bytes.fromhex("FF 00"))
    assert not bad_ff.supported and "Unsupported 0xFF subopcode" in (bad_ff.rejection_reason or "")


def test_whole_entry_function_comparison_with_capstone() -> None:
    """Verify whole-function stream comparison matches Capstone length on every instruction
    and marks non-subset instructions as 'out of subset' without failing."""
    # Realistic Windows x64 entry-point function prologue, body (with one LEA out-of-subset), and epilogue:
    # 48 89 5C 24 08       mov qword ptr [rsp+8], rbx
    # 57                   push rdi
    # 48 83 EC 20          sub rsp, 0x20
    # 48 8B D9             mov rbx, rcx
    # 48 8D 0D 20 10 00 00 lea rcx, [rip+0x1020]   <-- out of subset (0x8D)
    # FF 15 10 20 00 00    call qword ptr [rip+0x2010]
    # 85 C0                test eax, eax           <-- out of subset (0x85)
    # 74 07                je +7
    # B8 01 00 00 00       mov eax, 1
    # EB 02                jmp +2
    # 31 C0                xor eax, eax
    # 48 8B 5C 24 30       mov rbx, qword ptr [rsp+0x30]
    # 48 83 C4 20          add rsp, 0x20
    # 5F                   pop rdi
    # C3                   ret
    func_bytes = bytes.fromhex(
        "48 89 5C 24 08 "
        "57 "
        "48 83 EC 20 "
        "48 8B D9 "
        "48 8D 0D 20 10 00 00 "
        "FF 15 10 20 00 00 "
        "85 C0 "
        "74 07 "
        "B8 01 00 00 00 "
        "EB 02 "
        "31 C0 "
        "48 8B 5C 24 30 "
        "48 83 C4 20 "
        "5F "
        "C3"
    )
    summary = compare_function_with_capstone(func_bytes, start_address=0x140001000)
    assert summary.total_instructions == 15
    assert summary.supported_count == 13
    assert summary.out_of_subset_count == 2
    assert summary.length_mismatches == 0
    assert summary.family_mismatches == 0
