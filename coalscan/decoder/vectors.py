"""100 declared x86-64 decoder test vectors (Section 4 & Section 6).

Exact category mix required by specification:
- 12 register-direct ModR/M ('reg_direct')
- 14 memory mod 00/01/10 ('mem_modrm')
- 14 SIB including no-base and no-index cases ('sib')
- 10 RIP-relative including REX.B=1 cases ('rip_relative')
- 12 REX variants ('rex')
- 12 immediates including REX.W B8+r 64-bit immediate ('immediate')
- 12 relative branches ('branch')
-  6 push/pop/ret ('stack_ret')
-  4 unsupported encodings that must be rejected ('unsupported')
-  4 truncated encodings that must be rejected ('truncated')
Total = 100 vectors.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class DecoderVector:
    """Single declared decoder test vector with Intel manual ground truth."""

    vec_id: str
    category: str
    hex_bytes: str
    expected_supported: bool
    expected_length: int
    expected_family: str
    description: str
    address: int = 0x140001000

    @property
    def raw_bytes(self) -> bytes:
        return bytes.fromhex(self.hex_bytes)


DECODER_VECTORS_100: Final[tuple[DecoderVector, ...]] = (
    # =========================================================================
    # 1. 12 Register-Direct ModR/M (mod=11)
    # =========================================================================
    DecoderVector("V001", "reg_direct", "89 D8", True, 2, "MOV", "mov eax, ebx"),
    DecoderVector("V002", "reg_direct", "8B C1", True, 2, "MOV", "mov eax, ecx"),
    DecoderVector("V003", "reg_direct", "88 D0", True, 2, "MOV", "mov al, dl"),
    DecoderVector("V004", "reg_direct", "8A E3", True, 2, "MOV", "mov ah, bl"),
    DecoderVector("V005", "reg_direct", "01 D8", True, 2, "ADD", "add eax, ebx"),
    DecoderVector("V006", "reg_direct", "03 C2", True, 2, "ADD", "add eax, edx"),
    DecoderVector("V007", "reg_direct", "29 F7", True, 2, "SUB", "sub edi, esi"),
    DecoderVector("V008", "reg_direct", "2B C8", True, 2, "SUB", "sub ecx, eax"),
    DecoderVector("V009", "reg_direct", "31 C0", True, 2, "XOR", "xor eax, eax"),
    DecoderVector("V010", "reg_direct", "33 D2", True, 2, "XOR", "xor edx, edx"),
    DecoderVector("V011", "reg_direct", "39 D1", True, 2, "CMP", "cmp ecx, edx"),
    DecoderVector("V012", "reg_direct", "3B F8", True, 2, "CMP", "cmp edi, eax"),

    # =========================================================================
    # 2. 14 Memory ModR/M (mod=00, 01, 10 without SIB or RIP-relative)
    # =========================================================================
    DecoderVector("V013", "mem_modrm", "8B 00", True, 2, "MOV", "mov eax, dword ptr [rax]"),
    DecoderVector("V014", "mem_modrm", "89 19", True, 2, "MOV", "mov dword ptr [rcx], ebx"),
    DecoderVector("V015", "mem_modrm", "8A 02", True, 2, "MOV", "mov al, byte ptr [rdx]"),
    DecoderVector("V016", "mem_modrm", "88 0B", True, 2, "MOV", "mov byte ptr [rbx], cl"),
    DecoderVector("V017", "mem_modrm", "8B 40 08", True, 3, "MOV", "mov eax, dword ptr [rax+8]"),
    DecoderVector("V018", "mem_modrm", "89 55 F8", True, 3, "MOV", "mov dword ptr [rbp-8], edx"),
    DecoderVector("V019", "mem_modrm", "03 4E 10", True, 3, "ADD", "add ecx, dword ptr [rsi+0x10]"),
    DecoderVector("V020", "mem_modrm", "2B 7F 20", True, 3, "SUB", "sub edi, dword ptr [rdi+0x20]"),
    DecoderVector("V021", "mem_modrm", "33 43 7F", True, 3, "XOR", "xor eax, dword ptr [rbx+0x7f]"),
    DecoderVector("V022", "mem_modrm", "39 55 00", True, 3, "CMP", "cmp dword ptr [rbp], edx"),
    DecoderVector("V023", "mem_modrm", "8B 80 00 10 00 00", True, 6, "MOV", "mov eax, dword ptr [rax+0x1000]"),
    DecoderVector("V024", "mem_modrm", "89 91 80 00 00 00", True, 6, "MOV", "mov dword ptr [rcx+0x80], edx"),
    DecoderVector("V025", "mem_modrm", "01 86 00 02 00 00", True, 6, "ADD", "add dword ptr [rsi+0x200], eax"),
    DecoderVector("V026", "mem_modrm", "3B 8D 00 FF FF FF", True, 6, "CMP", "cmp ecx, dword ptr [rbp-0x100]"),

    # =========================================================================
    # 3. 14 SIB Addressing (including no-index, no-base disp32, scaled index)
    # =========================================================================
    DecoderVector("V027", "sib", "48 89 5C 24 08", True, 5, "MOV", "mov qword ptr [rsp+8], rbx (worked ex 2)"),
    DecoderVector("V028", "sib", "8B 04 25 78 56 34 12", True, 7, "MOV", "mov eax, dword ptr [0x12345678] (worked ex 3)"),
    DecoderVector("V029", "sib", "8B 04 24", True, 3, "MOV", "mov eax, dword ptr [rsp] (no index)"),
    DecoderVector("V030", "sib", "48 8B 44 24 20", True, 5, "MOV", "mov rax, qword ptr [rsp+0x20]"),
    DecoderVector("V031", "sib", "48 8B 84 24 00 01 00 00", True, 8, "MOV", "mov rax, qword ptr [rsp+0x100]"),
    DecoderVector("V032", "sib", "8B 04 88", True, 3, "MOV", "mov eax, dword ptr [rax+rcx*4]"),
    DecoderVector("V033", "sib", "48 8B 14 D0", True, 4, "MOV", "mov rdx, qword ptr [rax+rdx*8]"),
    DecoderVector("V034", "sib", "89 4C 53 04", True, 4, "MOV", "mov dword ptr [rbx+rdx*2+4], ecx"),
    DecoderVector("V035", "sib", "03 84 8B 00 10 00 00", True, 7, "ADD", "add eax, dword ptr [rbx+rcx*4+0x1000]"),
    DecoderVector("V036", "sib", "8B 04 8D 00 20 40 00", True, 7, "MOV", "mov eax, dword ptr [rcx*4+0x402000] (no base, scaled index)"),
    DecoderVector("V037", "sib", "41 8B 04 25 10 20 30 00", True, 8, "MOV", "mov eax, dword ptr [0x302010] (REX.B=1 with mod=00 base=101 still disp32)"),
    DecoderVector("V038", "sib", "49 8B 44 24 10", True, 5, "MOV", "mov rax, qword ptr [r12+0x10] (SIB base r12)"),
    DecoderVector("V039", "sib", "4A 8B 04 20", True, 4, "MOV", "mov rax, qword ptr [rax+r12] (REX.X=1 index=100 selects r12)"),
    DecoderVector("V040", "sib", "49 8B 45 00", True, 4, "MOV", "mov rax, qword ptr [r13] (mod=01 disp8=0 for r13)"),

    # =========================================================================
    # 4. 10 RIP-Relative Addressing (mod=00, r/m=101, including REX.B=1)
    # =========================================================================
    DecoderVector("V041", "rip_relative", "FF 15 10 00 00 00", True, 6, "CALL", "call qword ptr [rip+0x10] (worked ex 1)"),
    DecoderVector("V042", "rip_relative", "FF 25 20 00 00 00", True, 6, "JMP", "jmp qword ptr [rip+0x20]"),
    DecoderVector("V043", "rip_relative", "48 8B 05 00 10 00 00", True, 7, "MOV", "mov rax, qword ptr [rip+0x1000]"),
    DecoderVector("V044", "rip_relative", "48 89 1D F0 FF FF FF", True, 7, "MOV", "mov qword ptr [rip-0x10], rbx"),
    DecoderVector("V045", "rip_relative", "8B 0D 40 00 00 00", True, 6, "MOV", "mov ecx, dword ptr [rip+0x40]"),
    DecoderVector("V046", "rip_relative", "03 05 08 00 00 00", True, 6, "ADD", "add eax, dword ptr [rip+8]"),
    DecoderVector("V047", "rip_relative", "2B 15 18 00 00 00", True, 6, "SUB", "sub edx, dword ptr [rip+0x18]"),
    DecoderVector("V048", "rip_relative", "3B 3D 30 00 00 00", True, 6, "CMP", "cmp edi, dword ptr [rip+0x30]"),
    DecoderVector("V049", "rip_relative", "41 8B 05 10 00 00 00", True, 7, "MOV", "mov eax, dword ptr [rip+0x10] (REX.B=1 still RIP-relative)"),
    DecoderVector("V050", "rip_relative", "49 8B 05 24 00 00 00", True, 7, "MOV", "mov rax, qword ptr [rip+0x24] (REX.WB=1 still RIP-relative)"),

    # =========================================================================
    # 5. 12 REX Variants (40h..4Fh combinations of W, R, X, B)
    # =========================================================================
    DecoderVector("V051", "rex", "40 88 F0", True, 3, "MOV", "mov al, sil (REX=40h enables spl/bpl/sil/dil)"),
    DecoderVector("V052", "rex", "41 89 C0", True, 3, "MOV", "mov r8d, eax (REX.B)"),
    DecoderVector("V053", "rex", "44 89 C0", True, 3, "MOV", "mov eax, r8d (REX.R)"),
    DecoderVector("V054", "rex", "45 89 C1", True, 3, "MOV", "mov r9d, r8d (REX.RB)"),
    DecoderVector("V055", "rex", "48 89 D8", True, 3, "MOV", "mov rax, rbx (REX.W)"),
    DecoderVector("V056", "rex", "49 89 C7", True, 3, "MOV", "mov r15, rax (REX.WB)"),
    DecoderVector("V057", "rex", "4C 8B D1", True, 3, "MOV", "mov r10, rcx (REX.WR)"),
    DecoderVector("V058", "rex", "4D 01 C1", True, 3, "ADD", "add r9, r8 (REX.WRB)"),
    DecoderVector("V059", "rex", "4A 8B 0C 01", True, 4, "MOV", "mov ecx, dword ptr [rcx+r8] (REX.X)"),
    DecoderVector("V060", "rex", "4E 8B 04 18", True, 4, "MOV", "mov r8, qword ptr [rax+r11] (REX.WRX)"),
    DecoderVector("V061", "rex", "4B 8B 04 09", True, 4, "MOV", "mov eax, dword ptr [r9+r9] (REX.XB)"),
    DecoderVector("V062", "rex", "4F 31 FF", True, 3, "XOR", "xor r15, r15 (REX.WRXB=4Fh)"),

    # =========================================================================
    # 6. 12 Immediates (including B8+r 32-bit and REX.W B8+r 64-bit 10-byte form)
    # =========================================================================
    DecoderVector("V063", "immediate", "B8 78 56 34 12", True, 5, "MOV", "mov eax, 0x12345678 (32-bit imm without REX.W)"),
    DecoderVector("V064", "immediate", "41 B9 EF BE AD DE", True, 6, "MOV", "mov r9d, 0xdeadbeef (REX.B without REX.W = 32-bit imm)"),
    DecoderVector("V065", "immediate", "48 B8 88 77 66 55 44 33 22 11", True, 10, "MOV", "mov rax, 0x1122334455667788 (REX.W 64-bit imm, 10 bytes)"),
    DecoderVector("V066", "immediate", "49 BA 01 00 00 00 01 00 00 00", True, 10, "MOV", "mov r10, 0x100000001 (REX.WB 64-bit imm, 10 bytes)"),
    DecoderVector("V067", "immediate", "C6 00 2A", True, 3, "MOV", "mov byte ptr [rax], 0x2a (C6 /0 ib)"),
    DecoderVector("V068", "immediate", "48 C7 C0 FF FF FF FF", True, 7, "MOV", "mov rax, -1 sign-extended (REX.W C7 /0 id)"),
    DecoderVector("V069", "immediate", "04 10", True, 2, "ADD", "add al, 0x10 (04 ib)"),
    DecoderVector("V070", "immediate", "48 05 00 10 00 00", True, 6, "ADD", "add rax, 0x1000 (REX.W 05 id)"),
    DecoderVector("V071", "immediate", "48 83 EC 28", True, 4, "SUB", "sub rsp, 0x28 (83 /5 ib)"),
    DecoderVector("V072", "immediate", "81 E9 00 04 00 00", True, 6, "SUB", "sub ecx, 0x400 (81 /5 id)"),
    DecoderVector("V073", "immediate", "80 F1 5A", True, 3, "XOR", "xor cl, 0x5a (80 /6 ib)"),
    DecoderVector("V074", "immediate", "48 83 F8 00", True, 4, "CMP", "cmp rax, 0 (83 /7 ib)"),

    # =========================================================================
    # 7. 12 Relative Branches (E8, E9, EB, 70..7F, 0F 80..8F)
    # =========================================================================
    DecoderVector("V075", "branch", "74 05", True, 2, "Jcc", "je +5 (worked ex 4)"),
    DecoderVector("V076", "branch", "75 F4", True, 2, "Jcc", "jne -12 (short backward Jcc)"),
    DecoderVector("V077", "branch", "7C 10", True, 2, "Jcc", "jl +16"),
    DecoderVector("V078", "branch", "7F 08", True, 2, "Jcc", "jg +8"),
    DecoderVector("V079", "branch", "72 04", True, 2, "Jcc", "jb +4"),
    DecoderVector("V080", "branch", "EB 1E", True, 2, "JMP", "jmp short +0x1e"),
    DecoderVector("V081", "branch", "E8 FB 00 00 00", True, 5, "CALL", "call rel32 (+0xfb)"),
    DecoderVector("V082", "branch", "E9 00 FF FF FF", True, 5, "JMP", "jmp rel32 (-0x100)"),
    DecoderVector("V083", "branch", "0F 84 80 00 00 00", True, 6, "Jcc", "je near +0x80 (0F 84 rel32)"),
    DecoderVector("V084", "branch", "0F 85 40 FF FF FF", True, 6, "Jcc", "jne near -0xc0 (0F 85 rel32)"),
    DecoderVector("V085", "branch", "0F 8D 20 01 00 00", True, 6, "Jcc", "jge near +0x120 (0F 8D rel32)"),
    DecoderVector("V086", "branch", "0F 8F 10 00 00 00", True, 6, "Jcc", "jg near +0x10 (0F 8F rel32)"),

    # =========================================================================
    # 8. 6 Push / Pop / Ret
    # =========================================================================
    DecoderVector("V087", "stack_ret", "55", True, 1, "PUSH", "push rbp (50+r)"),
    DecoderVector("V088", "stack_ret", "41 54", True, 2, "PUSH", "push r12 (REX.B 50+r)"),
    DecoderVector("V089", "stack_ret", "5B", True, 1, "POP", "pop rbx (58+r)"),
    DecoderVector("V090", "stack_ret", "FF 30", True, 2, "PUSH", "push qword ptr [rax] (FF /6)"),
    DecoderVector("V091", "stack_ret", "C3", True, 1, "RET", "ret (C3)"),
    DecoderVector("V092", "stack_ret", "C2 10 00", True, 3, "RET", "ret 0x10 (C2 iw)"),

    # =========================================================================
    # 9. 4 Unsupported Encodings (must be rejected with explicit reason)
    # =========================================================================
    DecoderVector("V093", "unsupported", "66 89 D8", False, 0, "UNSUPPORTED", "Legacy operand-size prefix 0x66"),
    DecoderVector("V094", "unsupported", "F3 C3", False, 0, "UNSUPPORTED", "Legacy REP prefix 0xF3"),
    DecoderVector("V095", "unsupported", "65 48 8B 04 25 30 00 00 00", False, 0, "UNSUPPORTED", "GS segment override prefix 0x65"),
    DecoderVector("V096", "unsupported", "48 8D 05 10 00 00 00", False, 0, "UNSUPPORTED", "LEA (0x8D) is outside the declared subset"),

    # =========================================================================
    # 10. 4 Truncated Encodings (must be rejected with explicit reason)
    # =========================================================================
    DecoderVector("V097", "truncated", "48", False, 0, "UNSUPPORTED", "Bare REX prefix with no opcode"),
    DecoderVector("V098", "truncated", "48 89 5C 24", False, 0, "UNSUPPORTED", "Truncated SIB disp8 (missing disp8 byte)"),
    DecoderVector("V099", "truncated", "FF 15 10 00", False, 0, "UNSUPPORTED", "Truncated RIP-relative disp32 (only 2 of 4 bytes)"),
    DecoderVector("V100", "truncated", "48 B8 01 02 03 04", False, 0, "UNSUPPORTED", "Truncated 64-bit immediate in REX.W B8+r"),
)
