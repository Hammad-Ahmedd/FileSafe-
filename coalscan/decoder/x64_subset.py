"""Student-written x86-64 subset instruction decoder (64-bit mode only).

Implements Section 4 of the CSC-203 Revision 5 specification:
- Supported families: MOV, PUSH, POP, CALL, JMP, Jcc, ADD, SUB, XOR, CMP, RET
- Parses REX prefixes (40h-4Fh: W, R, X, B)
- Rejects legacy prefixes (66h, 67h, F2h, F3h, segment overrides, LOCK)
- Parses ModR/M (mod 00/01/10/11, reg, r/m), SIB (scale, index, base), and RIP-relative disp32
- Rejects unsupported or truncated instruction streams with an explicit reason (never guesses)
"""

from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Final, Optional

# Legacy prefixes rejected in the student x86-64 subset
LEGACY_PREFIXES: Final[dict[int, str]] = {
    0x66: "Operand-size override prefix (0x66) is unsupported in subset",
    0x67: "Address-size override prefix (0x67) is unsupported in subset",
    0xF2: "REPNE/BND prefix (0xF2) is unsupported in subset",
    0xF3: "REP/REPE prefix (0xF3) is unsupported in subset",
    0xF0: "LOCK prefix (0xF0) is unsupported in subset",
    0x26: "ES segment override prefix (0x26) is unsupported in subset",
    0x2E: "CS segment override prefix (0x2E) is unsupported in subset",
    0x36: "SS segment override prefix (0x36) is unsupported in subset",
    0x3E: "DS segment override prefix (0x3E) is unsupported in subset",
    0x64: "FS segment override prefix (0x64) is unsupported in subset",
    0x65: "GS segment override prefix (0x65) is unsupported in subset",
}

REG8_NO_REX: Final[tuple[str, ...]] = (
    "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"
)
REG8_WITH_REX: Final[tuple[str, ...]] = (
    "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
)
REG32: Final[tuple[str, ...]] = (
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
)
REG64: Final[tuple[str, ...]] = (
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)

JCC_MNEMONICS: Final[tuple[str, ...]] = (
    "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
    "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg",
)

# Group 1 (80/81/83) /reg field mapping (only /0 ADD, /5 SUB, /6 XOR, /7 CMP are in subset)
GROUP1_OPS: Final[dict[int, tuple[str, str]]] = {
    0: ("add", "ADD"),
    5: ("sub", "SUB"),
    6: ("xor", "XOR"),
    7: ("cmp", "CMP"),
}

# Standard binary ALU opcode bases: (base_opcode, mnemonic, family)
ALU_BASE_MAP: Final[dict[int, tuple[str, str]]] = {
    0x00: ("add", "ADD"),
    0x28: ("sub", "SUB"),
    0x30: ("xor", "XOR"),
    0x38: ("cmp", "CMP"),
}


@dataclass(frozen=True)
class DecodedInstruction:
    """Result of decoding a single x86-64 instruction from a byte buffer."""

    supported: bool
    length: int
    mnemonic: str
    mnemonic_family: str
    operands: str
    text: str
    address: int
    next_rip: Optional[int] = None
    memory_address: Optional[int] = None
    branch_target: Optional[int] = None
    rex_present: bool = False
    rex_w: bool = False
    rex_r: bool = False
    rex_x: bool = False
    rex_b: bool = False
    rejection_reason: Optional[str] = None


def _reject(address: int, reason: str) -> DecodedInstruction:
    """Construct a rejected DecodedInstruction with a clear explanation."""
    return DecodedInstruction(
        supported=False,
        length=0,
        mnemonic="",
        mnemonic_family="UNSUPPORTED",
        operands="",
        text="",
        address=address,
        rejection_reason=reason,
    )


def _reg_name(reg_num: int, size_bits: int, has_rex: bool) -> str:
    """Return the register name for a 4-bit register index and operand size."""
    if size_bits == 8:
        if has_rex:
            return REG8_WITH_REX[reg_num]
        return REG8_NO_REX[reg_num & 7]
    if size_bits == 32:
        return REG32[reg_num]
    return REG64[reg_num]


def _ptr_prefix(size_bits: int) -> str:
    """Return memory operand size qualifier."""
    if size_bits == 8:
        return "byte ptr"
    if size_bits == 32:
        return "dword ptr"
    return "qword ptr"


def _format_disp(disp: int) -> str:
    """Format signed displacement as +0x.. or -0x.. (or +N for small values)."""
    if disp == 0:
        return ""
    sign = "+" if disp > 0 else "-"
    mag = abs(disp)
    if mag < 10:
        return f"{sign}{mag}"
    return f"{sign}0x{mag:x}"


def _format_hex(val: int) -> str:
    """Format an unsigned integer as hex with 0x prefix (or plain digit if < 10)."""
    if 0 <= val < 10:
        return str(val)
    return f"0x{val:x}"


def _parse_modrm_rm(
    data: bytes,
    cursor: int,
    size_bits: int,
    has_rex: bool,
    rex_r: int,
    rex_x: int,
    rex_b: int,
) -> tuple[Optional[str], int, int, Optional[int], bool, Optional[str]]:
    """Parse ModR/M, optional SIB, and displacement starting at data[cursor].

    Returns:
        (rm_operand_str, reg_field_4bit, new_cursor, rip_disp32, is_rip_relative, error_reason)
    """
    if cursor >= len(data):
        return None, 0, cursor, None, False, "Truncated instruction: missing ModR/M byte"

    modrm = data[cursor]
    cursor += 1

    mod = (modrm >> 6) & 0x3
    reg_raw = (modrm >> 3) & 0x7
    rm_raw = modrm & 0x7

    reg_ext = (rex_r << 3) | reg_raw
    rm_ext = (rex_b << 3) | rm_raw

    # Case 1: Register-direct (mod == 0b11)
    if mod == 0b11:
        rm_str = _reg_name(rm_ext, size_bits, has_rex)
        return rm_str, reg_ext, cursor, None, False, None

    ptr_qual = _ptr_prefix(size_bits)

    # Case 2: RIP-relative addressing (mod == 0b00 and r/m == 0b101, even when REX.B is set)
    if mod == 0b00 and rm_raw == 0b101:
        if cursor + 4 > len(data):
            return (
                None,
                reg_ext,
                cursor,
                None,
                False,
                "Truncated instruction: missing 32-bit RIP-relative displacement",
            )
        disp32 = struct.unpack_from("<i", data, cursor)[0]
        cursor += 4
        disp_str = _format_disp(disp32) if disp32 != 0 else "+0"
        rm_str = f"{ptr_qual} [rip{disp_str}]"
        return rm_str, reg_ext, cursor, disp32, True, None

    # Case 3: SIB byte follows (r/m == 0b100 when mod != 0b11)
    if rm_raw == 0b100:
        if cursor >= len(data):
            return None, reg_ext, cursor, None, False, "Truncated instruction: missing SIB byte"
        sib = data[cursor]
        cursor += 1

        scale_bits = (sib >> 6) & 0x3
        scale = 1 << scale_bits
        index_raw = (sib >> 3) & 0x7
        base_raw = sib & 0x7

        index_ext = (rex_x << 3) | index_raw
        base_ext = (rex_b << 3) | base_raw

        # Index = 100 with REX.X = 0 means no index register
        if index_raw == 0b100 and rex_x == 0:
            index_reg: Optional[str] = None
        else:
            index_reg = REG64[index_ext]

        # Base = 101 with mod = 00 means disp32 with no base register (even when REX.B is set)
        no_base = mod == 0b00 and base_raw == 0b101
        base_reg: Optional[str] = None if no_base else REG64[base_ext]

        disp_val = 0
        has_disp = False
        if no_base or mod == 0b10:
            if cursor + 4 > len(data):
                return (
                    None,
                    reg_ext,
                    cursor,
                    None,
                    False,
                    "Truncated instruction: missing 32-bit SIB displacement",
                )
            disp_val = struct.unpack_from("<i", data, cursor)[0]
            cursor += 4
            has_disp = True
        elif mod == 0b01:
            if cursor + 1 > len(data):
                return (
                    None,
                    reg_ext,
                    cursor,
                    None,
                    False,
                    "Truncated instruction: missing 8-bit SIB displacement",
                )
            disp_val = struct.unpack_from("<b", data, cursor)[0]
            cursor += 1
            has_disp = True

        # Format SIB memory expression
        parts: list[str] = []
        if base_reg is not None:
            parts.append(base_reg)
        if index_reg is not None:
            if scale == 1:
                parts.append(index_reg)
            else:
                parts.append(f"{index_reg}*{scale}")

        if not parts:
            # Absolute disp32 with neither base nor index: e.g. [0x12345678]
            unsigned_disp = disp_val & 0xFFFFFFFF
            expr = f"0x{unsigned_disp:x}"
        else:
            expr = "+".join(parts)
            if has_disp and disp_val != 0:
                expr += _format_disp(disp_val)

        return f"{ptr_qual} [{expr}]", reg_ext, cursor, None, False, None

    # Case 4: Standard ModR/M memory addressing without SIB
    base_name = REG64[rm_ext]
    disp = 0
    if mod == 0b01:
        if cursor + 1 > len(data):
            return (
                None,
                reg_ext,
                cursor,
                None,
                False,
                "Truncated instruction: missing 8-bit displacement",
            )
        disp = struct.unpack_from("<b", data, cursor)[0]
        cursor += 1
    elif mod == 0b10:
        if cursor + 4 > len(data):
            return (
                None,
                reg_ext,
                cursor,
                None,
                False,
                "Truncated instruction: missing 32-bit displacement",
            )
        disp = struct.unpack_from("<i", data, cursor)[0]
        cursor += 4

    disp_str = _format_disp(disp) if (mod in (0b01, 0b10) and disp != 0) else ""
    return f"{ptr_qual} [{base_name}{disp_str}]", reg_ext, cursor, None, False, None


def decode_instruction(data: bytes, address: int = 0x140001000) -> DecodedInstruction:
    """Decode one x86-64 instruction at the start of `data` in 64-bit mode.

    Never guesses: returns `supported=False` with a clear `rejection_reason` if the
    bytes are empty, truncated, start with a legacy prefix, or use an opcode outside
    the declared CSC-203 subset.
    """
    if not data:
        return _reject(address, "Truncated instruction: empty byte buffer")

    cursor = 0
    b0 = data[cursor]

    # 1. Reject legacy prefixes immediately
    if b0 in LEGACY_PREFIXES:
        return _reject(address, LEGACY_PREFIXES[b0])

    # 2. Parse optional REX prefix (40h..4Fh)
    has_rex = False
    rex_w = 0
    rex_r = 0
    rex_x = 0
    rex_b = 0

    if 0x40 <= b0 <= 0x4F:
        has_rex = True
        rex_w = (b0 >> 3) & 1
        rex_r = (b0 >> 2) & 1
        rex_x = (b0 >> 1) & 1
        rex_b = b0 & 1
        cursor += 1
        if cursor >= len(data):
            return _reject(address, "Truncated instruction: REX prefix with no opcode byte")
        if data[cursor] in LEGACY_PREFIXES:
            return _reject(address, LEGACY_PREFIXES[data[cursor]])
        if 0x40 <= data[cursor] <= 0x4F:
            return _reject(address, "Multiple REX prefixes are invalid/unsupported")

    opcode = data[cursor]
    cursor += 1
    op_size = 64 if rex_w else 32

    def _finish(
        mnemonic: str,
        family: str,
        operands: str,
        end_cursor: int,
        rip_disp: Optional[int] = None,
        is_rip_rel: bool = False,
        branch_target: Optional[int] = None,
    ) -> DecodedInstruction:
        next_rip = address + end_cursor
        mem_addr = (next_rip + rip_disp) if (is_rip_rel and rip_disp is not None) else None
        text = f"{mnemonic} {operands}".strip()
        return DecodedInstruction(
            supported=True,
            length=end_cursor,
            mnemonic=mnemonic,
            mnemonic_family=family,
            operands=operands,
            text=text,
            address=address,
            next_rip=next_rip,
            memory_address=mem_addr,
            branch_target=branch_target,
            rex_present=has_rex,
            rex_w=bool(rex_w),
            rex_r=bool(rex_r),
            rex_x=bool(rex_x),
            rex_b=bool(rex_b),
        )

    # ------------------------------------------------------------------
    # Two-byte opcodes: 0F 80..8F rel32 (near Jcc)
    # ------------------------------------------------------------------
    if opcode == 0x0F:
        if cursor >= len(data):
            return _reject(address, "Truncated instruction: 0x0F escape with no second opcode byte")
        op2 = data[cursor]
        cursor += 1
        if 0x80 <= op2 <= 0x8F:
            if cursor + 4 > len(data):
                return _reject(address, "Truncated instruction: near Jcc (0F 8x) missing rel32")
            rel32 = struct.unpack_from("<i", data, cursor)[0]
            cursor += 4
            next_rip = address + cursor
            target = (next_rip + rel32) & 0xFFFFFFFFFFFFFFFF
            mnem = JCC_MNEMONICS[op2 - 0x80]
            return _finish(mnem, "Jcc", f"0x{target:x}", cursor, branch_target=target)
        return _reject(address, f"Unsupported two-byte opcode: 0F {op2:02X}")

    # ------------------------------------------------------------------
    # MOV r/m, r and r, r/m: 88, 89, 8A, 8B
    # ------------------------------------------------------------------
    if opcode in (0x88, 0x89, 0x8A, 0x8B):
        sz = 8 if opcode in (0x88, 0x8A) else op_size
        rm_str, reg_ext, cursor, rip_disp, is_rip, err = _parse_modrm_rm(
            data, cursor, sz, has_rex, rex_r, rex_x, rex_b
        )
        if err or rm_str is None:
            return _reject(address, err or "Invalid ModR/M")
        reg_str = _reg_name(reg_ext, sz, has_rex)
        if opcode in (0x88, 0x89):
            operands = f"{rm_str}, {reg_str}"
        else:
            operands = f"{reg_str}, {rm_str}"
        return _finish("mov", "MOV", operands, cursor, rip_disp=rip_disp, is_rip_rel=is_rip)

    # ------------------------------------------------------------------
    # MOV r/m8, imm8 (C6 /0 ib) and MOV r/m32|64, imm32 (C7 /0 id)
    # ------------------------------------------------------------------
    if opcode in (0xC6, 0xC7):
        sz = 8 if opcode == 0xC6 else op_size
        rm_str, reg_ext, cursor, rip_disp, is_rip, err = _parse_modrm_rm(
            data, cursor, sz, has_rex, rex_r, rex_x, rex_b
        )
        if err or rm_str is None:
            return _reject(address, err or "Invalid ModR/M")
        subop = reg_ext & 0x7
        if subop != 0:
            return _reject(
                address, f"Unsupported ModR/M subopcode /{subop} for opcode 0x{opcode:02X} (only /0 is MOV)"
            )
        if opcode == 0xC6:
            if cursor + 1 > len(data):
                return _reject(address, "Truncated instruction: MOV C6 /0 missing imm8")
            imm8 = data[cursor]
            cursor += 1
            return _finish(
                "mov", "MOV", f"{rm_str}, {_format_hex(imm8)}", cursor, rip_disp=rip_disp, is_rip_rel=is_rip
            )
        else:
            if cursor + 4 > len(data):
                return _reject(address, "Truncated instruction: MOV C7 /0 missing imm32")
            if rex_w:
                imm_s32 = struct.unpack_from("<i", data, cursor)[0]
                imm_str = _format_hex(imm_s32 & 0xFFFFFFFFFFFFFFFF) if imm_s32 < 0 else _format_hex(imm_s32)
            else:
                imm_u32 = struct.unpack_from("<I", data, cursor)[0]
                imm_str = _format_hex(imm_u32)
            cursor += 4
            return _finish(
                "mov", "MOV", f"{rm_str}, {imm_str}", cursor, rip_disp=rip_disp, is_rip_rel=is_rip
            )

    # ------------------------------------------------------------------
    # MOV reg, imm32 / imm64: B8+r id (without REX.W) or REX.W B8+r io (10 bytes)
    # ------------------------------------------------------------------
    if 0xB8 <= opcode <= 0xBF:
        reg_idx = (rex_b << 3) | (opcode - 0xB8)
        if rex_w:
            if cursor + 8 > len(data):
                return _reject(address, "Truncated instruction: REX.W MOV B8+r missing 64-bit immediate")
            imm64 = struct.unpack_from("<Q", data, cursor)[0]
            cursor += 8
            reg_str = REG64[reg_idx]
            return _finish("mov", "MOV", f"{reg_str}, {_format_hex(imm64)}", cursor)
        else:
            if cursor + 4 > len(data):
                return _reject(address, "Truncated instruction: MOV B8+r missing 32-bit immediate")
            imm32 = struct.unpack_from("<I", data, cursor)[0]
            cursor += 4
            reg_str = REG32[reg_idx]
            return _finish("mov", "MOV", f"{reg_str}, {_format_hex(imm32)}", cursor)

    # ------------------------------------------------------------------
    # PUSH / POP register: 50+r, 58+r
    # ------------------------------------------------------------------
    if 0x50 <= opcode <= 0x57:
        reg_idx = (rex_b << 3) | (opcode - 0x50)
        return _finish("push", "PUSH", REG64[reg_idx], cursor)

    if 0x58 <= opcode <= 0x5F:
        reg_idx = (rex_b << 3) | (opcode - 0x58)
        return _finish("pop", "POP", REG64[reg_idx], cursor)

    # ------------------------------------------------------------------
    # PUSH imm32 (68 id) and PUSH imm8 (6A ib)
    # ------------------------------------------------------------------
    if opcode == 0x68:
        if cursor + 4 > len(data):
            return _reject(address, "Truncated instruction: PUSH 0x68 missing imm32")
        imm32 = struct.unpack_from("<i", data, cursor)[0]
        cursor += 4
        imm_str = _format_hex(imm32 & 0xFFFFFFFF)
        return _finish("push", "PUSH", imm_str, cursor)

    if opcode == 0x6A:
        if cursor + 1 > len(data):
            return _reject(address, "Truncated instruction: PUSH 0x6A missing imm8")
        imm8 = struct.unpack_from("<b", data, cursor)[0]
        cursor += 1
        imm_str = _format_hex(imm8) if imm8 >= 0 else f"-0x{abs(imm8):x}"
        return _finish("push", "PUSH", imm_str, cursor)

    # ------------------------------------------------------------------
    # POP r/m64: 8F /0
    # ------------------------------------------------------------------
    if opcode == 0x8F:
        rm_str, reg_ext, cursor, rip_disp, is_rip, err = _parse_modrm_rm(
            data, cursor, 64, has_rex, rex_r, rex_x, rex_b
        )
        if err or rm_str is None:
            return _reject(address, err or "Invalid ModR/M")
        subop = reg_ext & 0x7
        if subop != 0:
            return _reject(address, f"Unsupported ModR/M subopcode /{subop} for 0x8F (only /0 is POP)")
        return _finish("pop", "POP", rm_str, cursor, rip_disp=rip_disp, is_rip_rel=is_rip)

    # ------------------------------------------------------------------
    # Group 5 (0xFF): /2 CALL r/m64, /4 JMP r/m64, /6 PUSH r/m64
    # ------------------------------------------------------------------
    if opcode == 0xFF:
        rm_str, reg_ext, cursor, rip_disp, is_rip, err = _parse_modrm_rm(
            data, cursor, 64, has_rex, rex_r, rex_x, rex_b
        )
        if err or rm_str is None:
            return _reject(address, err or "Invalid ModR/M")
        subop = reg_ext & 0x7
        if subop == 2:
            return _finish("call", "CALL", rm_str, cursor, rip_disp=rip_disp, is_rip_rel=is_rip)
        if subop == 4:
            return _finish("jmp", "JMP", rm_str, cursor, rip_disp=rip_disp, is_rip_rel=is_rip)
        if subop == 6:
            return _finish("push", "PUSH", rm_str, cursor, rip_disp=rip_disp, is_rip_rel=is_rip)
        return _reject(
            address,
            f"Unsupported 0xFF subopcode /{subop} (subset supports /2 CALL, /4 JMP, /6 PUSH)",
        )

    # ------------------------------------------------------------------
    # CALL rel32 (E8), JMP rel32 (E9), JMP rel8 (EB), Short Jcc (70..7F)
    # ------------------------------------------------------------------
    if opcode in (0xE8, 0xE9):
        if cursor + 4 > len(data):
            return _reject(address, f"Truncated instruction: opcode 0x{opcode:02X} missing rel32")
        rel32 = struct.unpack_from("<i", data, cursor)[0]
        cursor += 4
        next_rip = address + cursor
        target = (next_rip + rel32) & 0xFFFFFFFFFFFFFFFF
        mnem = "call" if opcode == 0xE8 else "jmp"
        fam = "CALL" if opcode == 0xE8 else "JMP"
        return _finish(mnem, fam, f"0x{target:x}", cursor, branch_target=target)

    if opcode == 0xEB:
        if cursor + 1 > len(data):
            return _reject(address, "Truncated instruction: JMP 0xEB missing rel8")
        rel8 = struct.unpack_from("<b", data, cursor)[0]
        cursor += 1
        next_rip = address + cursor
        target = (next_rip + rel8) & 0xFFFFFFFFFFFFFFFF
        return _finish("jmp", "JMP", f"0x{target:x}", cursor, branch_target=target)

    if 0x70 <= opcode <= 0x7F:
        if cursor + 1 > len(data):
            return _reject(address, f"Truncated instruction: short Jcc (0x{opcode:02X}) missing rel8")
        rel8 = struct.unpack_from("<b", data, cursor)[0]
        cursor += 1
        next_rip = address + cursor
        target = (next_rip + rel8) & 0xFFFFFFFFFFFFFFFF
        mnem = JCC_MNEMONICS[opcode - 0x70]
        return _finish(mnem, "Jcc", f"0x{target:x}", cursor, branch_target=target)

    # ------------------------------------------------------------------
    # Standard ALU families: ADD (00..05), SUB (28..2D), XOR (30..35), CMP (38..3D)
    # ------------------------------------------------------------------
    alu_base = opcode & 0xF8
    alu_low = opcode & 0x07
    if alu_base in ALU_BASE_MAP and alu_low <= 5:
        mnem, fam = ALU_BASE_MAP[alu_base]
        if alu_low in (0, 1, 2, 3):
            sz = 8 if alu_low in (0, 2) else op_size
            rm_str, reg_ext, cursor, rip_disp, is_rip, err = _parse_modrm_rm(
                data, cursor, sz, has_rex, rex_r, rex_x, rex_b
            )
            if err or rm_str is None:
                return _reject(address, err or "Invalid ModR/M")
            reg_str = _reg_name(reg_ext, sz, has_rex)
            if alu_low in (0, 1):
                operands = f"{rm_str}, {reg_str}"
            else:
                operands = f"{reg_str}, {rm_str}"
            return _finish(mnem, fam, operands, cursor, rip_disp=rip_disp, is_rip_rel=is_rip)

        if alu_low == 4:
            if cursor + 1 > len(data):
                return _reject(address, f"Truncated instruction: {fam} AL, imm8 missing imm8")
            imm8 = data[cursor]
            cursor += 1
            return _finish(mnem, fam, f"al, {_format_hex(imm8)}", cursor)

        if alu_low == 5:
            if cursor + 4 > len(data):
                return _reject(address, f"Truncated instruction: {fam} EAX/RAX, imm32 missing imm32")
            imm32 = struct.unpack_from("<I", data, cursor)[0]
            cursor += 4
            acc = "rax" if rex_w else "eax"
            return _finish(mnem, fam, f"{acc}, {_format_hex(imm32)}", cursor)

    # ------------------------------------------------------------------
    # Immediate ALU Group 1: 80 /op ib, 81 /op id, 83 /op ib
    # (/0 ADD, /5 SUB, /6 XOR, /7 CMP)
    # ------------------------------------------------------------------
    if opcode in (0x80, 0x81, 0x83):
        sz = 8 if opcode == 0x80 else op_size
        rm_str, reg_ext, cursor, rip_disp, is_rip, err = _parse_modrm_rm(
            data, cursor, sz, has_rex, rex_r, rex_x, rex_b
        )
        if err or rm_str is None:
            return _reject(address, err or "Invalid ModR/M")
        subop = reg_ext & 0x7
        if subop not in GROUP1_OPS:
            return _reject(
                address,
                f"Unsupported Group 1 subopcode /{subop} for 0x{opcode:02X} "
                "(subset supports /0 ADD, /5 SUB, /6 XOR, /7 CMP)",
            )
        mnem, fam = GROUP1_OPS[subop]
        if opcode in (0x80, 0x83):
            if cursor + 1 > len(data):
                return _reject(address, f"Truncated instruction: {fam} 0x{opcode:02X} missing imm8")
            if opcode == 0x83:
                imm_s8 = struct.unpack_from("<b", data, cursor)[0]
                imm_str = _format_hex(imm_s8) if imm_s8 >= 0 else f"-0x{abs(imm_s8):x}"
            else:
                imm_u8 = data[cursor]
                imm_str = _format_hex(imm_u8)
            cursor += 1
            return _finish(
                mnem, fam, f"{rm_str}, {imm_str}", cursor, rip_disp=rip_disp, is_rip_rel=is_rip
            )
        else:
            if cursor + 4 > len(data):
                return _reject(address, f"Truncated instruction: {fam} 0x81 missing imm32")
            imm32 = struct.unpack_from("<I", data, cursor)[0]
            cursor += 4
            return _finish(
                mnem,
                fam,
                f"{rm_str}, {_format_hex(imm32)}",
                cursor,
                rip_disp=rip_disp,
                is_rip_rel=is_rip,
            )

    # ------------------------------------------------------------------
    # RET: C3 (near return) and C2 iw (near return with 16-bit stack pop)
    # ------------------------------------------------------------------
    if opcode == 0xC3:
        return _finish("ret", "RET", "", cursor)

    if opcode == 0xC2:
        if cursor + 2 > len(data):
            return _reject(address, "Truncated instruction: RET 0xC2 missing imm16")
        imm16 = struct.unpack_from("<H", data, cursor)[0]
        cursor += 2
        return _finish("ret", "RET", _format_hex(imm16), cursor)

    return _reject(address, f"Unsupported opcode 0x{opcode:02X} (outside declared x86-64 subset)")


def normalize_capstone_family(mnemonic: str) -> str:
    """Map a Capstone x86-64 mnemonic to the student subset's mnemonic family."""
    m = mnemonic.lower()
    if m in ("mov", "movabs"):
        return "MOV"
    if m == "push":
        return "PUSH"
    if m == "pop":
        return "POP"
    if m == "call":
        return "CALL"
    if m == "jmp":
        return "JMP"
    if m.startswith("j"):
        return "Jcc"
    if m == "add":
        return "ADD"
    if m == "sub":
        return "SUB"
    if m == "xor":
        return "XOR"
    if m == "cmp":
        return "CMP"
    if m == "ret":
        return "RET"
    return m.upper()


@dataclass(frozen=True)
class FunctionComparisonSummary:
    """Result of comparing the student decoder against Capstone across a function byte stream."""

    total_instructions: int
    supported_count: int
    out_of_subset_count: int
    length_mismatches: int
    family_mismatches: int
    steps: list[dict[str, object]]


def compare_function_with_capstone(
    func_bytes: bytes,
    start_address: int = 0x140001000,
) -> FunctionComparisonSummary:
    """Step through a function's bytes and compare student decoder vs Capstone 64-bit mode.

    Per Section 4 ('Instruction-level explanation in the report'):
    - Student decoder and Capstone must agree on every instruction length across the function
      for supported instructions.
    - Any instruction outside the declared subset is counted as 'out of subset' and stepped
      over using Capstone's instruction length, not counted as a failure.
    """
    import capstone

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    offset = 0
    total = 0
    supported = 0
    out_of_subset = 0
    len_mismatches = 0
    fam_mismatches = 0
    steps: list[dict[str, object]] = []

    while offset < len(func_bytes):
        cur_addr = start_address + offset
        slice_bytes = func_bytes[offset:]
        cs_insns = list(md.disasm(slice_bytes, cur_addr, count=1))
        if not cs_insns:
            break
        cs_insn = cs_insns[0]
        student_res = decode_instruction(slice_bytes, address=cur_addr)
        total += 1

        if student_res.supported:
            supported += 1
            cs_fam = normalize_capstone_family(cs_insn.mnemonic)
            len_ok = student_res.length == cs_insn.size
            fam_ok = student_res.mnemonic_family == cs_fam
            if not len_ok:
                len_mismatches += 1
            if not fam_ok:
                fam_mismatches += 1
            steps.append(
                {
                    "address": cur_addr,
                    "bytes": slice_bytes[: cs_insn.size].hex(" "),
                    "status": "supported",
                    "student_length": student_res.length,
                    "capstone_length": cs_insn.size,
                    "student_text": student_res.text,
                    "capstone_text": f"{cs_insn.mnemonic} {cs_insn.op_str}".strip(),
                    "length_match": len_ok,
                    "family_match": fam_ok,
                }
            )
            offset += student_res.length
        else:
            out_of_subset += 1
            steps.append(
                {
                    "address": cur_addr,
                    "bytes": slice_bytes[: cs_insn.size].hex(" "),
                    "status": "out of subset",
                    "reason": student_res.rejection_reason,
                    "capstone_length": cs_insn.size,
                    "capstone_text": f"{cs_insn.mnemonic} {cs_insn.op_str}".strip(),
                }
            )
            offset += cs_insn.size

    return FunctionComparisonSummary(
        total_instructions=total,
        supported_count=supported,
        out_of_subset_count=out_of_subset,
        length_mismatches=len_mismatches,
        family_mismatches=fam_mismatches,
        steps=steps,
    )
