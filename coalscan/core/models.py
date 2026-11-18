"""Data models and status definitions for static PE triage.

Every file ends with Playbook-compliant status strings and structured findings.
All user-facing strings from untrusted files are escaped via escape_untrusted_text().
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import html
from typing import Optional


class FileStatus(StrEnum):
    """Exact file statuses permitted by Section 2 of the specification."""

    ANALYZED = "analyzed"
    ANALYZED_DOTNET_LIMITED = "analyzed (managed .NET, limited)"
    ANALYZED_DRIVER_LIMITED = "analyzed (driver, limited)"
    DRIVER_CANDIDATE = "driver candidate"
    UNSUPPORTED_ARCH = "unsupported architecture"
    NOT_A_PE = "not a PE file"
    SKIPPED = "skipped (extension or limit)"
    MALFORMED = "malformed"
    TOO_LARGE = "too large"
    TIMED_OUT = "timed out"
    FAILED = "failed"


class RiskBand(StrEnum):
    """Triage risk bands (never verdicts)."""

    ROUTINE = "Routine"
    REVIEW = "Review"
    REVIEW_CLOSELY = "Review closely"
    NOT_APPLICABLE = "-"


class RuleSeverity(StrEnum):
    """Rule severity levels."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


def escape_untrusted_text(value: str, max_len: int = 512) -> str:
    """Sanitize file names and strings extracted from scanned binaries for plain-text display.

    Replaces control characters (including nulls and newlines) with safe hex escapes,
    replaces em/en dashes with ASCII hyphens, and truncates overly long strings.
    Does NOT apply HTML entity escaping so plain-text Qt labels and table cells
    never display '&amp;' or '&#x27;'. Use `escape_xml_markup()` when rendering XML/PDF markup.
    """
    if not isinstance(value, str):
        value = str(value)
    # Remove any em-dash or en-dash characters to adhere to report rules
    value = value.replace("\u2014", "-").replace("\u2013", "-")
    cleaned_chars: list[str] = []
    for ch in value[:max_len]:
        code = ord(ch)
        if code < 32 or code == 127:
            cleaned_chars.append(f"\\x{code:02x}")
        else:
            cleaned_chars.append(ch)
    if len(value) > max_len:
        cleaned_chars.append("...")
    return "".join(cleaned_chars)


def escape_xml_markup(value: str, max_len: int = 512) -> str:
    """Sanitize untrusted text and escape XML/HTML entities for ReportLab Paragraph markup."""
    return html.escape(escape_untrusted_text(value, max_len=max_len), quote=True)


@dataclass(frozen=True)
class SectionInfo:
    """Metadata for a single PE section."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int
    entropy: float
    is_executable: bool
    is_writable: bool
    is_readable: bool


@dataclass(frozen=True)
class ImportInfo:
    """Metadata for a single imported function or ordinal."""

    dll_name: str
    function_name: str
    iat_rva: int
    file_offset: Optional[int] = None


@dataclass
class PEInspectionResult:
    """Structured result of static byte-level PE inspection (pefile)."""

    is_pe: bool = False
    is_malformed: bool = False
    malformed_reason: str = ""
    not_pe_reason: str = ""

    machine: int = 0
    architecture: str = "Unknown"
    pe_format: str = "Unknown"  # "PE32", "PE32+", or "Unknown"
    is_64bit: bool = False
    characteristics: int = 0
    is_dll: bool = False
    subsystem: int = 0
    is_native_subsystem: bool = False
    has_clr_header: bool = False
    clr_rva: int = 0
    clr_size: int = 0

    image_base: int = 0
    entry_point_rva: int = 0
    entry_point_offset: Optional[int] = None
    entry_point_in_exec_section: bool = False
    entry_point_section_name: str = ""

    num_sections: int = 0
    sections: list[SectionInfo] = field(default_factory=list)

    imports: list[ImportInfo] = field(default_factory=list)
    total_import_count: int = 0

    has_overlay: bool = False
    overlay_offset: Optional[int] = None
    overlay_size: int = 0

    has_tls_callbacks: bool = False
    tls_callback_rva: Optional[int] = None
    tls_callback_offset: Optional[int] = None
    tls_callbacks_count: int = 0

    has_signature: bool = False
    signature_offset: Optional[int] = None
    signature_size: int = 0


@dataclass(frozen=True)
class RouteDecision:
    """Routing decision produced by core/router.py from content and limits."""

    status: FileStatus
    reason: str
    file_kind: str
    run_full_rules: bool = False
    run_structural_rules_only: bool = False
    suppress_r08: bool = False
    skip_r11: bool = False
    skip_r11_reason: Optional[str] = None
    run_disassembly: bool = False
    capstone_arch_bits: Optional[int] = None  # 32 or 64 when disassembly is enabled


@dataclass(frozen=True)
class RuleFinding:
    """Single fired rule indicator with exact evidence location and context."""

    rule_id: str
    title: str
    severity: RuleSeverity
    points: int
    group: Optional[str]  # "A", "B", or None
    observed: str
    file_offset: Optional[int]
    rva: Optional[int]
    location_label: str
    explanation: str
    benign_example: str


@dataclass(frozen=True)
class DisasmInstruction:
    """Single disassembled instruction."""

    address: int
    file_offset: int
    size: int
    bytes_hex: str
    mnemonic: str
    op_str: str
    comment: str = ""


@dataclass
class DisasmRegion:
    """A bounded region of disassembled instructions around an entry point or finding."""

    label: str
    rva: int
    file_offset: int
    virtual_address: int
    instructions: list[DisasmInstruction] = field(default_factory=list)
    truncated: bool = False
    truncation_note: str = ""


@dataclass
class FileScanResult:
    """Complete triage output for a single file."""

    file_path: str
    file_name: str
    safe_file_name: str
    file_size: int
    sha256: Optional[str]
    status: FileStatus
    status_reason: str
    file_kind: str = "Unknown"
    pe_format: str = "-"
    architecture: str = "-"
    is_dll: bool = False
    entry_point_rva: Optional[int] = None
    entry_point_offset: Optional[int] = None
    skip_r11_note: Optional[str] = None
    findings: list[RuleFinding] = field(default_factory=list)
    band: RiskBand = RiskBand.NOT_APPLICABLE
    score: Optional[int] = None
    score_breakdown: str = ""
    disasm_regions: list[DisasmRegion] = field(default_factory=list)
    disasm_truncated: bool = False
    disasm_truncation_reason: str = ""
    inspection: Optional[PEInspectionResult] = None
