"""Plain-language presentation helpers for Standard (User) Mode.

Translates technical PE metadata, triage bands, and rule findings (R01-R14) into
clear, everyday explanations for general users without modifying any core rule,
banding, decoder, or supervisor logic.
"""

from __future__ import annotations

from coalscan.core.models import (
    FileScanResult,
    FileStatus,
    RiskBand,
    RuleFinding,
    escape_untrusted_text,
)

NON_ANALYZED_STATUSES_SET: frozenset[FileStatus] = frozenset(
    {
        FileStatus.SKIPPED,
        FileStatus.UNSUPPORTED_ARCH,
        FileStatus.NOT_A_PE,
        FileStatus.MALFORMED,
        FileStatus.TOO_LARGE,
        FileStatus.TIMED_OUT,
        FileStatus.FAILED,
    }
)


def format_human_size(num_bytes: int) -> str:
    """Format a byte count into a human-friendly string (e.g. '3.5 KB (3,600 bytes)')."""
    if num_bytes < 1024:
        return f"{num_bytes:,} bytes"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB ({num_bytes:,} bytes)"
    return f"{num_bytes / (1024 * 1024):.2f} MB ({num_bytes:,} bytes)"


def friendly_file_type(res: FileScanResult) -> str:
    """Return an everyday description of what kind of file `res` is."""
    arch_label = ""
    if res.architecture in ("x64", "x86"):
        arch_label = f" ({'64-bit' if res.architecture == 'x64' else '32-bit'})"

    if res.status == FileStatus.ANALYZED:
        if res.file_name.lower().endswith(".dll") or "DLL" in res.file_kind:
            return f"Windows Library / DLL{arch_label}"
        if res.file_name.lower().endswith(".ocx"):
            return f"Windows ActiveX Control{arch_label}"
        return f"Windows Program{arch_label}"
    if res.status == FileStatus.ANALYZED_DOTNET_LIMITED:
        return ".NET Program"
    if res.status == FileStatus.ANALYZED_DRIVER_LIMITED:
        return "Windows System Driver"
    if res.status == FileStatus.DRIVER_CANDIDATE:
        return f"Driver File (.sys){arch_label}"
    if res.status == FileStatus.UNSUPPORTED_ARCH:
        arch = escape_untrusted_text(res.architecture, max_len=32)
        return f"Other CPU Program ({arch})" if arch and arch != "-" else "Unsupported CPU Program"
    if res.status == FileStatus.NOT_A_PE:
        return "Not a Windows Program"
    if res.status == FileStatus.SKIPPED:
        return "Skipped File"
    if res.status == FileStatus.TOO_LARGE:
        return "File Too Large (> 50 MB)"
    if res.status == FileStatus.MALFORMED:
        return "Damaged / Incomplete File"
    if res.status == FileStatus.TIMED_OUT:
        return "Timed Out"
    return "Unreadable File"


def friendly_attention_level(res: FileScanResult) -> str:
    """Map RiskBand / status to a non-alarmist, easy-to-understand attention label."""
    if res.status in NON_ANALYZED_STATUSES_SET or res.score is None:
        return "Not Checked"
    if res.band == RiskBand.ROUTINE:
        return "Normal"
    if res.band == RiskBand.REVIEW:
        return "Worth Checking"
    if res.band == RiskBand.REVIEW_CLOSELY:
        return "Needs Closer Look"
    return "Not Checked"


def friendly_signature_status(res: FileScanResult) -> str:
    """Return a plain-English digital signature summary."""
    if res.status in NON_ANALYZED_STATUSES_SET:
        return "Not checked"
    if any(rf.rule_id == "R14" for rf in res.findings):
        return "Not digitally signed"
    return "Signed (certificate table present)"


_PLAIN_TITLES: dict[str, str] = {
    "R01": "Requests raw memory directly",
    "R02": "Can change memory permissions",
    "R03": "Can write into other running programs",
    "R04": "Can start tasks inside other programs",
    "R05": "Loads extra Windows features dynamically",
    "R06": "Can launch other programs or commands",
    "R07": "Includes internet / web client features",
    "R08": "Uses very few standard Windows functions",
    "R09": "Contains compressed or scrambled data",
    "R10": "Has memory that is both changeable and runnable",
    "R11": "Starts running from an unusual section",
    "R12": "Has extra data attached at the end of the file",
    "R13": "Runs startup code before the main program",
    "R14": "Not digitally signed by a verified publisher",
}


def friendly_finding_title(rf: RuleFinding) -> str:
    """Return a plain-English heading for a RuleFinding."""
    return _PLAIN_TITLES.get(rf.rule_id, escape_untrusted_text(rf.title, max_len=120))


def friendly_finding_what(rf: RuleFinding) -> str:
    """Return a plain-English description of what was observed without raw offsets."""
    obs = escape_untrusted_text(rf.observed, max_len=240)
    mapping = {
        "R01": f"This program asks Windows for flexible memory space ({obs}).",
        "R02": f"This program can change whether memory holds data or runnable code ({obs}).",
        "R03": f"This program includes a Windows feature that writes into another program's memory ({obs}).",
        "R04": f"This program includes a Windows feature that starts code inside another program ({obs}).",
        "R05": f"Instead of listing all needed features up front, it can look them up while running ({obs}).",
        "R06": f"This program can start other programs or system commands ({obs}).",
        "R07": f"This program includes built-in features to connect over the web/network ({obs}).",
        "R08": f"It lists fewer standard Windows functions than most normal apps ({obs}).",
        "R09": f"A part of this file looks tightly compressed or scrambled ({obs}).",
        "R10": f"A section of this program can modify itself and run the result ({obs}).",
        "R11": f"The program's starting point sits outside a normal code section ({obs}).",
        "R12": f"Extra data was found attached after the end of the main program ({obs}).",
        "R13": "It registers early startup code (TLS callback) that runs before the main window or entry point.",
        "R14": "No digital publisher signature was found inside this file.",
    }
    return mapping.get(rf.rule_id, obs)


def friendly_finding_advice(rf: RuleFinding) -> str:
    """Return practical, non-verdict user guidance for a RuleFinding."""
    if rf.rule_id in ("R03", "R04", "R10"):
        return (
            "If this is not a debugger, game overlay, or developer tool from a trusted source, "
            "double-check where you downloaded it before opening it."
        )
    if rf.rule_id in ("R09", "R11", "R12"):
        return (
            "Installers and media-heavy apps often compress or attach extra files. "
            "Make sure you recognize the publisher or website you got it from."
        )
    if rf.rule_id == "R14":
        return (
            "Many free, open-source, and student programs are unsigned. "
            "Just verify you downloaded it from the official source."
        )
    return (
        "This trait is common in everyday software, but if the file came from an unexpected "
        "email or download, verify it with your trusted antivirus before running it."
    )


def friendly_row_summary(res: FileScanResult) -> str:
    """Return a concise 1-line summary for the Standard Mode table."""
    if res.status in NON_ANALYZED_STATUSES_SET:
        return escape_untrusted_text(res.status_reason, max_len=160)

    count = len(res.findings)
    if count == 0:
        return "No unusual traits noticed"
    if count == 1:
        return friendly_finding_title(res.findings[0])
    first = friendly_finding_title(res.findings[0])
    return f"{count} items noticed (including: {first})"


def matches_standard_filter(
    res: FileScanResult, filter_key: str, search_text: str
) -> bool:
    """Return True if `res` matches the selected table filter and search query."""
    query = search_text.strip().lower()
    if query and query not in res.file_name.lower():
        return False

    if filter_key == "attention":
        return res.band in (RiskBand.REVIEW, RiskBand.REVIEW_CLOSELY)
    if filter_key == "analyzed":
        return res.status not in NON_ANALYZED_STATUSES_SET
    if filter_key == "skipped_errors":
        return res.status in NON_ANALYZED_STATUSES_SET
    return True
