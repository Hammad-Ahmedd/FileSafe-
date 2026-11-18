"""CSV report exporter for batch folder scans and single-file evidence.

Matches on-screen status, evidence, hashes, risk band, score, and includes
tool, rule, and banding versions plus per-file failures and skips.
Never outputs em dashes or unescaped untrusted strings.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Union

from coalscan.core.limits import (
    BANDING_VERSION,
    RULE_CATALOG_VERSION,
    TOOL_VERSION,
)
from coalscan.core.models import FileScanResult, escape_untrusted_text
from coalscan.core.supervisor import BatchScanSummary


def _clean_text(val: object) -> str:
    """Sanitize a value for CSV output and guarantee no em/en dashes."""
    if val is None:
        return "-"
    text = escape_untrusted_text(str(val), max_len=1024)
    return text.replace("\u2014", "-").replace("\u2013", "-")


CSV_COLUMNS = [
    "file_name",
    "file_size_bytes",
    "sha256",
    "file_kind",
    "pe_format",
    "architecture",
    "status",
    "status_reason",
    "band",
    "score",
    "score_breakdown",
    "findings_count",
    "fired_rule_ids",
    "findings_evidence",
    "skip_r11_note",
    "disasm_truncated",
    "tool_version",
    "rule_version",
    "banding_version",
]


def _result_to_csv_row(res: FileScanResult) -> dict[str, str]:
    fired_ids = ";".join(f.rule_id for f in res.findings)
    evidence_items = [
        f"{f.rule_id} [{f.severity.value}, {f.points}pt] @ {f.location_label}: {f.observed}"
        for f in res.findings
    ]
    return {
        "file_name": _clean_text(res.file_name),
        "file_size_bytes": str(res.file_size),
        "sha256": _clean_text(res.sha256 if res.sha256 else "-"),
        "file_kind": _clean_text(res.file_kind),
        "pe_format": _clean_text(res.pe_format),
        "architecture": _clean_text(res.architecture),
        "status": _clean_text(res.status.value),
        "status_reason": _clean_text(res.status_reason),
        "band": _clean_text(res.band.value),
        "score": str(res.score) if res.score is not None else "-",
        "score_breakdown": _clean_text(res.score_breakdown if res.score_breakdown else "-"),
        "findings_count": str(len(res.findings)),
        "fired_rule_ids": _clean_text(fired_ids if fired_ids else "-"),
        "findings_evidence": _clean_text(" | ".join(evidence_items) if evidence_items else "-"),
        "skip_r11_note": _clean_text(res.skip_r11_note if res.skip_r11_note else "-"),
        "disasm_truncated": "true" if res.disasm_truncated else "false",
        "tool_version": _clean_text(TOOL_VERSION),
        "rule_version": _clean_text(RULE_CATALOG_VERSION),
        "banding_version": _clean_text(BANDING_VERSION),
    }


def export_batch_csv(
    summary: BatchScanSummary,
    output_path: Union[str, Path],
) -> Path:
    """Export all files (including skipped, malformed, timed-out, and failed) to CSV."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for res in summary.results:
            writer.writerow(_result_to_csv_row(res))
    return out


def export_single_file_csv(
    result: FileScanResult,
    output_path: Union[str, Path],
) -> Path:
    """Export a single selected FileScanResult to CSV."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerow(_result_to_csv_row(result))
    return out
