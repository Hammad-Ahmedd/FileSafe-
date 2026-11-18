"""PDF report generator using ReportLab (Section 3 & Storage/Reports specification).

Generates structured, accessible static triage reports matching the UI's status,
hashes, risk bands, scores, rule findings, and bounded disassembly context.
Includes tool, rule, and banding versions plus skipped/failed/malformed files.
Never uses em dashes and never presents bands as malware verdicts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Union

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from coalscan.core.limits import (
    BANDING_VERSION,
    MAX_DISASM_INSTRUCTIONS_PER_FILE,
    MAX_FILES_PER_SCAN,
    MAX_FILE_SIZE_BYTES,
    PER_FILE_TIMEOUT_SECONDS,
    RULE_CATALOG_VERSION,
    TOOL_VERSION,
)
from coalscan.core.models import FileScanResult, escape_xml_markup
from coalscan.core.supervisor import BatchScanSummary


def _pdf_safe(text: object, max_len: int = 512) -> str:
    """Escape untrusted text for ReportLab Paragraph XML and remove any em/en dashes."""
    if text is None:
        return "-"
    s = escape_xml_markup(str(text), max_len=max_len)
    return s.replace("\u2014", "-").replace("\u2013", "-")


def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "CoalTitle",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=19,
            textColor=colors.HexColor("#1A365D"),
            spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "CoalSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#2D3748"),
            spaceAfter=6,
        ),
        "section": ParagraphStyle(
            "CoalSection",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#1A365D"),
            spaceBefore=8,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "CoalBody",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#1A202C"),
        ),
        "cell": ParagraphStyle(
            "CoalCell",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor("#1A202C"),
        ),
        "mono": ParagraphStyle(
            "CoalMono",
            parent=base["Code"],
            fontName="Courier",
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor("#1A202C"),
        ),
    }


def _append_file_evidence_blocks(
    story: list[object],
    res: FileScanResult,
    styles: dict[str, ParagraphStyle],
) -> None:
    """Append the observed facts, rule findings, and bounded disassembly for one file."""
    story.append(
        Paragraph(
            f"File Detail: {_pdf_safe(res.file_name)} ({_pdf_safe(res.status.value)})",
            styles["section"],
        )
    )

    # 1. Observed Facts Box (visually separated from rule scores)
    ep_str = (
        f"RVA 0x{res.entry_point_rva:X} (Offset 0x{res.entry_point_offset:X})"
        if res.entry_point_rva and res.entry_point_offset is not None
        else (f"RVA 0x{res.entry_point_rva:X}" if res.entry_point_rva else "None (0)")
    )
    facts_data = [
        [
            Paragraph("<b>Observed Facts (Metadata &amp; Structure)</b>", styles["cell"]),
            Paragraph("", styles["cell"]),
        ],
        [
            Paragraph(f"<b>File Name:</b> {_pdf_safe(res.file_name)}", styles["cell"]),
            Paragraph(f"<b>Size:</b> {res.file_size} bytes", styles["cell"]),
        ],
        [
            Paragraph(
                f"<b>Format / Arch:</b> {_pdf_safe(res.pe_format)} / {_pdf_safe(res.architecture)}",
                styles["cell"],
            ),
            Paragraph(f"<b>Kind:</b> {_pdf_safe(res.file_kind)}", styles["cell"]),
        ],
        [
            Paragraph(
                f"<b>SHA-256:</b> <font name='Courier'>{_pdf_safe(res.sha256 or '-')}</font>",
                styles["cell"],
            ),
            Paragraph(f"<b>Entry Point:</b> {_pdf_safe(ep_str)}", styles["cell"]),
        ],
        [
            Paragraph(
                f"<b>Status:</b> {_pdf_safe(res.status.value)}",
                styles["cell"],
            ),
            Paragraph(
                f"<b>Status Reason:</b> {_pdf_safe(res.status_reason)}",
                styles["cell"],
            ),
        ],
    ]
    if res.skip_r11_note:
        facts_data.append(
            [
                Paragraph("<b>Entry Point Note:</b>", styles["cell"]),
                Paragraph(_pdf_safe(res.skip_r11_note), styles["cell"]),
            ]
        )
    if res.disasm_truncated:
        facts_data.append(
            [
                Paragraph("<b>Disassembly Cap Note:</b>", styles["cell"]),
                Paragraph(_pdf_safe(res.disasm_truncation_reason), styles["cell"]),
            ]
        )

    facts_table = Table(facts_data, colWidths=[125 * mm, 135 * mm])
    facts_table.setStyle(
        TableStyle(
            [
                ("SPAN", (0, 0), (1, 0)),
                ("BACKGROUND", (0, 0), (1, 0), colors.HexColor("#EDF2F7")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    story.append(facts_table)
    story.append(Spacer(1, 3 * mm))

    # 2. Triage Band & Rule Scores (separated from observed facts)
    score_str = str(res.score) if res.score is not None else "-"
    band_line = (
        f"<b>Triage Band:</b> {_pdf_safe(res.band.value)} | "
        f"<b>Score:</b> {_pdf_safe(score_str)} "
        f"({_pdf_safe(res.score_breakdown or 'no rules evaluated')}) | "
        "<i>Bands are triage aids, not verdicts.</i>"
    )
    story.append(Paragraph(band_line, styles["body"]))
    story.append(Spacer(1, 2 * mm))

    if res.findings:
        f_rows = [
            [
                Paragraph("<b>Rule</b>", styles["cell"]),
                Paragraph("<b>Level (Pts)</b>", styles["cell"]),
                Paragraph("<b>Location</b>", styles["cell"]),
                Paragraph("<b>Observed Evidence</b>", styles["cell"]),
                Paragraph("<b>Why It May Matter / Benign Example</b>", styles["cell"]),
            ]
        ]
        for rf in res.findings:
            grp = f" [Group {rf.group}]" if rf.group else ""
            f_rows.append(
                [
                    Paragraph(
                        f"<b>{_pdf_safe(rf.rule_id)}</b><br/>{_pdf_safe(rf.title)}",
                        styles["cell"],
                    ),
                    Paragraph(
                        f"{_pdf_safe(rf.severity.value)} ({rf.points}){_pdf_safe(grp)}",
                        styles["cell"],
                    ),
                    Paragraph(_pdf_safe(rf.location_label), styles["cell"]),
                    Paragraph(_pdf_safe(rf.observed), styles["cell"]),
                    Paragraph(
                        f"<b>Why:</b> {_pdf_safe(rf.explanation)}<br/>"
                        f"<b>Benign:</b> {_pdf_safe(rf.benign_example)}",
                        styles["cell"],
                    ),
                ]
            )
        f_table = Table(
            f_rows,
            colWidths=[35 * mm, 25 * mm, 45 * mm, 65 * mm, 90 * mm],
        )
        f_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2B6CB0")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#A0AEC0")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E0")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        story.append(f_table)
        story.append(Spacer(1, 3 * mm))

    # 3. Bounded Disassembly Context (up to first 12 instructions per region in PDF)
    for reg in res.disasm_regions:
        story.append(
            Paragraph(
                f"<b>Disassembly Context:</b> {_pdf_safe(reg.label)} "
                f"(File Offset 0x{reg.file_offset:X})",
                styles["body"],
            )
        )
        lines: list[str] = []
        for insn in reg.instructions[:12]:
            cmt = f" ; {_pdf_safe(insn.comment)}" if insn.comment else ""
            lines.append(
                f"{insn.address:08X}  {insn.bytes_hex:<20}  "
                f"{_pdf_safe(insn.mnemonic)} {_pdf_safe(insn.op_str)}{cmt}"
            )
        if len(reg.instructions) > 12:
            lines.append(f"... ({len(reg.instructions) - 12} more instructions in region)")
        if reg.truncated and reg.truncation_note:
            lines.append(f"[Note: {_pdf_safe(reg.truncation_note)}]")
        code_html = "<br/>".join(lines)
        story.append(Paragraph(code_html, styles["mono"]))
        story.append(Spacer(1, 2 * mm))


def export_batch_pdf(
    summary: BatchScanSummary,
    output_path: Union[str, Path],
) -> Path:
    """Generate a complete folder triage PDF report with summary table and per-file evidence."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    styles = _build_styles()

    doc = SimpleDocTemplate(
        str(out),
        pagesize=landscape(A4),
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title="Assembly-Assisted Malware Analysis - Static Triage Report",
    )

    story: list[object] = []
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    story.append(
        Paragraph(
            "Assembly-Assisted Malware Analysis (CSC-203) - Static Triage Report",
            styles["title"],
        )
    )
    story.append(
        Paragraph(
            "<b>Boundary Notice:</b> Student static-triage prototype. Not a production antivirus "
            "and not a malware verdict. Selected files are read strictly as bytes and never launched. "
            "Triage bands (Routine, Review, Review closely) indicate review priority only.",
            styles["subtitle"],
        )
    )
    story.append(
        Paragraph(
            f"<b>Scanned Folder:</b> {_pdf_safe(summary.folder_path)} | "
            f"<b>Generated:</b> {now_str}<br/>"
            f"<b>Versions:</b> Tool={_pdf_safe(TOOL_VERSION)} | "
            f"Rules={_pdf_safe(RULE_CATALOG_VERSION)} | "
            f"Banding={_pdf_safe(BANDING_VERSION)}<br/>"
            f"<b>Configured Limits:</b> Max file size={MAX_FILE_SIZE_BYTES // (1024 * 1024)} MB, "
            f"Max files={MAX_FILES_PER_SCAN}, Per-file timeout={PER_FILE_TIMEOUT_SECONDS} s, "
            f"Top-level folder only, Max {MAX_DISASM_INSTRUCTIONS_PER_FILE} instructions/file.<br/>"
            f"<b>Counts:</b> {summary.processed_files} / {summary.total_files} processed "
            f"({summary.analyzed_count} analyzed | {summary.unsupported_count} unsupported | "
            f"{summary.skipped_count} skipped | {summary.failed_or_malformed_count} malformed/failed/timed-out)",
            styles["subtitle"],
        )
    )
    story.append(Spacer(1, 3 * mm))

    # Summary Table of all files (including skipped, unsupported, malformed, timed out, failed)
    story.append(Paragraph("1. Batch Scan Results Table", styles["section"]))
    table_rows = [
        [
            Paragraph("<b>File</b>", styles["cell"]),
            Paragraph("<b>Status</b>", styles["cell"]),
            Paragraph("<b>Band</b>", styles["cell"]),
            Paragraph("<b>Score</b>", styles["cell"]),
            Paragraph("<b>Findings</b>", styles["cell"]),
            Paragraph("<b>SHA-256</b>", styles["cell"]),
            Paragraph("<b>Reason / Fired Rules</b>", styles["cell"]),
        ]
    ]

    for res in summary.results:
        score_txt = str(res.score) if res.score is not None else "-"
        fired_list = ", ".join(f.rule_id for f in res.findings)
        reason_or_rules = (
            f"{_pdf_safe(res.status_reason)} | Rules: {_pdf_safe(fired_list)}"
            if fired_list
            else _pdf_safe(res.status_reason)
        )
        table_rows.append(
            [
                Paragraph(_pdf_safe(res.file_name), styles["cell"]),
                Paragraph(_pdf_safe(res.status.value), styles["cell"]),
                Paragraph(_pdf_safe(res.band.value), styles["cell"]),
                Paragraph(_pdf_safe(score_txt), styles["cell"]),
                Paragraph(str(len(res.findings)), styles["cell"]),
                Paragraph(
                    f"<font name='Courier'>{_pdf_safe(res.sha256 or '-')}</font>",
                    styles["cell"],
                ),
                Paragraph(reason_or_rules, styles["cell"]),
            ]
        )

    summary_table = Table(
        table_rows,
        colWidths=[35 * mm, 42 * mm, 25 * mm, 14 * mm, 16 * mm, 68 * mm, 60 * mm],
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A365D")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#A0AEC0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 5 * mm))

    story.append(Paragraph("2. Per-File Evidence and Disassembly Details", styles["section"]))
    for res in summary.results:
        _append_file_evidence_blocks(story, res, styles)
        story.append(Spacer(1, 4 * mm))

    doc.build(story)
    return out


def export_single_file_pdf(
    result: FileScanResult,
    output_path: Union[str, Path],
    folder_path: str = "",
) -> Path:
    """Export a single selected FileScanResult to a PDF report."""
    single_summary = BatchScanSummary(
        folder_path=folder_path or str(Path(result.file_path).parent),
        total_files=1,
        processed_files=1,
        analyzed_count=1 if result.score is not None else 0,
        unsupported_count=0,
        skipped_count=0,
        failed_or_malformed_count=0 if result.score is not None else 1,
        timed_out_count=0,
        cancelled=False,
        elapsed_seconds=0.0,
        results=[result],
    )
    return export_batch_pdf(single_summary, output_path)
