"""Evidence Detail section widget (Section 3 Mockup 3: EVIDENCE DETAIL).

Visually separates:
1. Observed Facts (file name, PE format, architecture, SHA-256 with 'Copy hash' button, status/entry point notes)
2. Triage Band & Score Breakdown + Findings List ('Routine/Review/Review closely', never 'clean/malicious')
3. Selected Rule Detail (Rule ID, exact offset/RVA, Observed, Why it may matter, Benign example)
   and Bounded Disassembly Context.

Non-analyzed statuses (skipped, unsupported, not-a-PE, malformed, too large, timed-out, failed)
never say "No rules fired": they show "Not analyzed: no rules were run" plus the status reason,
hide the "Benign example" line, and show "No disassembly for this status."
Only files with status "analyzed*" may say "No rules fired".
"""

from __future__ import annotations

from typing import Final, Optional

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from coalscan.core.models import (
    DisasmRegion,
    FileScanResult,
    FileStatus,
    RuleFinding,
    escape_untrusted_text,
)
from coalscan.ui.plain_language import (
    format_human_size,
    friendly_attention_level,
    friendly_file_type,
    friendly_finding_advice,
    friendly_finding_title,
    friendly_finding_what,
    friendly_signature_status,
)

NON_ANALYZED_STATUSES: Final[frozenset[FileStatus]] = frozenset(
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


def is_analyzed_star_status(status: FileStatus) -> bool:
    """Return True only for statuses beginning with 'analyzed' ('analyzed*')."""
    return status.value.startswith("analyzed")


class EvidencePageWidget(QFrame):
    """Bottom panel corresponding to '3 EVIDENCE DETAIL' in the Section 3 UI mockup."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("EvidencePageWidget")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self._developer_mode: bool = False
        self._current_result: Optional[FileScanResult] = None
        self._build_ui()
        self.set_developer_mode(False)

    def hasHeightForWidth(self) -> bool:
        return False

    def minimumSizeHint(self) -> QSize:
        return QSize(420, 260)

    def sizeHint(self) -> QSize:
        return QSize(460, 400)

    def _build_ui(self) -> None:
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 4, 10, 4)
        outer.setSpacing(2)

        top_hdr_row = QHBoxLayout()
        top_hdr_row.setContentsMargins(0, 0, 0, 0)
        top_hdr_row.setSpacing(8)
        self.header_label = QLabel("File inspector")
        self.header_label.setTextFormat(Qt.TextFormat.PlainText)
        self.header_label.setObjectName("SectionHeader")

        # Rule Score & Band Breakdown inline on top row to save vertical space
        self.band_label = QLabel("Band: not scored")
        self.band_label.setTextFormat(Qt.TextFormat.PlainText)
        self.band_label.setObjectName("BandSummaryLabel")
        self.band_label.setWordWrap(False)
        self.band_label.setMinimumWidth(100)
        self.band_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        top_hdr_row.addWidget(self.header_label, stretch=0)
        top_hdr_row.addWidget(self.band_label, stretch=1)
        outer.addLayout(top_hdr_row, stretch=0)

        # Observed Facts Frame (kept visually separate from rule scores)
        self.facts_frame = QFrame()
        self.facts_frame.setObjectName("ObservedFactsBox")
        self.facts_frame.setFrameShape(QFrame.Shape.NoFrame)
        self.facts_frame.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        facts_layout = QVBoxLayout(self.facts_frame)
        facts_layout.setContentsMargins(8, 4, 8, 4)
        facts_layout.setSpacing(2)

        self.file_header_label = QLabel("No file selected")
        self.file_header_label.setTextFormat(Qt.TextFormat.PlainText)
        self.file_header_label.setObjectName("FileTitleLabel")
        self.file_header_label.setWordWrap(True)
        self.file_header_label.setMinimumWidth(120)
        self.file_header_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        facts_layout.addWidget(self.file_header_label)

        sha_box = QFrame()
        sha_box.setObjectName("ShaRecessBox")
        sha_box.setMinimumHeight(30)
        sha_box.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        hash_row = QHBoxLayout(sha_box)
        hash_row.setContentsMargins(6, 1, 4, 1)
        hash_row.setSpacing(6)
        hash_row.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        self.sha256_label = QLabel("SHA-256: -")
        self.sha256_label.setObjectName("MonoLabel")
        self.sha256_label.setTextFormat(Qt.TextFormat.PlainText)
        self.sha256_label.setWordWrap(False)
        self.sha256_label.setMinimumWidth(100)
        self.sha256_label.setSizePolicy(
            QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred
        )
        self.sha256_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self.copy_hash_btn = QPushButton("Copy hash")
        self.copy_hash_btn.setMinimumHeight(28)
        self.copy_hash_btn.setMinimumWidth(90)
        self.copy_hash_btn.setEnabled(False)
        self.copy_hash_btn.clicked.connect(self._on_copy_hash)
        hash_row.addWidget(self.sha256_label, stretch=1)
        hash_row.addWidget(self.copy_hash_btn, stretch=0, alignment=Qt.AlignmentFlag.AlignVCenter)
        facts_layout.addWidget(sha_box)

        self.facts_meta_label = QLabel("Status: - | Entry Point: -")
        self.facts_meta_label.setObjectName("MutedLabel")
        self.facts_meta_label.setTextFormat(Qt.TextFormat.PlainText)
        self.facts_meta_label.setWordWrap(True)
        self.facts_meta_label.setMinimumWidth(120)
        self.facts_meta_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        facts_layout.addWidget(self.facts_meta_label)

        outer.addWidget(self.facts_frame, stretch=0)

        self.findings_hdr = QLabel("What was noticed")
        self.findings_hdr.setTextFormat(Qt.TextFormat.PlainText)
        self.findings_hdr.setObjectName("SubHeader")
        outer.addWidget(self.findings_hdr, stretch=0)

        self.findings_list = QListWidget()
        self.findings_list.setObjectName("FindingsRecessList")
        self.findings_list.setMinimumHeight(44)
        self.findings_list.setMaximumHeight(48)
        self.findings_list.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        self.findings_list.currentRowChanged.connect(self._on_finding_selected)
        outer.addWidget(self.findings_list, stretch=0)

        # Structured definition list panel for selected item — gets all remaining vertical stretch
        detail_box = QFrame()
        detail_box.setObjectName("EvidenceRightPane")
        detail_box.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        detail_layout = QVBoxLayout(detail_box)
        detail_layout.setContentsMargins(6, 2, 6, 2)
        detail_layout.setSpacing(1)

        self.rule_location_label = QLabel(
            "Select a finding or analyzed file to view evidence"
        )
        self.rule_location_label.setTextFormat(Qt.TextFormat.PlainText)
        self.rule_location_label.setObjectName("FileTitleLabel")
        self.rule_location_label.setWordWrap(True)
        self.rule_location_label.setMinimumWidth(120)
        self.rule_location_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        detail_layout.addWidget(self.rule_location_label, stretch=0)

        self.observed_label = QLabel("Observed: -")
        self.observed_label.setObjectName("EvidenceBlockLabel")
        self.observed_label.setTextFormat(Qt.TextFormat.PlainText)
        self.observed_label.setWordWrap(True)
        self.observed_label.setMinimumWidth(120)
        self.observed_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        detail_layout.addWidget(self.observed_label, stretch=0)

        self.why_label = QLabel("Why it may matter: -")
        self.why_label.setObjectName("EvidenceBlockLabel")
        self.why_label.setTextFormat(Qt.TextFormat.PlainText)
        self.why_label.setWordWrap(True)
        self.why_label.setMinimumWidth(120)
        self.why_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        detail_layout.addWidget(self.why_label, stretch=0)

        self.benign_label = QLabel("Benign example: -")
        self.benign_label.setObjectName("EvidenceBlockLabel")
        self.benign_label.setTextFormat(Qt.TextFormat.PlainText)
        self.benign_label.setWordWrap(True)
        self.benign_label.setMinimumWidth(120)
        self.benign_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        detail_layout.addWidget(self.benign_label, stretch=0)

        self.advice_label = QLabel("What you can do: -")
        self.advice_label.setObjectName("EvidenceBlockLabel")
        self.advice_label.setTextFormat(Qt.TextFormat.PlainText)
        self.advice_label.setWordWrap(True)
        self.advice_label.setMinimumWidth(120)
        self.advice_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        detail_layout.addWidget(self.advice_label, stretch=0)

        self.disasm_hdr = QLabel("Disassembly context (bounded)")
        self.disasm_hdr.setTextFormat(Qt.TextFormat.PlainText)
        self.disasm_hdr.setObjectName("SubHeader")
        detail_layout.addWidget(self.disasm_hdr, stretch=0)

        self.disasm_view = QPlainTextEdit()
        self.disasm_view.setReadOnly(True)
        self.disasm_view.setMinimumHeight(55)
        mono_font = QFont("JetBrains Mono", 9)
        mono_font.setStyleHint(QFont.StyleHint.Monospace)
        self.disasm_view.setFont(mono_font)
        detail_layout.addWidget(self.disasm_view, stretch=2)

        outer.addWidget(detail_box, stretch=1)

        # Dedicated row BELOW the Findings list for the footer note so it never overlaps
        self.footer_row_layout = QHBoxLayout()
        self.footer_row_layout.setContentsMargins(0, 0, 0, 0)
        self.separation_note = QLabel(
            "Observed facts are listed apart from rule scores. Bands are triage aids, not verdicts."
        )
        self.separation_note.setTextFormat(Qt.TextFormat.PlainText)
        self.separation_note.setObjectName("MutedLabel")
        self.separation_note.setWordWrap(True)
        self.separation_note.setMinimumWidth(120)
        self.separation_note.setMinimumHeight(18)
        self.separation_note.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self.footer_row_layout.addWidget(self.separation_note, stretch=1)
        outer.addLayout(self.footer_row_layout, stretch=0)

    def set_developer_mode(self, enabled: bool) -> None:
        """Switch Evidence Detail between Standard (User) Mode and Developer Mode."""
        selected_row = self.findings_list.currentRow()
        self._developer_mode = enabled

        if enabled:
            self.header_label.setText("EVIDENCE DETAIL")
            self.findings_hdr.setText("FINDINGS")
            self.separation_note.setText(
                "Observed facts are listed apart from rule scores. Bands are triage aids, not verdicts."
            )
            self.disasm_hdr.setVisible(True)
            self.disasm_view.setVisible(True)
            self.advice_label.setVisible(False)
        else:
            self.header_label.setText("FILE DETAILS")
            self.findings_hdr.setText("WHAT WAS NOTICED")
            self.separation_note.setText(
                "Traits listed here are clues for review, not a virus verdict. Normal programs often share them."
            )
            self.disasm_hdr.setVisible(False)
            self.disasm_view.setVisible(False)

        if self._current_result is not None:
            self.display_result(self._current_result)
            if 0 <= selected_row < self.findings_list.count():
                self.findings_list.setCurrentRow(selected_row)

    def display_result(self, res: FileScanResult) -> None:
        """Populate Observed Facts, Band/Score, Findings list, and Disassembly for `res`."""
        self._current_result = res
        safe_name = escape_untrusted_text(res.file_name, max_len=256)

        if self._developer_mode:
            safe_fmt = escape_untrusted_text(res.pe_format, max_len=32).strip()
            safe_arch = escape_untrusted_text(res.architecture, max_len=32).strip()
            known_parts = [
                part
                for part in (safe_fmt, safe_arch)
                if part and part not in ("-", "unknown", "Unknown")
            ]
            if known_parts:
                self.file_header_label.setText(f"{safe_name}   {' '.join(known_parts)}")
            else:
                self.file_header_label.setText(safe_name)

            if res.sha256:
                self.sha256_label.setText(f"SHA-256: {res.sha256}")
                self.copy_hash_btn.setEnabled(True)
            else:
                self.sha256_label.setText("SHA-256: - (not hashed)")
                self.copy_hash_btn.setEnabled(False)

            ep_text = (
                f"0x{res.entry_point_rva:X} (offset 0x{res.entry_point_offset:X})"
                if res.entry_point_rva and res.entry_point_offset is not None
                else ("None (0)" if res.entry_point_rva == 0 else "-")
            )
            notes_parts = [
                f"Status: {escape_untrusted_text(res.status.value)}",
                f"Size: {res.file_size} B",
                f"Entry Point: {ep_text}",
            ]
            if res.skip_r11_note:
                notes_parts.append(escape_untrusted_text(res.skip_r11_note))
            if res.disasm_truncated:
                notes_parts.append(escape_untrusted_text(res.disasm_truncation_reason))
            self.facts_meta_label.setText(" | ".join(notes_parts))

            if res.score is not None and res.status not in NON_ANALYZED_STATUSES:
                self.band_label.setText(
                    f"Band: {escape_untrusted_text(res.band.value)}  "
                    f"({escape_untrusted_text(res.score_breakdown)})"
                )
            else:
                self.band_label.setText("Band: not scored")

            self.findings_list.clear()
            for rf in res.findings:
                item_text = (
                    f"{escape_untrusted_text(rf.rule_id)}  "
                    f"{escape_untrusted_text(rf.title)}  [{escape_untrusted_text(rf.severity.value)}]"
                )
                self.findings_list.addItem(QListWidgetItem(item_text))
        else:
            file_type = friendly_file_type(res)
            self.file_header_label.setText(f"{safe_name}  -  {file_type}")

            if res.sha256:
                self.sha256_label.setText(f"Fingerprint (SHA-256): {res.sha256}")
                self.copy_hash_btn.setEnabled(True)
            else:
                self.sha256_label.setText("Fingerprint (SHA-256): Not computed")
                self.copy_hash_btn.setEnabled(False)

            sig_text = friendly_signature_status(res)
            self.facts_meta_label.setText(
                f"Size: {format_human_size(res.file_size)} | Digital Signature: {sig_text}"
            )

            att = friendly_attention_level(res)
            if res.status in NON_ANALYZED_STATUSES or res.score is None:
                self.band_label.setText("Attention Level: Not Checked")
            else:
                self.band_label.setText(
                    f"Attention Level: {att} (triage guide, not a virus verdict)"
                )

            self.findings_list.clear()
            for rf in res.findings:
                self.findings_list.addItem(QListWidgetItem(friendly_finding_title(rf)))

        if res.findings:
            self.findings_list.setCurrentRow(0)
        else:
            self._show_zero_findings_state(res)

    def _show_zero_findings_state(self, res: FileScanResult) -> None:
        safe_name = escape_untrusted_text(res.file_name, max_len=256)
        reason_clean = escape_untrusted_text(res.status_reason)

        if not self._developer_mode:
            if res.status in NON_ANALYZED_STATUSES:
                self.rule_location_label.setText(f"Not checked ({reason_clean})")
                self.observed_label.setText(
                    f"File: {safe_name} ({format_human_size(res.file_size)})"
                )
                self.why_label.setText(
                    "Why it wasn't checked: This file was skipped or could not be read as a valid Windows program."
                )
                self.benign_label.clear()
                self.benign_label.setVisible(False)
                self.advice_label.setText(
                    "What you can do: No program code was analyzed. Only open files from sources you trust."
                )
                self.advice_label.setVisible(True)
            else:
                self.rule_location_label.setText(f"No unusual traits noticed in {safe_name}")
                self.observed_label.setText(
                    f"File: {safe_name} ({format_human_size(res.file_size)})"
                )
                self.why_label.setText(
                    "Why it matters: None of the common risk indicators matched this file."
                )
                self.benign_label.setText(
                    "Normal programs: Standard utilities and signed apps typically look like this."
                )
                self.benign_label.setVisible(True)
                self.advice_label.setText(
                    "What you can do: Still verify you trust where the file came from before running it."
                )
                self.advice_label.setVisible(True)
            return

        if res.status in NON_ANALYZED_STATUSES:
            # Non-analyzed statuses must NEVER say "No rules fired".
            # Show status reason once in the Evidence title; Observed shows file name and size only.
            self.rule_location_label.setText(
                f"Not analyzed: no rules were run ({reason_clean})"
            )
            self.observed_label.setText(f"Observed: {safe_name} ({res.file_size} B)")
            self.why_label.setText(
                f"Why it may matter: Static rule evaluation was not run for status '{escape_untrusted_text(res.status.value)}'."
            )
            self.benign_label.clear()
            self.benign_label.setVisible(False)
            self.advice_label.setVisible(False)
            self.disasm_view.setPlainText("No disassembly for this status.")
        elif is_analyzed_star_status(res.status):
            # Only files with status "analyzed*" may say "No rules fired"
            self.rule_location_label.setText(f"No rules fired for {safe_name}")
            self.observed_label.setText(f"Observed: {safe_name} ({res.file_size} B)")
            self.why_label.setText(
                "Why it may matter: No static indicators from R01-R14 matched."
            )
            self.benign_label.setText(
                "Benign example: Standard utilities with ordinary imports and section flags."
            )
            self.benign_label.setVisible(True)
            self.advice_label.setVisible(False)
            self.disasm_view.setPlainText(
                self._format_disasm_regions(res.disasm_regions)
            )
        else:
            # Driver candidate with 0 findings: rules ran, but status is not "analyzed*"
            self.rule_location_label.setText(
                f"Driver candidate inspected ({safe_name}): 0 rules matched"
            )
            self.observed_label.setText(f"Observed: {safe_name} ({res.file_size} B)")
            self.why_label.setText(
                "Why it may matter: No static indicators from R01-R14 matched."
            )
            self.benign_label.setText(
                "Benign example: Standard utilities or unconfirmed .sys files with ordinary imports."
            )
            self.benign_label.setVisible(True)
            self.advice_label.setVisible(False)
            self.disasm_view.setPlainText(
                self._format_disasm_regions(res.disasm_regions)
            )

    def _on_finding_selected(self, row: int) -> None:
        res = self._current_result
        if res is None or row < 0 or row >= len(res.findings):
            return
        rf: RuleFinding = res.findings[row]
        if self._developer_mode:
            self.rule_location_label.setText(
                f"Rule {escape_untrusted_text(rf.rule_id)}   {escape_untrusted_text(rf.location_label)}"
            )
            self.observed_label.setText(f"Observed: {escape_untrusted_text(rf.observed)}")
            self.why_label.setText(
                f"Why it may matter: {escape_untrusted_text(rf.explanation)}"
            )
            self.benign_label.setText(
                f"Benign example: {escape_untrusted_text(rf.benign_example)}"
            )
            self.benign_label.setVisible(True)
            self.advice_label.setVisible(False)
            self.disasm_view.setPlainText(self._format_disasm_regions(res.disasm_regions))
        else:
            self.rule_location_label.setText(friendly_finding_title(rf))
            self.observed_label.setText(f"What was found: {friendly_finding_what(rf)}")
            self.why_label.setText(
                f"Why it matters: {escape_untrusted_text(rf.explanation)}"
            )
            self.benign_label.setText(
                f"Normal programs that also do this: {escape_untrusted_text(rf.benign_example)}"
            )
            self.benign_label.setVisible(True)
            self.advice_label.setText(
                f"What you can do: {friendly_finding_advice(rf)}"
            )
            self.advice_label.setVisible(True)

    def _format_disasm_regions(self, regions: list[DisasmRegion]) -> str:
        if not regions:
            return "(No disassembly regions available for this file type or entry point.)"
        lines: list[str] = []
        for reg in regions:
            lines.append(f"=== {escape_untrusted_text(reg.label)} ===")
            for insn in reg.instructions:
                cmt = (
                    f"  ; {escape_untrusted_text(insn.comment)}" if insn.comment else ""
                )
                lines.append(
                    f"{insn.address:08X}  {insn.bytes_hex:<22} "
                    f"{escape_untrusted_text(insn.mnemonic):<7} "
                    f"{escape_untrusted_text(insn.op_str)}{cmt}"
                )
            if reg.truncated and reg.truncation_note:
                lines.append(f"[{escape_untrusted_text(reg.truncation_note)}]")
            lines.append("")
        return "\n".join(lines).strip()

    def _on_copy_hash(self) -> None:
        if self._current_result and self._current_result.sha256:
            clipboard = QApplication.clipboard()
            if clipboard is not None:
                clipboard.setText(self._current_result.sha256)
