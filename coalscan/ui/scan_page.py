"""Scan Folder section widget (Section 3 Mockup 1: SCAN FOLDER).

Provides:
- Folder path input and Browse button
- Local-only mode toggle (ON by default, enforced offline operation)
- Scan folder button and Cancel button
- Progress bar and 'Progress X / Y files' counter
- Live status breakdown ('A analyzed | U unsupported | S skipped | R remaining')
- Visible scope and limits notice
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from coalscan.core.limits import (
    MAX_DISASM_INSTRUCTIONS_PER_FILE,
    MAX_FILES_PER_SCAN,
    MAX_FILE_SIZE_BYTES,
    PER_FILE_TIMEOUT_SECONDS,
)
from coalscan.core.supervisor import BatchProgress


class ScanPageWidget(QFrame):
    """Top panel corresponding to '1 SCAN FOLDER' in the Section 3 UI mockup."""

    scan_requested = Signal(str)
    cancel_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("ScanPageWidget")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self._developer_mode: bool = False
        self._last_progress: Optional[BatchProgress] = None
        self._build_ui()
        self.set_developer_mode(False)

    def hasHeightForWidth(self) -> bool:
        return False

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(4)

        # Row 1: Target path bar + Browse + Check folder + Cancel
        row1 = QHBoxLayout()
        row1.setContentsMargins(0, 0, 0, 0)
        row1.setSpacing(6)
        folder_lbl = QLabel("Target folder")
        folder_lbl.setObjectName("SecondaryLabel")
        folder_lbl.setTextFormat(Qt.TextFormat.PlainText)
        self.folder_input = QLineEdit()
        self.folder_input.setObjectName("MonoInput")
        self.folder_input.setFixedHeight(28)
        self.folder_input.setMinimumWidth(120)
        self.folder_input.setPlaceholderText(
            "Select a folder to inspect (e.g. D:\\Coal\\coalscan\\fixtures\\generated)"
        )
        folder_lbl.setBuddy(self.folder_input)

        self.browse_btn = QPushButton("Browse")
        self.browse_btn.setFixedHeight(28)
        self.browse_btn.setToolTip("Choose a folder to inspect safely")
        self.browse_btn.clicked.connect(self._on_browse)

        self.scan_btn = QPushButton("Check folder")
        self.scan_btn.setObjectName("PrimaryButton")
        self.scan_btn.setFixedHeight(28)
        self.scan_btn.clicked.connect(self._on_scan_clicked)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setFixedHeight(28)
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self.cancel_requested.emit)

        self.local_only_checkbox = QCheckBox("Offline-only")
        self.local_only_checkbox.setObjectName("OfflinePillCheck")
        self.local_only_checkbox.setChecked(True)
        self.local_only_checkbox.setToolTip(
            "All checks run 100% locally offline; files are never opened, launched, or uploaded."
        )
        self.local_only_checkbox.toggled.connect(self._on_local_toggled)

        row1.addWidget(folder_lbl)
        row1.addWidget(self.folder_input, stretch=1)
        row1.addWidget(self.browse_btn)
        row1.addWidget(self.scan_btn)
        row1.addWidget(self.cancel_btn)
        layout.addLayout(row1)

        # Row 2: 4-column metric strip + inline progress bar & file counter
        row2 = QHBoxLayout()
        row2.setContentsMargins(0, 0, 0, 0)
        row2.setSpacing(10)

        metric_strip = QFrame()
        metric_strip.setObjectName("MetricStrip")
        metric_layout = QHBoxLayout(metric_strip)
        metric_layout.setContentsMargins(0, 0, 0, 0)
        metric_layout.setSpacing(0)

        self._metric_analyzed_val, self._metric_analyzed_lbl = self._make_metric_cell(
            metric_layout, "0", "Checked", add_divider=True
        )
        self._metric_unsupported_val, self._metric_unsupported_lbl = self._make_metric_cell(
            metric_layout, "0", "Unsupported", add_divider=True
        )
        self._metric_skipped_val, self._metric_skipped_lbl = self._make_metric_cell(
            metric_layout, "0", "Skipped", add_divider=True
        )
        self._metric_remaining_val, self._metric_remaining_lbl = self._make_metric_cell(
            metric_layout, "0", "Remaining", add_divider=False
        )

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setMinimumWidth(80)

        self.progress_label = QLabel("Checked 0 / 0 files")
        self.progress_label.setTextFormat(Qt.TextFormat.PlainText)
        self.progress_label.setObjectName("MonoMutedLabel")

        row2.addWidget(metric_strip, stretch=3)
        row2.addWidget(self.progress_bar, stretch=1)
        row2.addWidget(self.progress_label, stretch=0)
        layout.addLayout(row2)

        # Row 3: Compact telemetry & limits footer line (Ignored horizontal policy so it never overflows)
        meta_row = QHBoxLayout()
        meta_row.setContentsMargins(0, 0, 0, 0)
        meta_row.setSpacing(8)
        self.header_label = QLabel("CHOOSE A FOLDER TO CHECK")
        self.header_label.setObjectName("SectionHeader")
        self.header_label.setVisible(False)

        self.counts_label = QLabel(
            "0 checked | 0 not supported | 0 skipped | 0 remaining"
        )
        self.counts_label.setTextFormat(Qt.TextFormat.PlainText)
        self.counts_label.setObjectName("CountsLabel")
        self.counts_label.setWordWrap(True)
        self.counts_label.setMinimumWidth(80)
        self.counts_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )

        self.limits_label = QLabel("")
        self.limits_label.setTextFormat(Qt.TextFormat.PlainText)
        self.limits_label.setObjectName("MutedLabel")
        self.limits_label.setWordWrap(True)
        self.limits_label.setMinimumWidth(80)
        self.limits_label.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        self.limits_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )

        meta_row.addWidget(self.counts_label, stretch=1)
        meta_row.addWidget(self.limits_label, stretch=1)
        meta_row.addWidget(self.local_only_checkbox, stretch=0)
        layout.addLayout(meta_row)

    @staticmethod
    def _make_metric_cell(
        parent_layout: QHBoxLayout,
        initial_val: str,
        caption: str,
        add_divider: bool,
    ) -> tuple[QLabel, QLabel]:
        cell = QWidget()
        cell_layout = QHBoxLayout(cell)
        cell_layout.setContentsMargins(12, 5, 12, 5)
        cell_layout.setSpacing(8)

        val_lbl = QLabel(initial_val)
        val_lbl.setObjectName("MetricValue")
        val_lbl.setTextFormat(Qt.TextFormat.PlainText)

        cap_lbl = QLabel(caption)
        cap_lbl.setObjectName("MetricCaption")
        cap_lbl.setTextFormat(Qt.TextFormat.PlainText)

        cell_layout.addWidget(val_lbl)
        cell_layout.addWidget(cap_lbl, stretch=1)
        parent_layout.addWidget(cell, stretch=1)

        if add_divider:
            div = QFrame()
            div.setObjectName("HairlineV")
            div.setFixedWidth(1)
            parent_layout.addWidget(div)

        return val_lbl, cap_lbl

    def set_developer_mode(self, enabled: bool) -> None:
        """Switch labels between Standard (User) Mode and Developer Mode."""
        self._developer_mode = enabled
        max_mb = MAX_FILE_SIZE_BYTES // (1024 * 1024)
        if enabled:
            self.header_label.setText("SCAN FOLDER")
            self.local_only_checkbox.setText("Local-only mode: ON")
            self.scan_btn.setText("Scan folder")
            self.limits_label.setText(
                f"Scope: top level of folder only. Limits: {MAX_FILES_PER_SCAN} files, "
                f"{max_mb} MB per file, {PER_FILE_TIMEOUT_SECONDS} s per file, "
                f"{MAX_DISASM_INSTRUCTIONS_PER_FILE} instructions per file. "
                "Samples are never launched."
            )
        else:
            self.header_label.setText("CHOOSE A FOLDER TO CHECK")
            self.local_only_checkbox.setText("Offline-Only Protection: ON")
            self.scan_btn.setText("Check folder")
            self.limits_label.setText(
                f"Checks the top level of the selected folder (up to {MAX_FILES_PER_SCAN} files, "
                f"{max_mb} MB each). Files are read safely and never opened or run."
            )

        if self._last_progress is not None:
            self.update_progress(self._last_progress)
        else:
            if enabled:
                self.progress_label.setText("Progress 0 / 0 files")
                self.counts_label.setText(
                    "0 analyzed | 0 unsupported | 0 skipped | 0 remaining (0 processed)"
                )
            else:
                self.progress_label.setText("Checked 0 / 0 files")
                self.counts_label.setText(
                    "0 checked | 0 not supported | 0 skipped | 0 remaining"
                )

    def _on_local_toggled(self, checked: bool) -> None:
        if not checked:
            self.local_only_checkbox.setChecked(True)
        if self._developer_mode:
            self.local_only_checkbox.setText("Local-only mode: ON")
        else:
            self.local_only_checkbox.setText("Offline-Only Protection: ON")

    def _on_browse(self) -> None:
        chosen = QFileDialog.getExistingDirectory(
            self,
            "Select Folder for Static PE Triage",
            self.folder_input.text() or str(Path.cwd()),
        )
        if chosen:
            self.folder_input.setText(chosen)

    def _on_scan_clicked(self) -> None:
        folder_text = self.folder_input.text().strip()
        if folder_text:
            self.scan_requested.emit(folder_text)

    def set_scanning_state(self, is_scanning: bool) -> None:
        """Enable or disable controls while a batch scan is running."""
        self.scan_btn.setEnabled(not is_scanning)
        self.browse_btn.setEnabled(not is_scanning)
        self.folder_input.setEnabled(not is_scanning)
        self.cancel_btn.setEnabled(is_scanning)

    def update_progress(self, progress: BatchProgress) -> None:
        """Update progress bar and live counters from a BatchProgress snapshot."""
        self._last_progress = progress
        total = progress.total_files
        proc = progress.processed_files
        if self._developer_mode:
            self.progress_label.setText(f"Progress {proc} / {total} files")
        else:
            self.progress_label.setText(f"Checked {proc} / {total} files")

        if total > 0:
            self.progress_bar.setRange(0, total)
            self.progress_bar.setValue(proc)
        else:
            self.progress_bar.setRange(0, 1)
            self.progress_bar.setValue(0)

        a = progress.analyzed_count
        u = progress.unsupported_count
        s = progress.skipped_count
        r = progress.remaining_count
        other = max(0, proc - (a + u + s))

        self._metric_analyzed_val.setText(str(a))
        self._metric_unsupported_val.setText(str(u))
        self._metric_skipped_val.setText(str(s + other))
        self._metric_remaining_val.setText(str(r))
        if self._developer_mode:
            if other > 0:
                self.counts_label.setText(
                    f"{a} analyzed | {u} unsupported | {s} skipped | {other} malformed/failed | "
                    f"{r} remaining ({a} + {u} + {s} + {other} = {proc} processed)"
                )
            else:
                self.counts_label.setText(
                    f"{a} analyzed | {u} unsupported | {s} skipped | {r} remaining "
                    f"({a} + {u} + {s} = {proc} processed)"
                )
        else:
            if other > 0:
                self.counts_label.setText(
                    f"{a} programs checked | {u} other CPU | {s} skipped | {other} damaged/unreadable | "
                    f"{r} remaining ({proc} of {total})"
                )
            else:
                self.counts_label.setText(
                    f"{a} programs checked | {u} other CPU | {s} skipped | {r} remaining "
                    f"({proc} of {total})"
                )
