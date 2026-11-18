"""Results Table section widget (Section 3 Mockup 2: RESULTS).

Displays a sortable table with columns:
FILE | STATUS | BAND | SCORE | FINDINGS | REASON
Skipped, failed, unsupported, malformed, and timed-out files remain in the table with reasons.
Provides buttons for 'Export folder PDF', 'Export folder CSV', and 'Export selected file'.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from coalscan.core.models import FileScanResult, RiskBand, escape_untrusted_text
from coalscan.ui.plain_language import (
    friendly_attention_level,
    friendly_file_type,
    friendly_row_summary,
    matches_standard_filter,
)


class _NumericTableItem(QTableWidgetItem):
    """Table item that sorts numerically when a numeric value is present."""

    def __init__(self, display_text: str, sort_val: int) -> None:
        super().__init__(display_text)
        self._sort_val = sort_val

    def __lt__(self, other: QTableWidgetItem) -> bool:
        if isinstance(other, _NumericTableItem):
            return self._sort_val < other._sort_val
        return super().__lt__(other)


class ResultsPageWidget(QFrame):
    """Middle panel corresponding to '2 RESULTS' in the Section 3 UI mockup."""

    file_selected = Signal(object)  # Emits FileScanResult
    export_folder_pdf_requested = Signal()
    export_folder_csv_requested = Signal()
    export_selected_pdf_requested = Signal(object)
    export_selected_csv_requested = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("ResultsPageWidget")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._developer_mode: bool = False
        self._dark_theme: bool = False
        self._all_results: list[FileScanResult] = []
        self._results_by_name: dict[str, FileScanResult] = {}
        self._build_ui()
        self.set_developer_mode(False)

    def hasHeightForWidth(self) -> bool:
        return False

    def minimumSizeHint(self) -> QSize:
        return QSize(420, 260)

    def sizeHint(self) -> QSize:
        return QSize(480, 400)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 14)
        layout.setSpacing(10)

        hdr_row = QHBoxLayout()
        hdr_row.setContentsMargins(0, 0, 0, 0)
        self.header_label = QLabel("Scan results")
        self.header_label.setTextFormat(Qt.TextFormat.PlainText)
        self.header_label.setObjectName("SectionHeader")
        self.shown_count_label = QLabel("0 files")
        self.shown_count_label.setTextFormat(Qt.TextFormat.PlainText)
        self.shown_count_label.setObjectName("CountPill")
        hdr_row.addWidget(self.header_label)
        hdr_row.addStretch(1)
        hdr_row.addWidget(self.shown_count_label)
        layout.addLayout(hdr_row, stretch=0)

        # Filter toolbar (36px height controls)
        filter_row = QHBoxLayout()
        filter_row.setContentsMargins(0, 0, 0, 0)
        filter_row.setSpacing(8)

        filter_lbl = QLabel("Show")
        filter_lbl.setTextFormat(Qt.TextFormat.PlainText)
        filter_lbl.setObjectName("MutedLabel")
        self.filter_combo = QComboBox()
        self.filter_combo.setFixedHeight(36)
        self.filter_combo.addItem("All files", "all")
        self.filter_combo.addItem("Only files needing attention", "attention")
        self.filter_combo.addItem("Analyzed programs only", "analyzed")
        self.filter_combo.addItem("Skipped & errors", "skipped_errors")
        self.filter_combo.currentIndexChanged.connect(self._apply_filter_and_render)

        self.search_input = QLineEdit()
        self.search_input.setObjectName("MonoInput")
        self.search_input.setFixedHeight(36)
        self.search_input.setPlaceholderText("Filter by file name...")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self._apply_filter_and_render)

        filter_row.addWidget(filter_lbl)
        filter_row.addWidget(self.filter_combo)
        filter_row.addWidget(self.search_input, stretch=1)
        layout.addLayout(filter_row, stretch=0)

        self.table = QTableWidget(0, 4)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTriggers.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(False)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)

        row_height = 36
        self.table.verticalHeader().setDefaultSectionSize(row_height)
        self.table.setMinimumHeight(190)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.table.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )

        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self.table, stretch=1)

        # Dedicated fixed-height export_bar below the table
        self.export_bar = QWidget()
        self.export_bar.setMinimumHeight(40)
        self.export_bar.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        self.export_row_layout = QHBoxLayout(self.export_bar)
        self.export_row_layout.setContentsMargins(0, 2, 0, 2)
        self.export_row_layout.setSpacing(6)

        self.export_folder_pdf_btn = QPushButton("Save folder PDF")
        self.export_folder_pdf_btn.setMinimumHeight(32)
        self.export_folder_pdf_btn.setEnabled(False)
        self.export_folder_pdf_btn.clicked.connect(self.export_folder_pdf_requested.emit)

        self.export_folder_csv_btn = QPushButton("Save folder CSV")
        self.export_folder_csv_btn.setMinimumHeight(32)
        self.export_folder_csv_btn.setEnabled(False)
        self.export_folder_csv_btn.clicked.connect(self.export_folder_csv_requested.emit)

        self.export_selected_btn = QPushButton("Save selected PDF")
        self.export_selected_btn.setMinimumHeight(32)
        self.export_selected_btn.setEnabled(False)
        self.export_selected_btn.clicked.connect(self._on_export_selected)

        self.export_selected_csv_btn = QPushButton("Export selected CSV")
        self.export_selected_csv_btn.setMinimumHeight(32)
        self.export_selected_csv_btn.setEnabled(False)
        self.export_selected_csv_btn.clicked.connect(self._on_export_selected_csv)

        self.hint_label = QLabel(
            "Select a file to inspect its details."
        )
        self.hint_label.setTextFormat(Qt.TextFormat.PlainText)
        self.hint_label.setObjectName("MutedLabel")
        self.hint_label.setWordWrap(True)
        self.hint_label.setMinimumWidth(60)
        self.hint_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )

        self.export_row_layout.addWidget(self.export_folder_pdf_btn)
        self.export_row_layout.addWidget(self.export_folder_csv_btn)
        self.export_row_layout.addWidget(self.export_selected_btn)
        self.export_row_layout.addWidget(self.export_selected_csv_btn)
        self.export_row_layout.addSpacing(6)
        self.export_row_layout.addWidget(self.hint_label, stretch=1)
        layout.addWidget(self.export_bar, stretch=0)

    def set_dark_theme(self, dark: bool) -> None:
        """Update table status colors for Light or Dark mode and re-render."""
        self._dark_theme = dark
        selected_name = None
        sel = self.selected_result()
        if sel is not None:
            selected_name = sel.file_name
        self._apply_filter_and_render(preserve_file_name=selected_name)

    def _configure_table_columns(self) -> None:
        hdr = self.table.horizontalHeader()
        hdr.setStretchLastSection(True)
        if self._developer_mode:
            self.table.setColumnCount(6)
            self.table.setHorizontalHeaderLabels(
                ["FILE", "STATUS", "BAND", "SCORE", "FINDINGS", "REASON"]
            )
            widths = [140, 110, 90, 55, 65]
            for col, w in enumerate(widths):
                hdr.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
                self.table.setColumnWidth(col, w)
            hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        else:
            self.table.setColumnCount(4)
            self.table.setHorizontalHeaderLabels(
                ["FILE NAME", "FILE TYPE", "ATTENTION LEVEL", "SUMMARY"]
            )
            widths = [150, 130, 130]
            for col, w in enumerate(widths):
                hdr.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
                self.table.setColumnWidth(col, w)
            hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)

    def set_developer_mode(self, enabled: bool) -> None:
        """Switch table columns and labels between Standard Mode and Developer Mode."""
        selected_name = None
        sel = self.selected_result()
        if sel is not None:
            selected_name = sel.file_name

        self._developer_mode = enabled
        if enabled:
            self.header_label.setText("RESULTS")
            self.export_folder_pdf_btn.setText("Export folder PDF")
            self.export_folder_csv_btn.setText("Export folder CSV")
            self.export_selected_btn.setText("Export selected file")
            self.export_selected_csv_btn.setVisible(True)
            self.hint_label.setText(
                "Select a row to open its evidence."
            )
        else:
            self.header_label.setText("SCAN RESULTS")
            self.export_folder_pdf_btn.setText("Save Folder PDF")
            self.export_folder_csv_btn.setText("Save CSV")
            self.export_selected_btn.setText("Save File PDF")
            self.export_selected_csv_btn.setVisible(False)
            self.hint_label.setText(
                "Click any file to view details."
            )

        self._configure_table_columns()
        self._apply_filter_and_render(preserve_file_name=selected_name)

    def clear_results(self) -> None:
        self._all_results.clear()
        self._results_by_name.clear()
        self._clear_table_rows()
        self.shown_count_label.setText("0 files")
        self.export_folder_pdf_btn.setEnabled(False)
        self.export_folder_csv_btn.setEnabled(False)
        self.export_selected_btn.setEnabled(False)
        self.export_selected_csv_btn.setEnabled(False)

    def _clear_table_rows(self) -> None:
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.table.setSortingEnabled(True)

    def set_results(self, results: list[FileScanResult]) -> None:
        """Populate the results table with a batch of FileScanResult items."""
        self.clear_results()
        self._all_results = list(results)
        for res in self._all_results:
            self._results_by_name[res.file_name] = res
        self._apply_filter_and_render()

    def append_live_result(self, res: FileScanResult) -> None:
        """Append a single FileScanResult as workers finish in real time."""
        self._all_results.append(res)
        self._results_by_name[res.file_name] = res
        if self._matches_current_filter(res):
            was_sorting = self.table.isSortingEnabled()
            self.table.setSortingEnabled(False)
            self._append_row(res)
            self.table.setSortingEnabled(was_sorting)
        self._update_shown_count()
        self.export_folder_pdf_btn.setEnabled(True)
        self.export_folder_csv_btn.setEnabled(True)

    def _matches_current_filter(self, res: FileScanResult) -> bool:
        filter_key = str(self.filter_combo.currentData() or "all")
        return matches_standard_filter(res, filter_key, self.search_input.text())

    def _update_shown_count(self) -> None:
        shown = self.table.rowCount()
        total = len(self._all_results)
        if shown == total:
            self.shown_count_label.setText(f"{total} files")
        else:
            self.shown_count_label.setText(f"Showing {shown} of {total} files")

    def _apply_filter_and_render(
        self, *_args: object, preserve_file_name: Optional[str] = None
    ) -> None:
        self._clear_table_rows()
        self.table.setSortingEnabled(False)
        for res in self._all_results:
            if self._matches_current_filter(res):
                self._append_row(res)
        self.table.setSortingEnabled(True)

        has_any = len(self._all_results) > 0
        self.export_folder_pdf_btn.setEnabled(has_any)
        self.export_folder_csv_btn.setEnabled(has_any)
        self._update_shown_count()

        if self.table.rowCount() > 0:
            target_row = 0
            if preserve_file_name:
                for r_idx in range(self.table.rowCount()):
                    it = self.table.item(r_idx, 0)
                    if it and str(it.data(Qt.ItemDataRole.UserRole) or "") == preserve_file_name:
                        target_row = r_idx
                        break
            self.table.selectRow(target_row)
        else:
            self.export_selected_btn.setEnabled(False)
            self.export_selected_csv_btn.setEnabled(False)

    def _append_row(self, res: FileScanResult) -> None:
        row_idx = self.table.rowCount()
        self.table.insertRow(row_idx)

        file_item = QTableWidgetItem(escape_untrusted_text(res.file_name, max_len=256))
        file_item.setData(Qt.ItemDataRole.UserRole, res.file_name)

        if self._developer_mode:
            status_item = QTableWidgetItem(escape_untrusted_text(res.status.value, max_len=128))
            band_item = QTableWidgetItem(escape_untrusted_text(res.band.value, max_len=64))

            if res.score is not None:
                score_item = _NumericTableItem(str(res.score), res.score)
                findings_item = _NumericTableItem(str(len(res.findings)), len(res.findings))
            else:
                score_item = _NumericTableItem("-", -1)
                findings_item = _NumericTableItem("-", -1)

            reason_item = QTableWidgetItem(escape_untrusted_text(res.status_reason, max_len=256))

            self.table.setItem(row_idx, 0, file_item)
            self.table.setItem(row_idx, 1, status_item)
            self.table.setItem(row_idx, 2, band_item)
            self.table.setItem(row_idx, 3, score_item)
            self.table.setItem(row_idx, 4, findings_item)
            self.table.setItem(row_idx, 5, reason_item)
        else:
            type_item = QTableWidgetItem(friendly_file_type(res))
            att_text = friendly_attention_level(res)
            if res.band == RiskBand.REVIEW_CLOSELY:
                att_item = QTableWidgetItem(f"!  {att_text}")
                att_item.setForeground(QColor("#F87171" if self._dark_theme else "#B42318"))
                att_item.setBackground(QColor("#2E191A" if self._dark_theme else "#FDF1EF"))
            elif res.band == RiskBand.REVIEW:
                att_item = QTableWidgetItem(f"▲  {att_text}")
                att_item.setForeground(QColor("#F87171" if self._dark_theme else "#B42318"))
                att_item.setBackground(QColor("#2E191A" if self._dark_theme else "#FDF1EF"))
            elif res.band == RiskBand.ROUTINE and res.score is not None:
                att_item = QTableWidgetItem(f"✓  {att_text}")
                att_item.setForeground(QColor("#34D399" if self._dark_theme else "#1F6B45"))
                att_item.setBackground(QColor("#14281E" if self._dark_theme else "#EDF6F0"))
            else:
                att_item = QTableWidgetItem(f"●  {att_text}")
                att_item.setForeground(QColor("#FBBF24" if self._dark_theme else "#8A5A00"))
                att_item.setBackground(QColor("#2A2212" if self._dark_theme else "#FBF4E4"))

            summary_item = QTableWidgetItem(friendly_row_summary(res))

            self.table.setItem(row_idx, 0, file_item)
            self.table.setItem(row_idx, 1, type_item)
            self.table.setItem(row_idx, 2, att_item)
            self.table.setItem(row_idx, 3, summary_item)

    def selected_result(self) -> Optional[FileScanResult]:
        """Return the currently selected FileScanResult, or None."""
        sel = self.table.selectedItems()
        if not sel:
            return None
        row = sel[0].row()
        first_item = self.table.item(row, 0)
        if first_item is None:
            return None
        key = str(first_item.data(Qt.ItemDataRole.UserRole) or "")
        return self._results_by_name.get(key)

    def _on_selection_changed(self) -> None:
        res = self.selected_result()
        has_sel = res is not None
        self.export_selected_btn.setEnabled(has_sel)
        self.export_selected_csv_btn.setEnabled(has_sel)
        if res is not None:
            self.file_selected.emit(res)

    def _on_export_selected(self) -> None:
        res = self.selected_result()
        if res is not None:
            self.export_selected_pdf_requested.emit(res)

    def _on_export_selected_csv(self) -> None:
        res = self.selected_result()
        if res is not None:
            self.export_selected_csv_requested.emit(res)
