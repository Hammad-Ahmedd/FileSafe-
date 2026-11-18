"""Main application window for Assembly-Assisted Malware Analysis (CSC-203).

Integrates:
- 1 SCAN FOLDER (`ScanPageWidget`)
- 2 RESULTS (`ResultsPageWidget`)
- 3 EVIDENCE DETAIL (`EvidencePageWidget`)
- Vertical `QSplitter` between Results and Evidence so the results table expands
  and the evidence section is never clipped
- High-contrast selected-row stylesheet readable in both light and dark Windows themes
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from PySide6.QtCore import QByteArray, Qt, QThread, Signal
from PySide6.QtGui import QFont, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from coalscan.core.limits import (
    BANDING_VERSION,
    RULE_CATALOG_VERSION,
    TOOL_VERSION,
)
from coalscan.core.models import FileScanResult, escape_untrusted_text
from coalscan.core.supervisor import BatchProgress, BatchScanSummary, BatchSupervisor
from coalscan.report.csv_export import export_batch_csv, export_single_file_csv
from coalscan.report.pdf_report import export_batch_pdf, export_single_file_pdf
from coalscan.storage.history import DEFAULT_DB_PATH, ScanHistoryStore
from coalscan.ui.evidence_page import EvidencePageWidget
from coalscan.ui.results_page import ResultsPageWidget
from coalscan.ui.scan_page import ScanPageWidget

def _render_filesafe_logo(size: int = 24, dark: bool = False) -> QPixmap:
    """Render a flat outline FileSafe shield-folder mark in the petrol accent color."""
    stroke = "#147C92" if dark else "#0F5E6E"
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
  <path d="M12 2.5 L20 5.5 V11.5 C20 16.5 16.6 20.1 12 21.8 C7.4 20.1 4 16.5 4 11.5 V5.5 Z" fill="none" stroke="{stroke}" stroke-width="1.8" stroke-linejoin="round"/>
  <path d="M9 12.2 L11.1 14.3 L15.2 9.8" fill="none" stroke="{stroke}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
</svg>"""
    renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    pixmap = QPixmap(size * 2, size * 2)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()
    pixmap.setDevicePixelRatio(2.0)
    return pixmap


def _render_lock_icon(size: int = 14, dark: bool = False) -> QPixmap:
    """Render a flat static lock outline icon for the offline-only status indicator."""
    stroke = "#34D399" if dark else "#1F6B45"
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
  <rect x="5" y="11" width="14" height="10" rx="2" fill="none" stroke="{stroke}" stroke-width="2"/>
  <path d="M8 11 V7 A4 4 0 0 1 16 7 V11" fill="none" stroke="{stroke}" stroke-width="2" stroke-linecap="round"/>
</svg>"""
    renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    pixmap = QPixmap(size * 2, size * 2)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()
    pixmap.setDevicePixelRatio(2.0)
    return pixmap


def build_stylesheet(dark: bool = False) -> str:
    """Return the Linear/1Password-inspired QSS theme for Light or Dark mode."""
    if dark:
        bg = "#121316"
        surface = "#181A1E"
        subtle = "#1C1F24"
        border = "#2A2D35"
        text_primary = "#F1F2F5"
        text_secondary = "#9BA1A6"
        accent = "#147C92"
        accent_hover = "#1B9BB7"
        sel_bg = "#1B2A30"
        hover_bg = "#202329"
        status_ok_fg = "#34D399"
        status_ok_bg = "#14281E"
        danger_fg = "#F87171"
        danger_bg = "#2E191A"
        danger_btn = "#B42318"
        scroll_handle = "#343842"
    else:
        bg = "#F7F6F3"
        surface = "#FFFFFF"
        subtle = "#FAFAF8"
        border = "#E4E2DC"
        text_primary = "#16181B"
        text_secondary = "#5B6068"
        accent = "#0F5E6E"
        accent_hover = "#0B4A57"
        sel_bg = "#EBF3F5"
        hover_bg = "#F2F1ED"
        status_ok_fg = "#1F6B45"
        status_ok_bg = "#EDF6F0"
        danger_fg = "#B42318"
        danger_bg = "#FDF1EF"
        danger_btn = "#B42318"
        scroll_handle = "#CFCBC2"

    return f"""
QMainWindow {{
    background-color: {bg};
    color: {text_primary};
    font-family: "Geist", "Inter", "Segoe UI", system-ui, sans-serif;
}}
QDialog {{
    background-color: {surface};
    color: {text_primary};
    font-family: "Geist", "Inter", "Segoe UI", system-ui, sans-serif;
}}
QWidget {{
    color: {text_primary};
    font-family: "Geist", "Inter", "Segoe UI", system-ui, sans-serif;
}}
QScrollArea, QScrollArea > QWidget > QWidget {{
    background-color: {bg};
    border: none;
}}
QFrame#Sidebar {{
    background-color: {subtle};
    border-right: 1px solid {border};
}}
QFrame#TopHeaderBar {{
    background-color: {surface};
    border-bottom: 1px solid {border};
}}
QFrame#ScanPageWidget, QFrame#ResultsPageWidget, QFrame#EvidencePageWidget {{
    background-color: {surface};
    border: 1px solid {border};
    border-radius: 8px;
}}
QFrame#MetricStrip {{
    background-color: {subtle};
    border: 1px solid {border};
    border-radius: 6px;
}}
QFrame#HairlineV {{
    background-color: {border};
    border: none;
}}
QFrame#ObservedFactsBox, QFrame#EvidenceRightPane {{
    background-color: {subtle};
    border: 1px solid {border};
    border-radius: 6px;
}}
QFrame#ShaRecessBox, QFrame#InfoBannerBox {{
    background-color: {bg};
    border: 1px solid {border};
    border-radius: 6px;
}}
QFrame#ModeTrack {{
    background-color: {bg};
    border: 1px solid {border};
    border-radius: 6px;
}}
QFrame#OfflineStatusChip {{
    background-color: {status_ok_bg};
    border: 1px solid {border};
    border-radius: 6px;
}}
QLabel {{
    background-color: transparent;
    color: {text_primary};
}}
QLabel#AppTitleLabel {{
    font-weight: 700;
    font-size: 15px;
    color: {text_primary};
}}
QLabel#PageTitleLabel {{
    font-weight: 600;
    font-size: 14px;
    color: {text_primary};
}}
QLabel#OfflineStatusLabel {{
    font-size: 12px;
    font-weight: 500;
    color: {status_ok_fg};
}}
QLabel#SectionHeader {{
    color: {text_primary};
    font-weight: 600;
    font-size: 13px;
}}
QLabel#FileTitleLabel {{
    font-weight: 600;
    font-size: 13px;
    color: {text_primary};
}}
QLabel#MetricValue {{
    font-family: "JetBrains Mono", "Consolas", monospace;
    font-weight: 700;
    font-size: 16px;
    color: {text_primary};
}}
QLabel#MetricCaption {{
    font-size: 11px;
    color: {text_secondary};
}}
QLabel#BandSummaryLabel {{
    background-color: {subtle};
    border: 1px solid {border};
    border-radius: 4px;
    padding: 2px 8px;
    font-weight: 600;
    font-size: 11px;
    color: {text_primary};
}}
QLabel#SubHeader {{
    font-weight: 600;
    font-size: 11px;
    color: {text_secondary};
}}
QLabel#SecondaryLabel {{
    color: {text_secondary};
    font-size: 12px;
}}
QLabel#CountsLabel {{
    font-family: "JetBrains Mono", "Consolas", monospace;
    font-size: 11px;
    color: {text_secondary};
}}
QLabel#MutedLabel {{
    color: {text_secondary};
    font-size: 11px;
}}
QLabel#MonoLabel {{
    font-family: "JetBrains Mono", "Consolas", monospace;
    font-size: 10.5px;
    color: {text_primary};
}}
QLabel#MonoMutedLabel {{
    font-family: "JetBrains Mono", "Consolas", monospace;
    font-size: 11px;
    color: {text_secondary};
}}
QLabel#CountPill {{
    background-color: {subtle};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 3px 8px;
    font-family: "JetBrains Mono", "Consolas", monospace;
    font-size: 11px;
    color: {text_secondary};
}}
QLabel#EvidenceBlockLabel {{
    background-color: transparent;
    border: none;
    border-left: 2px solid {accent};
    border-radius: 0px;
    padding: 1px 6px;
    color: {text_primary};
    font-size: 10.5px;
}}
QLineEdit {{
    background-color: {surface};
    color: {text_primary};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 6px 10px;
    selection-background-color: {accent};
    selection-color: #FFFFFF;
}}
QLineEdit:focus {{
    border: 2px solid {accent};
}}
QLineEdit#MonoInput {{
    font-family: "JetBrains Mono", "Consolas", monospace;
    font-size: 12px;
}}
QComboBox {{
    background-color: {surface};
    color: {text_primary};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 4px 10px;
}}
QComboBox:focus {{
    border: 2px solid {accent};
}}
QComboBox::drop-down {{
    border: none;
    width: 20px;
}}
QComboBox QAbstractItemView {{
    background-color: {surface};
    color: {text_primary};
    border: 1px solid {border};
    selection-background-color: {sel_bg};
    selection-color: {text_primary};
}}
QCheckBox#OfflinePillCheck {{
    background-color: {status_ok_bg};
    color: {status_ok_fg};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 4px 10px;
    font-weight: 600;
    font-size: 11px;
}}
QCheckBox#OfflinePillCheck::indicator {{
    width: 8px;
    height: 8px;
    border-radius: 4px;
    background-color: {status_ok_fg};
    border: 1px solid {status_ok_fg};
}}
QProgressBar {{
    background-color: {border};
    border: none;
    border-radius: 2px;
}}
QProgressBar::chunk {{
    background-color: {accent};
    border-radius: 2px;
}}
QTableWidget {{
    background-color: {surface};
    color: {text_primary};
    gridline-color: {border};
    border: 1px solid {border};
    border-radius: 6px;
    selection-background-color: {sel_bg};
    selection-color: {text_primary};
}}
QTableCornerButton::section {{
    background-color: {subtle};
    border: none;
    border-bottom: 1px solid {border};
}}
QHeaderView::section {{
    background-color: {subtle};
    color: {text_secondary};
    font-weight: 600;
    font-size: 11px;
    padding: 6px 10px;
    border: none;
    border-bottom: 1px solid {border};
    border-right: 1px solid {border};
}}
QTableWidget::item {{
    color: {text_primary};
    padding: 4px 10px;
    border-bottom: 1px solid {border};
}}
QTableWidget::item:hover {{
    background-color: {hover_bg};
}}
QTableWidget::item:selected, QTableWidget::item:selected:active, QTableWidget::item:selected:!active {{
    background-color: {sel_bg};
    color: {text_primary};
}}
QListWidget, QListWidget#FindingsRecessList {{
    background-color: {surface};
    color: {text_primary};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 4px;
    selection-background-color: {sel_bg};
    selection-color: {text_primary};
}}
QListWidget::item {{
    color: {text_primary};
    padding: 6px 8px;
    border-radius: 4px;
}}
QListWidget::item:hover {{
    background-color: {hover_bg};
}}
QListWidget::item:selected, QListWidget::item:selected:active, QListWidget::item:selected:!active {{
    background-color: {sel_bg};
    color: {text_primary};
}}
QPushButton {{
    padding: 6px 12px;
    border: 1px solid {border};
    border-radius: 6px;
    background-color: {surface};
    color: {text_primary};
    font-weight: 500;
    font-size: 12px;
}}
QPushButton:hover {{
    background-color: {hover_bg};
}}
QPushButton:focus {{
    border: 2px solid {accent};
}}
QPushButton:disabled {{
    color: {text_secondary};
    background-color: {subtle};
}}
QPushButton#SidebarNavButton {{
    text-align: left;
    padding: 8px 12px;
    border: none;
    border-radius: 6px;
    background-color: transparent;
    color: {text_secondary};
    font-weight: 500;
    font-size: 13px;
}}
QPushButton#SidebarNavButton:hover {{
    background-color: {hover_bg};
    color: {text_primary};
}}
QPushButton#SidebarNavButton:checked {{
    background-color: {sel_bg};
    color: {accent};
    font-weight: 600;
    border-left: 2px solid {accent};
}}
QPushButton#PrimaryButton {{
    background-color: {accent};
    color: #FFFFFF;
    border: 1px solid {accent};
    font-weight: 600;
}}
QPushButton#PrimaryButton:hover {{
    background-color: {accent_hover};
    border-color: {accent_hover};
}}
QPushButton#PrimaryButton:disabled {{
    background-color: {subtle};
    border-color: {border};
    color: {text_secondary};
}}
QPushButton#ModeToggleButton {{
    padding: 4px 12px;
    background-color: transparent;
    color: {text_secondary};
    border: none;
    border-radius: 4px;
    font-weight: 500;
    font-size: 12px;
}}
QPushButton#ModeToggleButton:hover {{
    color: {text_primary};
}}
QPushButton#ModeToggleButton:checked {{
    background-color: {accent};
    color: #FFFFFF;
    font-weight: 600;
}}
QPushButton#DangerOutlineButton {{
    background-color: {danger_bg};
    color: {danger_fg};
    border: 1px solid {danger_fg};
}}
QPushButton#DangerButton {{
    background-color: {danger_btn};
    color: #FFFFFF;
    border: 1px solid {danger_btn};
}}
QPlainTextEdit {{
    background-color: {bg};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 6px;
    color: {text_primary};
    selection-background-color: {accent};
    selection-color: #FFFFFF;
}}
QSplitter::handle:horizontal {{
    background: transparent;
    width: 8px;
}}
QScrollBar:vertical {{
    background: transparent;
    width: 8px;
    margin: 0px;
}}
QScrollBar::handle:vertical {{
    background: {scroll_handle};
    min-height: 24px;
    border-radius: 4px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
    width: 0px;
}}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
    background: transparent;
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 8px;
    margin: 0px;
}}
QScrollBar::handle:horizontal {{
    background: {scroll_handle};
    min-width: 24px;
    border-radius: 4px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    height: 0px;
    width: 0px;
}}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
    background: transparent;
}}
"""


APP_STYLESHEET = build_stylesheet(dark=False)


class _ScanWorkerThread(QThread):
    """Background Qt thread that drives BatchSupervisor without blocking the UI."""

    progress_signal = Signal(object)  # BatchProgress
    finished_signal = Signal(object)  # BatchScanSummary
    error_signal = Signal(str)

    def __init__(self, supervisor: BatchSupervisor, folder_path: str) -> None:
        super().__init__()
        self.supervisor = supervisor
        self.folder_path = folder_path

    def run(self) -> None:
        try:
            summary = self.supervisor.scan_folder(
                self.folder_path,
                on_progress=self.progress_signal.emit,
            )
            self.finished_signal.emit(summary)
        except Exception as exc:
            self.error_signal.emit(str(exc))


class HistoryDialog(QDialog):
    """Modal dialog for viewing and deleting local SQLite scan metadata history."""

    def __init__(self, store: ScanHistoryStore, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.store = store
        self.setWindowTitle("Local Scan History (SQLite Metadata Only)")
        self.resize(680, 380)
        self._build_ui()
        self.refresh_list()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        info_box = QFrame()
        info_box.setObjectName("InfoBannerBox")
        info_layout = QHBoxLayout(info_box)
        info_layout.setContentsMargins(10, 8, 10, 8)
        info = QLabel(
            "Local SQLite history stores metadata and rule findings only (never binary file bytes)."
        )
        info.setObjectName("MutedLabel")
        info.setTextFormat(Qt.TextFormat.PlainText)
        info_layout.addWidget(info)
        layout.addWidget(info_box)

        self.list_widget = QListWidget()
        mono_font = QFont("JetBrains Mono", 9)
        mono_font.setStyleHint(QFont.StyleHint.Monospace)
        self.list_widget.setFont(mono_font)
        layout.addWidget(self.list_widget, stretch=1)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        self.delete_one_btn = QPushButton("Delete Selected Scan")
        self.delete_one_btn.setObjectName("DangerOutlineButton")
        self.delete_one_btn.setMinimumHeight(30)
        self.delete_one_btn.clicked.connect(self._on_delete_selected)

        self.delete_all_btn = QPushButton("Delete All History")
        self.delete_all_btn.setObjectName("DangerButton")
        self.delete_all_btn.setMinimumHeight(30)
        self.delete_all_btn.clicked.connect(self._on_delete_all)

        close_btn = QPushButton("Close")
        close_btn.setMinimumHeight(30)
        close_btn.clicked.connect(self.accept)

        btn_row.addWidget(self.delete_one_btn)
        btn_row.addWidget(self.delete_all_btn)
        btn_row.addStretch(1)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)

    def refresh_list(self) -> None:
        self.list_widget.clear()
        scans = self.store.list_scans()
        for sc in scans:
            scan_id = int(sc["scan_id"])
            text = (
                f"Scan #{scan_id} | {sc['scan_date']} | Folder: {sc['folder_path']} | "
                f"Files: {sc['processed_files']}/{sc['total_files']} "
                f"(Analyzed: {sc['analyzed_count']}, Skipped: {sc['skipped_count']})"
            )
            item = QListWidgetItem(text)
            item.setData(256, scan_id)
            self.list_widget.addItem(item)

    def _on_delete_selected(self) -> None:
        item = self.list_widget.currentItem()
        if item is None:
            return
        scan_id = int(item.data(256))
        self.store.delete_scan(scan_id)
        self.refresh_list()

    def _on_delete_all(self) -> None:
        self.store.delete_all_history()
        self.refresh_list()


class MainWindow(QMainWindow):
    """Main desktop triage window matching the Section 3 3-panel workflow."""

    def __init__(
        self,
        db_path: Path = DEFAULT_DB_PATH,
        developer_mode: bool = False,
        dark_theme: bool = False,
    ) -> None:
        super().__init__()
        self.setWindowTitle("FileSafe")
        self.resize(1200, 800)
        self.setMinimumSize(960, 640)
        self._dark_theme: bool = dark_theme
        self.setStyleSheet(build_stylesheet(dark=dark_theme))

        self.history_store = ScanHistoryStore(db_path=db_path)
        self.supervisor = BatchSupervisor()
        self._scan_thread: Optional[_ScanWorkerThread] = None
        self._latest_summary: Optional[BatchScanSummary] = None
        self._developer_mode: bool = developer_mode

        self._build_ui()
        self.set_developer_mode(developer_mode)
        self.set_dark_theme(dark_theme)

    def _build_ui(self) -> None:
        # Root container: 220px fixed left sidebar (100% window height, never scrolled)
        # + right workspace column
        shell = QWidget(self)
        shell_layout = QHBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)

        # =====================================================================
        # 1. Fixed 220px Left Sidebar (permanently anchored top & bottom)
        # =====================================================================
        self.sidebar = QFrame()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(220)
        sb_layout = QVBoxLayout(self.sidebar)
        sb_layout.setContentsMargins(12, 12, 12, 12)
        sb_layout.setSpacing(8)

        brand_row = QHBoxLayout()
        brand_row.setContentsMargins(2, 2, 2, 4)
        brand_row.setSpacing(8)
        self.logo_label = QLabel()
        self.logo_label.setFixedSize(24, 24)
        self.logo_label.setPixmap(_render_filesafe_logo(24, self._dark_theme))

        self.app_title_label = QLabel("FileSafe")
        self.app_title_label.setTextFormat(Qt.TextFormat.PlainText)
        self.app_title_label.setObjectName("AppTitleLabel")
        brand_row.addWidget(self.logo_label)
        brand_row.addWidget(self.app_title_label, stretch=1)
        sb_layout.addLayout(brand_row)

        # Top navigation items in an expanding container so footer stays anchored at bottom
        nav_container = QWidget()
        from PySide6.QtWidgets import QSizePolicy

        nav_container.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        nav_layout = QVBoxLayout(nav_container)
        nav_layout.setContentsMargins(0, 0, 0, 0)
        nav_layout.setSpacing(6)

        nav_hdr = QLabel("Workspace")
        nav_hdr.setObjectName("SubHeader")
        nav_hdr.setTextFormat(Qt.TextFormat.PlainText)
        nav_layout.addWidget(nav_hdr)

        self.nav_triage_btn = QPushButton("Folder triage")
        self.nav_triage_btn.setObjectName("SidebarNavButton")
        self.nav_triage_btn.setCheckable(True)
        self.nav_triage_btn.setChecked(True)
        nav_layout.addWidget(self.nav_triage_btn)

        self.history_btn = QPushButton("Scan history")
        self.history_btn.setObjectName("SidebarNavButton")
        self.history_btn.clicked.connect(self._on_open_history)
        nav_layout.addWidget(self.history_btn)

        exp_hdr = QLabel("Reports")
        exp_hdr.setObjectName("SubHeader")
        exp_hdr.setTextFormat(Qt.TextFormat.PlainText)
        nav_layout.addWidget(exp_hdr)

        self.sidebar_pdf_btn = QPushButton("Export folder PDF")
        self.sidebar_pdf_btn.setObjectName("SidebarNavButton")
        self.sidebar_pdf_btn.clicked.connect(self._on_export_folder_pdf)
        nav_layout.addWidget(self.sidebar_pdf_btn)

        self.sidebar_csv_btn = QPushButton("Export folder CSV")
        self.sidebar_csv_btn.setObjectName("SidebarNavButton")
        self.sidebar_csv_btn.clicked.connect(self._on_export_folder_csv)
        nav_layout.addWidget(self.sidebar_csv_btn)

        nav_layout.addStretch(1)
        sb_layout.addWidget(nav_container, stretch=1)

        # Bottom Footer Block (permanently anchored at bottom of sidebar)
        self.sidebar_footer = QWidget()
        footer_layout = QVBoxLayout(self.sidebar_footer)
        footer_layout.setContentsMargins(0, 4, 0, 0)
        footer_layout.setSpacing(6)

        self.theme_toggle_btn = QPushButton("Theme: Light")
        self.theme_toggle_btn.setFixedHeight(32)
        self.theme_toggle_btn.clicked.connect(
            lambda: self.set_dark_theme(not self._dark_theme)
        )
        footer_layout.addWidget(self.theme_toggle_btn)

        self.footer_version_label = QLabel(f"v{TOOL_VERSION} · Static triage")
        self.footer_version_label.setObjectName("MutedLabel")
        self.footer_version_label.setTextFormat(Qt.TextFormat.PlainText)
        footer_layout.addWidget(self.footer_version_label)

        self.footer_security_label = QLabel("Files are never executed")
        self.footer_security_label.setObjectName("MutedLabel")
        self.footer_security_label.setTextFormat(Qt.TextFormat.PlainText)
        footer_layout.addWidget(self.footer_security_label)

        sb_layout.addWidget(self.sidebar_footer, stretch=0)

        shell_layout.addWidget(self.sidebar)

        # =====================================================================
        # 2. Right Workspace Column (Top Header + Scrollable Body)
        # =====================================================================
        right_col = QWidget()
        right_layout = QVBoxLayout(right_col)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        # Top Header Bar (anchored at top of right column)
        top_bar_frame = QFrame()
        top_bar_frame.setObjectName("TopHeaderBar")
        top_bar_frame.setFixedHeight(40)
        top_bar = QHBoxLayout(top_bar_frame)
        top_bar.setContentsMargins(14, 4, 14, 4)
        top_bar.setSpacing(10)

        self.banner_label = QLabel("Folder triage")
        self.banner_label.setTextFormat(Qt.TextFormat.PlainText)
        self.banner_label.setObjectName("PageTitleLabel")

        offline_chip = QFrame()
        offline_chip.setObjectName("OfflineStatusChip")
        offline_layout = QHBoxLayout(offline_chip)
        offline_layout.setContentsMargins(8, 4, 10, 4)
        offline_layout.setSpacing(6)
        self.lock_icon_label = QLabel()
        self.lock_icon_label.setFixedSize(14, 14)
        self.lock_icon_label.setPixmap(_render_lock_icon(14, self._dark_theme))
        offline_txt = QLabel("Offline-only · Files never executed")
        offline_txt.setObjectName("OfflineStatusLabel")
        offline_txt.setTextFormat(Qt.TextFormat.PlainText)
        offline_layout.addWidget(self.lock_icon_label)
        offline_layout.addWidget(offline_txt)

        mode_track = QFrame()
        mode_track.setObjectName("ModeTrack")
        mode_layout = QHBoxLayout(mode_track)
        mode_layout.setContentsMargins(3, 3, 3, 3)
        mode_layout.setSpacing(2)

        self.standard_mode_btn = QPushButton("Standard mode")
        self.standard_mode_btn.setObjectName("ModeToggleButton")
        self.standard_mode_btn.setCheckable(True)
        self.standard_mode_btn.setToolTip(
            "Plain-English summaries, file types, and practical guidance"
        )
        self.standard_mode_btn.clicked.connect(lambda: self.set_developer_mode(False))

        self.dev_mode_btn = QPushButton("Developer mode")
        self.dev_mode_btn.setObjectName("ModeToggleButton")
        self.dev_mode_btn.setCheckable(True)
        self.dev_mode_btn.setToolTip(
            "Technical PE metadata, rule IDs, offsets, score breakdown, and disassembly"
        )
        self.dev_mode_btn.clicked.connect(lambda: self.set_developer_mode(True))

        mode_layout.addWidget(self.standard_mode_btn)
        mode_layout.addWidget(self.dev_mode_btn)

        top_bar.addWidget(self.banner_label)
        top_bar.addStretch(1)
        top_bar.addWidget(offline_chip)
        top_bar.addWidget(mode_track)
        right_layout.addWidget(top_bar_frame, stretch=0)

        # Workspace scroll area (wraps only the right-hand workspace body so sidebar never scrolls)
        self.main_scroll = QScrollArea()
        self.main_scroll.setWidgetResizable(True)
        self.main_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.main_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.main_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        workspace_body = QWidget()
        body_layout = QVBoxLayout(workspace_body)
        body_layout.setContentsMargins(10, 6, 10, 6)
        body_layout.setSpacing(6)

        # Action & Metrics Row
        self.scan_page = ScanPageWidget()
        self.scan_page.scan_requested.connect(self.start_folder_scan)
        self.scan_page.cancel_requested.connect(self.cancel_active_scan)
        body_layout.addWidget(self.scan_page, stretch=0)

        # Split-View Workspace: Left (~56% Results table) | Right (~44% Sticky inspector)
        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.main_splitter.setChildrenCollapsible(False)
        self.main_splitter.setHandleWidth(8)

        self.results_page = ResultsPageWidget()
        self.results_page.setMinimumHeight(260)
        self.results_page.file_selected.connect(self.evidence_page_display)
        self.results_page.export_folder_pdf_requested.connect(self._on_export_folder_pdf)
        self.results_page.export_folder_csv_requested.connect(self._on_export_folder_csv)
        self.results_page.export_selected_pdf_requested.connect(self._on_export_selected_pdf)
        self.results_page.export_selected_csv_requested.connect(self._on_export_selected_csv)

        self.evidence_page = EvidencePageWidget()
        self.evidence_page.setMinimumHeight(260)

        self.main_splitter.addWidget(self.results_page)
        self.main_splitter.addWidget(self.evidence_page)
        self.main_splitter.setStretchFactor(0, 5)
        self.main_splitter.setStretchFactor(1, 5)
        self.main_splitter.setSizes([500, 480])

        body_layout.addWidget(self.main_splitter, stretch=1)
        self.main_scroll.setWidget(workspace_body)
        right_layout.addWidget(self.main_scroll, stretch=1)

        shell_layout.addWidget(right_col, stretch=1)

        self.setCentralWidget(shell)

    def set_dark_theme(self, dark: bool) -> None:
        """Switch between Light (#F7F6F3/#0F5E6E) and Dark (#121316/#147C92) themes."""
        self._dark_theme = dark
        self.setStyleSheet(build_stylesheet(dark=dark))
        self.theme_toggle_btn.setText("Theme: Dark" if dark else "Theme: Light")
        self.logo_label.setPixmap(_render_filesafe_logo(24, dark))
        self.lock_icon_label.setPixmap(_render_lock_icon(14, dark))
        self.results_page.set_dark_theme(dark)

    def set_developer_mode(self, enabled: bool) -> None:
        """Toggle between Standard (User) Mode and Developer Mode across all panels."""
        self._developer_mode = enabled
        self.standard_mode_btn.setChecked(not enabled)
        self.dev_mode_btn.setChecked(enabled)

        if enabled:
            self.banner_label.setText("Folder triage · Developer mode")
            self.history_btn.setText("Local scan history")
        else:
            self.banner_label.setText("Folder triage")
            self.history_btn.setText("Scan history")

        self.scan_page.set_developer_mode(enabled)
        self.results_page.set_developer_mode(enabled)
        self.evidence_page.set_developer_mode(enabled)

    def evidence_page_display(self, res: FileScanResult) -> None:
        self.evidence_page.display_result(res)

    def start_folder_scan(self, folder_path: str) -> None:
        """Start a supervised asynchronous batch scan on `folder_path`."""
        folder = Path(folder_path)
        if not folder.exists() or not folder.is_dir():
            QMessageBox.warning(
                self,
                "Invalid Folder",
                f"The selected folder does not exist:\n{escape_untrusted_text(folder_path)}",
            )
            return

        self.results_page.clear_results()
        self.scan_page.set_scanning_state(True)

        self._scan_thread = _ScanWorkerThread(self.supervisor, str(folder))
        self._scan_thread.progress_signal.connect(self._on_scan_progress)
        self._scan_thread.finished_signal.connect(self._on_scan_finished)
        self._scan_thread.error_signal.connect(self._on_scan_error)
        self._scan_thread.start()

    def cancel_active_scan(self) -> None:
        """Cancel the currently running folder scan."""
        self.supervisor.cancel()

    def load_summary_directly(self, summary: BatchScanSummary) -> None:
        """Load a pre-computed BatchScanSummary into the UI and record it in SQLite history."""
        self._latest_summary = summary
        self.history_store.record_scan(summary)
        self.scan_page.update_progress(
            BatchProgress(
                total_files=summary.total_files,
                processed_files=summary.processed_files,
                analyzed_count=summary.analyzed_count,
                unsupported_count=summary.unsupported_count,
                skipped_count=summary.skipped_count,
                remaining_count=0,
            )
        )
        self.results_page.set_results(summary.results)

    def _on_scan_progress(self, progress: BatchProgress) -> None:
        self.scan_page.update_progress(progress)
        if progress.latest_result is not None:
            self.results_page.append_live_result(progress.latest_result)

    def _on_scan_finished(self, summary: BatchScanSummary) -> None:
        self.scan_page.set_scanning_state(False)
        self._latest_summary = summary
        self.history_store.record_scan(summary)
        self.results_page.set_results(summary.results)

    def _on_scan_error(self, err_msg: str) -> None:
        self.scan_page.set_scanning_state(False)
        QMessageBox.critical(
            self,
            "Scan Error",
            f"Could not complete folder scan:\n{escape_untrusted_text(err_msg)}",
        )

    def _on_open_history(self) -> None:
        dlg = HistoryDialog(self.history_store, self)
        dlg.exec()

    def _on_export_folder_pdf(self) -> None:
        if self._latest_summary is None:
            return
        out_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Folder Triage PDF Report",
            "coalscan_folder_report.pdf",
            "PDF Files (*.pdf)",
        )
        if out_path:
            export_batch_pdf(self._latest_summary, out_path)

    def _on_export_folder_csv(self) -> None:
        if self._latest_summary is None:
            return
        out_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Folder Triage CSV Report",
            "coalscan_folder_report.csv",
            "CSV Files (*.csv)",
        )
        if out_path:
            export_batch_csv(self._latest_summary, out_path)

    def _on_export_selected_pdf(self, res: FileScanResult) -> None:
        default_name = f"{res.file_name}_evidence.pdf"
        out_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Selected File PDF Report",
            default_name,
            "PDF Files (*.pdf)",
        )
        if out_path:
            export_single_file_pdf(res, out_path)

    def _on_export_selected_csv(self, res: FileScanResult) -> None:
        default_name = f"{res.file_name}_evidence.csv"
        out_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Selected File CSV Report",
            default_name,
            "CSV Files (*.csv)",
        )
        if out_path:
            export_single_file_csv(res, out_path)
