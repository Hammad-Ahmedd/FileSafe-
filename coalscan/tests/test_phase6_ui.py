"""Phase 6 tests: PySide6 desktop UI widgets, plain-text non-double-escaping,
per-status Evidence text rules, clipboard Copy hash, sortable results table,
observed-facts separation, history dialog, and documentation/packaging verification."""

from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QHBoxLayout, QScrollArea, QSplitter, QVBoxLayout
import pymupdf
import pytest

from coalscan.core.models import (
    DisasmInstruction,
    DisasmRegion,
    FileScanResult,
    FileStatus,
    RiskBand,
)
from coalscan.report.pdf_report import export_single_file_pdf
from coalscan.tests.test_phase5_storage_reports import _build_sample_batch
from coalscan.ui.evidence_page import (
    EvidencePageWidget,
    NON_ANALYZED_STATUSES,
    is_analyzed_star_status,
)
from coalscan.ui.main_window import HistoryDialog, MainWindow


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create or reuse a QApplication instance in offscreen mode for headless UI testing."""
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        app = existing
    else:
        app = QApplication(["coalscan_test", "-platform", "offscreen"])
    yield app
    app.processEvents()
    for w in list(app.topLevelWidgets()):
        w.close()
        w.deleteLater()
    app.processEvents()


def test_main_window_three_pages_and_evidence_workflow(
    qapp: QApplication, tmp_path: Path
) -> None:
    """Verify ScanPage, ResultsPage, and EvidencePage match the Section 3 workflow
    and layout requirements."""
    summary, _ = _build_sample_batch(tmp_path)
    db_path = tmp_path / "ui_history.sqlite3"

    win = MainWindow(db_path=db_path, developer_mode=True)

    # 1. Verify default window size (~1200x800), minimum size, anchored 220px sidebar, main_scroll, and QSplitter
    assert win.width() == 1200
    assert win.height() == 800
    assert win.minimumWidth() >= 900
    assert win.minimumHeight() >= 600
    assert win.sidebar.width() == 220
    sb_margins = win.sidebar.layout().contentsMargins()
    assert (sb_margins.left(), sb_margins.top(), sb_margins.right(), sb_margins.bottom()) == (12, 12, 12, 12)
    assert win.sidebar.layout().spacing() == 8
    assert not win.main_scroll.isAncestorOf(win.sidebar)
    assert win.sidebar.isAncestorOf(win.theme_toggle_btn)
    assert win.sidebar.isAncestorOf(win.footer_version_label)
    assert win.sidebar.isAncestorOf(win.footer_security_label)
    assert isinstance(win.main_scroll, QScrollArea)
    assert win.main_scroll.horizontalScrollBarPolicy() == Qt.ScrollBarPolicy.ScrollBarAlwaysOff
    assert win.main_scroll.verticalScrollBarPolicy() == Qt.ScrollBarPolicy.ScrollBarAsNeeded
    assert isinstance(win.main_splitter, QSplitter)
    assert win.main_splitter.orientation() == Qt.Orientation.Horizontal
    assert win.main_splitter.childrenCollapsible() is False
    assert win.main_splitter.count() == 2
    assert win.main_splitter.widget(0) is win.results_page
    assert win.main_splitter.widget(1) is win.evidence_page
    assert win.results_page.minimumHeight() >= 250
    assert win.evidence_page.minimumHeight() >= 250

    # Verify NO nested QScrollArea inside EvidencePageWidget
    assert len(win.evidence_page.findChildren(QScrollArea)) == 0

    # Verify Copy hash button minimum height (28 px), minimum width (90 px), and disabled initially
    assert win.evidence_page.copy_hash_btn.minimumHeight() == 28
    assert win.evidence_page.copy_hash_btn.minimumWidth() == 90
    assert win.evidence_page.copy_hash_btn.isEnabled() is False

    # Verify Findings list minimum height (>= 44 px) and footer note in its own row below Findings list
    assert win.evidence_page.findings_list.minimumHeight() >= 44
    assert isinstance(win.evidence_page.footer_row_layout, QHBoxLayout)
    assert "Observed facts are listed apart from rule scores" in win.evidence_page.separation_note.text()

    # Verify Results table minimum height (190 px), stretch factor,
    # 10 px spacing between table and dedicated export_bar below it
    assert win.results_page.table.minimumHeight() == 190
    results_layout = win.results_page.layout()
    assert isinstance(results_layout, QVBoxLayout)
    table_idx = results_layout.indexOf(win.results_page.table)
    export_idx = results_layout.indexOf(win.results_page.export_bar)
    assert table_idx >= 0 and export_idx > table_idx
    assert results_layout.stretch(table_idx) >= 1
    assert results_layout.spacing() == 10
    assert win.results_page.export_bar.minimumHeight() == 40
    assert isinstance(win.results_page.export_row_layout, QHBoxLayout)

    # 2. Verify Scan Page defaults & plain-text label modes
    assert win.scan_page.local_only_checkbox.isChecked() is True
    assert "Local-only mode: ON" in win.scan_page.local_only_checkbox.text()
    assert "500 files" in win.scan_page.limits_label.text()
    assert "50 MB" in win.scan_page.limits_label.text()
    assert "20 s" in win.scan_page.limits_label.text()
    assert win.scan_page.progress_label.textFormat() == Qt.TextFormat.PlainText

    # Load batch summary into UI
    win.load_summary_directly(summary)

    assert win.scan_page.progress_label.text() == "Progress 5 / 5 files"
    assert "3 analyzed" in win.scan_page.counts_label.text()
    assert "1 skipped" in win.scan_page.counts_label.text()

    # 3. Verify Results Page table keeps all 5 files (analyzed, .NET, skipped, malformed)
    assert win.results_page.table.rowCount() == 5
    assert win.results_page.export_folder_pdf_btn.isEnabled() is True
    assert win.results_page.export_folder_csv_btn.isEnabled() is True

    # Find and select 'setup.exe' in the table
    for r_idx in range(win.results_page.table.rowCount()):
        item = win.results_page.table.item(r_idx, 0)
        if item and item.text() == "setup.exe":
            win.results_page.table.selectRow(r_idx)
            break

    sel_res = win.results_page.selected_result()
    assert sel_res is not None
    assert sel_res.file_name == "setup.exe"
    assert sel_res.band == RiskBand.REVIEW
    assert sel_res.score == 6

    # 4. Verify Evidence Page populates Observed Facts, Band/Score, Findings, and Disassembly
    ev = win.evidence_page
    assert ev.file_header_label.textFormat() == Qt.TextFormat.PlainText
    assert ev.sha256_label.textFormat() == Qt.TextFormat.PlainText
    assert ev.band_label.textFormat() == Qt.TextFormat.PlainText
    assert ev.rule_location_label.textFormat() == Qt.TextFormat.PlainText
    assert ev.observed_label.textFormat() == Qt.TextFormat.PlainText
    assert ev.why_label.textFormat() == Qt.TextFormat.PlainText
    assert ev.benign_label.textFormat() == Qt.TextFormat.PlainText

    assert ev.file_header_label.text() == "setup.exe   PE32+ x64"
    assert sel_res.sha256 is not None
    assert sel_res.sha256 in ev.sha256_label.text()

    # Test Copy hash button copies SHA-256 to system clipboard
    ev.copy_hash_btn.click()
    assert QApplication.clipboard().text() == sel_res.sha256

    # Verify Band and Findings list
    assert "Band: Review" in ev.band_label.text()
    assert "score 6" in ev.band_label.text()
    assert ev.findings_list.count() == 2

    # Select finding R10 and check detail labels (must not contain &#x27; for '.text')
    for i in range(ev.findings_list.count()):
        if "R10" in ev.findings_list.item(i).text():
            ev.findings_list.setCurrentRow(i)
            break

    assert "Rule R10" in ev.rule_location_label.text()
    assert "Section '.text' flags = read + write + execute" in ev.observed_label.text()
    assert "&#x27;" not in ev.observed_label.text()
    assert "Why it may matter:" in ev.why_label.text()
    assert "Benign example:" in ev.benign_label.text()
    assert not ev.benign_label.isHidden()
    assert len(ev.disasm_view.toPlainText()) > 0

    # Ensure forbidden verdict words ("clean", "malicious") never appear in UI labels
    ui_texts = " ".join(
        [
            ev.band_label.text(),
            ev.observed_label.text(),
            ev.why_label.text(),
            ev.benign_label.text(),
        ]
    ).lower()
    assert "clean" not in ui_texts
    assert "malicious" not in ui_texts

    # 5. Verify HistoryDialog delete scan and delete all history
    dlg = HistoryDialog(win.history_store, win)
    assert dlg.list_widget.count() == 1
    dlg.list_widget.setCurrentRow(0)
    dlg._on_delete_selected()
    assert dlg.list_widget.count() == 0

    win.history_store.record_scan(summary)
    dlg.refresh_list()
    assert dlg.list_widget.count() == 1
    dlg._on_delete_all()
    assert dlg.list_widget.count() == 0


def test_special_chars_filename_unchanged_in_ui_and_safe_in_pdf(
    qapp: QApplication, tmp_path: Path
) -> None:
    """Verify a file name containing <, >, & and a single quote ' (plus single-quoted
    status reasons like "Skipped non-candidate extension '.pdf'") displays unchanged in
    the UI model (no &#x27; or &amp;) and renders safely in the PDF report."""
    tricky_name = "report_<v1>&'draft'>.pdf"
    tricky_reason = "Skipped non-candidate extension '.pdf' (allowed: .exe, .dll, .sys, .ocx)"
    res = FileScanResult(
        file_path=str(tmp_path / tricky_name),
        file_name=tricky_name,
        safe_file_name=tricky_name,
        file_size=1024,
        sha256=None,
        status=FileStatus.SKIPPED,
        status_reason=tricky_reason,
        file_kind="Skipped file",
    )

    win = MainWindow(db_path=tmp_path / "special_chars.sqlite3", developer_mode=True)
    win.results_page.set_results([res])

    # Check QTableWidget cells display exact characters without HTML entity escaping
    file_cell_text = win.results_page.table.item(0, 0).text()
    reason_cell_text = win.results_page.table.item(0, 5).text()
    assert file_cell_text == tricky_name
    assert reason_cell_text == tricky_reason
    assert "&#x27;" not in file_cell_text
    assert "&amp;" not in file_cell_text
    assert "&lt;" not in file_cell_text
    assert "&#x27;" not in reason_cell_text

    # Check EvidencePageWidget labels display exact characters without HTML entity escaping
    # and follow the non-duplicated reason / header / band / observed rules
    ev = win.evidence_page
    assert ev.file_header_label.text() == tricky_name
    assert "- -" not in ev.file_header_label.text()
    assert "&#x27;" not in ev.file_header_label.text()
    assert "&amp;" not in ev.file_header_label.text()

    assert ev.band_label.text() == "Band: not scored"
    assert ev.observed_label.text() == f"Observed: {tricky_name} (1024 B)"
    assert "'.pdf'" in ev.rule_location_label.text()
    assert "&#x27;" not in ev.rule_location_label.text()
    assert tricky_reason not in ev.band_label.text()
    assert tricky_reason not in ev.observed_label.text()
    assert tricky_reason not in ev.why_label.text()

    # Check PDF export succeeds without ReportLab XML parse error and contains the filename & reason
    pdf_out = tmp_path / "tricky_report.pdf"
    export_single_file_pdf(res, pdf_out, folder_path=str(tmp_path))
    assert pdf_out.exists() and pdf_out.stat().st_size > 0

    doc = pymupdf.open(str(pdf_out))
    pdf_text = " ".join("\n".join(page.get_text("text") for page in doc).split())
    doc.close()
    assert tricky_name in pdf_text
    assert "Skipped non-candidate extension '.pdf'" in pdf_text


def test_header_line_omits_placeholders_and_shows_known_format_arch(
    qapp: QApplication,
) -> None:
    """UI-model test confirming the header line reads '<filename>' when format/architecture
    are unknown (omitting '- -' placeholders) and appends format/architecture only when known."""
    ev = EvidencePageWidget()
    ev.set_developer_mode(True)

    # Case 1: Both format and architecture unknown ("-")
    res_unknown = FileScanResult(
        file_path="C:\\test\\readme.txt",
        file_name="readme.txt",
        safe_file_name="readme.txt",
        file_size=512,
        sha256=None,
        status=FileStatus.SKIPPED,
        status_reason="Skipped non-candidate extension '.txt'",
        file_kind="Skipped file",
        pe_format="-",
        architecture="-",
    )
    ev.display_result(res_unknown)
    assert ev.file_header_label.text() == "readme.txt"
    assert "-" not in ev.file_header_label.text()

    # Case 2: Both format and architecture known
    res_known = FileScanResult(
        file_path="C:\\test\\app.exe",
        file_name="app.exe",
        safe_file_name="app.exe",
        file_size=4096,
        sha256="b" * 64,
        status=FileStatus.ANALYZED,
        status_reason="Analyzed native PE32+ (x64)",
        file_kind="Native PE",
        pe_format="PE32+",
        architecture="x64",
        band=RiskBand.ROUTINE,
        score=0,
        score_breakdown="score 0 (no rules fired)",
    )
    ev.display_result(res_known)
    assert ev.file_header_label.text() == "app.exe   PE32+ x64"

    # Case 3: Only architecture known (e.g. unsupported architecture header)
    res_arch_only = FileScanResult(
        file_path="C:\\test\\arm_tool.exe",
        file_name="arm_tool.exe",
        safe_file_name="arm_tool.exe",
        file_size=2048,
        sha256="c" * 64,
        status=FileStatus.UNSUPPORTED_ARCH,
        status_reason="Unsupported machine architecture ARM64 (0xAA64)",
        file_kind="Unsupported PE",
        pe_format="-",
        architecture="ARM64 (0xAA64)",
    )
    ev.display_result(res_arch_only)
    assert ev.file_header_label.text() == "arm_tool.exe   ARM64 (0xAA64)"


@pytest.mark.parametrize("status", list(FileStatus), ids=lambda s: s.name)
def test_evidence_text_per_status_rule(
    qapp: QApplication, tmp_path: Path, status: FileStatus
) -> None:
    """UI-model test for every FileStatus confirming:
    - Skipped, unsupported, not-a-PE, malformed, too large, timed-out, and failed files:
      * NEVER say 'No rules fired'
      * Show the status reason ONCE in the Evidence title ('Not analyzed: no rules were run (<reason>)')
        and ONCE in the table REASON column
      * Band line reads 'Band: not scored'
      * Observed line shows file name and size only ('Observed: sample.exe (2048 B)')
      * Hide the 'Benign example' line
      * Show 'No disassembly for this status.'
      * Header line reads '<filename>' without '- -' placeholders when format/arch are unknown
    - Only files with status 'analyzed*' may say 'No rules fired'."""
    sample_reason = f"UniqueReason_{status.name}_detail"
    sample_disasm = (
        [
            DisasmRegion(
                label="Entry point (RVA 0x1000, .text)",
                rva=0x1000,
                file_offset=0x200,
                virtual_address=0x140001000,
                instructions=[
                    DisasmInstruction(
                        address=0x140001000,
                        file_offset=0x200,
                        size=1,
                        bytes_hex="c3",
                        mnemonic="ret",
                        op_str="",
                    )
                ],
            )
        ]
        if status in (FileStatus.ANALYZED, FileStatus.DRIVER_CANDIDATE)
        else []
    )

    res = FileScanResult(
        file_path="C:\\test\\sample.exe",
        file_name="sample.exe",
        safe_file_name="sample.exe",
        file_size=2048,
        sha256="a" * 64 if status != FileStatus.TOO_LARGE else None,
        status=status,
        status_reason=sample_reason,
        file_kind="Test file",
        pe_format="PE32+" if status not in NON_ANALYZED_STATUSES else "-",
        architecture="x64" if status not in NON_ANALYZED_STATUSES else "-",
        findings=[],
        band=RiskBand.ROUTINE if status not in NON_ANALYZED_STATUSES else RiskBand.NOT_APPLICABLE,
        score=0 if status not in NON_ANALYZED_STATUSES else None,
        score_breakdown="score 0 (no rules fired)" if status not in NON_ANALYZED_STATUSES else "",
        disasm_regions=sample_disasm,
    )

    win = MainWindow(db_path=tmp_path / f"status_{status.name}.sqlite3", developer_mode=True)
    win.results_page.set_results([res])
    ev = win.evidence_page

    rule_hdr = ev.rule_location_label.text()
    obs_txt = ev.observed_label.text()
    band_txt = ev.band_label.text()
    why_txt = ev.why_label.text()
    hdr_txt = ev.file_header_label.text()
    disasm_txt = ev.disasm_view.toPlainText()

    # Check table columns: status_reason appears only once in REASON column (col 5)
    table_cells = [win.results_page.table.item(0, col).text() for col in range(6)]
    assert table_cells[5] == sample_reason
    assert sum(1 for c in table_cells if sample_reason in c) == 1

    if status in NON_ANALYZED_STATUSES:
        assert hdr_txt == "sample.exe"
        assert "- -" not in hdr_txt
        assert "No rules fired" not in rule_hdr
        assert "No rules fired" not in obs_txt
        assert rule_hdr == f"Not analyzed: no rules were run ({sample_reason})"
        assert band_txt == "Band: not scored"
        assert obs_txt == "Observed: sample.exe (2048 B)"
        # Ensure status_reason is NOT duplicated in band, observed, why, header, or metadata
        assert sample_reason not in band_txt
        assert sample_reason not in obs_txt
        assert sample_reason not in why_txt
        assert sample_reason not in hdr_txt
        assert sample_reason not in ev.facts_meta_label.text()
        assert ev.benign_label.isHidden() is True
        assert disasm_txt == "No disassembly for this status."
    elif is_analyzed_star_status(status):
        assert hdr_txt == "sample.exe   PE32+ x64"
        assert "No rules fired" in rule_hdr
        assert obs_txt == "Observed: sample.exe (2048 B)"
        assert ev.benign_label.isHidden() is False
        assert "Benign example:" in ev.benign_label.text()
        assert disasm_txt != "No disassembly for this status."
    else:
        # DRIVER_CANDIDATE does not start with "analyzed", so it must not say "No rules fired"
        assert hdr_txt == "sample.exe   PE32+ x64"
        assert "No rules fired" not in rule_hdr
        assert obs_txt == "Observed: sample.exe (2048 B)"
        assert ev.benign_label.isHidden() is False


def test_docs_and_pyinstaller_spec_exist_and_state_prototype_boundary() -> None:
    """Verify ARCHITECTURE.md, TESTING.md, LIMITS.md, README.md, and coalscan.spec exist
    and clearly state that this is a student prototype and not a production security product."""
    root = Path(__file__).resolve().parent.parent.parent
    required_files = [
        root / "README.md",
        root / "coalscan.spec",
        root / "coalscan" / "docs" / "ARCHITECTURE.md",
        root / "coalscan" / "docs" / "TESTING.md",
        root / "coalscan" / "docs" / "LIMITS.md",
    ]
    for path in required_files:
        assert path.exists(), f"Missing required file: {path}"
        content = path.read_text(encoding="utf-8")
        assert len(content) > 200
        assert "\u2014" not in content, f"Em dash found in {path}"

    arch_text = (root / "coalscan" / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8").lower()
    limits_text = (root / "coalscan" / "docs" / "LIMITS.md").read_text(encoding="utf-8").lower()
    readme_text = (root / "README.md").read_text(encoding="utf-8").lower()

    assert "student" in arch_text and "prototype" in arch_text
    assert "student" in limits_text and "not a production" in limits_text
    assert "student" in readme_text and "not a production" in readme_text


def test_standard_mode_default_filters_and_live_mode_switching(
    qapp: QApplication, tmp_path: Path
) -> None:
    """Verify Standard Mode is the default, shows plain-English info & practical
    filtering/search options, hides raw disassembly, and toggles cleanly to Developer Mode."""
    summary, _ = _build_sample_batch(tmp_path)
    win = MainWindow(db_path=tmp_path / "std_mode.sqlite3")

    # Defaults to Standard Mode with FileSafe branding
    assert "FileSafe" in win.windowTitle()
    assert win.standard_mode_btn.isChecked() is True
    assert win.dev_mode_btn.isChecked() is False
    assert win.results_page.table.columnCount() == 4
    assert win.evidence_page.disasm_view.isHidden() is True
    assert win.results_page.export_selected_csv_btn.isHidden() is True

    win.load_summary_directly(summary)
    assert win.results_page.table.rowCount() == 5
    assert "Checked 5 / 5 files" in win.scan_page.progress_label.text()

    # Verify Standard Mode attention levels & plain-English evidence
    for r_idx in range(win.results_page.table.rowCount()):
        if win.results_page.table.item(r_idx, 0).text() == "setup.exe":
            win.results_page.table.selectRow(r_idx)
            assert "Worth Checking" in win.results_page.table.item(r_idx, 2).text()
            break

    ev = win.evidence_page
    assert "Attention Level: Worth Checking" in ev.band_label.text()
    assert "Digital Signature:" in ev.facts_meta_label.text()
    assert "What was found:" in ev.observed_label.text()
    assert "What you can do:" in ev.advice_label.text()
    assert ev.advice_label.isHidden() is False
    assert ev.disasm_view.isHidden() is True

    # Filter: "Only files needing attention" -> only setup.exe (Review)
    att_idx = win.results_page.filter_combo.findData("attention")
    win.results_page.filter_combo.setCurrentIndex(att_idx)
    assert win.results_page.table.rowCount() == 1
    assert win.results_page.table.item(0, 0).text() == "setup.exe"

    # Filter: "Skipped & errors" -> notes.txt and broken.exe
    skip_idx = win.results_page.filter_combo.findData("skipped_errors")
    win.results_page.filter_combo.setCurrentIndex(skip_idx)
    assert win.results_page.table.rowCount() == 2

    # Search filter back on "All files"
    all_idx = win.results_page.filter_combo.findData("all")
    win.results_page.filter_combo.setCurrentIndex(all_idx)
    assert win.results_page.table.rowCount() == 5
    win.results_page.search_input.setText("setup")
    assert win.results_page.table.rowCount() == 1
    win.results_page.search_input.clear()
    assert win.results_page.table.rowCount() == 5

    # Switch live to Developer Mode and verify full 6-column table & disassembly appear
    win.dev_mode_btn.click()
    assert win.dev_mode_btn.isChecked() is True
    assert win.results_page.table.columnCount() == 6
    assert win.results_page.export_selected_csv_btn.isHidden() is False
    assert ev.disasm_view.isHidden() is False
    assert ev.advice_label.isHidden() is True

    # Switch back to Standard Mode and verify Light/Dark theme switching
    win.standard_mode_btn.click()
    assert win.standard_mode_btn.isChecked() is True
    assert win.results_page.table.columnCount() == 4
    assert ev.disasm_view.isHidden() is True

    assert win.theme_toggle_btn.text() == "Theme: Light"
    win.theme_toggle_btn.click()
    assert win.theme_toggle_btn.text() == "Theme: Dark"
    win.theme_toggle_btn.click()
    assert win.theme_toggle_btn.text() == "Theme: Light"

    # Verify zero horizontal or vertical overflow on a 1366x768 laptop viewport (1200x680)
    win.resize(1200, 680)
    win.show()
    qapp.processEvents()
    ws = win.main_scroll.widget()
    vp = win.main_scroll.viewport()
    assert ws.minimumSizeHint().width() <= vp.width()
    assert ws.minimumSizeHint().height() <= vp.height()
    assert win.main_scroll.horizontalScrollBar().maximum() == 0
    assert win.main_scroll.verticalScrollBar().maximum() == 0

    # Verify none of the 4 File Details explanation labels are vertically squished/clipped
    for lbl in (ev.observed_label, ev.why_label, ev.benign_label, ev.advice_label):
        if not lbl.isHidden():
            assert lbl.height() >= lbl.heightForWidth(lbl.width())
