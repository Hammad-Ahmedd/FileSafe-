"""Phase 5 tests: SQLite local metadata history, PDF & CSV export, and report consistency."""

from __future__ import annotations

import csv
from pathlib import Path
import sqlite3

import pymupdf

from coalscan.core.limits import (
    BANDING_VERSION,
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE,
    RULE_CATALOG_VERSION,
    TOOL_VERSION,
)
from coalscan.core.models import FileStatus, RiskBand, escape_untrusted_text
from coalscan.core.supervisor import BatchScanSummary
from coalscan.core.worker import analyze_single_file
from coalscan.fixtures.generate_fixtures import BASELINE_IMPORTS
from coalscan.report.csv_export import export_batch_csv, export_single_file_csv
from coalscan.report.pdf_report import export_batch_pdf, export_single_file_pdf
from coalscan.storage.history import ScanHistoryStore
from coalscan.tests.pe_builder import build_synthetic_pe


def _build_sample_batch(tmp_path: Path) -> tuple[BatchScanSummary, bytes]:
    """Create a diverse sample batch with analyzed, .NET, skipped, and malformed files."""
    folder = tmp_path / "report_batch"
    folder.mkdir()

    # Secret raw marker inside the binary code section that must NEVER appear in SQLite DB
    secret_binary_marker = b"RAW_BINARY_BYTES_SECRET_MARKER_DO_NOT_SYNC_998877"
    rwx_pe = build_synthetic_pe(
        is_64bit=True,
        text_Flags=IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | 0x20,
        text_data=b"\x48\x89\x5C\x24\x08\xFF\x15\x10\x00\x00\x00\xC3" + secret_binary_marker,
        imports=[
            (
                "KERNEL32.dll",
                [
                    "VirtualAlloc",
                    "GetModuleHandleW",
                    "GetCommandLineW",
                    "WriteFile",
                    "ExitProcess",
                ],
            )
        ],
        has_certificate=True,
    )
    f1 = folder / "setup.exe"
    f1.write_bytes(rwx_pe)

    f2_pe = build_synthetic_pe(
        is_64bit=True,
        imports=BASELINE_IMPORTS,
        has_certificate=True,
    )
    f2 = folder / "notes.exe"
    f2.write_bytes(f2_pe)

    f3_dotnet = build_synthetic_pe(
        is_64bit=False,
        has_clr=True,
        imports=[("mscoree.dll", ["_CorExeMain"])],
        has_certificate=False,
    )
    f3 = folder / "viewer.exe"
    f3.write_bytes(f3_dotnet)

    f4 = folder / "data.bin"
    f4.write_bytes(b"Non-candidate extension binary blob")

    f5 = folder / "corrupt.exe"
    f5.write_bytes(b"")

    results = [analyze_single_file(p) for p in (f1, f2, f3, f4, f5)]
    summary = BatchScanSummary(
        folder_path=str(folder),
        total_files=len(results),
        processed_files=len(results),
        analyzed_count=3,
        unsupported_count=0,
        skipped_count=1,
        failed_or_malformed_count=1,
        timed_out_count=0,
        cancelled=False,
        elapsed_seconds=0.42,
        results=results,
    )
    return summary, secret_binary_marker


def test_sqlite_history_store_crud_and_no_binary_bytes(tmp_path: Path) -> None:
    """Verify SQLite history stores metadata only, never raw file bytes, and supports
    delete_scan and delete_all_history."""
    summary, secret_marker = _build_sample_batch(tmp_path)
    db_file = tmp_path / "test_history.sqlite3"
    store = ScanHistoryStore(db_file)

    scan_id_1 = store.record_scan(summary)
    scan_id_2 = store.record_scan(summary)
    assert scan_id_1 > 0
    assert scan_id_2 > scan_id_1

    scans = store.list_scans()
    assert len(scans) == 2

    loaded = store.get_scan(scan_id_1)
    assert loaded is not None
    assert loaded["tool_version"] == TOOL_VERSION
    assert loaded["rule_version"] == RULE_CATALOG_VERSION
    assert loaded["banding_version"] == BANDING_VERSION
    files = loaded["files"]
    assert isinstance(files, list) and len(files) == 5

    setup_row = next(r for r in files if r["file_name"] == "setup.exe")
    assert setup_row["band"] == RiskBand.REVIEW.value
    assert setup_row["score"] == 6
    assert {f["rule_id"] for f in setup_row["findings"]} == {"R01", "R10"}

    # Verify raw binary bytes are NEVER present in the SQLite database file on disk
    raw_db_bytes = db_file.read_bytes()
    assert secret_marker not in raw_db_bytes

    # Test delete_scan cascades to scan_files
    deleted = store.delete_scan(scan_id_1)
    assert deleted is True
    assert store.get_scan(scan_id_1) is None
    with sqlite3.connect(str(db_file)) as conn:
        rem_files = conn.execute(
            "SELECT COUNT(*) FROM scan_files WHERE scan_id = ?", (scan_id_1,)
        ).fetchone()[0]
        assert rem_files == 0

    # Test delete_all_history clears everything
    cleared = store.delete_all_history()
    assert cleared >= 1
    assert store.list_scans() == []


def test_pdf_and_csv_export_consistency_and_no_em_dashes(tmp_path: Path) -> None:
    """Verify PDF and CSV exports match the in-memory BatchScanSummary (statuses, hashes,
    bands, scores, findings, versions, skips, failures) and contain no em dashes."""
    summary, _ = _build_sample_batch(tmp_path)

    csv_path = tmp_path / "batch_report.csv"
    pdf_path = tmp_path / "batch_report.pdf"
    single_csv_path = tmp_path / "single_setup.csv"
    single_pdf_path = tmp_path / "single_setup.pdf"

    export_batch_csv(summary, csv_path)
    export_batch_pdf(summary, pdf_path)
    export_single_file_csv(summary.results[0], single_csv_path)
    export_single_file_pdf(summary.results[0], single_pdf_path)

    assert csv_path.exists() and csv_path.stat().st_size > 0
    assert pdf_path.exists() and pdf_path.stat().st_size > 0
    assert single_csv_path.exists() and single_pdf_path.exists()

    # 1. Verify CSV content matches every result in summary
    csv_raw_text = csv_path.read_text(encoding="utf-8")
    assert "\u2014" not in csv_raw_text
    assert "\u2013" not in csv_raw_text

    with csv_path.open("r", encoding="utf-8") as fh:
        csv_rows = list(csv.DictReader(fh))

    assert len(csv_rows) == len(summary.results)
    for res, row in zip(summary.results, csv_rows):
        assert row["file_name"] == res.file_name
        assert row["status"] == res.status.value
        assert row["band"] == res.band.value
        assert row["sha256"] == (res.sha256 if res.sha256 else "-")
        assert row["score"] == (str(res.score) if res.score is not None else "-")
        assert row["tool_version"] == TOOL_VERSION
        assert row["rule_version"] == RULE_CATALOG_VERSION
        assert row["banding_version"] == BANDING_VERSION
        for rf in res.findings:
            assert rf.rule_id in row["fired_rule_ids"]
            assert escape_untrusted_text(rf.observed) in row["findings_evidence"]

    # 2. Extract text from generated PDF and verify consistency with UI/summary
    doc = pymupdf.open(str(pdf_path))
    pdf_text = "\n".join(page.get_text("text") for page in doc)
    doc.close()

    # No em dashes or en dashes in generated PDF text
    assert "\u2014" not in pdf_text
    assert "\u2013" not in pdf_text

    # Normalize line-wrapped table cell whitespace for substring assertions
    pdf_text_norm = " ".join(pdf_text.split())
    pdf_text_compact = "".join(pdf_text.split())

    # Tool, rule, and banding versions present in PDF
    assert TOOL_VERSION in pdf_text_norm
    assert RULE_CATALOG_VERSION in pdf_text_norm
    assert BANDING_VERSION in pdf_text_norm

    # Every file name, status, band, hash, and fired rule ID appears in the PDF
    for res in summary.results:
        assert res.file_name in pdf_text_norm
        assert res.status.value in pdf_text_norm
        assert res.band.value in pdf_text_norm
        if res.sha256:
            assert res.sha256 in pdf_text_compact
        for rf in res.findings:
            assert rf.rule_id in pdf_text_norm
            assert rf.title in pdf_text_norm
