"""SQLite local scan history storage (Section 1 & Storage specification).

Stores scan metadata and findings ONLY. Never stores raw binary file bytes.
Supports recording scans, listing scans, loading scan details, deleting a single
scan (`delete_scan`), and deleting all history (`delete_all_history`).
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Optional, Union

from coalscan.core.limits import (
    BANDING_VERSION,
    RULE_CATALOG_VERSION,
    TOOL_VERSION,
)
from coalscan.core.models import FileScanResult, escape_untrusted_text
from coalscan.core.supervisor import BatchScanSummary

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent / "coalscan_history.sqlite3"


class ScanHistoryStore:
    """SQLite-backed metadata store for local batch triage scans."""

    def __init__(self, db_path: Union[str, Path] = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_schema(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_date TEXT NOT NULL,
                    folder_path TEXT NOT NULL,
                    tool_version TEXT NOT NULL,
                    rule_version TEXT NOT NULL,
                    banding_version TEXT NOT NULL,
                    total_files INTEGER NOT NULL,
                    processed_files INTEGER NOT NULL,
                    analyzed_count INTEGER NOT NULL,
                    unsupported_count INTEGER NOT NULL,
                    skipped_count INTEGER NOT NULL,
                    failed_or_malformed_count INTEGER NOT NULL,
                    timed_out_count INTEGER NOT NULL,
                    elapsed_seconds REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_files (
                    file_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    file_name TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    sha256 TEXT,
                    file_type TEXT NOT NULL,
                    pe_format TEXT NOT NULL,
                    architecture TEXT NOT NULL,
                    status TEXT NOT NULL,
                    status_reason TEXT NOT NULL,
                    band TEXT NOT NULL,
                    score INTEGER,
                    score_breakdown TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );
                """
            )

    def record_scan(self, summary: BatchScanSummary) -> int:
        """Persist a BatchScanSummary (metadata only, never file bytes) and return scan_id."""
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        safe_folder = escape_untrusted_text(summary.folder_path, max_len=512)

        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO scans (
                    scan_date, folder_path, tool_version, rule_version, banding_version,
                    total_files, processed_files, analyzed_count, unsupported_count,
                    skipped_count, failed_or_malformed_count, timed_out_count, elapsed_seconds
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now_iso,
                    safe_folder,
                    TOOL_VERSION,
                    RULE_CATALOG_VERSION,
                    BANDING_VERSION,
                    summary.total_files,
                    summary.processed_files,
                    summary.analyzed_count,
                    summary.unsupported_count,
                    summary.skipped_count,
                    summary.failed_or_malformed_count,
                    summary.timed_out_count,
                    summary.elapsed_seconds,
                ),
            )
            scan_id = int(cur.lastrowid or 0)

            for f in summary.results:
                findings_payload = [
                    {
                        "rule_id": rf.rule_id,
                        "title": escape_untrusted_text(rf.title),
                        "severity": rf.severity.value,
                        "points": rf.points,
                        "group": rf.group,
                        "observed": escape_untrusted_text(rf.observed),
                        "file_offset": rf.file_offset,
                        "rva": rf.rva,
                        "location_label": escape_untrusted_text(rf.location_label),
                        "explanation": escape_untrusted_text(rf.explanation),
                        "benign_example": escape_untrusted_text(rf.benign_example),
                    }
                    for rf in f.findings
                ]
                conn.execute(
                    """
                    INSERT INTO scan_files (
                        scan_id, file_name, file_size, sha256, file_type, pe_format,
                        architecture, status, status_reason, band, score,
                        score_breakdown, findings_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        escape_untrusted_text(f.file_name, max_len=256),
                        f.file_size,
                        f.sha256,
                        escape_untrusted_text(f.file_kind, max_len=128),
                        escape_untrusted_text(f.pe_format, max_len=32),
                        escape_untrusted_text(f.architecture, max_len=32),
                        f.status.value,
                        escape_untrusted_text(f.status_reason, max_len=512),
                        f.band.value,
                        f.score,
                        escape_untrusted_text(f.score_breakdown, max_len=256),
                        json.dumps(findings_payload),
                    ),
                )
            return scan_id

    def list_scans(self) -> list[dict[str, object]]:
        """Return all recorded scans ordered newest first."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY scan_id DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def get_scan(self, scan_id: int) -> Optional[dict[str, object]]:
        """Retrieve a scan and all of its per-file records by `scan_id`."""
        with self._connect() as conn:
            scan_row = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            if scan_row is None:
                return None

            file_rows = conn.execute(
                "SELECT * FROM scan_files WHERE scan_id = ? ORDER BY file_id ASC",
                (scan_id,),
            ).fetchall()

            scan_dict = dict(scan_row)
            files_list: list[dict[str, object]] = []
            for fr in file_rows:
                fd = dict(fr)
                fd["findings"] = json.loads(str(fd.pop("findings_json", "[]")))
                files_list.append(fd)
            scan_dict["files"] = files_list
            return scan_dict

    def delete_scan(self, scan_id: int) -> bool:
        """Delete a single scan and cascade-delete its file records."""
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            return (cur.rowcount or 0) > 0

    def delete_all_history(self) -> int:
        """Delete all scans and file metadata from the local history database."""
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM scans")
            conn.execute("DELETE FROM scan_files")
            return int(cur.rowcount or 0)
