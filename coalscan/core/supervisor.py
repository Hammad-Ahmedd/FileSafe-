"""Supervised per-file worker process manager (Section 1 & Section 2).

IMPORTANT ARCHITECTURAL RULE:
Does NOT use `concurrent.futures.ProcessPoolExecutor` because `ProcessPoolExecutor`
cannot cancel an already-running worker and killing one worker breaks the shared pool.

Instead, this supervisor spawns one short-lived `multiprocessing.Process` per file,
with at most `min(4, cpu_count - 1)` (at least 1) running simultaneously, communicating
results over an isolated `multiprocessing.Pipe`. If a worker exceeds `PER_FILE_TIMEOUT_SECONDS`
(20 s), the supervisor terminates it and records `FileStatus.TIMED_OUT` without affecting
any other file in the batch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import multiprocessing
from multiprocessing.connection import Connection
import os
from pathlib import Path
import threading
import time
from typing import Callable, Optional, Union

from coalscan.core.banding import BandingConfig, DEFAULT_BANDING_CONFIG
from coalscan.core.limits import (
    MAX_CONCURRENT_WORKERS_CAP,
    MAX_FILES_PER_SCAN,
    MAX_FILE_SIZE_BYTES,
    MIN_CONCURRENT_WORKERS,
    PER_FILE_TIMEOUT_SECONDS,
)
from coalscan.core.models import FileScanResult, FileStatus, escape_untrusted_text
from coalscan.core.router import is_candidate_extension, route_file
from coalscan.core.worker import worker_process_entry


def get_max_concurrent_workers(cpu_count: Optional[int] = None) -> int:
    """Compute `max(1, min(4, cpu_count - 1))` as specified in Section 1."""
    cores = cpu_count if cpu_count is not None else (os.cpu_count() or 2)
    return max(MIN_CONCURRENT_WORKERS, min(MAX_CONCURRENT_WORKERS_CAP, cores - 1))


@dataclass(frozen=True)
class BatchProgress:
    """Live progress snapshot matching the Section 3 UI mockup counters."""

    total_files: int
    processed_files: int
    analyzed_count: int
    unsupported_count: int
    skipped_count: int
    remaining_count: int
    latest_result: Optional[FileScanResult] = None


@dataclass
class BatchScanSummary:
    """Complete result of scanning a top-level folder."""

    folder_path: str
    total_files: int
    processed_files: int
    analyzed_count: int
    unsupported_count: int
    skipped_count: int
    failed_or_malformed_count: int
    timed_out_count: int
    cancelled: bool
    elapsed_seconds: float
    results: list[FileScanResult] = field(default_factory=list)


@dataclass
class _ActiveWorker:
    """Internal tracking state for a single running per-file worker process."""

    file_path: Path
    file_size: int
    process: multiprocessing.Process
    recv_conn: Connection
    start_monotonic: float


def _safe_poll(conn: Connection) -> bool:
    """Safely check if a Pipe connection has data without raising BrokenPipeError on Windows."""
    try:
        return conn.poll(0.0)
    except (BrokenPipeError, EOFError, OSError):
        return False


def _terminate_process_safely(proc: multiprocessing.Process) -> None:
    """Terminate a worker process and ensure it is reaped."""
    try:
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=1.0)
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=1.0)
    except Exception:
        pass


class BatchSupervisor:
    """Supervisor that scans top-level files in a folder using isolated per-file processes."""

    def __init__(
        self,
        config: BandingConfig = DEFAULT_BANDING_CONFIG,
        timeout_seconds: float = float(PER_FILE_TIMEOUT_SECONDS),
        max_files: int = MAX_FILES_PER_SCAN,
        max_file_size_bytes: int = MAX_FILE_SIZE_BYTES,
        max_workers: Optional[int] = None,
    ) -> None:
        self.config = config
        self.timeout_seconds = timeout_seconds
        self.max_files = max_files
        self.max_file_size_bytes = max_file_size_bytes
        self.max_workers = (
            max_workers if max_workers is not None else get_max_concurrent_workers()
        )
        self._cancel_event = threading.Event()

    def cancel(self) -> None:
        """Signal the supervisor to terminate all active workers and stop the batch."""
        self._cancel_event.set()

    @property
    def is_cancelled(self) -> bool:
        return self._cancel_event.is_set()

    def scan_folder(
        self,
        folder_path: Union[str, Path],
        on_progress: Optional[Callable[[BatchProgress], None]] = None,
        per_file_delay_map: Optional[dict[str, float]] = None,
        per_file_crash_set: Optional[set[str]] = None,
        per_file_hard_exit_set: Optional[set[str]] = None,
    ) -> BatchScanSummary:
        """Scan top-level files in `folder_path` (no recursion) with isolated per-file workers."""
        self._cancel_event.clear()
        start_wall = time.perf_counter()
        folder = Path(folder_path)

        if not folder.exists() or not folder.is_dir():
            raise ValueError(f"Folder does not exist or is not a directory: {folder}")

        # Top-level files only (subfolders are never scanned in committed scope)
        all_top_level_files = sorted(
            (entry for entry in folder.iterdir() if entry.is_file()),
            key=lambda p: p.name.lower(),
        )

        total_files = len(all_top_level_files)
        results_by_name: dict[str, FileScanResult] = {}
        pending_files: list[tuple[Path, int]] = []

        analyzed_count = 0
        unsupported_count = 0
        skipped_count = 0
        failed_or_malformed_count = 0
        timed_out_count = 0

        def _record_result(res: FileScanResult) -> None:
            nonlocal analyzed_count, unsupported_count, skipped_count
            nonlocal failed_or_malformed_count, timed_out_count

            results_by_name[res.file_name] = res
            st = res.status
            if st in (
                FileStatus.ANALYZED,
                FileStatus.ANALYZED_DOTNET_LIMITED,
                FileStatus.ANALYZED_DRIVER_LIMITED,
                FileStatus.DRIVER_CANDIDATE,
            ):
                analyzed_count += 1
            elif st in (FileStatus.UNSUPPORTED_ARCH, FileStatus.NOT_A_PE):
                unsupported_count += 1
            elif st in (FileStatus.SKIPPED, FileStatus.TOO_LARGE):
                skipped_count += 1
            elif st == FileStatus.TIMED_OUT:
                timed_out_count += 1
                failed_or_malformed_count += 1
            else:
                failed_or_malformed_count += 1

            processed = len(results_by_name)
            remaining = max(0, total_files - processed)
            if on_progress is not None:
                on_progress(
                    BatchProgress(
                        total_files=total_files,
                        processed_files=processed,
                        analyzed_count=analyzed_count,
                        unsupported_count=unsupported_count,
                        skipped_count=skipped_count,
                        remaining_count=remaining,
                        latest_result=res,
                    )
                )

        # Pre-filter files by scan count limit (500), candidate extension, and size limit (50 MB)
        for idx, fpath in enumerate(all_top_level_files):
            fname = fpath.name
            safe_name = escape_untrusted_text(fname, max_len=256)
            try:
                fsize = fpath.stat().st_size
            except Exception as exc:
                _record_result(
                    FileScanResult(
                        file_path=str(fpath),
                        file_name=fname,
                        safe_file_name=safe_name,
                        file_size=0,
                        sha256=None,
                        status=FileStatus.FAILED,
                        status_reason=f"Stat error: {escape_untrusted_text(str(exc), max_len=160)}",
                        file_kind="Failed",
                    )
                )
                continue

            # 1. Over 500 files per scan limit
            if idx >= self.max_files:
                _record_result(
                    FileScanResult(
                        file_path=str(fpath),
                        file_name=fname,
                        safe_file_name=safe_name,
                        file_size=fsize,
                        sha256=None,
                        status=FileStatus.SKIPPED,
                        status_reason=f"skipped: over limit (max {self.max_files} files per scan)",
                        file_kind="Skipped (over limit)",
                    )
                )
                continue

            # 2. Non-candidate extension
            if not is_candidate_extension(fname):
                dec = route_file(fname, fsize, inspection=None, check_extension=True)
                _record_result(
                    FileScanResult(
                        file_path=str(fpath),
                        file_name=fname,
                        safe_file_name=safe_name,
                        file_size=fsize,
                        sha256=None,
                        status=dec.status,
                        status_reason=dec.reason,
                        file_kind=dec.file_kind,
                    )
                )
                continue

            # 3. File size > 50 MB (never parsed, never hashed)
            if fsize > self.max_file_size_bytes:
                _record_result(
                    FileScanResult(
                        file_path=str(fpath),
                        file_name=fname,
                        safe_file_name=safe_name,
                        file_size=fsize,
                        sha256=None,
                        status=FileStatus.TOO_LARGE,
                        status_reason=(
                            f"File size ({fsize} bytes) exceeds limit ({self.max_file_size_bytes} bytes); "
                            "not parsed, not hashed"
                        ),
                        file_kind="Too large",
                    )
                )
                continue

            pending_files.append((fpath, fsize))

        # Supervisor process loop for candidate files
        active_workers: list[_ActiveWorker] = []
        mp_ctx = multiprocessing.get_context("spawn")
        queue_idx = 0

        while queue_idx < len(pending_files) or active_workers:
            if self._cancel_event.is_set():
                # Terminate all currently running workers
                for aw in active_workers:
                    _terminate_process_safely(aw.process)
                    try:
                        aw.recv_conn.close()
                    except Exception:
                        pass
                    _record_result(
                        FileScanResult(
                            file_path=str(aw.file_path),
                            file_name=aw.file_path.name,
                            safe_file_name=escape_untrusted_text(aw.file_path.name, max_len=256),
                            file_size=aw.file_size,
                            sha256=None,
                            status=FileStatus.SKIPPED,
                            status_reason="Scan cancelled by user",
                            file_kind="Cancelled",
                        )
                    )
                active_workers.clear()

                # Mark remaining queued files as skipped due to cancellation
                while queue_idx < len(pending_files):
                    rem_path, rem_size = pending_files[queue_idx]
                    queue_idx += 1
                    _record_result(
                        FileScanResult(
                            file_path=str(rem_path),
                            file_name=rem_path.name,
                            safe_file_name=escape_untrusted_text(rem_path.name, max_len=256),
                            file_size=rem_size,
                            sha256=None,
                            status=FileStatus.SKIPPED,
                            status_reason="Scan cancelled by user",
                            file_kind="Cancelled",
                        )
                    )
                break

            # Spawn new short-lived workers up to self.max_workers
            while (
                queue_idx < len(pending_files)
                and len(active_workers) < self.max_workers
                and not self._cancel_event.is_set()
            ):
                fpath, fsize = pending_files[queue_idx]
                queue_idx += 1

                recv_conn, send_conn = mp_ctx.Pipe(duplex=False)
                delay_s = (
                    per_file_delay_map.get(fpath.name, 0.0)
                    if per_file_delay_map
                    else 0.0
                )
                sim_crash = (
                    (fpath.name in per_file_crash_set)
                    if per_file_crash_set
                    else False
                )
                sim_exit = (
                    (fpath.name in per_file_hard_exit_set)
                    if per_file_hard_exit_set
                    else False
                )

                proc = mp_ctx.Process(
                    target=worker_process_entry,
                    args=(
                        str(fpath),
                        send_conn,
                        self.config,
                        delay_s,
                        sim_crash,
                        sim_exit,
                    ),
                    daemon=True,
                )
                proc.start()
                # Close parent's copy of send_conn so recv_conn detects EOF if child crashes
                send_conn.close()

                active_workers.append(
                    _ActiveWorker(
                        file_path=fpath,
                        file_size=fsize,
                        process=proc,
                        recv_conn=recv_conn,
                        start_monotonic=time.monotonic(),
                    )
                )

            # Poll active workers for completion, abnormal crash, or timeout
            still_running: list[_ActiveWorker] = []
            now_mono = time.monotonic()

            for aw in active_workers:
                elapsed = now_mono - aw.start_monotonic

                if _safe_poll(aw.recv_conn):
                    try:
                        worker_res: FileScanResult = aw.recv_conn.recv()
                        aw.process.join(timeout=1.0)
                        _record_result(worker_res)
                    except Exception as exc:
                        _terminate_process_safely(aw.process)
                        _record_result(
                            FileScanResult(
                                file_path=str(aw.file_path),
                                file_name=aw.file_path.name,
                                safe_file_name=escape_untrusted_text(aw.file_path.name, max_len=256),
                                file_size=aw.file_size,
                                sha256=None,
                                status=FileStatus.FAILED,
                                status_reason=f"Pipe read error: {escape_untrusted_text(str(exc), max_len=160)}",
                                file_kind="Failed",
                            )
                        )
                    finally:
                        try:
                            aw.recv_conn.close()
                        except Exception:
                            pass

                elif not aw.process.is_alive():
                    # Process exited without sending a result (or result arrived just before exit)
                    aw.process.join(timeout=0.5)
                    if _safe_poll(aw.recv_conn):
                        try:
                            worker_res = aw.recv_conn.recv()
                            _record_result(worker_res)
                        except Exception:
                            _record_result(
                                FileScanResult(
                                    file_path=str(aw.file_path),
                                    file_name=aw.file_path.name,
                                    safe_file_name=escape_untrusted_text(aw.file_path.name, max_len=256),
                                    file_size=aw.file_size,
                                    sha256=None,
                                    status=FileStatus.FAILED,
                                    status_reason=(
                                        f"Worker process terminated unexpectedly "
                                        f"(exit code {aw.process.exitcode})"
                                    ),
                                    file_kind="Failed",
                                )
                            )
                    else:
                        _record_result(
                            FileScanResult(
                                file_path=str(aw.file_path),
                                file_name=aw.file_path.name,
                                safe_file_name=escape_untrusted_text(aw.file_path.name, max_len=256),
                                file_size=aw.file_size,
                                sha256=None,
                                status=FileStatus.FAILED,
                                status_reason=(
                                    f"Worker process terminated unexpectedly "
                                    f"(exit code {aw.process.exitcode})"
                                ),
                                file_kind="Failed",
                            )
                        )
                    try:
                        aw.recv_conn.close()
                    except Exception:
                        pass

                elif elapsed >= self.timeout_seconds:
                    # Per-file timeout exceeded: terminate worker and record TIMED_OUT
                    _terminate_process_safely(aw.process)
                    try:
                        aw.recv_conn.close()
                    except Exception:
                        pass
                    _record_result(
                        FileScanResult(
                            file_path=str(aw.file_path),
                            file_name=aw.file_path.name,
                            safe_file_name=escape_untrusted_text(aw.file_path.name, max_len=256),
                            file_size=aw.file_size,
                            sha256=None,
                            status=FileStatus.TIMED_OUT,
                            status_reason=(
                                f"Worker killed after exceeding {self.timeout_seconds:g} s per-file limit"
                            ),
                            file_kind="Timed out",
                        )
                    )
                else:
                    still_running.append(aw)

            active_workers = still_running
            if active_workers:
                time.sleep(0.01)

        ordered_results = [
            results_by_name[f.name]
            for f in all_top_level_files
            if f.name in results_by_name
        ]
        elapsed_total = time.perf_counter() - start_wall

        return BatchScanSummary(
            folder_path=str(folder),
            total_files=total_files,
            processed_files=len(ordered_results),
            analyzed_count=analyzed_count,
            unsupported_count=unsupported_count,
            skipped_count=skipped_count,
            failed_or_malformed_count=failed_or_malformed_count,
            timed_out_count=timed_out_count,
            cancelled=self._cancel_event.is_set(),
            elapsed_seconds=round(elapsed_total, 3),
            results=ordered_results,
        )
