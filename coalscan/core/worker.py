"""Isolated single-file static triage worker (Section 1 & Section 2).

Reads a candidate file purely as raw bytes, computes SHA-256, inspects PE headers/sections/imports,
routes by content, evaluates rules R01-R14, computes the risk band, and disassembles bounded regions.
Never executes, imports, or loads the scanned binary.
"""

from __future__ import annotations

from multiprocessing.connection import Connection
import os
from pathlib import Path
import time
from typing import Union

from coalscan.core.banding import BandingConfig, DEFAULT_BANDING_CONFIG, compute_banding
from coalscan.core.disasm import disassemble_bounded_regions
from coalscan.core.hashing import FileTooLargeError, compute_sha256_bytes
from coalscan.core.limits import MAX_FILE_SIZE_BYTES
from coalscan.core.models import (
    FileScanResult,
    FileStatus,
    RiskBand,
    escape_untrusted_text,
)
from coalscan.core.pe_inspect import inspect_pe_bytes
from coalscan.core.router import is_candidate_extension, route_file
from coalscan.core.rules import evaluate_rules


def analyze_single_file(
    file_path: Union[str, Path],
    config: BandingConfig = DEFAULT_BANDING_CONFIG,
    simulated_delay_s: float = 0.0,
    simulate_crash: bool = False,
) -> FileScanResult:
    """Statically analyze one file on disk and return a structured FileScanResult.

    All exceptions are caught and converted into `FileStatus.FAILED` so one file
    can never crash a batch scan.
    """
    path = Path(file_path)
    raw_name = path.name
    safe_name = escape_untrusted_text(raw_name, max_len=256)

    if simulate_crash:
        raise RuntimeError("Simulated internal worker failure for fault-tolerance testing")

    if simulated_delay_s > 0:
        time.sleep(simulated_delay_s)

    try:
        stat_info = path.stat()
        file_size = stat_info.st_size
    except Exception as exc:
        return FileScanResult(
            file_path=str(path),
            file_name=raw_name,
            safe_file_name=safe_name,
            file_size=0,
            sha256=None,
            status=FileStatus.FAILED,
            status_reason=f"Could not stat file: {escape_untrusted_text(str(exc), max_len=160)}",
        )

    # 1. Extension check
    if not is_candidate_extension(raw_name):
        decision = route_file(raw_name, file_size, inspection=None, check_extension=True)
        return FileScanResult(
            file_path=str(path),
            file_name=raw_name,
            safe_file_name=safe_name,
            file_size=file_size,
            sha256=None,
            status=decision.status,
            status_reason=decision.reason,
            file_kind=decision.file_kind,
        )

    # 2. Size check: Too-large files (> 50 MB) are not parsed or hashed
    if file_size > MAX_FILE_SIZE_BYTES:
        decision = route_file(raw_name, file_size, inspection=None, check_extension=True)
        return FileScanResult(
            file_path=str(path),
            file_name=raw_name,
            safe_file_name=safe_name,
            file_size=file_size,
            sha256=None,
            status=decision.status,
            status_reason=decision.reason,
            file_kind=decision.file_kind,
        )

    try:
        # Read file strictly as raw bytes (never launched or loaded)
        data = path.read_bytes()
        if len(data) > MAX_FILE_SIZE_BYTES:
            raise FileTooLargeError("File grew beyond 50 MB limit while reading")

        # 3. Inspect PE structure and route by content
        inspection = inspect_pe_bytes(data)
        decision = route_file(raw_name, len(data), inspection, check_extension=True)

        # Compute SHA-256 for valid/analyzed/unsupported/malformed candidate files,
        # except 'not a PE file' if we still want hash or Section 2 says "Listed, not parsed"
        sha256_hex = (
            compute_sha256_bytes(data)
            if decision.status != FileStatus.TOO_LARGE
            else None
        )

        # 4. Evaluate rules and risk band if applicable
        if decision.run_full_rules or decision.run_structural_rules_only:
            findings = evaluate_rules(inspection, decision, config=config)
            banding_res = compute_banding(findings, config=config)
            band = banding_res.band
            score = banding_res.score
            breakdown = banding_res.breakdown
        else:
            findings = []
            band = RiskBand.NOT_APPLICABLE
            score = None
            breakdown = ""

        # 5. Bounded disassembly if applicable
        if decision.run_disassembly:
            disasm_regions, disasm_trunc, trunc_reason = disassemble_bounded_regions(
                data=data,
                inspection=inspection,
                route=decision,
                findings=findings,
            )
        else:
            disasm_regions = []
            disasm_trunc = False
            trunc_reason = ""

        return FileScanResult(
            file_path=str(path),
            file_name=raw_name,
            safe_file_name=safe_name,
            file_size=len(data),
            sha256=sha256_hex,
            status=decision.status,
            status_reason=decision.reason,
            file_kind=decision.file_kind,
            pe_format=inspection.pe_format if inspection.is_pe else "-",
            architecture=inspection.architecture if inspection.is_pe else "-",
            is_dll=inspection.is_dll,
            entry_point_rva=inspection.entry_point_rva if inspection.is_pe else None,
            entry_point_offset=inspection.entry_point_offset if inspection.is_pe else None,
            skip_r11_note=decision.skip_r11_reason,
            findings=findings,
            band=band,
            score=score,
            score_breakdown=breakdown,
            disasm_regions=disasm_regions,
            disasm_truncated=disasm_trunc,
            disasm_truncation_reason=trunc_reason,
            inspection=inspection if inspection.is_pe else None,
        )
    except Exception as exc:
        return FileScanResult(
            file_path=str(path),
            file_name=raw_name,
            safe_file_name=safe_name,
            file_size=file_size,
            sha256=None,
            status=FileStatus.FAILED,
            status_reason=f"Worker error: {escape_untrusted_text(str(exc), max_len=200)}",
            file_kind="Failed",
        )


def worker_process_entry(
    file_path_str: str,
    send_conn: Connection,
    config: BandingConfig = DEFAULT_BANDING_CONFIG,
    simulated_delay_s: float = 0.0,
    simulate_crash: bool = False,
    simulate_hard_exit: bool = False,
) -> None:
    """Entry point executed inside a short-lived `multiprocessing.Process` worker."""
    try:
        if simulate_hard_exit:
            os._exit(1)
        result = analyze_single_file(
            file_path=file_path_str,
            config=config,
            simulated_delay_s=simulated_delay_s,
            simulate_crash=simulate_crash,
        )
        send_conn.send(result)
    except Exception as exc:
        p = Path(file_path_str)
        fallback = FileScanResult(
            file_path=file_path_str,
            file_name=p.name,
            safe_file_name=escape_untrusted_text(p.name, max_len=256),
            file_size=p.stat().st_size if p.exists() else 0,
            sha256=None,
            status=FileStatus.FAILED,
            status_reason=f"Unhandled worker exception: {escape_untrusted_text(str(exc), max_len=200)}",
            file_kind="Failed",
        )
        try:
            send_conn.send(fallback)
        except Exception:
            pass
    finally:
        try:
            send_conn.close()
        except Exception:
            pass
