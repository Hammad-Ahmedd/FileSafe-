"""Phase 4 tests: supervisor & worker isolation, all 11 statuses reachability,
malformed corpus batch resilience, no-execution security audit, and 50-file batch benchmark."""

from __future__ import annotations

import ast
from pathlib import Path
import platform
import threading
import time
from unittest.mock import patch

import psutil
import pytest

from coalscan.core import limits, supervisor as supervisor_mod, worker as worker_mod
from coalscan.core.limits import IMAGE_FILE_MACHINE_ARM64, IMAGE_SUBSYSTEM_NATIVE
from coalscan.core.models import FileStatus
from coalscan.core.supervisor import (
    BatchProgress,
    BatchSupervisor,
    get_max_concurrent_workers,
)
from coalscan.core.worker import analyze_single_file
from coalscan.fixtures.generate_fixtures import (
    BASELINE_IMPORTS,
    GENERATED_DIR,
    generate_all_fixtures,
)
from coalscan.tests.pe_builder import build_synthetic_pe


def test_supervisor_concurrency_and_no_process_pool_executor() -> None:
    """Verify supervisor concurrency formula and ensure ProcessPoolExecutor is never used."""
    assert get_max_concurrent_workers(1) == 1
    assert get_max_concurrent_workers(2) == 1
    assert get_max_concurrent_workers(4) == 3
    assert get_max_concurrent_workers(8) == 4
    assert get_max_concurrent_workers(16) == 4

    for mod in (supervisor_mod, worker_mod):
        src = Path(mod.__file__).read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                assert node.id != "ProcessPoolExecutor"
            elif isinstance(node, ast.Attribute):
                assert node.attr != "ProcessPoolExecutor"


def test_all_11_statuses_reachable_and_worker_fault_isolation(tmp_path: Path) -> None:
    """Verify every one of the 11 FileStatus values is reached in a single supervised batch,
    and neither a timed-out worker nor a crashing worker stops the batch."""
    scan_dir = tmp_path / "all_statuses_batch"
    scan_dir.mkdir()

    # 1. ANALYZED
    (scan_dir / "01_native.exe").write_bytes(
        build_synthetic_pe(is_64bit=True, imports=BASELINE_IMPORTS, has_certificate=True)
    )
    # 2. ANALYZED_DOTNET_LIMITED
    (scan_dir / "02_dotnet.exe").write_bytes(
        build_synthetic_pe(
            is_64bit=False,
            has_clr=True,
            imports=[("mscoree.dll", ["_CorExeMain"])],
            has_certificate=True,
        )
    )
    # 3. ANALYZED_DRIVER_LIMITED
    (scan_dir / "03_driver.sys").write_bytes(
        build_synthetic_pe(
            is_64bit=True,
            subsystem=IMAGE_SUBSYSTEM_NATIVE,
            imports=BASELINE_IMPORTS,
            has_certificate=True,
        )
    )
    # 4. DRIVER_CANDIDATE (.sys with non-NATIVE subsystem)
    (scan_dir / "04_cand.sys").write_bytes(
        build_synthetic_pe(
            is_64bit=True,
            subsystem=3,
            imports=BASELINE_IMPORTS,
            has_certificate=True,
        )
    )
    # 5. UNSUPPORTED_ARCH (ARM64)
    (scan_dir / "05_arm64.exe").write_bytes(
        build_synthetic_pe(
            is_64bit=True,
            machine=IMAGE_FILE_MACHINE_ARM64,
            imports=BASELINE_IMPORTS,
            has_certificate=True,
        )
    )
    # 6. NOT_A_PE
    (scan_dir / "06_notpe.exe").write_bytes(b"Plain text masquerading as an executable")
    # 7. SKIPPED (non-candidate extension)
    (scan_dir / "07_skip.txt").write_bytes(b"Readme notes")
    # 8. MALFORMED (zero-byte .exe)
    (scan_dir / "08_malformed.exe").write_bytes(b"")
    # 9. TOO_LARGE (exceeds custom max_file_size_bytes=50_000 for fast test without writing 51MB)
    (scan_dir / "09_huge.exe").write_bytes(b"M" * 60_000)
    # 10. TIMED_OUT (simulated 2.0s delay with 0.4s supervisor timeout)
    (scan_dir / "10_slow.exe").write_bytes(
        build_synthetic_pe(is_64bit=True, imports=BASELINE_IMPORTS, has_certificate=True)
    )
    # 11. FAILED (simulated hard worker crash via os._exit(1))
    (scan_dir / "11_crash.exe").write_bytes(
        build_synthetic_pe(is_64bit=True, imports=BASELINE_IMPORTS, has_certificate=True)
    )

    progress_updates: list[BatchProgress] = []
    sup = BatchSupervisor(
        timeout_seconds=15.0,
        max_file_size_bytes=50_000,
    )
    summary = sup.scan_folder(
        scan_dir,
        on_progress=progress_updates.append,
        per_file_delay_map={"10_slow.exe": 18.0},
        per_file_hard_exit_set={"11_crash.exe"},
    )

    assert summary.total_files == 11
    assert summary.processed_files == 11
    assert len(progress_updates) == 11

    observed_statuses = {res.status for res in summary.results}
    all_defined_statuses = set(FileStatus)
    assert observed_statuses == all_defined_statuses, (
        f"Missing statuses: {all_defined_statuses - observed_statuses}"
    )

    # Verify too-large file was NOT hashed
    huge_res = next(r for r in summary.results if r.file_name == "09_huge.exe")
    assert huge_res.status == FileStatus.TOO_LARGE
    assert huge_res.sha256 is None


def test_top_level_folder_only_and_max_files_limit(tmp_path: Path) -> None:
    """Verify subfolders are ignored and files over max_files are marked 'skipped: over limit'."""
    scan_dir = tmp_path / "limit_folder"
    scan_dir.mkdir()
    sub_dir = scan_dir / "nested_subfolder"
    sub_dir.mkdir()

    pe_bytes = build_synthetic_pe(imports=BASELINE_IMPORTS, has_certificate=True)
    # Put a file inside subfolder (must be ignored)
    (sub_dir / "hidden.exe").write_bytes(pe_bytes)

    # Put 5 top-level files and set max_files=3
    for i in range(5):
        (scan_dir / f"app_{i:02d}.exe").write_bytes(pe_bytes)

    sup = BatchSupervisor(max_files=3)
    summary = sup.scan_folder(scan_dir)

    assert summary.total_files == 5
    assert summary.processed_files == 5
    assert summary.analyzed_count == 3
    assert summary.skipped_count == 2

    over_limit_results = [
        r for r in summary.results if r.status == FileStatus.SKIPPED
    ]
    assert len(over_limit_results) == 2
    for r in over_limit_results:
        assert "skipped: over limit" in r.status_reason


def test_cancel_button_terminates_running_workers(tmp_path: Path) -> None:
    """Verify cancelling an active scan terminates running workers immediately."""
    scan_dir = tmp_path / "cancel_folder"
    scan_dir.mkdir()
    pe_bytes = build_synthetic_pe(imports=BASELINE_IMPORTS, has_certificate=True)
    for i in range(6):
        (scan_dir / f"slow_{i}.exe").write_bytes(pe_bytes)

    sup = BatchSupervisor(timeout_seconds=10.0, max_workers=2)
    timer = threading.Timer(0.35, sup.cancel)
    timer.start()
    start_t = time.perf_counter()
    summary = sup.scan_folder(
        scan_dir,
        per_file_delay_map={f"slow_{i}.exe": 5.0 for i in range(6)},
    )
    elapsed = time.perf_counter() - start_t
    timer.cancel()

    assert summary.cancelled is True
    assert elapsed < 4.0
    assert summary.processed_files == 6
    assert any("cancelled" in r.status_reason.lower() for r in summary.results)


def test_malformed_corpus_batch_zero_crashes(tmp_path: Path) -> None:
    """Run the supervised batch scanner across all 12 malformed corpus fixtures."""
    generate_all_fixtures()
    mal_dir = tmp_path / "malformed_batch"
    mal_dir.mkdir()

    mal_files = sorted(GENERATED_DIR.glob("malformed_*.exe"))
    assert len(mal_files) >= 12
    for mf in mal_files:
        (mal_dir / mf.name).write_bytes(mf.read_bytes())

    sup = BatchSupervisor()
    summary = sup.scan_folder(mal_dir)

    assert summary.total_files == len(mal_files)
    assert summary.processed_files == len(mal_files)
    for res in summary.results:
        assert res.status == FileStatus.MALFORMED, (
            f"{res.file_name} expected MALFORMED, got {res.status} ({res.status_reason})"
        )
        assert res.status_reason


def test_no_execution_security_audit() -> None:
    """Prove via runtime mocking and static AST audit that scanned files are never launched."""
    generate_all_fixtures()
    sample_files = [
        GENERATED_DIR / "r01_pos.exe",
        GENERATED_DIR / "type_dll_with_ep.dll",
        GENERATED_DIR / "type_managed_dotnet.exe",
        GENERATED_DIR / "malformed_01_zero_byte.exe",
    ]

    with (
        patch("subprocess.Popen") as mock_popen,
        patch("subprocess.run") as mock_run,
        patch("subprocess.call") as mock_call,
        patch("subprocess.check_call") as mock_check_call,
        patch("subprocess.check_output") as mock_check_output,
        patch("os.system") as mock_system,
    ):
        for sf in sample_files:
            res = analyze_single_file(sf)
            assert res.file_name == sf.name

        assert mock_popen.call_count == 0
        assert mock_run.call_count == 0
        assert mock_call.call_count == 0
        assert mock_check_call.call_count == 0
        assert mock_check_output.call_count == 0
        assert mock_system.call_count == 0

    # AST audit across all production modules under coalscan/
    coalscan_root = Path(limits.__file__).resolve().parent.parent
    forbidden_calls = {"startfile", "system", "execv", "execve", "spawnl", "spawnv"}
    for py_file in coalscan_root.rglob("*.py"):
        if "tests" in py_file.parts:
            continue
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in forbidden_calls:
                pytest.fail(f"Forbidden execution API '{node.attr}' found in {py_file}")


def test_batch_performance_50_files_under_60_seconds(tmp_path: Path) -> None:
    """Benchmark 50 files up to 5 MB on the current machine; require completion under 60 s."""
    bench_dir = tmp_path / "bench_50_files"
    bench_dir.mkdir()

    # Build a mix of 50 PE files including larger files up to ~2-5 MB
    small_pe = build_synthetic_pe(
        is_64bit=True,
        imports=BASELINE_IMPORTS,
        has_certificate=True,
    )
    # 2.5 MB PE with large resource section + 4.5 MB PE near the 5 MB mark
    medium_pe = build_synthetic_pe(
        is_64bit=True,
        imports=BASELINE_IMPORTS,
        has_certificate=True,
        extra_sections=[(b".rsrc", 0x40000040, b"\x55" * (2 * 1024 * 1024))],
    )
    large_5mb_pe = build_synthetic_pe(
        is_64bit=True,
        imports=BASELINE_IMPORTS,
        has_certificate=True,
        extra_sections=[(b".rsrc", 0x40000040, b"\xAA" * (4 * 1024 * 1024))],
    )

    for i in range(50):
        if i in (0, 25):
            payload = large_5mb_pe
        elif i % 10 == 0:
            payload = medium_pe
        else:
            payload = small_pe
        (bench_dir / f"bench_{i:02d}.exe").write_bytes(payload)

    os_info = f"{platform.system()} {platform.release()} ({platform.version()})"
    cpu_info = platform.processor() or "x86_64"
    ram_gb = round(psutil.virtual_memory().total / (1024**3), 2)

    sup = BatchSupervisor()
    summary = sup.scan_folder(bench_dir)

    print(
        f"\n[BENCHMARK RECORD] OS={os_info} | CPU={cpu_info} | RAM={ram_gb} GB | "
        f"Files={summary.processed_files}/{summary.total_files} | "
        f"WallTime={summary.elapsed_seconds:.2f}s (Target < 60.0s)"
    )

    assert summary.total_files == 50
    assert summary.processed_files == 50
    assert summary.analyzed_count == 50
    assert summary.elapsed_seconds < 60.0, (
        f"50-file batch took {summary.elapsed_seconds:.2f}s, exceeding 60s target"
    )
