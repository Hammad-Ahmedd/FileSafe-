# Architecture Overview - Assembly-Assisted Malware Analysis (CSC-203)

> **Prototype Boundary Disclaimer:** This application is a student static-triage prototype built for **CSC-203 (Computer Organization and Assembly Language)**. It is not a production security product or antivirus product and never issues a "clean" or "malicious" verdict. Triage bands (`Routine`, `Review`, `Review closely`) represent review priority only.

## 1. End-to-End Pipeline

```
[Folder Pick]
     |  (Top-level folder only, max 500 files, max 50 MB/file, candidate extensions)
     v
[BatchSupervisor (core/supervisor.py)]
     |  Spawns 1 short-lived multiprocessing.Process per file (max min(4, CPU-1))
     |  20 s kill timeout per worker; isolated Pipe per worker (no ProcessPoolExecutor)
     v
[Worker Process (core/worker.py)]
  1. Hashing (core/hashing.py): Streamed SHA-256 on raw bytes (skipped if > 50 MB)
  2. Static PE Inspection (core/pe_inspect.py): MZ/PE headers, sections, entropy, imports, CLR, TLS, overlay, cert
  3. Content Router (core/router.py): Native PE32/PE32+, DLL, Managed .NET, Driver, Driver Candidate, ARM64, Not-a-PE
  4. Rule Engine (core/rules.py): Evaluates R01-R14 with exact file offsets / RVAs and benign counterexamples
  5. Transparent Banding (core/banding.py): Group A cap (2), Group B cap (2), Routine / Review / Review closely
  6. Bounded Disassembly (core/disasm.py + decoder/x64_subset.py): Entry point (<=256 B) + <=3 evidence slices (<=128 B), <=2,000 instructions/file
     |
     v
[UI + Storage + Reports]
  - PySide6 Desktop UI (ui/main_window.py, scan_page.py, results_page.py, evidence_page.py)
  - SQLite Local Metadata History (storage/history.py - metadata only, never binary bytes)
  - ReportLab PDF & CSV Exporters (report/pdf_report.py, report/csv_export.py)
```

## 2. Key Architectural Decisions

### 2.1 Hard Safety Guarantees
1. **Zero Execution:** Scanned files are opened with `open(..., "rb")` / `Path.read_bytes()` only. No scanned file is ever passed to `subprocess`, `os.system`, `os.startfile`, `ctypes`, or `importlib`.
2. **Offline Local-Only Operation:** Zero network calls at runtime; binary bytes never leave the user's computer and are never stored in SQLite.
3. **Output Escaping:** Every untrusted string (file names, section names, DLL/import names, parser errors) is sanitized via `escape_untrusted_text()` before display in the UI or inclusion in PDF/CSV reports.

### 2.2 Supervised Per-File Workers (Why Not `ProcessPoolExecutor`)
Python's `concurrent.futures.ProcessPoolExecutor` cannot cancel a task once it is running on a worker process, and terminating a hung worker process corrupts the entire shared pool. Instead, `BatchSupervisor` in `coalscan/core/supervisor.py` spawns one short-lived `multiprocessing.Process` per file (up to `min(4, cpu_count - 1)` concurrently, minimum 1) communicating over a dedicated `multiprocessing.Pipe`. If a worker exceeds 20 seconds or crashes (`exitcode != 0`), the supervisor terminates or reaps that single worker and records `timed out` or `failed` without interrupting the remaining files.

### 2.3 Student x86-64 Subset Decoder vs. Capstone
- `coalscan/decoder/x64_subset.py` is a hand-written 64-bit instruction decoder for the declared CSC-203 subset (`MOV`, `PUSH`, `POP`, `CALL`, `JMP`, `Jcc`, `ADD`, `SUB`, `XOR`, `CMP`, `RET`), implementing REX (`40h-4Fh`), ModR/M (`mod 00/01/10/11`), SIB (including `index=100` no-index and `mod=00, base=101` `disp32` no-base), and RIP-relative `next_rip + disp32` addressing.
- Legacy prefixes (`66`, `67`, `F2`, `F3`, `F0`, segment overrides) and truncated/unknown encodings are explicitly rejected with a diagnostic reason (`supported=False`).
- Capstone (`CS_ARCH_X86`) handles general 32-bit and 64-bit bounded disassembly in the scanner and serves as the comparison oracle across the 100 declared test vectors (`coalscan/decoder/vectors.py`).
