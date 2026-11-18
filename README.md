# Assembly-Assisted Malware Analysis (CSC-203)

**Static Windows PE Triage Desktop Prototype (Revision 5)**  
Course: Computer Organization and Assembly Language (CSC-203)  
Team: Hammad Ahmed (S25CSC040), Abdul Wasay (S25CSC027), Ghulam Mohiuddin (S25CSC034), Shayan Yousuf (S25CSC008)

> **Prototype Disclaimer:** This software is a student static-triage prototype built for university coursework. It is not a production security product or antivirus, and it never presents results as a "clean" or "malicious" verdict. Selected files are read strictly as raw bytes and are never executed, loaded, or uploaded.

---

## 1. Features & Architecture

- **Safe Static PE Triage:** Inspects Windows PE32 (`x86`) and PE32+ (`x64`) executables and DLLs without launching them, plus defined limited handling for Managed `.NET` (`CLR` directory 14), Native Drivers (`Subsystem NATIVE`), `.sys` driver candidates, and unsupported CPUs (`ARM`/`ARM64`).
- **Supervised Per-File Worker Isolation:** Uses a custom process supervisor (`coalscan/core/supervisor.py`) that spawns one short-lived `multiprocessing.Process` per file (up to `min(4, cpu_count - 1)` at once) with a 20-second kill timeout and a Cancel button. Does not use `ProcessPoolExecutor`.
- **Student x86-64 Subset Decoder + Capstone Oracle:** Hand-written 64-bit instruction decoder (`coalscan/decoder/x64_subset.py`) covering `MOV`, `PUSH/POP`, `CALL`, `JMP`, `Jcc`, `ADD`, `SUB`, `XOR`, `CMP`, and `RET` with full REX, ModR/M, SIB, and RIP-relative `disp32` support, verified against Capstone across 100 declared test vectors.
- **Rules R01-R14 & Transparent Banding:** Evaluates 14 static indicators linked to exact file offsets/RVAs and benign counterexamples. Applies Group A (`R01, R02, R05` capped at 2) and Group B (`R06-R08, R12-R14` capped at 2) caps to assign `Routine` (0-3, no High), `Review` (4-6 or single High), or `Review closely` (7+).
- **Local SQLite Metadata History & PDF/CSV Reports:** Records scan metadata and findings locally in SQLite (never storing binary bytes) and exports matching PDF (ReportLab) and CSV reports.

---

## 2. Commands: Run, Test, Calibrate, and Package

### Run the Desktop Application
```powershell
python -m coalscan
```

### Generate Benign & Malformed Test Fixtures and `manifest.csv`
```powershell
python -m coalscan.fixtures.generate_fixtures
```

### Run the Full Pytest Suite
```powershell
python -m pytest -v
```

### Run the Calibration Gate & Held-Out Evaluation
```powershell
python -m coalscan.tests.calibration
python -m coalscan.tests.heldout
```

### Build the Windows One-Folder Package (PyInstaller)
> **Note:** PyInstaller builds are OS-specific and must be built and tested on Windows 10/11 x64.
```powershell
pyinstaller --clean --noconfirm coalscan.spec
```
The packaged one-folder Windows build is output to `dist\coalscan\coalscan.exe`.

---

## 3. Documentation
- [Architecture Guide](file:///d:/Coal/coalscan/docs/ARCHITECTURE.md)
- [Testing & Calibration Guide](file:///d:/Coal/coalscan/docs/TESTING.md)
- [Operational Limits & Status Reference](file:///d:/Coal/coalscan/docs/LIMITS.md)
- [Fixtures & Manifest README](file:///d:/Coal/coalscan/fixtures/README.md)
