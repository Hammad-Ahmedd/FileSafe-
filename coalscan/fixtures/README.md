# Synthetic Benign Fixtures & Manifest (CSC-203)

All test fixtures in this directory are **100% synthetic and benign**, constructed deterministically by `generate_fixtures.py` using `coalscan/tests/pe_builder.py`.
- **No real malware is ever downloaded, stored, or generated.**
- **No fixture is ever executed or loaded.** Every file is inspected purely as raw bytes.

## Fixture Sets (`manifest.csv`)

1. **`rule` (28 files: `r01_pos.exe`..`r14_pos.exe` and `r01_neg.exe`..`r14_neg.exe`)**
   - One positive and one negative fixture for every rule in the R01-R14 catalog.
2. **`router` (10 files)**
   - Covers native PE32 (`x86`), native PE32+ (`x64`), DLL without entry point (`AddressOfEntryPoint = 0`, skipping R11), DLL with entry point, managed .NET (`CLR` directory 14 non-empty, suppressing R08), confirmed NATIVE driver (`Subsystem = 1`), unconfirmed `.sys` (`driver candidate`), `ARM64` PE (`unsupported architecture`), plain-text `.exe` (`not a PE file`), and `.txt` (`skipped (extension or limit)`).
3. **`calibration` (8 benign files assigned up front before rule tuning)**
   - Used by `coalscan/tests/calibration.py` to verify the Week 4 calibration gate: every benign file in the calibration set must land in `Routine` (score 0-3 and no High rule).
4. **`heldout` (8 benign files assigned up front, run once after freeze)**
   - Used by `coalscan/tests/heldout.py` to evaluate false positives on held-out benign files without retuning weights.
5. **`malformed` (12 corrupt/truncated/bit-flipped files)**
   - Zero-byte, truncated DOS/COFF/Optional headers, invalid `e_lfanew`, invalid Optional Header magic, truncated section table, >96 sections, out-of-bounds section raw offset, huge virtual size, unmapped import RVA, and deterministic seeded bit flips (`seed=203`).

## Regenerating Fixtures

```powershell
python -m coalscan.fixtures.generate_fixtures
```
