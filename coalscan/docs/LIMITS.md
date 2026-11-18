# Operational Limits, File Statuses, and Prototype Boundaries (CSC-203)

> **Important Boundary Statement:** CoalScan is a student static-triage prototype developed for CSC-203 (*Computer Organization and Assembly Language*). It is not a production security product, not an antivirus scanner, and never produces a malware verdict.

## 1. Hard Numeric Limits (`coalscan/core/limits.py`)

Every operational limit is defined as a named constant in `coalscan/core/limits.py`:

| Constant Name | Value | Behavior When Exceeded |
| :--- | :--- | :--- |
| `MAX_FILE_SIZE_BYTES` | `52,428,800` (50 MB) | Status `'too large'`. File is neither parsed nor hashed. |
| `MAX_FILES_PER_SCAN` | `500` files | Extra files in the folder are listed as `'skipped (extension or limit)'` with reason `'skipped: over limit'`. |
| `TOP_LEVEL_FOLDER_ONLY` | `True` | Subfolders are not traversed in committed scope. |
| `PER_FILE_TIMEOUT_SECONDS` | `20` seconds | Supervisor terminates the isolated worker process and records status `'timed out'`. |
| `MAX_DISASM_INSTRUCTIONS_PER_FILE` | `2,000` instructions | Disassembly output is truncated and noted in the UI and PDF/CSV reports. |
| `MAX_ENTRY_DISASM_BYTES` | `256` bytes | Maximum slice disassembled at `AddressOfEntryPoint`. |
| `MAX_EVIDENCE_DISASM_BYTES` | `128` bytes | Maximum slice disassembled around each executable-section evidence location. |
| `MAX_EVIDENCE_LOCATIONS_PER_FILE` | `3` locations | At most 3 evidence locations disassembled per file. |
| `MAX_SECTIONS` | `96` sections | Status `'malformed'`, reason recorded. |
| `MAX_IMPORT_ENTRIES` | `20,000` imports | Status `'malformed'`, reason recorded. |
| `CANDIDATE_EXTENSIONS` | `.exe`, `.dll`, `.sys`, `.ocx` | Non-matching extensions receive status `'skipped (extension or limit)'`. |

## 2. File-Type Routing & Exact Statuses (`coalscan/core/router.py`)

Every file in a batch ends with **exactly one** of the following 11 statuses plus an explicit reason:

1. `analyzed` - Native PE32 (`0x014C`) or PE32+ (`0x8664`) executable or DLL without a CLR header. Full analysis: rules `R01-R14` and bounded Capstone disassembly (32-bit or 64-bit mode). If a DLL has `AddressOfEntryPoint == 0`, `R11` is skipped and noted.
2. `analyzed (managed .NET, limited)` - PE file with non-empty COM descriptor (CLR) data directory (index 14). SHA-256 hash, header metadata, and structural rules `R09-R14` only. `R08` is suppressed because managed binaries typically import only `mscoree.dll`. No x86 disassembly; CIL bytecode is not examined.
3. `analyzed (driver, limited)` - PE file with `Subsystem == IMAGE_SUBSYSTEM_NATIVE (1)`. SHA-256 hash, metadata, and structural rules `R09-R14` only.
4. `driver candidate` - File with a `.sys` extension whose optional header does not specify `IMAGE_SUBSYSTEM_NATIVE`. Analyzed as an ordinary PE (`R01-R14` and bounded disassembly) and labeled `driver candidate`.
5. `unsupported architecture` - Valid PE header whose `Machine` field is not `0x014C` (x86) or `0x8664` (x64), such as `ARM64` (`0xAA64`) or `ARM` (`0x01C0`/`0x01C4`). SHA-256 hash and header metadata only; no rules and no disassembly.
6. `not a PE file` - Candidate extension file lacking an `MZ` header or valid `PE\0\0` signature. Listed, not parsed.
7. `skipped (extension or limit)` - File skipped due to non-candidate extension, exceeding the 500-file folder limit, or user scan cancellation.
8. `malformed` - Zero-byte file, truncated DOS/COFF/Optional header, corrupt section table, invalid data directory offsets, huge declared sizes, or exceeding parser sanity caps (96 sections / 20,000 imports).
9. `too large` - File size exceeds 50 MB (`MAX_FILE_SIZE_BYTES`). Not parsed and not hashed.
10. `timed out` - Per-file worker process exceeded 20 seconds (`PER_FILE_TIMEOUT_SECONDS`) and was terminated by the supervisor.
11. `failed` - Unexpected worker process crash or I/O failure; isolated to that single file so the batch never stops.
