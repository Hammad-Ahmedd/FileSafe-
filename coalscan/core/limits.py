"""Named constants and hard operational limits for static PE triage.

All numeric limits from the CSC-203 Revision 5 specification live in this module.
Never use magic numbers in scanner, parser, router, or worker code.
"""

from typing import Final

# Version metadata for auditability in UI, SQLite history, PDF, and CSV reports
TOOL_VERSION: Final[str] = "0.5.0-rev5"
RULE_CATALOG_VERSION: Final[str] = "rev5-1.0"
BANDING_VERSION: Final[str] = "rev5-1.0"

# File & folder scan limits
MAX_FILE_SIZE_BYTES: Final[int] = 50 * 1024 * 1024  # 50 MB per file
MAX_FILES_PER_SCAN: Final[int] = 500                # Max 500 files per scan
PER_FILE_TIMEOUT_SECONDS: Final[int] = 20           # 20 s per file worker timeout
TOP_LEVEL_FOLDER_ONLY: Final[bool] = True           # No subfolder recursion in committed scope

# Bounded disassembly limits
MAX_DISASM_INSTRUCTIONS_PER_FILE: Final[int] = 2000  # Max 2,000 disassembled instructions per file
MAX_ENTRY_DISASM_BYTES: Final[int] = 256             # Up to 256 bytes at the entry point
MAX_EVIDENCE_DISASM_BYTES: Final[int] = 128          # Up to 128 bytes around each evidence location
MAX_EVIDENCE_LOCATIONS_PER_FILE: Final[int] = 3      # At most 3 evidence locations per file

# Parser sanity limits
MAX_SECTIONS: Final[int] = 96               # Max 96 sections
MAX_IMPORT_ENTRIES: Final[int] = 20_000     # Max 20,000 import entries

# Worker concurrency limits
MAX_CONCURRENT_WORKERS_CAP: Final[int] = 4  # At most min(4, cpu_count - 1), minimum 1
MIN_CONCURRENT_WORKERS: Final[int] = 1

# Candidate file extensions (lowercased with leading dot)
CANDIDATE_EXTENSIONS: Final[frozenset[str]] = frozenset({
    ".exe",
    ".dll",
    ".sys",
    ".ocx",
})

# PE format constants
MZ_SIGNATURE: Final[bytes] = b"MZ"
PE_SIGNATURE: Final[bytes] = b"PE\x00\x00"
DOS_HEADER_MIN_SIZE: Final[int] = 64
LFANEW_OFFSET: Final[int] = 0x3C

# Machine types (IMAGE_FILE_HEADER.Machine)
IMAGE_FILE_MACHINE_I386: Final[int] = 0x014C
IMAGE_FILE_MACHINE_AMD64: Final[int] = 0x8664
IMAGE_FILE_MACHINE_ARM: Final[int] = 0x01C0
IMAGE_FILE_MACHINE_ARMNT: Final[int] = 0x01C4
IMAGE_FILE_MACHINE_ARM64: Final[int] = 0xAA64

SUPPORTED_X86_MACHINES: Final[frozenset[int]] = frozenset({
    IMAGE_FILE_MACHINE_I386,
    IMAGE_FILE_MACHINE_AMD64,
})

# Optional Header Magic
PE32_MAGIC: Final[int] = 0x10B
PE32_PLUS_MAGIC: Final[int] = 0x20B

# Characteristics & Subsystem flags
IMAGE_FILE_DLL: Final[int] = 0x2000
IMAGE_SUBSYSTEM_NATIVE: Final[int] = 1

# Section characteristic flags
IMAGE_SCN_MEM_EXECUTE: Final[int] = 0x20000000
IMAGE_SCN_MEM_READ: Final[int] = 0x40000000
IMAGE_SCN_MEM_WRITE: Final[int] = 0x80000000

# Data directory indices
SECURITY_DATA_DIRECTORY_INDEX: Final[int] = 4      # Certificate table (file offset, not RVA)
TLS_DATA_DIRECTORY_INDEX: Final[int] = 9           # TLS directory
CLR_DATA_DIRECTORY_INDEX: Final[int] = 14          # .NET COM descriptor (CLR) directory

# Rule parameters
MIN_IMPORTS_NATIVE_PE: Final[int] = 5              # R08 fires when < 5 imported functions
ENTROPY_MIN_SECTION_BYTES: Final[int] = 1024       # R09 checks sections >= 1 KB
ENTROPY_THRESHOLD_BITS_PER_BYTE: Final[float] = 7.0
