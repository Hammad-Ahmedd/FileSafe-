"""Safe SHA-256 hashing utilities for static file triage.

Files are strictly read as raw bytes and never executed or loaded.
Files exceeding MAX_FILE_SIZE_BYTES are rejected before hashing.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Union

from coalscan.core.limits import MAX_FILE_SIZE_BYTES

HASH_CHUNK_SIZE = 65536  # 64 KB chunks


class FileTooLargeError(ValueError):
    """Raised when a file exceeds the configured maximum byte size."""


def compute_sha256_bytes(data: bytes) -> str:
    """Compute the lowercase hexadecimal SHA-256 digest of in-memory bytes."""
    if len(data) > MAX_FILE_SIZE_BYTES:
        raise FileTooLargeError(
            f"Byte buffer size ({len(data)} bytes) exceeds limit ({MAX_FILE_SIZE_BYTES} bytes)"
        )
    return hashlib.sha256(data).hexdigest()


def compute_sha256_file(
    file_path: Union[str, Path],
    max_bytes: int = MAX_FILE_SIZE_BYTES,
) -> str:
    """Compute the lowercase hexadecimal SHA-256 digest of a file on disk.

    Raises FileTooLargeError without reading the file if its size exceeds max_bytes.
    """
    path = Path(file_path)
    file_size = path.stat().st_size
    if file_size > max_bytes:
        raise FileTooLargeError(
            f"File size ({file_size} bytes) exceeds limit ({max_bytes} bytes)"
        )

    hasher = hashlib.sha256()
    bytes_read = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(HASH_CHUNK_SIZE)
            if not chunk:
                break
            bytes_read += len(chunk)
            if bytes_read > max_bytes:
                raise FileTooLargeError(
                    f"File stream exceeded limit ({max_bytes} bytes) while hashing"
                )
            hasher.update(chunk)
    return hasher.hexdigest()
