import hashlib
from collections.abc import Iterable
from pathlib import PurePath

from app.engines.static.signatures import (
    SIGNATURE_INSPECTION_BYTES,
    detect_signature,
)
from app.schemas.fingerprint import (
    DetectedFormat,
    FingerprintResponse,
    FormatConsistency,
)

EXTENSION_FORMATS: dict[str, DetectedFormat] = {
    ".pdf": "pdf",
    ".png": "png",
    ".jpg": "jpeg",
    ".jpeg": "jpeg",
    ".gif": "gif",
    ".zip": "zip",
    ".exe": "pe",
    ".dll": "pe",
    ".elf": "elf",
}


def extract_extension(filename: str) -> str | None:
    extension = PurePath(filename).suffix.lower()
    return extension or None


def compare_format(
    extension: str | None,
    detected_format: DetectedFormat,
) -> FormatConsistency:
    expected_format = EXTENSION_FORMATS.get(extension or "")
    if detected_format == "unknown" or expected_format is None:
        return "unknown"
    if expected_format == detected_format:
        return "match"
    return "mismatch"


class FingerprintAccumulator:
    """Incrementally hash bytes while retaining only a bounded leading prefix."""

    def __init__(self) -> None:
        self._hasher = hashlib.sha256()
        self._header = bytearray()
        self.size_bytes = 0

    def update(self, chunk: bytes) -> None:
        self._hasher.update(chunk)
        self.size_bytes += len(chunk)
        header_remaining = SIGNATURE_INSPECTION_BYTES - len(self._header)
        if header_remaining > 0:
            self._header.extend(chunk[:header_remaining])

    def finalize(self, filename: str) -> FingerprintResponse:
        signature = detect_signature(bytes(self._header))
        extension = extract_extension(filename)
        return FingerprintResponse(
            filename=filename,
            sha256=self._hasher.hexdigest(),
            size_bytes=self.size_bytes,
            detected_format=signature.format,
            signature_name=signature.name,
            extension=extension,
            format_consistency=compare_format(extension, signature.format),
            signature_offset=signature.offset,
            signature_hex=(
                signature.signature.hex() if signature.signature is not None else None
            ),
        )


def fingerprint_chunks(
    chunks: Iterable[bytes],
    filename: str,
) -> FingerprintResponse:
    accumulator = FingerprintAccumulator()
    for chunk in chunks:
        accumulator.update(chunk)
    return accumulator.finalize(filename)
