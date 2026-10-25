from collections.abc import Callable
from dataclasses import dataclass
from uuid import uuid4

from fastapi import UploadFile

from app.engines.static.fingerprint import FingerprintAccumulator
from app.schemas.common import validate_filename
from app.schemas.fingerprint import FingerprintResponse
from app.schemas.upload import UploadResponse

UPLOAD_READ_CHUNK_BYTES = 64 * 1024


class UploadValidationError(ValueError):
    """Base class for expected client upload errors."""


class InvalidFilenameError(UploadValidationError):
    """The multipart filename failed the metadata policy."""


class EmptyUploadError(UploadValidationError):
    """The uploaded file contained no bytes."""


class UploadTooLargeError(UploadValidationError):
    """The uploaded file exceeded the configured application limit."""


@dataclass(frozen=True)
class IngestedMetadata:
    filename: str
    size_bytes: int
    content_type: str | None


async def _consume_upload(
    upload: UploadFile,
    max_bytes: int,
    on_chunk: Callable[[bytes], None] | None = None,
) -> IngestedMetadata:
    try:
        filename = validate_filename(upload.filename or "")
    except ValueError as exc:
        raise InvalidFilenameError(str(exc)) from exc

    size_bytes = 0
    while True:
        remaining_with_sentinel = max_bytes - size_bytes + 1
        read_size = min(UPLOAD_READ_CHUNK_BYTES, remaining_with_sentinel)
        chunk = await upload.read(read_size)
        if not chunk:
            break
        size_bytes += len(chunk)
        if size_bytes > max_bytes:
            raise UploadTooLargeError(
                f"file exceeds the maximum size of {max_bytes} bytes"
            )
        if on_chunk is not None:
            on_chunk(chunk)

    if size_bytes == 0:
        raise EmptyUploadError("file must not be empty")

    return IngestedMetadata(
        filename=filename,
        size_bytes=size_bytes,
        content_type=upload.content_type,
    )


async def consume_upload(
    upload: UploadFile,
    max_bytes: int,
    on_chunk: Callable[[bytes], None] | None = None,
) -> IngestedMetadata:
    """Consume one validated upload and always close its underlying resource."""
    try:
        return await _consume_upload(upload, max_bytes, on_chunk)
    finally:
        await upload.close()


async def ingest_upload(upload: UploadFile, max_bytes: int) -> UploadResponse:
    """Validate and count an upload without executing or persisting its bytes."""
    metadata = await consume_upload(upload, max_bytes)
    return UploadResponse(
        upload_id=uuid4(),
        filename=metadata.filename,
        size_bytes=metadata.size_bytes,
        content_type=metadata.content_type,
        status="validated",
        persisted=False,
    )


async def fingerprint_upload(
    upload: UploadFile,
    max_bytes: int,
) -> FingerprintResponse:
    """Fingerprint a validated upload during the existing single read pass."""
    accumulator = FingerprintAccumulator()
    metadata = await consume_upload(upload, max_bytes, accumulator.update)
    return accumulator.finalize(metadata.filename)
