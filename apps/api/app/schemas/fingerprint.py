from typing import Annotated, Literal

from pydantic import BaseModel, Field

DetectedFormat = Literal["pdf", "png", "jpeg", "gif", "zip", "pe", "elf", "unknown"]
FormatConsistency = Literal["match", "mismatch", "unknown"]


class FingerprintResponse(BaseModel):
    """Deterministic identity and format evidence for non-persisted bytes."""

    filename: Annotated[str, Field(min_length=1, max_length=255)]
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    size_bytes: Annotated[int, Field(gt=0)]
    detected_format: DetectedFormat
    signature_name: str | None
    extension: str | None
    format_consistency: FormatConsistency
    signature_offset: Annotated[int | None, Field(ge=0)] = None
    signature_hex: Annotated[str | None, Field(pattern=r"^[0-9a-f]+$")] = None
