from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, Field


class UploadResponse(BaseModel):
    """Metadata for one validated, deliberately non-persisted upload."""

    upload_id: UUID
    filename: Annotated[str, Field(min_length=1, max_length=255)]
    size_bytes: Annotated[int, Field(gt=0)]
    content_type: str | None
    status: Literal["validated"]
    persisted: Literal[False]
