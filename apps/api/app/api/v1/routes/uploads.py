from typing import Annotated

from fastapi import APIRouter, File, HTTPException, Request, UploadFile, status

from app.core.config import Settings
from app.schemas.upload import UploadResponse
from app.services.ingestion import (
    EmptyUploadError,
    InvalidFilenameError,
    UploadTooLargeError,
    ingest_upload,
)

router = APIRouter(prefix="/uploads", tags=["Uploads"])


@router.post(
    "/",
    response_model=UploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Validate and discard an uploaded file",
    responses={
        status.HTTP_413_CONTENT_TOO_LARGE: {
            "description": "The file exceeds the configured byte limit."
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "description": "The file or its filename is invalid."
        },
    },
)
async def create_upload(
    request: Request,
    file: Annotated[
        UploadFile,
        File(description="Untrusted file bytes to validate; the bytes are discarded."),
    ],
) -> UploadResponse:
    settings: Settings = request.app.state.settings
    try:
        return await ingest_upload(file, settings.MAX_UPLOAD_BYTES)
    except UploadTooLargeError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=str(exc),
        ) from exc
    except (EmptyUploadError, InvalidFilenameError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
