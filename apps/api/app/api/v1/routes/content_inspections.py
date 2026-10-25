from typing import Annotated

from fastapi import APIRouter, File, HTTPException, Request, UploadFile, status

from app.core.config import Settings
from app.schemas.content_inspection import ContentInspectionResponse
from app.services.content_inspection import inspect_content
from app.services.ingestion import (
    EmptyUploadError,
    InvalidFilenameError,
    UploadTooLargeError,
)

router = APIRouter(prefix="/content-inspections", tags=["Content Inspections"])


@router.post(
    "/",
    response_model=ContentInspectionResponse,
    summary="Inspect and discard uploaded content",
    responses={
        status.HTTP_413_CONTENT_TOO_LARGE: {
            "description": "The file exceeds the configured byte limit."
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "description": "The file or its filename is invalid."
        },
    },
)
async def create_content_inspection(
    request: Request,
    file: Annotated[
        UploadFile,
        File(description="Untrusted bytes to inspect and then discard."),
    ],
) -> ContentInspectionResponse:
    settings: Settings = request.app.state.settings
    try:
        return await inspect_content(
            file,
            max_bytes=settings.MAX_UPLOAD_BYTES,
            minimum_string_length=settings.INSPECTION_MIN_STRING_LENGTH,
            maximum_strings=settings.INSPECTION_MAX_STRINGS,
            maximum_string_length=settings.INSPECTION_MAX_STRING_LENGTH,
            maximum_indicators=settings.INSPECTION_MAX_INDICATORS,
        )
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
