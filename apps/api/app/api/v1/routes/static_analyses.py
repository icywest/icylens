import logging
from typing import Annotated

from fastapi import APIRouter, File, HTTPException, Request, UploadFile, status

from app.core.config import Settings
from app.schemas.static_analysis import StaticAnalysisResponse
from app.services.ingestion import (
    EmptyUploadError,
    InvalidFilenameError,
    UploadTooLargeError,
)
from app.services.static_analysis import analyze_static_upload

logger = logging.getLogger("icylens.static_analysis")

router = APIRouter(prefix="/static-analyses", tags=["Static Analyses"])


@router.post(
    "/",
    response_model=StaticAnalysisResponse,
    summary="Analyze and discard an uploaded file",
    responses={
        status.HTTP_413_CONTENT_TOO_LARGE: {
            "description": "The file exceeds the configured byte limit."
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "description": "The file or its filename is invalid."
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "The static analysis could not be completed."
        },
    },
)
async def create_static_analysis(
    request: Request,
    file: Annotated[
        UploadFile,
        File(description="Untrusted bytes to analyze statically and then discard."),
    ],
) -> StaticAnalysisResponse:
    settings: Settings = request.app.state.settings
    try:
        return await analyze_static_upload(
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
    except Exception as exc:
        await file.close()
        logger.error(
            "Static analysis failed with exception type %s",
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Static analysis could not be completed.",
        ) from None
