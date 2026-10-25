from typing import Annotated

from fastapi import APIRouter, File, HTTPException, Request, UploadFile, status

from app.core.config import Settings
from app.schemas.fingerprint import FingerprintResponse
from app.services.ingestion import (
    EmptyUploadError,
    InvalidFilenameError,
    UploadTooLargeError,
    fingerprint_upload,
)

router = APIRouter(prefix="/fingerprints", tags=["Fingerprints"])


@router.post(
    "/",
    response_model=FingerprintResponse,
    summary="Fingerprint and discard an uploaded file",
    responses={
        status.HTTP_413_CONTENT_TOO_LARGE: {
            "description": "The file exceeds the configured byte limit."
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "description": "The file or its filename is invalid."
        },
    },
)
async def create_fingerprint(
    request: Request,
    file: Annotated[
        UploadFile,
        File(description="Untrusted bytes to fingerprint and then discard."),
    ],
) -> FingerprintResponse:
    settings: Settings = request.app.state.settings
    try:
        return await fingerprint_upload(file, settings.MAX_UPLOAD_BYTES)
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
