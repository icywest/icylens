import logging
from typing import Annotated

from fastapi import APIRouter, File, HTTPException, Request, UploadFile, status

from app.core.config import Settings
from app.ml.model_runtime import TrustedModelRuntime
from app.schemas.ml_inference import MLInferenceResponse
from app.services.ingestion import (
    EmptyUploadError,
    InvalidFilenameError,
    UploadTooLargeError,
)
from app.services.ml_inference import (
    InferenceCapacity,
    InferenceCapacityError,
    InferenceUnavailableError,
    infer_upload,
)

logger = logging.getLogger("icylens.ml_inference")

router = APIRouter(prefix="/ml-inferences", tags=["ML Inferences"])


@router.post(
    "/",
    response_model=MLInferenceResponse,
    summary="Run explicitly authorized local synthetic-model inference",
    responses={
        status.HTTP_413_CONTENT_TOO_LARGE: {
            "description": "The file exceeds the configured byte limit."
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "description": "The file or its filename is invalid."
        },
        status.HTTP_429_TOO_MANY_REQUESTS: {
            "description": "The bounded local inference capacity is exhausted."
        },
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "description": "Inference is disabled or no compatible model is active."
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "ML inference could not be completed."
        },
    },
)
async def create_ml_inference(
    request: Request,
    file: Annotated[
        UploadFile,
        File(description="Untrusted bytes analyzed once and then discarded."),
    ],
) -> MLInferenceResponse:
    settings: Settings = request.app.state.settings
    runtime: TrustedModelRuntime = request.app.state.ml_runtime
    capacity: InferenceCapacity = request.app.state.ml_inference_capacity
    try:
        return await infer_upload(
            file,
            settings=settings,
            runtime=runtime,
            capacity=capacity,
        )
    except UploadTooLargeError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail=str(exc)
        ) from exc
    except (EmptyUploadError, InvalidFilenameError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    except InferenceCapacityError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="ML inference capacity is exhausted.",
        ) from exc
    except InferenceUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML inference is unavailable.",
        ) from exc
    except Exception as exc:
        await file.close()
        logger.error("ML inference failed with exception type %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="ML inference could not be completed.",
        ) from None
