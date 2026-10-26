import asyncio
from uuid import uuid4

from fastapi import UploadFile

from app.core.config import Settings
from app.ml.features import extract_ml_features
from app.ml.model_runtime import ModelRuntimeError, TrustedModelRuntime
from app.schemas.ml_dataset import FeatureExtractionSettings
from app.schemas.ml_inference import (
    InferenceLimitation,
    InferenceModelSummary,
    InferencePrediction,
    MLInferenceResponse,
)
from app.services.static_analysis import analyze_static_upload

INFERENCE_LIMITATIONS = (
    InferenceLimitation(
        code="synthetic_model_only",
        description=(
            "The active model was trained only on synthetic metadata and has no "
            "demonstrated real-world malware detection performance."
        ),
    ),
    InferenceLimitation(
        code="not_security_verdict",
        description="The predicted label is model output, not a verified security finding.",
    ),
    InferenceLimitation(
        code="probability_not_calibrated",
        description=(
            "Probability estimates are not independently calibrated and are not a "
            "security risk score."
        ),
    ),
    InferenceLimitation(
        code="static_analysis_only",
        description="Only bounded static observations were used; content was not executed.",
    ),
    InferenceLimitation(
        code="bounded_analysis",
        description="Configured upload, extraction, indicator, and concurrency bounds apply.",
    ),
)


class InferenceServiceError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class InferenceUnavailableError(InferenceServiceError):
    pass


class InferenceCapacityError(InferenceServiceError):
    pass


class InferenceCapacity:
    """Small non-queuing admission counter for local inference requests."""

    def __init__(self, maximum: int) -> None:
        if maximum < 1:
            raise ValueError("inference capacity must be positive")
        self.maximum = maximum
        self._active = 0
        self._lock = asyncio.Lock()

    @property
    def active(self) -> int:
        return self._active

    async def try_acquire(self) -> bool:
        async with self._lock:
            if self._active >= self.maximum:
                return False
            self._active += 1
            return True

    async def release(self) -> None:
        async with self._lock:
            if self._active <= 0:
                raise RuntimeError("inference capacity release is unbalanced")
            self._active -= 1


async def infer_upload(
    upload: UploadFile,
    *,
    settings: Settings,
    runtime: TrustedModelRuntime,
    capacity: InferenceCapacity,
) -> MLInferenceResponse:
    if not settings.ML_INFERENCE_ENABLED:
        await upload.close()
        raise InferenceUnavailableError(
            "inference_disabled", "ML inference is disabled"
        )
    try:
        _, descriptor = runtime.require_active()
    except ModelRuntimeError as error:
        await upload.close()
        raise InferenceUnavailableError(error.code, str(error)) from error
    if not await capacity.try_acquire():
        await upload.close()
        raise InferenceCapacityError(
            "inference_capacity_exhausted", "ML inference capacity is exhausted"
        )
    try:
        report = await analyze_static_upload(
            upload,
            max_bytes=settings.MAX_UPLOAD_BYTES,
            minimum_string_length=settings.INSPECTION_MIN_STRING_LENGTH,
            maximum_strings=settings.INSPECTION_MAX_STRINGS,
            maximum_string_length=settings.INSPECTION_MAX_STRING_LENGTH,
            maximum_indicators=settings.INSPECTION_MAX_INDICATORS,
        )
        extraction = FeatureExtractionSettings(
            minimum_string_length=settings.INSPECTION_MIN_STRING_LENGTH,
            maximum_retained_strings=settings.INSPECTION_MAX_STRINGS,
            maximum_characters_per_string=settings.INSPECTION_MAX_STRING_LENGTH,
            maximum_indicators=settings.INSPECTION_MAX_INDICATORS,
        )
        features = extract_ml_features(report, extraction)
        try:
            prediction = await asyncio.to_thread(runtime.predict, features)
        except ModelRuntimeError as error:
            raise InferenceUnavailableError(error.code, str(error)) from error
        return MLInferenceResponse(
            inference_id=uuid4(),
            analysis_id=report.analysis_id,
            inference_mode="synthetic_demo",
            demo_only=True,
            prediction=InferencePrediction(
                label=prediction.label,
                probability_estimates=prediction.probabilities,
                probability_calibrated=False,
            ),
            model=InferenceModelSummary.from_descriptor(descriptor),
            limitations=INFERENCE_LIMITATIONS,
        )
    finally:
        await upload.close()
        await capacity.release()
