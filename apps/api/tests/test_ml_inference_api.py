import asyncio
import json
import math
import pickle
import socket
from collections.abc import Callable
from io import BytesIO
from typing import Any
from uuid import UUID

import joblib
import numpy as np
import pytest
from fastapi import UploadFile
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sklearn.pipeline import Pipeline

from app.api.v1.routes import ml_inferences as inference_route
from app.core.config import Settings
from app.main import create_app
from app.ml.demo import initialize_synthetic_demo
from app.ml.model_runtime import (
    ModelRuntimeError,
    TrustedModelRuntime,
    validate_trusted_pipeline,
)
from app.ml.models import build_model_pipelines
from app.schemas.ml_experiment import TrainingConfiguration
from app.schemas.ml_features import MLFeatureVector
from app.schemas.ml_inference import (
    ActiveModelDescriptor,
    ClassProbabilities,
    MLInferenceResponse,
)
from app.services.ml_inference import InferenceCapacity, infer_upload


@pytest.fixture(scope="module")
def trusted_model() -> tuple[Pipeline, ActiveModelDescriptor]:
    source = TrustedModelRuntime()
    descriptor = initialize_synthetic_demo(source)
    pipeline, _ = source.require_active()
    return pipeline, descriptor


def enabled_settings(**updates: object) -> Settings:
    values: dict[str, object] = {
        "APP_ENV": "testing",
        "ML_INFERENCE_ENABLED": True,
        "ML_DEMO_MODE_ENABLED": True,
        "ML_MAX_CONCURRENT_INFERENCES": 2,
        "_env_file": None,
    }
    values.update(updates)
    return Settings(**values)  # type: ignore[arg-type]


def register_trusted(
    trusted_model: tuple[Pipeline, ActiveModelDescriptor],
) -> Callable[[TrustedModelRuntime], ActiveModelDescriptor]:
    pipeline, descriptor = trusted_model

    def initialize(runtime: TrustedModelRuntime) -> ActiveModelDescriptor:
        return runtime.register(pipeline, descriptor)

    return initialize


@pytest.fixture
def demo_application(trusted_model):
    return create_app(
        enabled_settings(), model_initializer=register_trusted(trusted_model)
    )


@pytest.fixture
def demo_client(demo_application):
    with TestClient(demo_application) as client:
        yield client


def post_inference(
    client: TestClient,
    content: bytes,
    *,
    filename: str = "sample.txt",
):
    return client.post(
        "/api/v1/ml-inferences/",
        files={"file": (filename, content, "application/octet-stream")},
    )


def safe_features(**updates: object) -> MLFeatureVector:
    values: dict[str, object] = {
        "file_size_bytes": 100,
        "shannon_entropy": 2.5,
        "printable_string_count": 2,
        "retained_string_count": 2,
        "indicator_count": 0,
        "detected_format": "unknown",
        "format_consistency": "unknown",
        "has_url_candidate": False,
        "has_ipv4_candidate": False,
        "has_powershell_reference": False,
        "has_encoded_command_token": False,
        "has_script_reference": False,
        "strings_truncated": False,
        "indicators_truncated": False,
    }
    values.update(updates)
    return MLFeatureVector.model_validate(values)


@pytest.mark.unit
def test_inference_is_disabled_and_unregistered_by_default() -> None:
    settings = Settings(APP_ENV="testing", _env_file=None)
    application = create_app(settings)

    assert settings.ML_INFERENCE_ENABLED is False
    assert settings.ML_DEMO_MODE_ENABLED is False
    assert application.state.ml_runtime.status == "unavailable"
    with TestClient(application) as client:
        response = post_inference(client, b"harmless")
        assert application.state.ml_runtime.status == "unavailable"

    assert response.status_code == 503


@pytest.mark.unit
def test_demo_mode_requires_explicit_inference_enablement() -> None:
    with pytest.raises(ValidationError, match="requires ML_INFERENCE_ENABLED"):
        Settings(
            APP_ENV="testing",
            ML_DEMO_MODE_ENABLED=True,
            _env_file=None,
        )


@pytest.mark.integration
def test_initializer_runs_once_at_startup_not_per_request(trusted_model) -> None:
    calls = 0
    base_initializer = register_trusted(trusted_model)

    def initialize(runtime: TrustedModelRuntime) -> ActiveModelDescriptor:
        nonlocal calls
        calls += 1
        return base_initializer(runtime)

    application = create_app(enabled_settings(), model_initializer=initialize)
    assert calls == 0
    with TestClient(application) as client:
        assert calls == 1
        assert post_inference(client, b"first").status_code == 200
        assert post_inference(client, b"second").status_code == 200
        assert calls == 1

    assert application.state.ml_runtime.status == "revoked"


@pytest.mark.integration
def test_enabled_without_demo_has_no_active_model() -> None:
    application = create_app(
        Settings(
            APP_ENV="testing",
            ML_INFERENCE_ENABLED=True,
            ML_DEMO_MODE_ENABLED=False,
            _env_file=None,
        )
    )
    with TestClient(application) as client:
        response = post_inference(client, b"harmless")

    assert response.status_code == 503


@pytest.mark.integration
def test_failed_initialization_leaves_runtime_rejected() -> None:
    def fail(_: TrustedModelRuntime) -> ActiveModelDescriptor:
        raise RuntimeError("private initialization detail")

    application = create_app(enabled_settings(), model_initializer=fail)
    with TestClient(application) as client:
        assert application.state.ml_runtime.status == "rejected"
        response = post_inference(client, b"harmless")

    assert response.status_code == 503
    assert "private" not in response.text


@pytest.mark.unit
def test_valid_fitted_pipeline_registers_and_revokes(trusted_model) -> None:
    pipeline, descriptor = trusted_model
    runtime = TrustedModelRuntime()

    assert runtime.register(pipeline, descriptor) == descriptor
    assert runtime.status == "registered_demo"
    assert runtime.active_descriptor == descriptor
    runtime.revoke()
    assert runtime.status == "revoked"
    assert runtime.lifecycle_history == (
        "unavailable",
        "registered_demo",
        "revoked",
    )
    assert runtime.active_descriptor is None
    with pytest.raises(ModelRuntimeError, match="no trusted"):
        runtime.require_active()


@pytest.mark.unit
def test_demo_initialization_records_training_and_evaluation_lifecycle() -> None:
    runtime = TrustedModelRuntime()

    initialize_synthetic_demo(runtime)

    assert runtime.lifecycle_history == (
        "unavailable",
        "trained",
        "evaluated",
        "registered_demo",
    )


@pytest.mark.unit
def test_unfitted_pipeline_is_rejected(trusted_model) -> None:
    _, descriptor = trusted_model
    unfitted = build_model_pipelines(TrainingConfiguration())["logistic_regression"]
    runtime = TrustedModelRuntime()

    with pytest.raises(ModelRuntimeError) as error:
        runtime.register(unfitted, descriptor)

    assert error.value.code == "model_not_fitted"
    assert runtime.status == "rejected"


@pytest.mark.unit
def test_algorithm_estimator_mismatch_is_rejected(trusted_model) -> None:
    pipeline, descriptor = trusted_model
    incompatible = descriptor.model_copy(update={"algorithm": "random_forest"})

    with pytest.raises(ModelRuntimeError) as error:
        validate_trusted_pipeline(pipeline, incompatible)

    assert error.value.code == "algorithm_mismatch"


@pytest.mark.unit
def test_unsupported_algorithm_is_rejected_by_descriptor(trusted_model) -> None:
    _, descriptor = trusted_model
    payload = descriptor.model_dump()
    payload["algorithm"] = "support_vector_machine"

    with pytest.raises(ValidationError):
        ActiveModelDescriptor.model_validate(payload)


@pytest.mark.unit
def test_feature_schema_mismatch_is_rejected(trusted_model) -> None:
    pipeline, descriptor = trusted_model
    incompatible = descriptor.model_copy(update={"feature_schema_version": "2.0.0"})

    with pytest.raises(ModelRuntimeError) as error:
        validate_trusted_pipeline(pipeline, incompatible)

    assert error.value.code == "feature_schema_mismatch"


@pytest.mark.unit
def test_preprocessing_mismatch_is_rejected(trusted_model) -> None:
    pipeline, descriptor = trusted_model
    preprocessing = descriptor.preprocessing.model_copy(
        update={"transformed_feature_count": 24}
    )
    incompatible = descriptor.model_copy(update={"preprocessing": preprocessing})

    with pytest.raises(ModelRuntimeError) as error:
        validate_trusted_pipeline(pipeline, incompatible)

    assert error.value.code == "preprocessing_mismatch"


@pytest.mark.unit
def test_incorrect_classes_are_rejected(
    trusted_model, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline, descriptor = trusted_model
    model = pipeline.named_steps["model"]
    monkeypatch.setattr(model, "classes_", np.asarray(["benign", "unknown"]))

    with pytest.raises(ModelRuntimeError) as error:
        validate_trusted_pipeline(pipeline, descriptor)

    assert error.value.code == "unsupported_model_classes"


@pytest.mark.unit
def test_unauthorized_descriptor_is_rejected(trusted_model) -> None:
    pipeline, descriptor = trusted_model
    unauthorized = descriptor.model_copy(update={"demonstration_authorized": False})

    with pytest.raises(ModelRuntimeError) as error:
        validate_trusted_pipeline(pipeline, unauthorized)

    assert error.value.code == "demo_not_authorized"


@pytest.mark.unit
def test_prediction_maps_labels_and_probabilities(trusted_model) -> None:
    pipeline, descriptor = trusted_model
    runtime = TrustedModelRuntime()
    runtime.register(pipeline, descriptor)

    result = runtime.predict(safe_features())

    assert result.label in {"benign", "malicious"}
    assert (
        result.probabilities.benign + result.probabilities.malicious == pytest.approx(1)
    )


@pytest.mark.unit
def test_unknown_categories_remain_supported(trusted_model) -> None:
    pipeline, descriptor = trusted_model
    runtime = TrustedModelRuntime()
    runtime.register(pipeline, descriptor)

    result = runtime.predict(
        safe_features(detected_format="unknown", format_consistency="unknown")
    )

    assert math.isfinite(result.probabilities.malicious)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("probabilities", "code"),
    [
        (np.asarray([[0.5]]), "invalid_probability_shape"),
        (np.asarray([[np.nan, np.nan]]), "non_finite_probability"),
        (np.asarray([[-0.1, 1.1]]), "probability_out_of_range"),
        (np.asarray([[0.2, 0.2]]), "invalid_probability_sum"),
        (np.asarray([[0.1, 0.9]]), "probability_class_mismatch"),
    ],
)
def test_invalid_probability_output_is_rejected(
    trusted_model,
    monkeypatch: pytest.MonkeyPatch,
    probabilities: np.ndarray,
    code: str,
) -> None:
    pipeline, descriptor = trusted_model
    runtime = TrustedModelRuntime()
    runtime.register(pipeline, descriptor)
    monkeypatch.setattr(pipeline, "predict_proba", lambda _: probabilities)
    if code == "probability_class_mismatch":
        monkeypatch.setattr(pipeline, "predict", lambda _: np.asarray(["benign"]))

    with pytest.raises(ModelRuntimeError) as error:
        runtime.predict(safe_features())

    assert error.value.code == code


@pytest.mark.unit
def test_probability_contract_rejects_nonfinite_and_invalid_sum() -> None:
    with pytest.raises(ValidationError):
        ClassProbabilities(benign=float("nan"), malicious=float("nan"))
    with pytest.raises(ValidationError, match="sum to one"):
        ClassProbabilities(benign=0.2, malicious=0.2)


@pytest.mark.contract
def test_success_response_is_demo_only_and_strict(demo_client: TestClient) -> None:
    response = post_inference(demo_client, b"harmless educational text")
    body = response.json()

    assert response.status_code == 200
    assert UUID(body["inference_id"])
    assert UUID(body["analysis_id"])
    assert body["inference_mode"] == "synthetic_demo"
    assert body["demo_only"] is True
    assert body["prediction"]["probability_calibrated"] is False
    assert body["prediction"]["interpretation"] == "model_output_not_security_verdict"
    assert body["model"]["dataset_provenance_type"] == "synthetic"
    assert body["model"]["model_selection_status"] == "not_selected"
    assert body["model"]["operational_detection_approved"] is False
    assert {item["code"] for item in body["limitations"]} == {
        "synthetic_model_only",
        "not_security_verdict",
        "probability_not_calibrated",
        "static_analysis_only",
        "bounded_analysis",
    }
    assert "safe" not in json.dumps(body).lower()
    assert "risk_score" not in body


@pytest.mark.integration
def test_same_content_is_reproducible_across_filenames(demo_client: TestClient) -> None:
    content = b"same harmless educational bytes"
    first = post_inference(demo_client, content, filename="one.txt").json()
    second = post_inference(demo_client, content, filename="two.txt").json()

    assert first["inference_id"] != second["inference_id"]
    assert first["analysis_id"] != second["analysis_id"]
    assert first["prediction"] == second["prediction"]
    assert first["model"] == second["model"]


class SegmentedBytesIO(BytesIO):
    def __init__(self, content: bytes, segment_size: int) -> None:
        super().__init__(content)
        self.segment_size = segment_size
        self.bytes_returned = 0

    def read(self, size: int = -1) -> bytes:
        value = super().read(min(size, self.segment_size))
        self.bytes_returned += len(value)
        return value


@pytest.mark.security
def test_chunk_segmentation_is_reproducible_and_single_pass(trusted_model) -> None:
    content = b"A harmless string split across several input chunks"
    settings = enabled_settings()
    runtime = TrustedModelRuntime()
    runtime.register(*trusted_model)

    async def run(segment_size: int) -> tuple[MLInferenceResponse, SegmentedBytesIO]:
        stream = SegmentedBytesIO(content, segment_size)
        upload = UploadFile(file=stream, filename="sample.txt")
        response = await infer_upload(
            upload,
            settings=settings,
            runtime=runtime,
            capacity=InferenceCapacity(1),
        )
        return response, stream

    first, first_stream = asyncio.run(run(3))
    second, second_stream = asyncio.run(run(64 * 1024))

    assert first.prediction == second.prediction
    assert first.model == second.model
    assert first_stream.bytes_returned == len(content)
    assert second_stream.bytes_returned == len(content)
    assert first_stream.closed and second_stream.closed


@pytest.mark.security
@pytest.mark.parametrize(
    ("content", "filename", "status_code"),
    [
        (b"", "empty.txt", 422),
        (b"data", "../unsafe.txt", 422),
    ],
)
def test_invalid_uploads_are_rejected(
    demo_client: TestClient,
    content: bytes,
    filename: str,
    status_code: int,
) -> None:
    assert (
        post_inference(demo_client, content, filename=filename).status_code
        == status_code
    )


@pytest.mark.security
def test_oversized_upload_is_413(trusted_model) -> None:
    application = create_app(
        enabled_settings(MAX_UPLOAD_BYTES=8),
        model_initializer=register_trusted(trusted_model),
    )
    with TestClient(application) as client:
        exact = post_inference(client, b"12345678")
        oversized = post_inference(client, b"123456789")

    assert exact.status_code == 200
    assert oversized.status_code == 413


@pytest.mark.security
def test_missing_and_malformed_multipart_are_4xx(demo_client: TestClient) -> None:
    assert demo_client.post("/api/v1/ml-inferences/").status_code == 422
    malformed = demo_client.post(
        "/api/v1/ml-inferences/",
        content=b"not multipart",
        headers={"content-type": "multipart/form-data"},
    )
    assert 400 <= malformed.status_code < 500


@pytest.mark.security
def test_capacity_exhaustion_is_immediate_429(
    demo_client: TestClient, demo_application, monkeypatch: pytest.MonkeyPatch
) -> None:
    capacity = demo_application.state.ml_inference_capacity

    async def reject() -> bool:
        return False

    monkeypatch.setattr(capacity, "try_acquire", reject)
    response = post_inference(demo_client, b"harmless")

    assert response.status_code == 429
    assert response.json() == {"detail": "ML inference capacity is exhausted."}


@pytest.mark.security
def test_unexpected_error_is_generic_and_content_free(
    demo_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    logged: list[tuple[str, str]] = []

    async def fail(*args: object, **kwargs: object) -> MLInferenceResponse:
        del args, kwargs
        raise RuntimeError("sensitive inference context")

    def record(message: str, exception_type: str) -> None:
        logged.append((message, exception_type))

    monkeypatch.setattr(inference_route, "infer_upload", fail)
    monkeypatch.setattr(inference_route.logger, "error", record)
    response = post_inference(demo_client, b"private sample content")

    assert response.status_code == 500
    assert response.json() == {"detail": "ML inference could not be completed."}
    assert "sensitive" not in response.text
    assert "private" not in response.text
    assert logged == [("ML inference failed with exception type %s", "RuntimeError")]


@pytest.mark.security
def test_request_never_trains_loads_models_or_uses_network(
    demo_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> Any:
        del args, kwargs
        raise AssertionError("forbidden request-time operation")

    monkeypatch.setattr(joblib, "load", forbidden)
    monkeypatch.setattr(pickle, "load", forbidden)
    monkeypatch.setattr("app.ml.training.train_experiment", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)

    response = post_inference(demo_client, b"harmless local bytes")

    assert response.status_code == 200


@pytest.mark.security
def test_endpoint_has_no_model_path_or_candidate_parameter(
    demo_client: TestClient,
) -> None:
    schema = demo_client.get("/openapi.json").json()
    operation = schema["paths"]["/api/v1/ml-inferences/"]["post"]
    serialized = json.dumps(operation)

    assert "model_path" not in serialized
    assert "artifact" not in serialized
    assert "candidate" not in serialized
    assert "multipart/form-data" in operation["requestBody"]["content"]


@pytest.mark.contract
def test_openapi_and_existing_endpoints_are_preserved(demo_client: TestClient) -> None:
    schema = demo_client.get("/openapi.json").json()
    operation = schema["paths"]["/api/v1/ml-inferences/"]["post"]

    assert operation["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/MLInferenceResponse"
    }
    assert {"413", "422", "429", "500", "503"} <= set(operation["responses"])
    assert demo_client.get("/api/v1/health/").status_code == 200
    assert (
        demo_client.post(
            "/api/v1/static-analyses/",
            files={"file": ("sample.txt", b"data")},
        ).status_code
        == 200
    )


@pytest.mark.unit
def test_response_schema_forbids_extra_fields(demo_client: TestClient) -> None:
    payload = post_inference(demo_client, b"harmless").json()
    payload["model_path"] = "untrusted.joblib"

    with pytest.raises(ValidationError, match="extra_forbidden"):
        MLInferenceResponse.model_validate(payload)


@pytest.mark.unit
def test_capacity_counter_is_bounded_and_balanced() -> None:
    capacity = InferenceCapacity(1)

    async def exercise() -> None:
        assert await capacity.try_acquire() is True
        assert await capacity.try_acquire() is False
        assert capacity.active == 1
        await capacity.release()
        assert capacity.active == 0
        with pytest.raises(RuntimeError, match="unbalanced"):
            await capacity.release()

    asyncio.run(exercise())
