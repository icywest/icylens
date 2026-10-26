import hashlib
from datetime import UTC, date, datetime

from app.ml.builder import build_dataset
from app.ml.model_runtime import TrustedModelRuntime
from app.ml.training import train_experiment
from app.schemas.ml_dataset import (
    DatasetLabel,
    DatasetProvenance,
    FeatureExtractionSettings,
    MLDatasetRecord,
    SampleIdentity,
)
from app.schemas.ml_experiment import TrainingConfiguration
from app.schemas.ml_features import MLFeatureVector
from app.schemas.ml_inference import ActiveModelDescriptor

DEMO_DATASET_ID = "builtin-synthetic-inference-demo"
DEMO_DATASET_VERSION = "1.0.0"
DEMO_EXPERIMENT_ID = "builtin-synthetic-inference-demo-v1"
DEMO_MODEL_ID = "builtin-synthetic-logistic-demo-v1"
DEMO_CREATED_AT = datetime(2026, 10, 25, tzinfo=UTC)


def _demo_record(label: str, index: int) -> MLDatasetRecord:
    malicious = label == "malicious"
    identity_text = f"icylens-demo-{label}-{index}"
    return MLDatasetRecord(
        identity=SampleIdentity(
            sha256=hashlib.sha256(identity_text.encode()).hexdigest(),
            record_id=identity_text,
        ),
        features=MLFeatureVector(
            file_size_bytes=(100_000 + index if malicious else 1_000 + index),
            shannon_entropy=(7.0 + index / 1000 if malicious else 2.0 + index / 1000),
            printable_string_count=(10 + index if malicious else 100 + index),
            retained_string_count=(5 + index if malicious else 50 + index),
            indicator_count=(3 + index % 3 if malicious else index % 2),
            detected_format="unknown" if malicious else "pdf",
            format_consistency="mismatch" if malicious else "match",
            has_url_candidate=malicious,
            has_ipv4_candidate=malicious and index % 2 == 0,
            has_powershell_reference=malicious,
            has_encoded_command_token=malicious and index % 3 == 0,
            has_script_reference=malicious,
            strings_truncated=malicious and index % 4 == 0,
            indicators_truncated=False,
        ),
        label=DatasetLabel(
            value=label,
            source="built-in synthetic educational demonstration",
            confidence=1.0,
            verified_on=date(2026, 10, 25),
            synthetic=True,
        ),
        provenance=DatasetProvenance(
            dataset_id=DEMO_DATASET_ID,
            source_kind="synthetic",
            source_description="Deterministic metadata-only local demonstration",
            collected_on=date(2026, 10, 25),
            license="CC0-1.0",
            usage_restrictions="Educational local demonstration only",
        ),
        extraction=FeatureExtractionSettings(
            minimum_string_length=4,
            maximum_retained_strings=100,
            maximum_characters_per_string=256,
            maximum_indicators=100,
        ),
    )


def build_demo_records() -> tuple[MLDatasetRecord, ...]:
    return tuple(
        _demo_record(label, index)
        for label in ("benign", "malicious")
        for index in range(20)
    )


def initialize_synthetic_demo(runtime: TrustedModelRuntime) -> ActiveModelDescriptor:
    dataset = build_dataset(
        build_demo_records(),
        dataset_id=DEMO_DATASET_ID,
        dataset_version=DEMO_DATASET_VERSION,
        created_at=DEMO_CREATED_AT,
    )
    trained = train_experiment(
        dataset.manifest,
        dataset.records,
        experiment_id=DEMO_EXPERIMENT_ID,
        configuration=TrainingConfiguration(),
        created_at=DEMO_CREATED_AT,
    )
    runtime.mark_trained()
    runtime.mark_evaluated()
    descriptor = ActiveModelDescriptor(
        model_id=DEMO_MODEL_ID,
        algorithm="logistic_regression",
        experiment_id=trained.report.experiment_id,
        feature_schema_version=trained.report.feature_schema_version,
        preprocessing=trained.report.preprocessing,
        dataset_id=trained.report.dataset_id,
        dataset_integrity_digest=trained.report.dataset_integrity_digest,
        dataset_provenance_type="synthetic",
        evaluation_status="synthetic_validation_only",
        synthetic_data=True,
        demonstration_authorized=True,
        initialization_status="ready",
        lifecycle_status="registered_demo",
        operational_detection_approved=False,
    )
    return runtime.register(trained.pipelines["logistic_regression"], descriptor)
