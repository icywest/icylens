import json
from datetime import UTC, date, datetime
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.ml.datasets import is_supervised_training_eligible
from app.ml.features import extract_ml_features
from app.ml.validation import validate_dataset
from app.schemas.content_inspection import (
    EntropySummary,
    StaticIndicator,
    StringExtractionSummary,
)
from app.schemas.ml_dataset import (
    DatasetLabel,
    DatasetProvenance,
    FeatureExtractionSettings,
    MLDatasetRecord,
    SampleIdentity,
)
from app.schemas.ml_features import (
    FEATURE_SCHEMA_VERSION,
    PREDICTIVE_FEATURE_ORDER,
    MLFeatureVector,
)
from app.schemas.static_analysis import (
    StaticAnalysisContent,
    StaticAnalysisFingerprint,
    StaticAnalysisResponse,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "ml_dataset_v1.json"
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


def extraction_settings() -> FeatureExtractionSettings:
    return FeatureExtractionSettings(
        minimum_string_length=4,
        maximum_retained_strings=100,
        maximum_characters_per_string=256,
        maximum_indicators=100,
    )


def static_report(
    *,
    detected_format: str = "pdf",
    format_consistency: str = "match",
    indicators: list[StaticIndicator] | None = None,
    strings_truncated: bool = False,
    indicators_truncated: bool = False,
) -> StaticAnalysisResponse:
    return StaticAnalysisResponse.model_validate(
        {
            "analysis_id": "11111111-1111-4111-8111-111111111111",
            "analysis_type": "static",
            "status": "completed",
            "filename": "identity-must-not-be-a-feature.pdf",
            "created_at": datetime(2026, 10, 25, tzinfo=UTC),
            "completed_at": datetime(2026, 10, 25, tzinfo=UTC),
            "fingerprint": StaticAnalysisFingerprint(
                sha256=HASH_A,
                size_bytes=128,
                detected_format=detected_format,
                format_consistency=format_consistency,
            ),
            "content": StaticAnalysisContent(
                entropy=EntropySummary(shannon_entropy=4.25, total_bytes=128),
                strings=StringExtractionSummary(
                    observed_count=7,
                    retained_count=5,
                    truncated=strings_truncated,
                    raw_strings_exposed=False,
                    minimum_length=4,
                    maximum_retained_strings=100,
                    maximum_characters_per_string=256,
                ),
            ),
            "indicators": indicators or [],
            "indicators_truncated": indicators_truncated,
            "analysis_limitations": [],
        }
    )


def feature_vector(**updates: object) -> MLFeatureVector:
    values: dict[str, object] = {
        "file_size_bytes": 128,
        "shannon_entropy": 4.25,
        "printable_string_count": 7,
        "retained_string_count": 5,
        "indicator_count": 0,
        "detected_format": "pdf",
        "format_consistency": "match",
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


def dataset_record(
    *,
    sha256: str = HASH_A,
    record_id: str = "synthetic-001",
    label: str = "benign",
    split: str = "training",
    source_kind: str = "synthetic",
    synthetic_label: bool = True,
    verified_on: date | None = date(2026, 10, 25),
    features: MLFeatureVector | None = None,
) -> MLDatasetRecord:
    return MLDatasetRecord.model_validate(
        {
            "identity": SampleIdentity(sha256=sha256, record_id=record_id),
            "features": features or feature_vector(),
            "label": DatasetLabel(
                value=label,
                source="deterministic test fixture declaration",
                confidence=1.0 if label != "unknown" else None,
                verified_on=verified_on,
                synthetic=synthetic_label,
            ),
            "provenance": DatasetProvenance(
                dataset_id="icylens-safe-synthetic-v1",
                source_kind=source_kind,
                source_description="Locally authored non-executable test data",
                collected_on=date(2026, 10, 25),
                license="Project test fixture",
                usage_restrictions="Testing and education only",
            ),
            "extraction": extraction_settings(),
            "split": split,
        }
    )


@pytest.mark.unit
def test_adapter_extracts_valid_features_from_existing_static_report() -> None:
    features = extract_ml_features(static_report(), extraction_settings())

    assert features.file_size_bytes == 128
    assert features.shannon_entropy == 4.25
    assert features.printable_string_count == 7
    assert features.retained_string_count == 5
    assert features.feature_schema_version == FEATURE_SCHEMA_VERSION


@pytest.mark.unit
def test_indicator_ids_map_to_explicit_boolean_features() -> None:
    ids = (
        "network.url_candidate",
        "network.ipv4_candidate",
        "command.powershell_reference",
        "command.encoded_command_token",
        "file.script_reference",
        "file.executable_reference",
        "future.unmapped_indicator",
    )
    indicators = [
        StaticIndicator(
            id=indicator_id,
            category="network" if indicator_id.startswith("network") else "command",
            description="safe synthetic indicator",
            source="printable_ascii",
        )
        for indicator_id in ids
    ]

    features = extract_ml_features(
        static_report(indicators=indicators), extraction_settings()
    )

    assert features.indicator_count == len(ids)
    assert features.has_url_candidate
    assert features.has_ipv4_candidate
    assert features.has_powershell_reference
    assert features.has_encoded_command_token
    assert features.has_script_reference


@pytest.mark.unit
def test_adapter_preserves_unknown_categories_and_truncation() -> None:
    features = extract_ml_features(
        static_report(
            detected_format="unknown",
            format_consistency="unknown",
            strings_truncated=True,
            indicators_truncated=True,
        ),
        extraction_settings(),
    )

    assert features.detected_format == "unknown"
    assert features.format_consistency == "unknown"
    assert features.strings_truncated is True
    assert features.indicators_truncated is True


@pytest.mark.unit
def test_adapter_rejects_missing_extraction_context_instead_of_guessing() -> None:
    incompatible = extraction_settings().model_copy(update={"minimum_string_length": 5})

    with pytest.raises(ValueError, match="do not match"):
        extract_ml_features(static_report(), incompatible)


@pytest.mark.unit
def test_predictive_order_is_stable_and_excludes_identity_and_lifecycle() -> None:
    features = extract_ml_features(static_report(), extraction_settings())
    ordered = features.ordered_predictive_values()

    assert len(ordered) == len(PREDICTIVE_FEATURE_ORDER) == 14
    assert ordered[0:2] == (128, 4.25)
    assert "sha256" not in PREDICTIVE_FEATURE_ORDER
    assert "analysis_id" not in PREDICTIVE_FEATURE_ORDER
    assert "created_at" not in PREDICTIVE_FEATURE_ORDER
    assert HASH_A not in ordered
    assert UUID("11111111-1111-4111-8111-111111111111") not in ordered


@pytest.mark.unit
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("file_size_bytes", 0),
        ("shannon_entropy", -0.01),
        ("shannon_entropy", 8.01),
        ("shannon_entropy", float("nan")),
        ("printable_string_count", -1),
        ("has_url_candidate", 1),
    ],
)
def test_feature_contract_rejects_invalid_ranges_and_types(
    field: str, value: object
) -> None:
    with pytest.raises(ValidationError):
        feature_vector(**{field: value})


@pytest.mark.unit
def test_feature_contract_rejects_missing_and_unexpected_fields() -> None:
    payload = feature_vector().model_dump()
    del payload["shannon_entropy"]
    payload["label"] = "malicious"

    with pytest.raises(ValidationError) as error:
        MLFeatureVector.model_validate(payload)

    error_types = {item["type"] for item in error.value.errors()}
    assert {"missing", "extra_forbidden"} <= error_types


@pytest.mark.unit
def test_feature_schema_version_is_fixed() -> None:
    with pytest.raises(ValidationError, match="literal_error"):
        feature_vector(feature_schema_version="2.0.0")


@pytest.mark.unit
def test_dataset_record_serialization_round_trip() -> None:
    record = dataset_record()

    restored = MLDatasetRecord.model_validate_json(record.model_dump_json())

    assert restored == record
    assert "filename" not in restored.model_dump_json()


@pytest.mark.unit
def test_unknown_label_is_valid_but_not_supervised_training_eligible() -> None:
    record = dataset_record(label="unknown", synthetic_label=False, verified_on=None)
    report = validate_dataset([record])

    assert report.is_valid
    assert not is_supervised_training_eligible(record)
    assert [warning.code for warning in report.warnings] == ["unknown_label_excluded"]


@pytest.mark.unit
def test_synthetic_label_must_be_explicit_for_training_eligibility() -> None:
    explicit = dataset_record()
    hidden = dataset_record(synthetic_label=False)

    assert is_supervised_training_eligible(explicit)
    assert not is_supervised_training_eligible(hidden)
    assert validate_dataset([hidden]).warnings[0].code == "not_training_eligible"


@pytest.mark.unit
def test_validation_reports_invalid_label_hash_and_unexpected_field() -> None:
    invalid = dataset_record().model_dump(mode="json")
    invalid["identity"]["sha256"] = "not-a-hash"
    invalid["label"]["value"] = "suspicious"
    invalid["features"]["analysis_uuid"] = "forbidden"

    report = validate_dataset([invalid])

    assert not report.is_valid
    assert len(report.invalid_records) == 1
    messages = " ".join(report.invalid_records[0].errors)
    assert "identity.sha256" in messages
    assert "label.value" in messages
    assert "features.analysis_uuid" in messages


@pytest.mark.unit
def test_validation_detects_duplicate_hash_and_record_id() -> None:
    records = [
        dataset_record(),
        dataset_record(record_id="synthetic-001", split="training"),
    ]

    report = validate_dataset(records)

    assert {issue.code for issue in report.dataset_errors} == {
        "duplicate_record_id",
        "duplicate_sha256",
    }


@pytest.mark.unit
def test_validation_detects_conflicting_labels_and_cross_split_overlap() -> None:
    records = [
        dataset_record(split="training", label="benign"),
        dataset_record(
            record_id="synthetic-002",
            split="test",
            label="malicious",
        ),
    ]

    report = validate_dataset(records)
    codes = {issue.code for issue in report.dataset_errors}

    assert {
        "duplicate_sha256",
        "conflicting_labels",
        "cross_split_duplicate",
    } <= codes


@pytest.mark.unit
def test_validation_rejects_unsupported_provenance() -> None:
    record = dataset_record(source_kind="unknown")
    report = validate_dataset([record])

    assert not report.is_valid
    assert report.dataset_errors[0].code == "unsupported_provenance"
    assert not is_supervised_training_eligible(record)


@pytest.mark.unit
def test_validation_warns_about_repeated_synthetic_feature_templates() -> None:
    records = [
        dataset_record(),
        dataset_record(sha256=HASH_B, record_id="synthetic-002"),
    ]

    report = validate_dataset(records)

    assert report.is_valid
    assert "repeated_synthetic_template" in {
        warning.code for warning in report.warnings
    }


@pytest.mark.contract
def test_committed_fixture_is_deterministic_safe_and_valid() -> None:
    payload = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    report = validate_dataset(payload)

    assert report.is_valid
    assert not report.invalid_records
    assert len(report.valid_records) == 3
    assert all(
        record.provenance.source_kind == "synthetic" for record in report.valid_records
    )
    assert {record.identity.sha256 for record in report.valid_records} == {
        HASH_A,
        HASH_B,
        HASH_C,
    }
    assert {record.split for record in report.valid_records} == {"unassigned"}
