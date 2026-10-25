import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.ml.artifacts import (
    DatasetArtifactError,
    export_dataset_artifact,
    load_and_verify_artifact,
)
from app.ml.builder import (
    DatasetBuildError,
    assess_dataset,
    build_dataset,
    verify_dataset_integrity,
)
from app.ml.importing import (
    DatasetImportError,
    DatasetImportLimits,
    load_dataset_records,
)
from app.ml.splitting import SplitPlanningError, plan_splits
from app.schemas.ml_dataset import MLDatasetRecord
from app.schemas.ml_manifest import SplitConfiguration
from scripts.dataset_cli import main as cli_main

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "ml_dataset_v1.json"
CREATED_AT = datetime(2026, 10, 25, 18, tzinfo=UTC)


def record_payload(
    number: int,
    *,
    label: str = "benign",
    split: str = "unassigned",
    source_kind: str = "owned",
    dataset_id: str = "authorized-local-source",
    synthetic: bool = False,
    verified_on: str | None = "2026-10-25",
) -> dict[str, object]:
    sha256 = f"{number:064x}"
    return {
        "identity": {"sha256": sha256, "record_id": f"record-{number:04d}"},
        "features": {
            "file_size_bytes": 100 + number,
            "shannon_entropy": 4.0 + (number % 10) / 10,
            "printable_string_count": number % 8,
            "retained_string_count": number % 8,
            "indicator_count": number % 3,
            "detected_format": "unknown",
            "format_consistency": "unknown",
            "has_url_candidate": False,
            "has_ipv4_candidate": False,
            "has_powershell_reference": False,
            "has_encoded_command_token": False,
            "has_script_reference": False,
            "strings_truncated": False,
            "indicators_truncated": False,
            "feature_schema_version": "1.0.0",
        },
        "label": {
            "value": label,
            "source": "authorized deterministic test declaration",
            "confidence": None if label == "unknown" else 1.0,
            "verified_on": verified_on,
            "synthetic": synthetic,
        },
        "provenance": {
            "dataset_id": dataset_id,
            "source_kind": source_kind,
            "source_description": "Safe local metadata-only fixture",
            "collected_on": "2026-10-25",
            "license": "Test-only authorization",
            "usage_restrictions": "Automated tests only",
        },
        "extraction": {
            "extractor_version": "static-analysis-adapter/1.0.0",
            "feature_schema_version": "1.0.0",
            "minimum_string_length": 4,
            "maximum_retained_strings": 100,
            "maximum_characters_per_string": 256,
            "maximum_indicators": 100,
        },
        "split": split,
    }


def eligible_records(per_label: int = 20) -> list[MLDatasetRecord]:
    return [
        MLDatasetRecord.model_validate(record_payload(number, label=label))
        for label, start in (("benign", 1), ("malicious", 10_001))
        for number in range(start, start + per_label)
    ]


def write_bytes(path: Path, content: bytes) -> Path:
    path.write_bytes(content)
    return path


@pytest.mark.unit
def test_imports_existing_json_fixture() -> None:
    records = load_dataset_records(FIXTURE_PATH)

    assert len(records) == 3
    assert records[0]["identity"]["record_id"] == "synthetic-001"


@pytest.mark.unit
def test_imports_bounded_jsonl(tmp_path: Path) -> None:
    payloads = [record_payload(1), record_payload(2)]
    path = tmp_path / "records.jsonl"
    path.write_text(
        "".join(json.dumps(payload) + "\n" for payload in payloads),
        encoding="utf-8",
    )

    assert load_dataset_records(path) == tuple(payloads)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("name", "content", "code"),
    [
        ("empty.json", b"", "empty_input"),
        ("broken.json", b"[{", "invalid_json"),
        ("invalid.json", b"\xff", "invalid_utf8"),
        ("object.json", b"{}", "invalid_top_level"),
        ("empty-list.json", b"[]", "empty_dataset"),
        ("records.csv", b"value", "unsupported_format"),
        ("blank.jsonl", b"\n", "blank_line"),
        ("scalar.jsonl", b"1\n", "invalid_record_type"),
    ],
)
def test_import_rejects_malformed_inputs(
    tmp_path: Path, name: str, content: bytes, code: str
) -> None:
    path = write_bytes(tmp_path / name, content)

    with pytest.raises(DatasetImportError) as error:
        load_dataset_records(path)

    assert error.value.code == code


@pytest.mark.unit
def test_import_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(DatasetImportError) as error:
        load_dataset_records(tmp_path / "missing.json")

    assert error.value.code == "input_unreadable"


@pytest.mark.unit
def test_import_enforces_input_record_and_line_limits(tmp_path: Path) -> None:
    json_path = write_bytes(tmp_path / "records.json", b"[{},{}]")
    jsonl_path = write_bytes(tmp_path / "records.jsonl", b'{"value":"long"}\n')

    with pytest.raises(DatasetImportError) as byte_error:
        load_dataset_records(
            json_path,
            DatasetImportLimits(maximum_input_bytes=2),
        )
    with pytest.raises(DatasetImportError) as record_error:
        load_dataset_records(
            json_path,
            DatasetImportLimits(maximum_records=1),
        )
    with pytest.raises(DatasetImportError) as line_error:
        load_dataset_records(
            jsonl_path,
            DatasetImportLimits(maximum_jsonl_line_bytes=5),
        )

    assert byte_error.value.code == "input_too_large"
    assert record_error.value.code == "too_many_records"
    assert line_error.value.code == "line_too_large"


@pytest.mark.unit
def test_import_limits_must_be_positive() -> None:
    with pytest.raises(ValueError, match="positive"):
        DatasetImportLimits(maximum_records=0)


@pytest.mark.unit
def test_assessment_accepts_unique_eligible_records() -> None:
    assessment = assess_dataset(eligible_records(3))

    assert assessment.report.ready_for_splitting
    assert assessment.report.accepted_count == 6
    assert assessment.report.rejected_count == 0
    assert not assessment.report.errors


@pytest.mark.unit
def test_assessment_excludes_unknown_label_without_relabeling() -> None:
    unknown = record_payload(999_999, label="unknown", verified_on=None)
    valid = eligible_records(3)

    assessment = assess_dataset([*valid, unknown])

    assert assessment.report.ready_for_splitting
    assert assessment.report.rejected_count == 1
    assert assessment.report.exclusions[0].code == "unknown_label_excluded"
    assert all(
        record.label.value != "unknown" for record in assessment.accepted_records
    )


@pytest.mark.unit
def test_assessment_fails_unsupported_provenance() -> None:
    candidate = record_payload(1, source_kind="unknown")
    assessment = assess_dataset([candidate])

    assert not assessment.report.ready_for_splitting
    assert "unsupported_provenance" in {
        issue.code for issue in assessment.report.errors
    }


@pytest.mark.unit
def test_assessment_reports_structural_failure_and_unexpected_fields() -> None:
    candidate = record_payload(1)
    candidate["unexpected"] = True

    assessment = assess_dataset([candidate])

    assert not assessment.report.ready_for_splitting
    assert assessment.report.structurally_valid_count == 0
    assert assessment.report.exclusions[0].code == "invalid_record"
    assert "Extra inputs" in assessment.report.exclusions[0].message


@pytest.mark.unit
@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("missing_provenance", "missing_provenance"),
        ("unsupported_version", "unsupported_feature_schema_version"),
        ("invalid_label", "invalid_label"),
    ],
)
def test_assessment_categorizes_schema_failures(
    mutation: str, expected_code: str
) -> None:
    candidate = record_payload(1)
    if mutation == "missing_provenance":
        del candidate["provenance"]
    elif mutation == "unsupported_version":
        candidate["features"]["feature_schema_version"] = "2.0.0"
    else:
        candidate["label"]["value"] = "suspicious"

    assessment = assess_dataset([candidate])

    assert assessment.report.exclusions[0].code == expected_code


@pytest.mark.unit
def test_exact_duplicate_selection_is_order_invariant() -> None:
    first = record_payload(1)
    second = copy.deepcopy(first)
    second["identity"]["record_id"] = "aaa-canonical"

    forward = assess_dataset([first, second])
    reverse = assess_dataset([second, first])

    assert forward.accepted_records[0].identity.record_id == "aaa-canonical"
    assert reverse.accepted_records[0].identity.record_id == "aaa-canonical"
    assert forward.report.duplicate_hashes == reverse.report.duplicate_hashes
    assert forward.report.warnings[0].code == "exact_duplicate_excluded"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("label", "conflicting_labels"),
        ("label_metadata", "conflicting_label_metadata"),
        ("provenance", "conflicting_provenance"),
        ("features", "conflicting_record_content"),
        ("split", "cross_split_duplicate"),
    ],
)
def test_hash_conflicts_are_fatal(mutation: str, expected_code: str) -> None:
    first = record_payload(1, split="training" if mutation == "split" else "unassigned")
    second = copy.deepcopy(first)
    second["identity"]["record_id"] = "second"
    if mutation == "label":
        second["label"]["value"] = "malicious"
    elif mutation == "label_metadata":
        second["label"]["source"] = "different label authority"
    elif mutation == "provenance":
        second["provenance"]["dataset_id"] = "different-source"
    elif mutation == "features":
        second["features"]["file_size_bytes"] = 999
    else:
        second["split"] = "test"

    assessment = assess_dataset([second, first])

    assert not assessment.report.ready_for_splitting
    assert expected_code in {issue.code for issue in assessment.report.errors}
    assert not assessment.accepted_records


@pytest.mark.unit
def test_exact_duplicate_preserves_existing_assignment() -> None:
    unassigned = record_payload(1)
    assigned = copy.deepcopy(unassigned)
    assigned["identity"]["record_id"] = "z-assigned"
    assigned["split"] = "test"

    assessment = assess_dataset([unassigned, assigned])

    assert assessment.report.ready_for_splitting
    assert assessment.accepted_records[0].identity.record_id == "z-assigned"
    assert assessment.accepted_records[0].split == "test"


@pytest.mark.unit
def test_duplicate_record_id_for_different_hashes_is_fatal() -> None:
    first = record_payload(1)
    second = record_payload(2)
    second["identity"]["record_id"] = first["identity"]["record_id"]

    assessment = assess_dataset([first, second])

    assert "duplicate_record_id" in {issue.code for issue in assessment.report.errors}


@pytest.mark.unit
def test_split_is_seeded_and_input_order_invariant() -> None:
    records = eligible_records()
    configuration = SplitConfiguration(random_seed=90210)

    forward = plan_splits(records, configuration)
    reverse = plan_splits(list(reversed(records)), configuration)

    forward_map = {record.identity.sha256: record.split for record in forward.records}
    reverse_map = {record.identity.sha256: record.split for record in reverse.records}
    assert forward_map == reverse_map
    assert forward.split_counts == {"training": 28, "validation": 6, "test": 6}
    assert forward.label_split_counts == {
        "benign": {"training": 14, "validation": 3, "test": 3},
        "malicious": {"training": 14, "validation": 3, "test": 3},
    }


@pytest.mark.unit
def test_different_seed_changes_assignments_not_counts() -> None:
    records = eligible_records()

    first = plan_splits(records, SplitConfiguration(random_seed=1))
    second = plan_splits(records, SplitConfiguration(random_seed=2))

    assert first.split_counts == second.split_counts
    assert [record.split for record in first.records] != [
        record.split for record in second.records
    ]


@pytest.mark.unit
def test_split_partitions_are_exclusive_and_preserve_hashes() -> None:
    records = eligible_records()
    plan = plan_splits(records, SplitConfiguration())
    grouped = {
        split: {
            record.identity.sha256 for record in plan.records if record.split == split
        }
        for split in ("training", "validation", "test")
    }

    assert grouped["training"].isdisjoint(grouped["validation"])
    assert grouped["training"].isdisjoint(grouped["test"])
    assert grouped["validation"].isdisjoint(grouped["test"])
    assert set.union(*grouped.values()) == {
        record.identity.sha256 for record in records
    }


@pytest.mark.unit
def test_split_respects_existing_assignment() -> None:
    records = eligible_records()
    locked = records[0].model_copy(update={"split": "test"})
    records[0] = locked

    plan = plan_splits(records, SplitConfiguration())

    assigned = {record.identity.sha256: record.split for record in plan.records}
    assert assigned[locked.identity.sha256] == "test"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("records", "code"),
    [
        ([], "empty_eligible_dataset"),
        (eligible_records(2), "infeasible_stratification"),
        (eligible_records(3)[:3], "single_class_dataset"),
    ],
)
def test_split_rejects_empty_tiny_and_single_class(
    records: list[MLDatasetRecord], code: str
) -> None:
    with pytest.raises(SplitPlanningError) as error:
        plan_splits(records, SplitConfiguration())

    assert error.value.code == code


@pytest.mark.unit
def test_split_rejects_unknown_labels_and_duplicates() -> None:
    unknown = MLDatasetRecord.model_validate(
        record_payload(1, label="unknown", verified_on=None)
    )
    duplicate = eligible_records(3)
    duplicate.append(duplicate[0])

    with pytest.raises(SplitPlanningError) as unknown_error:
        plan_splits([unknown], SplitConfiguration())
    with pytest.raises(SplitPlanningError) as duplicate_error:
        plan_splits(duplicate, SplitConfiguration())

    assert unknown_error.value.code == "unknown_label"
    assert duplicate_error.value.code == "duplicate_sha256"


@pytest.mark.unit
def test_infeasible_existing_assignments_are_rejected() -> None:
    records = eligible_records(3)
    for index in range(3):
        records[index] = records[index].model_copy(update={"split": "training"})

    with pytest.raises(SplitPlanningError) as error:
        plan_splits(records, SplitConfiguration())

    assert error.value.code == "infeasible_existing_assignments"


@pytest.mark.unit
def test_invalid_split_fractions_are_rejected() -> None:
    with pytest.raises(ValidationError, match="sum to 1.0"):
        SplitConfiguration(
            training_fraction=0.8,
            validation_fraction=0.15,
            test_fraction=0.15,
        )


@pytest.mark.unit
def test_manifest_digest_is_stable_across_input_order_and_creation_time() -> None:
    records = eligible_records()
    first = build_dataset(
        records,
        dataset_id="safe-dataset",
        dataset_version="1.0.0",
        created_at=CREATED_AT,
    )
    second = build_dataset(
        list(reversed(records)),
        dataset_id="safe-dataset",
        dataset_version="1.0.0",
        created_at=datetime(2026, 10, 25, 19, tzinfo=UTC),
    )

    assert first.manifest.content_integrity_digest == (
        second.manifest.content_integrity_digest
    )
    assert first.manifest.created_at != second.manifest.created_at
    assert verify_dataset_integrity(first.manifest, first.records)
    assert first.manifest.record_count == 40
    assert first.manifest.label_counts == {"benign": 20, "malicious": 20}


@pytest.mark.unit
def test_integrity_rejects_corrupted_record_or_count() -> None:
    result = build_dataset(
        eligible_records(),
        dataset_id="safe-dataset",
        dataset_version="1.0.0",
        created_at=CREATED_AT,
    )
    corrupted = list(result.records)
    corrupted[0] = corrupted[0].model_copy(
        update={
            "features": corrupted[0].features.model_copy(
                update={"file_size_bytes": 9999}
            )
        }
    )

    assert not verify_dataset_integrity(result.manifest, corrupted)
    assert not verify_dataset_integrity(result.manifest, result.records[:-1])


@pytest.mark.unit
def test_builder_rejects_infeasible_and_fatal_datasets() -> None:
    with pytest.raises(DatasetBuildError) as tiny:
        build_dataset(
            eligible_records(2),
            dataset_id="tiny",
            dataset_version="1",
        )
    invalid = record_payload(1)
    invalid["unexpected"] = True
    with pytest.raises(DatasetBuildError) as malformed:
        build_dataset([invalid], dataset_id="invalid", dataset_version="1")

    assert tiny.value.code == "infeasible_stratification"
    assert malformed.value.code == "dataset_not_ready"
    assert malformed.value.report.exclusions


@pytest.mark.security
def test_dataset_identifiers_prevent_path_traversal() -> None:
    with pytest.raises(ValidationError):
        build_dataset(
            eligible_records(),
            dataset_id="../escape",
            dataset_version="1",
            created_at=CREATED_AT,
        )


@pytest.mark.integration
def test_artifact_round_trip_and_deterministic_serialization(tmp_path: Path) -> None:
    result = build_dataset(
        eligible_records(),
        dataset_id="safe-dataset",
        dataset_version="1.0.0",
        created_at=CREATED_AT,
    )
    first = export_dataset_artifact(result, tmp_path / "one")
    second = export_dataset_artifact(result, tmp_path / "two")

    manifest, records = load_and_verify_artifact(first)
    assert manifest == result.manifest
    assert records == result.records
    for name in ("records.jsonl", "manifest.json", "validation_report.json"):
        assert (first / name).read_bytes() == (second / name).read_bytes()


@pytest.mark.security
def test_export_never_overwrites_existing_artifact(tmp_path: Path) -> None:
    result = build_dataset(
        eligible_records(),
        dataset_id="safe-dataset",
        dataset_version="1",
        created_at=CREATED_AT,
    )
    export_dataset_artifact(result, tmp_path)

    with pytest.raises(DatasetArtifactError) as error:
        export_dataset_artifact(result, tmp_path)

    assert error.value.code == "artifact_exists"


@pytest.mark.security
def test_export_rejects_symlinked_dataset_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = build_dataset(
        eligible_records(),
        dataset_id="safe-dataset",
        dataset_version="1",
        created_at=CREATED_AT,
    )
    dataset_root = tmp_path / "safe-dataset"
    dataset_root.mkdir()
    original = Path.is_symlink

    def report_dataset_symlink(self: Path) -> bool:
        return self == dataset_root or original(self)

    monkeypatch.setattr(Path, "is_symlink", report_dataset_symlink)

    with pytest.raises(DatasetArtifactError) as error:
        export_dataset_artifact(result, tmp_path)

    assert error.value.code == "unsafe_output_path"


@pytest.mark.security
def test_export_cleans_staging_directory_after_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = build_dataset(
        eligible_records(),
        dataset_id="safe-dataset",
        dataset_version="1",
        created_at=CREATED_AT,
    )
    original = Path.write_text

    def fail_manifest(self: Path, data: str, **kwargs: object) -> int:
        if self.name == "manifest.json":
            raise OSError("synthetic write failure")
        return original(self, data, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_manifest)
    with pytest.raises(OSError, match="synthetic write failure"):
        export_dataset_artifact(result, tmp_path)

    dataset_root = tmp_path / "safe-dataset"
    assert not (dataset_root / "1").exists()
    assert list(dataset_root.glob(".building-*")) == []


@pytest.mark.security
def test_artifact_verification_detects_tampering(tmp_path: Path) -> None:
    result = build_dataset(
        eligible_records(),
        dataset_id="safe-dataset",
        dataset_version="1",
        created_at=CREATED_AT,
    )
    artifact = export_dataset_artifact(result, tmp_path)
    path = artifact / "records.jsonl"
    content = path.read_text(encoding="utf-8")
    path.write_text(
        content.replace('"file_size_bytes":101', '"file_size_bytes":999'),
        encoding="utf-8",
    )

    with pytest.raises(DatasetArtifactError) as error:
        load_and_verify_artifact(artifact)

    assert error.value.code == "integrity_mismatch"


@pytest.mark.security
def test_artifact_verification_detects_manifest_count_tampering(
    tmp_path: Path,
) -> None:
    result = build_dataset(
        eligible_records(),
        dataset_id="safe-dataset",
        dataset_version="1",
        created_at=CREATED_AT,
    )
    artifact = export_dataset_artifact(result, tmp_path)
    path = artifact / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["label_counts"]["benign"] += 1
    path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(DatasetArtifactError) as error:
        load_and_verify_artifact(artifact)

    assert error.value.code == "invalid_manifest"


@pytest.mark.security
def test_artifact_verification_detects_validation_report_tampering(
    tmp_path: Path,
) -> None:
    result = build_dataset(
        eligible_records(),
        dataset_id="safe-dataset",
        dataset_version="1",
        created_at=CREATED_AT,
    )
    artifact = export_dataset_artifact(result, tmp_path)
    path = artifact / "validation_report.json"
    report = json.loads(path.read_text(encoding="utf-8"))
    report["input_count"] += 1
    path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(DatasetArtifactError) as error:
        load_and_verify_artifact(artifact)

    assert error.value.code == "validation_summary_mismatch"


@pytest.mark.security
def test_artifact_verification_rejects_invalid_manifest_and_missing_files(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing"
    missing.mkdir()
    with pytest.raises(DatasetArtifactError) as missing_error:
        load_and_verify_artifact(missing)
    assert missing_error.value.code == "manifest_unreadable"

    (missing / "manifest.json").write_text("{}", encoding="utf-8")
    with pytest.raises(DatasetArtifactError) as invalid_error:
        load_and_verify_artifact(missing)
    assert invalid_error.value.code == "invalid_manifest"


@pytest.mark.contract
def test_manifest_contains_no_raw_content_or_secret_fields() -> None:
    result = build_dataset(
        eligible_records(),
        dataset_id="safe-dataset",
        dataset_version="1",
        created_at=CREATED_AT,
    )
    serialized = result.manifest.model_dump_json().lower()

    assert "raw_content" not in serialized
    assert "password" not in serialized
    assert "api_key" not in serialized
    assert result.manifest.feature_schema_version == "1.0.0"
    assert result.manifest.builder_version == "dataset-builder/1.0.0"
    assert result.manifest.validation_summary.ready_for_training


@pytest.mark.integration
def test_cli_validate_is_read_only_and_checks_split_feasibility(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    valid_path = tmp_path / "valid.json"
    valid_path.write_text(
        json.dumps([record.model_dump(mode="json") for record in eligible_records(3)]),
        encoding="utf-8",
    )

    assert cli_main(["validate", str(valid_path)]) == 0
    valid_output = json.loads(capsys.readouterr().out)
    assert valid_output["split_counts"] == {
        "test": 2,
        "training": 2,
        "validation": 2,
    }
    assert sorted(tmp_path.iterdir()) == [valid_path]

    assert cli_main(["validate", str(FIXTURE_PATH)]) == 2
    fixture_output = json.loads(capsys.readouterr().out)
    assert fixture_output["split_error"]["code"] == "infeasible_stratification"


@pytest.mark.integration
def test_cli_build_inspect_and_non_overwrite(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    input_path = tmp_path / "records.json"
    input_path.write_text(
        json.dumps([record.model_dump(mode="json") for record in eligible_records(3)]),
        encoding="utf-8",
    )
    output = tmp_path / "generated"
    arguments = [
        "build",
        str(input_path),
        str(output),
        "--dataset-id",
        "cli-dataset",
        "--dataset-version",
        "1",
    ]

    assert cli_main(arguments) == 0
    build_output = json.loads(capsys.readouterr().out)
    artifact = Path(build_output["artifact"])
    assert artifact.exists()

    assert cli_main(["inspect", str(artifact)]) == 0
    inspect_output = json.loads(capsys.readouterr().out)
    assert inspect_output["integrity"] == "valid"
    assert inspect_output["records"] == 6

    assert cli_main(arguments) == 2
    conflict_output = json.loads(capsys.readouterr().out)
    assert conflict_output["code"] == "artifact_exists"


@pytest.mark.security
def test_cli_rejects_unsafe_dataset_id_without_writing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    input_path = tmp_path / "records.json"
    input_path.write_text(
        json.dumps([record.model_dump(mode="json") for record in eligible_records(3)]),
        encoding="utf-8",
    )
    output = tmp_path / "generated"

    result = cli_main(
        [
            "build",
            str(input_path),
            str(output),
            "--dataset-id",
            "../escape",
            "--dataset-version",
            "1",
        ]
    )

    assert result == 2
    assert json.loads(capsys.readouterr().out)["code"] == "invalid_arguments"
    assert not (tmp_path / "escape").exists()
