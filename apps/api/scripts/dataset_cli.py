from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from pydantic import ValidationError

from app.ml.artifacts import (
    DatasetArtifactError,
    export_dataset_artifact,
    load_and_verify_artifact,
)
from app.ml.builder import DatasetBuildError, assess_dataset, build_dataset
from app.ml.importing import DatasetImportError, load_dataset_records
from app.ml.splitting import SplitPlanningError, plan_splits
from app.schemas.ml_manifest import SplitConfiguration


def _print(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))


def _validate(path: Path) -> int:
    records = load_dataset_records(path)
    assessment = assess_dataset(records)
    output = assessment.report.model_dump(mode="json")
    if not assessment.report.ready_for_splitting:
        _print(output)
        return 2
    try:
        plan = plan_splits(assessment.accepted_records, SplitConfiguration())
    except SplitPlanningError as error:
        output["split_error"] = {"code": error.code, "message": str(error)}
        _print(output)
        return 2
    output["split_counts"] = plan.split_counts
    _print(output)
    return 0


def _build(arguments: argparse.Namespace) -> int:
    records = load_dataset_records(arguments.input)
    configuration = SplitConfiguration(random_seed=arguments.seed)
    result = build_dataset(
        records,
        dataset_id=arguments.dataset_id,
        dataset_version=arguments.dataset_version,
        split_configuration=configuration,
    )
    destination = export_dataset_artifact(result, arguments.output_root)
    _print(
        {
            "artifact": str(destination),
            "digest": result.manifest.content_integrity_digest,
            "records": result.manifest.record_count,
        }
    )
    return 0


def _inspect(path: Path) -> int:
    manifest, _ = load_and_verify_artifact(path)
    _print(
        {
            "dataset_id": manifest.dataset_id,
            "dataset_version": manifest.dataset_version,
            "digest": manifest.content_integrity_digest,
            "integrity": "valid",
            "records": manifest.record_count,
        }
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage local iCYLENS datasets.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate")
    validate.add_argument("input", type=Path)

    build = subparsers.add_parser("build")
    build.add_argument("input", type=Path)
    build.add_argument("output_root", type=Path)
    build.add_argument("--dataset-id", required=True)
    build.add_argument("--dataset-version", required=True)
    build.add_argument("--seed", type=int, default=42)

    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("artifact", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "validate":
            return _validate(arguments.input)
        if arguments.command == "build":
            return _build(arguments)
        return _inspect(arguments.artifact)
    except (DatasetImportError, DatasetBuildError, DatasetArtifactError) as error:
        _print({"code": error.code, "error": str(error)})
        return 2
    except ValidationError:
        _print({"code": "invalid_arguments", "error": "arguments failed validation"})
        return 2
    except OSError:
        _print({"code": "filesystem_error", "error": "filesystem operation failed"})
        return 2


if __name__ == "__main__":
    sys.exit(main())
