from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from pydantic import ValidationError

from app.ml.artifacts import DatasetArtifactError, load_and_verify_artifact
from app.ml.experiments import (
    ExperimentArtifactError,
    export_experiment,
)
from app.ml.training import TrainingError, train_experiment
from app.schemas.ml_experiment import TrainingConfiguration


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Train the three local iCYLENS baseline models.",
    )
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--seed", type=int, default=42)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        manifest, records = load_and_verify_artifact(arguments.dataset)
        configuration = TrainingConfiguration(random_seed=arguments.seed)
        trained = train_experiment(
            manifest,
            records,
            experiment_id=arguments.experiment_id,
            configuration=configuration,
        )
        destination, experiment_manifest = export_experiment(trained, arguments.output)
    except (
        DatasetArtifactError,
        ExperimentArtifactError,
        TrainingError,
    ) as error:
        print(json.dumps({"code": error.code, "error": str(error)}, sort_keys=True))
        return 2
    except ValidationError:
        print(
            json.dumps(
                {"code": "invalid_arguments", "error": "arguments failed validation"},
                sort_keys=True,
            )
        )
        return 2
    except OSError:
        print(
            json.dumps(
                {"code": "filesystem_error", "error": "filesystem operation failed"},
                sort_keys=True,
            )
        )
        return 2

    print(
        json.dumps(
            {
                "artifact": str(destination),
                "experiment_id": experiment_manifest.report.experiment_id,
                "mode": experiment_manifest.report.mode,
                "models": {
                    model.algorithm: model.validation_metrics.model_dump(mode="json")
                    for model in experiment_manifest.report.models
                },
                "notice": (
                    "Synthetic smoke-test metrics are not evidence of real-world "
                    "malware detection performance."
                    if experiment_manifest.report.mode == "synthetic_demo"
                    else "Scientific representativeness is not established."
                ),
                "test_set_accessed": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
