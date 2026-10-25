from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from pydantic import ValidationError

from app.ml.artifacts import DatasetArtifactError, load_and_verify_artifact
from app.ml.evaluation import EvaluationError, evaluate_experiment
from app.ml.evaluation_artifacts import EvaluationArtifactError, export_evaluation
from app.ml.training import TrainingError, train_experiment
from app.schemas.ml_evaluation import EvaluationConfiguration
from app.schemas.ml_experiment import TrainingConfiguration


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Train and evaluate iCYLENS baselines in one trusted local process."
    )
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--evaluation-id", required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--permutation-repeats", type=int, default=5)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        training_configuration = TrainingConfiguration(random_seed=arguments.seed)
        evaluation_configuration = EvaluationConfiguration(
            random_seed=arguments.seed,
            permutation_repeats=arguments.permutation_repeats,
        )
        manifest, records = load_and_verify_artifact(arguments.dataset)
        trained = train_experiment(
            manifest,
            records,
            experiment_id=arguments.experiment_id,
            configuration=training_configuration,
        )
        evaluated = evaluate_experiment(
            trained,
            manifest,
            records,
            evaluation_id=arguments.evaluation_id,
            configuration=evaluation_configuration,
        )
        destination, artifact = export_evaluation(evaluated, arguments.output)
    except (
        DatasetArtifactError,
        EvaluationArtifactError,
        EvaluationError,
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
                "evaluation_id": artifact.report.evaluation_id,
                "mode": artifact.report.mode,
                "selection": artifact.report.selection.model_dump(mode="json"),
                "notice": (
                    "Synthetic smoke-test evaluation is not evidence of real-world "
                    "malware detection performance."
                    if artifact.report.mode == "synthetic_demo"
                    else "Scientific representativeness and calibration are not established."
                ),
                "test_set_accessed": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
