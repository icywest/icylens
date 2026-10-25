from sklearn.ensemble import (  # type: ignore[import-untyped]
    HistGradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.linear_model import LogisticRegression  # type: ignore[import-untyped]
from sklearn.pipeline import Pipeline  # type: ignore[import-untyped]

from app.ml.preprocessing import build_preprocessor
from app.schemas.ml_experiment import ModelAlgorithm, TrainingConfiguration


def build_model_pipelines(
    configuration: TrainingConfiguration,
) -> dict[ModelAlgorithm, Pipeline]:
    seed = configuration.random_seed
    logistic = configuration.logistic_regression
    forest = configuration.random_forest
    boosting = configuration.hist_gradient_boosting
    return {
        "logistic_regression": Pipeline(
            steps=[
                ("preprocessing", build_preprocessor("standard_scaler")),
                (
                    "model",
                    LogisticRegression(
                        C=logistic.regularization_c,
                        class_weight=logistic.class_weight,
                        max_iter=logistic.maximum_iterations,
                        random_state=seed,
                        solver="lbfgs",
                    ),
                ),
            ]
        ),
        "random_forest": Pipeline(
            steps=[
                ("preprocessing", build_preprocessor("passthrough")),
                (
                    "model",
                    RandomForestClassifier(
                        class_weight=forest.class_weight,
                        max_depth=forest.maximum_depth,
                        min_samples_leaf=forest.minimum_samples_per_leaf,
                        n_estimators=forest.estimator_count,
                        n_jobs=forest.parallel_jobs,
                        random_state=seed,
                    ),
                ),
            ]
        ),
        "hist_gradient_boosting": Pipeline(
            steps=[
                ("preprocessing", build_preprocessor("passthrough")),
                (
                    "model",
                    HistGradientBoostingClassifier(
                        learning_rate=boosting.learning_rate,
                        max_iter=boosting.maximum_iterations,
                        max_leaf_nodes=boosting.maximum_leaf_nodes,
                        min_samples_leaf=boosting.minimum_samples_per_leaf,
                        random_state=seed,
                    ),
                ),
            ]
        ),
    }


def effective_hyperparameters(
    algorithm: ModelAlgorithm,
    configuration: TrainingConfiguration,
) -> dict[str, str | int | float | bool | None]:
    if algorithm == "logistic_regression":
        model = configuration.logistic_regression
        return {
            "C": model.regularization_c,
            "class_weight": model.class_weight,
            "max_iter": model.maximum_iterations,
            "random_state": configuration.random_seed,
            "solver": "lbfgs",
        }
    if algorithm == "random_forest":
        forest_model = configuration.random_forest
        return {
            "class_weight": forest_model.class_weight,
            "max_depth": forest_model.maximum_depth,
            "min_samples_leaf": forest_model.minimum_samples_per_leaf,
            "n_estimators": forest_model.estimator_count,
            "n_jobs": forest_model.parallel_jobs,
            "random_state": configuration.random_seed,
        }
    boosting_model = configuration.hist_gradient_boosting
    return {
        "learning_rate": boosting_model.learning_rate,
        "max_iter": boosting_model.maximum_iterations,
        "max_leaf_nodes": boosting_model.maximum_leaf_nodes,
        "min_samples_leaf": boosting_model.minimum_samples_per_leaf,
        "random_state": configuration.random_seed,
    }
