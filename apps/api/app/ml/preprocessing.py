from collections.abc import Sequence
from typing import Literal

import numpy as np
from numpy.typing import NDArray
from sklearn.compose import ColumnTransformer  # type: ignore[import-untyped]
from sklearn.pipeline import Pipeline  # type: ignore[import-untyped]
from sklearn.preprocessing import (  # type: ignore[import-untyped]
    FunctionTransformer,
    OneHotEncoder,
    StandardScaler,
)

from app.schemas.ml_dataset import MLDatasetRecord
from app.schemas.ml_experiment import PreprocessingConfiguration
from app.schemas.ml_features import PREDICTIVE_FEATURE_ORDER

NUMERIC_FEATURES = PREDICTIVE_FEATURE_ORDER[:5]
CATEGORICAL_FEATURES = PREDICTIVE_FEATURE_ORDER[5:7]
BOOLEAN_FEATURES = PREDICTIVE_FEATURE_ORDER[7:]
NUMERIC_COLUMNS = tuple(range(5))
CATEGORICAL_COLUMNS = (5, 6)
BOOLEAN_COLUMNS = tuple(range(7, 14))
DETECTED_FORMAT_CATEGORIES = (
    "pdf",
    "png",
    "jpeg",
    "gif",
    "zip",
    "pe",
    "elf",
    "unknown",
)
FORMAT_CONSISTENCY_CATEGORIES = ("match", "mismatch", "unknown")
TRANSFORMED_FEATURE_COUNT = 23

NumericScaling = Literal["standard_scaler", "passthrough"]


def _as_float(values: NDArray[np.object_]) -> NDArray[np.float64]:
    return values.astype(np.float64)


def build_feature_matrix(records: Sequence[MLDatasetRecord]) -> NDArray[np.object_]:
    rows: list[list[int | float | str]] = []
    for record in records:
        values = record.features.ordered_predictive_values()
        rows.append(
            [
                *[float(value) for value in values[:5]],
                str(values[5]),
                str(values[6]),
                *[int(bool(value)) for value in values[7:]],
            ]
        )
    return np.asarray(rows, dtype=object)


def build_labels(records: Sequence[MLDatasetRecord]) -> NDArray[np.str_]:
    return np.asarray([record.label.value for record in records], dtype=str)


def build_preprocessor(numeric_scaling: NumericScaling) -> ColumnTransformer:
    numeric: StandardScaler | FunctionTransformer
    numeric = (
        StandardScaler()
        if numeric_scaling == "standard_scaler"
        else FunctionTransformer(_as_float, feature_names_out="one-to-one")
    )
    categorical = OneHotEncoder(
        categories=[
            list(DETECTED_FORMAT_CATEGORIES),
            list(FORMAT_CONSISTENCY_CATEGORIES),
        ],
        handle_unknown="ignore",
        sparse_output=False,
        dtype=np.float64,
    )
    return ColumnTransformer(
        transformers=[
            ("numeric", numeric, list(NUMERIC_COLUMNS)),
            ("categorical", categorical, list(CATEGORICAL_COLUMNS)),
            (
                "boolean",
                FunctionTransformer(_as_float, feature_names_out="one-to-one"),
                list(BOOLEAN_COLUMNS),
            ),
        ],
        remainder="drop",
        sparse_threshold=0,
        verbose_feature_names_out=True,
    )


def preprocessing_configuration() -> PreprocessingConfiguration:
    return PreprocessingConfiguration(
        transformed_feature_count=TRANSFORMED_FEATURE_COUNT,
        numeric_features=NUMERIC_FEATURES,
        categorical_features=CATEGORICAL_FEATURES,
        boolean_features=BOOLEAN_FEATURES,
    )


def transformed_feature_names(pipeline: Pipeline) -> tuple[str, ...]:
    preprocessor = pipeline.named_steps["preprocessing"]
    if not isinstance(preprocessor, ColumnTransformer):
        raise TypeError("pipeline preprocessing step is not a ColumnTransformer")
    return tuple(str(value) for value in preprocessor.get_feature_names_out())
