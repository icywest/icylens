import hashlib
import math
from collections import Counter, defaultdict
from collections.abc import Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.schemas.ml_dataset import DatasetLabelName, MLDatasetRecord
from app.schemas.ml_manifest import SplitConfiguration

AssignedSplit = Literal["training", "validation", "test"]
ASSIGNED_SPLITS: tuple[AssignedSplit, ...] = (
    "training",
    "validation",
    "test",
)


class SplitPlanningError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class SplitPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    records: tuple[MLDatasetRecord, ...]
    split_counts: dict[str, int]
    label_split_counts: dict[str, dict[str, int]]
    warnings: tuple[str, ...]


def _target_counts(total: int, configuration: SplitConfiguration) -> dict[str, int]:
    fractions = {
        "training": configuration.training_fraction,
        "validation": configuration.validation_fraction,
        "test": configuration.test_fraction,
    }
    raw = {name: total * fraction for name, fraction in fractions.items()}
    counts = {name: math.floor(value) for name, value in raw.items()}
    remaining = total - sum(counts.values())
    priority = sorted(
        ASSIGNED_SPLITS,
        key=lambda name: (-(raw[name] - counts[name]), ASSIGNED_SPLITS.index(name)),
    )
    for name in priority[:remaining]:
        counts[name] += 1
    minimum = configuration.minimum_per_class_per_split
    for name in ASSIGNED_SPLITS:
        while counts[name] < minimum:
            donors = [
                candidate
                for candidate in ASSIGNED_SPLITS
                if counts[candidate] > minimum
            ]
            if not donors:
                break
            donor = max(
                donors,
                key=lambda candidate: (
                    counts[candidate] - raw[candidate],
                    counts[candidate],
                    -ASSIGNED_SPLITS.index(candidate),
                ),
            )
            counts[donor] -= 1
            counts[name] += 1
    return counts


def _stable_rank(record: MLDatasetRecord, seed: int) -> tuple[str, str]:
    value = f"{seed}:{record.identity.sha256}".encode()
    return hashlib.sha256(value).hexdigest(), record.identity.sha256


def plan_splits(
    records: Sequence[MLDatasetRecord],
    configuration: SplitConfiguration,
) -> SplitPlan:
    if not records:
        raise SplitPlanningError("empty_eligible_dataset", "no eligible records remain")
    hashes = [record.identity.sha256 for record in records]
    if len(hashes) != len(set(hashes)):
        raise SplitPlanningError(
            "duplicate_sha256", "split planning requires unique SHA-256 identities"
        )
    if any(record.label.value == "unknown" for record in records):
        raise SplitPlanningError(
            "unknown_label", "unknown labels cannot enter supervised partitions"
        )

    by_label: dict[DatasetLabelName, list[MLDatasetRecord]] = defaultdict(list)
    for record in records:
        by_label[record.label.value].append(record)
    if len(by_label) < 2:
        raise SplitPlanningError(
            "single_class_dataset", "at least two eligible label classes are required"
        )

    assignments: dict[str, AssignedSplit] = {}
    warnings: list[str] = []
    minimum = configuration.minimum_per_class_per_split
    for label in sorted(by_label):
        members = by_label[label]
        if len(members) < minimum * len(ASSIGNED_SPLITS):
            raise SplitPlanningError(
                "infeasible_stratification",
                f"label {label} cannot satisfy the minimum per split",
            )
        targets = _target_counts(len(members), configuration)
        locked: Counter[str] = Counter(
            record.split for record in members if record.split != "unassigned"
        )
        pending = sorted(
            (record for record in members if record.split == "unassigned"),
            key=lambda record: _stable_rank(record, configuration.random_seed),
        )
        for record in members:
            if record.split != "unassigned":
                assignments[record.identity.sha256] = record.split

        for record in pending:
            chosen = max(
                ASSIGNED_SPLITS,
                key=lambda name: (
                    targets[name] - locked[name],
                    -ASSIGNED_SPLITS.index(name),
                ),
            )
            assignments[record.identity.sha256] = chosen
            locked[chosen] += 1

        if any(locked[name] < minimum for name in ASSIGNED_SPLITS):
            raise SplitPlanningError(
                "infeasible_existing_assignments",
                f"existing assignments prevent minimum coverage for label {label}",
            )
        if any(locked[name] != targets[name] for name in ASSIGNED_SPLITS):
            warnings.append(f"existing_assignment_distribution:{label}")

    planned = tuple(
        record.model_copy(update={"split": assignments[record.identity.sha256]})
        for record in sorted(records, key=lambda item: item.identity.sha256)
    )
    split_counts = Counter(record.split for record in planned)
    label_split_counts: dict[str, dict[str, int]] = {}
    for label in sorted(by_label):
        label_split_counts[label] = {
            split: sum(
                record.label.value == label and record.split == split
                for record in planned
            )
            for split in ASSIGNED_SPLITS
        }
    return SplitPlan(
        records=planned,
        split_counts={split: split_counts[split] for split in ASSIGNED_SPLITS},
        label_split_counts=label_split_counts,
        warnings=tuple(warnings),
    )
