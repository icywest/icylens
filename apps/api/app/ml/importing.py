import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DatasetImportLimits:
    maximum_input_bytes: int = 10 * 1024 * 1024
    maximum_records: int = 10_000
    maximum_jsonl_line_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        if (
            min(
                self.maximum_input_bytes,
                self.maximum_records,
                self.maximum_jsonl_line_bytes,
            )
            <= 0
        ):
            raise ValueError("all import limits must be positive")


class DatasetImportError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _require_mapping(value: object, index: int) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise DatasetImportError(
            "invalid_record_type",
            f"record {index} must be a JSON object",
        )
    return value


def _decode_json(data: bytes) -> object:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise DatasetImportError("invalid_utf8", "input must use UTF-8") from error
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise DatasetImportError("invalid_json", "input is not valid JSON") from error


def load_dataset_records(
    path: Path,
    limits: DatasetImportLimits | None = None,
) -> tuple[Mapping[str, Any], ...]:
    limits = limits or DatasetImportLimits()
    try:
        size = path.stat().st_size
    except OSError as error:
        raise DatasetImportError("input_unreadable", "input cannot be read") from error
    if size == 0:
        raise DatasetImportError("empty_input", "input must not be empty")
    if size > limits.maximum_input_bytes:
        raise DatasetImportError("input_too_large", "input exceeds the byte limit")

    suffix = path.suffix.casefold()
    if suffix == ".json":
        try:
            with path.open("rb") as stream:
                data = stream.read(limits.maximum_input_bytes + 1)
        except OSError as error:
            raise DatasetImportError(
                "input_unreadable", "input cannot be read"
            ) from error
        if len(data) > limits.maximum_input_bytes:
            raise DatasetImportError("input_too_large", "input exceeds the byte limit")
        payload = _decode_json(data)
        if not isinstance(payload, list):
            raise DatasetImportError(
                "invalid_top_level", "JSON input must contain a list of records"
            )
        if not payload:
            raise DatasetImportError("empty_dataset", "dataset contains no records")
        if len(payload) > limits.maximum_records:
            raise DatasetImportError(
                "too_many_records", "dataset exceeds the record limit"
            )
        return tuple(
            _require_mapping(value, index) for index, value in enumerate(payload)
        )

    if suffix != ".jsonl":
        raise DatasetImportError(
            "unsupported_format", "only .json and .jsonl inputs are supported"
        )

    records: list[Mapping[str, Any]] = []
    total_bytes = 0
    try:
        with path.open("rb") as stream:
            line_number = 0
            while line := stream.readline(limits.maximum_jsonl_line_bytes + 1):
                line_number += 1
                if len(line) > limits.maximum_jsonl_line_bytes:
                    raise DatasetImportError(
                        "line_too_large",
                        f"JSONL line {line_number} exceeds the byte limit",
                    )
                total_bytes += len(line)
                if total_bytes > limits.maximum_input_bytes:
                    raise DatasetImportError(
                        "input_too_large", "input exceeds the byte limit"
                    )
                if not line.strip():
                    raise DatasetImportError(
                        "blank_line", f"JSONL line {line_number} is blank"
                    )
                value = _decode_json(line)
                records.append(_require_mapping(value, line_number - 1))
                if len(records) > limits.maximum_records:
                    raise DatasetImportError(
                        "too_many_records", "dataset exceeds the record limit"
                    )
    except DatasetImportError:
        raise
    except OSError as error:
        raise DatasetImportError("input_unreadable", "input cannot be read") from error
    if not records:
        raise DatasetImportError("empty_dataset", "dataset contains no records")
    return tuple(records)
