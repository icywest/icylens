from app.schemas.ml_dataset import MLDatasetRecord


def is_supervised_training_eligible(record: MLDatasetRecord) -> bool:
    """Conservative eligibility check; it does not assign or infer labels."""
    return (
        record.label.value in {"benign", "malicious"}
        and record.provenance.source_kind != "unknown"
        and record.label.verified_on is not None
        and (record.provenance.source_kind != "synthetic" or record.label.synthetic)
    )
