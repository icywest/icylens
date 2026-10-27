from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.evidence.adapters import (
    SourceContractMismatchError,
    UnsupportedSourceModuleError,
    UnsupportedSourceSchemaError,
    adapt_behavioral_analysis,
    adapt_ml_inference,
    adapt_static_analysis,
    adapt_vulnerability_intelligence,
    create_evidence_batch,
    get_evidence_schema_descriptor,
    normalize_source_output,
)
from app.schemas.behavior import EventNature, EventValidationResult
from app.schemas.behavior_analysis import (
    BehavioralAnalysisExplanation,
    BehavioralAnalysisProvenance,
    BehavioralAnalysisResult,
    BehavioralAnalysisSource,
    BehavioralAnalysisStatus,
    BehavioralAnalysisSummary,
    BehavioralEventSummary,
)
from app.schemas.content_inspection import EntropySummary, StringExtractionSummary
from app.schemas.evidence import (
    EvidenceBatch,
    EvidenceClassification,
    EvidenceContext,
    EvidenceIdentifier,
    EvidenceLimitation,
    EvidenceOriginType,
    EvidenceReference,
    EvidenceReferenceProvenance,
    EvidenceReferenceType,
    EvidenceSource,
    EvidenceSourceModule,
    EvidenceTimestamp,
    EvidenceTimestampMeaning,
    EvidenceTrustClassification,
    EvidenceVerificationStatus,
)
from app.schemas.ml_inference import (
    ClassProbabilities,
    InferenceLimitation,
    InferenceModelSummary,
    InferencePrediction,
    MLInferenceResponse,
)
from app.schemas.static_analysis import (
    AnalysisLimitation,
    StaticAnalysisContent,
    StaticAnalysisFingerprint,
    StaticAnalysisResponse,
)
from app.schemas.unified_vulnerability import (
    CorrelationStatus,
    EPSSSourceResult,
    KEVSourceResult,
    NVDSourceResult,
    SourceErrorCode,
    SourceStatus,
    UnifiedSources,
    UnifiedVulnerabilityIntelligenceResponse,
)

NOW = datetime(2026, 10, 27, 12, tzinfo=UTC)
ANALYSIS_ID = UUID("10000000-0000-4000-8000-000000000001")
SECOND_ID = UUID("20000000-0000-4000-8000-000000000002")
SHA256 = "a" * 64


def static_source() -> StaticAnalysisResponse:
    return StaticAnalysisResponse(
        analysis_id=ANALYSIS_ID,
        analysis_type="static",
        status="completed",
        filename="secret-user-path.exe",
        created_at=NOW,
        completed_at=NOW,
        fingerprint=StaticAnalysisFingerprint(
            sha256=SHA256,
            size_bytes=4,
            detected_format="pe",
            format_consistency="match",
        ),
        content=StaticAnalysisContent(
            entropy=EntropySummary(shannon_entropy=1.0, total_bytes=4),
            strings=StringExtractionSummary(
                observed_count=0,
                retained_count=0,
                truncated=False,
                raw_strings_exposed=False,
                minimum_length=4,
                maximum_retained_strings=100,
                maximum_characters_per_string=256,
            ),
        ),
        indicators=[],
        indicators_truncated=False,
        analysis_limitations=[
            AnalysisLimitation(
                code="no_execution", description="No execution was performed."
            ),
            AnalysisLimitation(
                code="no_malware_verdict", description="No malware verdict."
            ),
        ],
    )


def ml_source() -> MLInferenceResponse:
    limitations = tuple(
        InferenceLimitation(code=code, description=code.replace("_", " "))
        for code in (
            "synthetic_model_only",
            "not_security_verdict",
            "probability_not_calibrated",
            "static_analysis_only",
            "bounded_analysis",
        )
    )
    return MLInferenceResponse(
        inference_id=SECOND_ID,
        analysis_id=ANALYSIS_ID,
        inference_mode="synthetic_demo",
        prediction=InferencePrediction(
            label="malicious",
            probability_estimates=ClassProbabilities(benign=0.2, malicious=0.8),
        ),
        model=InferenceModelSummary(
            model_id="demo-model",
            algorithm="logistic_regression",
            experiment_id="experiment-1",
            feature_schema_version="1.0.0",
            dataset_id="synthetic-dataset",
            dataset_integrity_digest="b" * 64,
            dataset_provenance_type="synthetic",
            evaluation_status="synthetic_validation_only",
            model_selection_status="not_selected",
            lifecycle_status="registered_demo",
            operational_detection_approved=False,
        ),
        limitations=limitations,
    )


def vulnerability_source() -> UnifiedVulnerabilityIntelligenceResponse:
    return UnifiedVulnerabilityIntelligenceResponse(
        correlation_id=ANALYSIS_ID,
        cve_id="CVE-2026-1234",
        generated_at=NOW,
        status=CorrelationStatus.PARTIAL,
        sources=UnifiedSources(
            nvd=NVDSourceResult(
                status=SourceStatus.NOT_FOUND,
                evidence=None,
                source_timestamp=None,
                retrieved_at=NOW,
                error_code=None,
                limitations=("No NVD record was returned.",),
            ),
            cisa_kev=KEVSourceResult(
                status=SourceStatus.NOT_LISTED,
                evidence=None,
                source_timestamp=None,
                retrieved_at=NOW,
                freshness="fresh",
                error_code=None,
                limitations=("Not listed does not prove non-exploitation.",),
            ),
            first_epss=EPSSSourceResult(
                status=SourceStatus.UNAVAILABLE,
                evidence=None,
                source_timestamp=None,
                retrieved_at=NOW,
                freshness="unavailable",
                error_code=SourceErrorCode.PROVIDER_UNAVAILABLE,
                limitations=("No EPSS estimate is available.",),
            ),
        ),
        interpretation=None,
        applicability=None,
        evidence_summary=(),
        limitations=("Partial provider result.",),
    )


def behavioral_source() -> BehavioralAnalysisResult:
    return BehavioralAnalysisResult.model_construct(
        analysis_id=ANALYSIS_ID,
        status=BehavioralAnalysisStatus.COMPLETE,
        generated_at=NOW,
        source=BehavioralAnalysisSource.DECLARED_BATCH,
        provenance=BehavioralAnalysisProvenance(
            source=BehavioralAnalysisSource.DECLARED_BATCH,
            event_natures=(EventNature.DECLARED,),
            scenario_id=None,
            scenario_kind=None,
            scenario_seed=None,
        ),
        event_summary=BehavioralEventSummary(
            submitted_events=2,
            unique_event_ids=2,
            declared_events=2,
            synthetic_events=0,
            process_events=2,
            file_events=0,
            network_events=0,
            configuration_events=0,
        ),
        validation=EventValidationResult(
            valid=True, event_count=2, issues=(), limitations=()
        ),
        rule_findings=(),
        rule_summary=None,
        temporal_relationships=(),
        temporal_sequences=(),
        temporal_summary=None,
        attack_mapping_evaluations=(),
        attack_mapping_summary=None,
        catalog_version="19.2",
        stages=(),
        issues=(),
        summary=BehavioralAnalysisSummary(
            valid_events=2,
            validation_errors=0,
            validation_warnings=0,
            evaluated_rules=12,
            matched_rules=1,
            temporal_relationships=1,
            strong_relationships=0,
            weak_relationships=1,
            mapping_policies=3,
            mapping_candidates=1,
            insufficient_mappings=2,
            unknowns=2,
        ),
        explanation=BehavioralAnalysisExplanation(
            input_statement="Declared input.",
            validation_statement="Valid schema.",
            rule_statement="One rule matched.",
            temporal_statement="One non-causal relation.",
            mapping_statement="One candidate.",
            unknowns=(),
        ),
        limitations=("Temporal proximity is non-causal.",),
    )


@pytest.mark.parametrize(
    ("adapter", "source", "domain"),
    [
        (adapt_static_analysis, static_source, "static"),
        (adapt_ml_inference, ml_source, "synthetic_ml"),
        (adapt_vulnerability_intelligence, vulnerability_source, "vulnerability"),
        (adapt_behavioral_analysis, behavioral_source, "behavioral"),
    ],
)
def test_source_adapters_are_deterministic_and_domain_typed(
    adapter: object, source: object, domain: str
) -> None:
    conversion = adapter  # type: ignore[assignment]
    first = conversion(source())  # type: ignore[operator]
    second = conversion(source())  # type: ignore[operator]
    assert first == second
    assert first.identifier.evidence_id == second.identifier.evidence_id
    assert first.observation.domain == domain
    assert not first.references


def test_static_evidence_is_content_scoped_and_does_not_claim_execution() -> None:
    record = adapt_static_analysis(static_source())
    serialized = record.model_dump_json()
    assert record.subject.value == SHA256
    assert record.observation.execution_observed is False
    assert "secret-user-path.exe" not in serialized
    assert "filename" in record.context.sensitive_fields_omitted


def test_ml_prediction_is_never_promoted_to_fact_or_verdict() -> None:
    record = adapt_ml_inference(ml_source())
    assert record.classification.semantics == "educational_prediction"
    assert record.classification.threat_verdict is False
    assert record.observation.confirmed_fact is False
    assert record.observation.model_version is None
    assert not record.context.timestamps


def test_vulnerability_does_not_claim_exploitation_or_attack_mapping() -> None:
    record = adapt_vulnerability_intelligence(vulnerability_source())
    assert record.observation.exploitation_observed is False
    assert record.observation.attack_mapping_performed is False
    assert record.provenance.origin_verified is False
    assert all(item.meaning != "event_time" for item in record.context.timestamps)


def test_behavioral_output_remains_non_causal_and_client_origin_is_unverified() -> None:
    record = adapt_behavioral_analysis(behavioral_source())
    assert record.provenance.origin_type == EvidenceOriginType.CLIENT_DECLARED
    assert record.provenance.origin_verified is False
    assert record.observation.attack_confirmed is False
    assert record.observation.causal_inference_performed is False
    serialized = record.model_dump_json()
    for sensitive in (
        "secret-command-value",
        "C:/Users/secret/file.exe",
        "192.0.2.99",
        "secret-hostname",
    ):
        assert sensitive not in serialized


def test_dispatch_rejects_unknown_module_version_and_contract() -> None:
    with pytest.raises(UnsupportedSourceModuleError):
        normalize_source_output("mystery", "1.0.0", static_source())
    with pytest.raises(UnsupportedSourceSchemaError):
        normalize_source_output("static_analysis", "9.9.9", static_source())
    with pytest.raises(SourceContractMismatchError):
        normalize_source_output("static_analysis", "1.0.0", ml_source())
    assert normalize_source_output(
        "static_analysis", "1.0.0", static_source()
    ) == adapt_static_analysis(static_source())


def test_schema_descriptor_and_source_phase_pair_are_bounded() -> None:
    descriptor = get_evidence_schema_descriptor()
    assert descriptor.maximum_records_per_batch == 256
    assert descriptor.correlation is False
    with pytest.raises(ValidationError, match="inconsistent"):
        EvidenceSource(
            module=EvidenceSourceModule.STATIC_ANALYSIS,
            phase="05",
            source_schema_version="1.0.0",
        )


def test_provenance_rejects_client_trust_elevation_and_contradiction() -> None:
    record = adapt_behavioral_analysis(behavioral_source())
    payload = record.provenance.model_dump()
    payload["trust_classification"] = EvidenceTrustClassification.VERSIONED_KNOWLEDGE
    with pytest.raises(ValidationError, match="elevated"):
        type(record.provenance).model_validate(payload)
    payload = record.provenance.model_dump()
    payload["origin_verified"] = True
    with pytest.raises(ValidationError, match="client-declared"):
        type(record.provenance).model_validate(payload)
    payload = adapt_vulnerability_intelligence(
        vulnerability_source()
    ).provenance.model_dump()
    payload["origin_verified"] = True
    with pytest.raises(ValidationError, match="external intelligence"):
        type(record.provenance).model_validate(payload)
    payload = adapt_static_analysis(static_source()).provenance.model_dump()
    payload["synthetic"] = True
    with pytest.raises(ValidationError, match="synthetic status"):
        type(record.provenance).model_validate(payload)


def test_invalid_and_duplicate_ids_are_rejected() -> None:
    record = adapt_static_analysis(static_source())
    payload = record.model_dump()
    payload["identifier"] = EvidenceIdentifier(evidence_id="evd_" + "0" * 64)
    with pytest.raises(ValidationError, match="canonical"):
        type(record).model_validate(payload)
    with pytest.raises(ValidationError, match="unique"):
        EvidenceBatch(
            batch_id="evb_" + "0" * 64,
            records=(record, record),
        )


def test_batch_reverifies_copied_record_content() -> None:
    record = adapt_static_analysis(static_source())
    altered_subject = record.subject.model_copy(update={"value": "b" * 64})
    altered = record.model_copy(update={"subject": altered_subject})
    with pytest.raises(ValidationError, match="canonical record content"):
        EvidenceBatch(
            batch_id="evb_" + "0" * 64,
            records=(altered,),
        )


def test_batch_order_and_identity_are_deterministic() -> None:
    static = adapt_static_analysis(static_source())
    ml = adapt_ml_inference(ml_source())
    first = create_evidence_batch((static, ml))
    second = create_evidence_batch((ml, static))
    assert first == second
    assert first.batch_id == second.batch_id
    assert [item.identifier.evidence_id for item in first.records] == sorted(
        (static.identifier.evidence_id, ml.identifier.evidence_id)
    )


def test_cross_module_identity_mismatch_and_cycles_are_rejected() -> None:
    first = adapt_static_analysis(static_source())
    second = adapt_ml_inference(ml_source())
    first_ref = EvidenceReference(
        source_evidence_id=first.identifier.evidence_id,
        referenced_evidence_id=second.identifier.evidence_id,
        reference_type=EvidenceReferenceType.EXPLICIT_SAME_SUBJECT,
        provenance=EvidenceReferenceProvenance(
            established_by="backend_validation",
            origin_type=EvidenceOriginType.LOCALLY_DERIVED,
            description="Test-only explicit reference.",
        ),
        identity_assumptions=("Subjects are asserted equal for this test.",),
        verification_status=EvidenceVerificationStatus.STRUCTURALLY_VALID,
    )
    mismatched = first.model_copy(update={"references": (first_ref,)})
    with pytest.raises(ValidationError, match="identity mismatch"):
        create_evidence_batch((mismatched, second))

    first_ref = first_ref.model_copy(
        update={"reference_type": EvidenceReferenceType.EXPLICIT_DERIVATION}
    )
    second_ref = EvidenceReference(
        source_evidence_id=second.identifier.evidence_id,
        referenced_evidence_id=first.identifier.evidence_id,
        reference_type=EvidenceReferenceType.EXPLICIT_DERIVATION,
        provenance=first_ref.provenance,
        identity_assumptions=("Explicit derivation asserted for cycle test.",),
        verification_status=EvidenceVerificationStatus.STRUCTURALLY_VALID,
    )
    cyclic_first = first.model_copy(update={"references": (first_ref,)})
    cyclic_second = second.model_copy(update={"references": (second_ref,)})
    with pytest.raises(ValidationError, match="circular"):
        create_evidence_batch((cyclic_first, cyclic_second))


def test_dangling_wrong_source_and_wrong_domain_references_are_rejected() -> None:
    static = adapt_static_analysis(static_source())
    ml = adapt_ml_inference(ml_source())
    wrong_source = EvidenceReference(
        source_evidence_id=ml.identifier.evidence_id,
        referenced_evidence_id="evd_" + "f" * 64,
        reference_type=EvidenceReferenceType.EXPLICIT_DERIVATION,
        provenance=EvidenceReferenceProvenance(
            established_by="backend_validation",
            origin_type=EvidenceOriginType.LOCALLY_DERIVED,
            description="Adversarial reference.",
        ),
        identity_assumptions=("No identity equivalence is claimed.",),
        verification_status=EvidenceVerificationStatus.PARTIAL,
    )
    payload = static.model_dump()
    payload["references"] = (wrong_source,)
    with pytest.raises(ValidationError, match="containing evidence"):
        type(static).model_validate(payload)

    dangling = wrong_source.model_copy(
        update={"source_evidence_id": static.identifier.evidence_id}
    )
    dangling_record = static.model_copy(update={"references": (dangling,)})
    with pytest.raises(ValidationError, match="resolve inside"):
        create_evidence_batch((dangling_record, ml))

    payload = static.model_dump()
    payload["observation"] = ml.observation
    with pytest.raises(ValidationError, match="observation domain"):
        type(static).model_validate(payload)


def test_nested_models_and_collections_are_effectively_immutable() -> None:
    batch = create_evidence_batch((adapt_static_analysis(static_source()),))
    with pytest.raises(ValidationError, match="frozen"):
        batch.records[0].quality = batch.records[0].quality  # type: ignore[misc]
    with pytest.raises(TypeError):
        batch.records[0].limitations[0] = batch.records[0].limitations[0]  # type: ignore[index]


def test_schema_forbids_arbitrary_fields_and_self_references() -> None:
    record = adapt_static_analysis(static_source())
    payload = record.classification.model_dump()
    payload["threat_score"] = 100
    with pytest.raises(ValidationError, match="Extra inputs"):
        EvidenceClassification.model_validate(payload)
    with pytest.raises(ValidationError, match="itself"):
        EvidenceReference(
            source_evidence_id=record.identifier.evidence_id,
            referenced_evidence_id=record.identifier.evidence_id,
            reference_type=EvidenceReferenceType.EXPLICIT_DERIVATION,
            provenance=EvidenceReferenceProvenance(
                established_by="explicit_source_contract",
                origin_type=EvidenceOriginType.LOCALLY_DERIVED,
                description="Invalid self-reference.",
            ),
            identity_assumptions=("None.",),
            verification_status=EvidenceVerificationStatus.STRUCTURALLY_VALID,
        )


def test_missing_identity_oversized_fields_and_oversized_batch_are_rejected() -> None:
    record = adapt_static_analysis(static_source())
    subject = record.subject.model_dump()
    subject["value"] = ""
    with pytest.raises(ValidationError):
        type(record.subject).model_validate(subject)
    with pytest.raises(ValidationError):
        EvidenceLimitation(
            code="oversized_value",
            description="x" * 513,
            source_declared=False,
        )
    with pytest.raises(ValidationError):
        EvidenceBatch(batch_id="evb_" + "0" * 64, records=(record,) * 257)
    oversized_source = static_source().model_copy(
        update={
            "analysis_limitations": [
                AnalysisLimitation.model_construct(
                    code="static_only", description="x" * 513
                )
            ]
        }
    )
    with pytest.raises(ValidationError):
        adapt_static_analysis(oversized_source)


def test_timestamp_meanings_remain_distinct_and_normalize_to_utc() -> None:
    source = static_source()
    offset = timezone(timedelta(hours=-6))
    adjusted = source.model_copy(
        update={
            "created_at": NOW.astimezone(offset),
            "completed_at": NOW.astimezone(offset),
        }
    )
    record = adapt_static_analysis(adjusted)
    assert [item.meaning for item in record.context.timestamps] == [
        "analysis_started_time",
        "analysis_completed_time",
    ]
    assert all(item.value.tzinfo == UTC for item in record.context.timestamps)
    duplicate = EvidenceTimestamp(
        meaning=EvidenceTimestampMeaning.GENERATED_TIME,
        value=NOW,
        precision="exact",
    )
    with pytest.raises(ValidationError, match="unique"):
        EvidenceContext(
            timestamps=(duplicate, duplicate),
            source_status="completed",
            sensitive_fields_omitted=(),
        )


def test_unsorted_records_and_wrong_batch_identity_are_rejected() -> None:
    records = tuple(
        sorted(
            (
                adapt_static_analysis(static_source()),
                adapt_ml_inference(ml_source()),
            ),
            key=lambda item: item.identifier.evidence_id,
        )
    )
    with pytest.raises(ValidationError, match="deterministic ID ordering"):
        EvidenceBatch(batch_id="evb_" + "0" * 64, records=tuple(reversed(records)))
    with pytest.raises(ValidationError, match="batch ID"):
        EvidenceBatch(batch_id="evb_" + "0" * 64, records=records)


def test_synthetic_behavioral_provenance_is_preserved() -> None:
    source = behavioral_source().model_copy(
        update={"source": BehavioralAnalysisSource.SYNTHETIC_SCENARIO}
    )
    record = adapt_behavioral_analysis(source)
    assert record.provenance.synthetic is True
    assert record.provenance.origin_type == EvidenceOriginType.SYNTHETIC_GENERATED
    assert record.provenance.trust_classification == "derived_evidence"


def test_normalization_module_has_no_io_persistence_or_execution_primitives() -> None:
    import app.evidence.adapters as adapters

    source = inspect.getsource(adapters)
    forbidden = ("requests", "httpx", "subprocess", "socket", "pathlib", "open(")
    assert all(token not in source for token in forbidden)
