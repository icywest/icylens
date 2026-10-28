from __future__ import annotations

import hashlib
import json

from pydantic import BaseModel

from app.evidence.adapters import create_evidence_batch
from app.schemas.evidence import (
    EVIDENCE_SCHEMA_VERSION,
    BehavioralEvidenceObservation,
    EvidenceBatch,
    EvidenceClassification,
    EvidenceContext,
    EvidenceIdentifier,
    EvidenceIdentityStrength,
    EvidenceLimitation,
    EvidenceObservationSemantics,
    EvidenceOriginType,
    EvidencePrecision,
    EvidenceProvenance,
    EvidenceQuality,
    EvidenceQualityState,
    EvidenceRecord,
    EvidenceReference,
    EvidenceReferenceProvenance,
    EvidenceReferenceType,
    EvidenceSource,
    EvidenceSourceModule,
    EvidenceSubjectReference,
    EvidenceSubjectType,
    EvidenceTrustClassification,
    EvidenceVerificationStatus,
    MLEvidenceObservation,
    StaticEvidenceObservation,
    VulnerabilityEvidenceObservation,
)
from app.schemas.synthetic_scenarios import (
    SyntheticBehavioralSource,
    SyntheticEvidenceSource,
    SyntheticMLSource,
    SyntheticScenario,
    SyntheticStaticSource,
    SyntheticVulnerabilitySource,
)


class SyntheticScenarioGenerationError(ValueError):
    pass


def _digest(value: object) -> str:
    def normalize(item: object) -> object:
        if isinstance(item, BaseModel):
            return item.model_dump(mode="json")
        if isinstance(item, dict):
            return {str(key): normalize(child) for key, child in item.items()}
        if isinstance(item, tuple | list):
            return [normalize(child) for child in item]
        return item

    encoded = json.dumps(
        normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _record(fields: dict[str, object]) -> EvidenceRecord:
    identifier = EvidenceIdentifier(evidence_id=f"evd_{_digest(fields)}")
    return EvidenceRecord(identifier=identifier, references=(), **fields)


def _common(source: SyntheticEvidenceSource) -> dict[str, object]:
    source_id = source.source_id
    source_analysis_id = source.source_analysis_id
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "provenance": EvidenceProvenance(
            source_analysis_id=source_analysis_id,
            origin_type=EvidenceOriginType.SYNTHETIC_GENERATED,
            origin_verified=True,
            trust_classification=EvidenceTrustClassification.INTERNAL_DERIVATION,
            synthetic=True,
            integrity_verification=EvidenceVerificationStatus.STRUCTURALLY_VALID,
            generation_context=f"registered_scenario:{source_id}",
        ),
        "classification": EvidenceClassification(
            semantics=EvidenceObservationSemantics.OBSERVED_FACT,
            factual_certainty=EvidenceVerificationStatus.STRUCTURALLY_VALID,
        ),
        "quality": EvidenceQuality(
            overall=EvidenceQualityState.SUFFICIENT,
            completeness=EvidenceQualityState.SUFFICIENT,
            consistency=EvidenceQualityState.SUFFICIENT,
            temporal_precision=EvidencePrecision.NOT_AVAILABLE,
            identity_strength=EvidenceIdentityStrength.NAMESPACE_IDENTIFIER,
            provenance_availability=EvidenceQualityState.SUFFICIENT,
            verification_status=EvidenceVerificationStatus.STRUCTURALLY_VALID,
        ),
        "context": EvidenceContext(
            timestamps=(),
            source_status="synthetic_educational_fixture",
            sensitive_fields_omitted=(
                "paths",
                "commands",
                "users",
                "hosts",
                "network_values",
                "raw_payloads",
            ),
        ),
        "limitations": (
            EvidenceLimitation(
                code="synthetic_educational_only",
                description="This backend-generated fixture is educational and is not authenticated external telemetry.",
                source_declared=False,
            ),
            EvidenceLimitation(
                code="no_operational_threat_claim",
                description="The fixture does not establish malware, exploitation, compromise, execution, attribution, or causality.",
                source_declared=False,
            ),
        ),
    }


def _generate_record(source: SyntheticEvidenceSource) -> EvidenceRecord:
    fields = _common(source)
    if isinstance(source, SyntheticStaticSource):
        fields.update(
            source=EvidenceSource(
                module=EvidenceSourceModule.STATIC_ANALYSIS,
                phase="02",
                source_schema_version="1.0.0",
            ),
            subject=EvidenceSubjectReference(
                subject_type=EvidenceSubjectType.FILE_CONTENT,
                namespace="sha256",
                value=source.sha256,
                identity_strength=EvidenceIdentityStrength.CONTENT,
                verified=True,
                scope=source.scope,
            ),
            observation=StaticEvidenceObservation(
                sha256=source.sha256,
                size_bytes=source.size_bytes,
                detected_format="synthetic",
                format_consistency="not_assessed",
                indicator_count=0,
                indicators_truncated=False,
            ),
        )
    elif isinstance(source, SyntheticVulnerabilitySource):
        fields.update(
            source=EvidenceSource(
                module=EvidenceSourceModule.VULNERABILITY_INTELLIGENCE,
                phase="04",
                source_schema_version="1.0.0",
            ),
            subject=EvidenceSubjectReference(
                subject_type=EvidenceSubjectType.VULNERABILITY,
                namespace="cve",
                value=source.cve_id,
                identity_strength=EvidenceIdentityStrength.NAMESPACE_IDENTIFIER,
                verified=True,
                scope=source.scope,
            ),
            observation=VulnerabilityEvidenceObservation(
                cve_id=source.cve_id,
                nvd_status="not_queried",
                kev_status="not_queried",
                epss_status="not_queried",
                cvss_metric_count=None,
                weakness_count=None,
                cpe_configuration_count=None,
            ),
        )
    elif isinstance(source, SyntheticMLSource):
        fields["classification"] = EvidenceClassification(
            semantics=EvidenceObservationSemantics.EDUCATIONAL_PREDICTION,
            factual_certainty=EvidenceVerificationStatus.STRUCTURALLY_VALID,
        )
        fields.update(
            source=EvidenceSource(
                module=EvidenceSourceModule.SYNTHETIC_ML,
                phase="03",
                source_schema_version="1.0.0",
            ),
            subject=EvidenceSubjectReference(
                subject_type=EvidenceSubjectType.ANALYSIS,
                namespace="analysis_uuid",
                value=str(source.analysis_context_id),
                identity_strength=EvidenceIdentityStrength.ANALYSIS_SCOPED,
                verified=True,
                scope=source.scope,
            ),
            observation=MLEvidenceObservation(
                model_id="educational-fixture-model",
                model_version="1.0.0",
                dataset_id="synthetic-fixture-dataset",
                dataset_integrity_digest="d" * 64,
                output_label=source.output_label,
                benign_probability=0.75 if source.output_label == "benign" else 0.25,
                malicious_probability=0.25 if source.output_label == "benign" else 0.75,
            ),
        )
    elif isinstance(source, SyntheticBehavioralSource):
        fields["classification"] = EvidenceClassification(
            semantics=EvidenceObservationSemantics.BEHAVIORAL_ASSESSMENT,
            factual_certainty=EvidenceVerificationStatus.STRUCTURALLY_VALID,
        )
        fields.update(
            source=EvidenceSource(
                module=EvidenceSourceModule.BEHAVIORAL_ANALYSIS,
                phase="05",
                source_schema_version="1.0.0",
            ),
            subject=EvidenceSubjectReference(
                subject_type=EvidenceSubjectType.BEHAVIORAL_ANALYSIS,
                namespace="analysis_uuid",
                value=str(source.analysis_context_id),
                identity_strength=EvidenceIdentityStrength.ANALYSIS_SCOPED,
                verified=True,
                scope=source.scope,
            ),
            observation=BehavioralEvidenceObservation(
                analysis_status="complete",
                submitted_events=2,
                matched_rules=0,
                temporal_relationships=0,
                mapping_candidates=0,
                unknowns=0,
            ),
        )
    else:
        raise SyntheticScenarioGenerationError("unsupported synthetic source type")
    return _record(fields)


def generate_synthetic_evidence(
    scenario: SyntheticScenario,
) -> tuple[EvidenceBatch, dict[str, str]]:
    records_by_source = {
        source.source_id: _generate_record(source)
        for source in scenario.definition.sources
    }
    completed: list[EvidenceRecord] = []
    for source in scenario.definition.sources:
        record = records_by_source[source.source_id]
        if source.explicit_derivation_of is not None:
            target = records_by_source[source.explicit_derivation_of]
            reference = EvidenceReference(
                source_evidence_id=record.identifier.evidence_id,
                referenced_evidence_id=target.identifier.evidence_id,
                reference_type=EvidenceReferenceType.EXPLICIT_DERIVATION,
                provenance=EvidenceReferenceProvenance(
                    established_by="backend_validation",
                    origin_type=EvidenceOriginType.SYNTHETIC_GENERATED,
                    description="The immutable registered fixture declares this educational derivation link.",
                ),
                identity_assumptions=(
                    "The link is a validated fixture reference and does not assert subject identity.",
                ),
                verification_status=EvidenceVerificationStatus.STRUCTURALLY_VALID,
            )
            payload = record.model_dump(
                mode="python", exclude={"identifier", "references"}
            )
            record = EvidenceRecord(
                identifier=record.identifier,
                references=(reference,),
                **payload,
            )
        completed.append(record)
    try:
        batch = create_evidence_batch(tuple(completed))
    except ValueError as error:
        raise SyntheticScenarioGenerationError(
            "registered scenario could not produce valid bounded evidence"
        ) from error
    return batch, {
        source_id: record.identifier.evidence_id
        for source_id, record in records_by_source.items()
    }
