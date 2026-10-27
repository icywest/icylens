from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any, TypeVar

from pydantic import BaseModel

from app.schemas.behavior_analysis import (
    BehavioralAnalysisResult,
    BehavioralAnalysisSource,
    BehavioralAnalysisStatus,
)
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
    EvidenceSchemaDescriptor,
    EvidenceSource,
    EvidenceSourceModule,
    EvidenceSubjectReference,
    EvidenceSubjectType,
    EvidenceTimestamp,
    EvidenceTimestampMeaning,
    EvidenceTrustClassification,
    EvidenceVerificationStatus,
    MLEvidenceObservation,
    StaticEvidenceObservation,
    VulnerabilityEvidenceObservation,
)
from app.schemas.ml_inference import MLInferenceResponse
from app.schemas.static_analysis import StaticAnalysisResponse
from app.schemas.unified_vulnerability import (
    CorrelationStatus,
    UnifiedVulnerabilityIntelligenceResponse,
)

T = TypeVar("T", bound=BaseModel)


class EvidenceNormalizationError(ValueError):
    """Controlled rejection at the internal source-contract boundary."""


class UnsupportedSourceModuleError(EvidenceNormalizationError):
    pass


class UnsupportedSourceSchemaError(EvidenceNormalizationError):
    pass


class SourceContractMismatchError(EvidenceNormalizationError):
    pass


def _canonical_digest(value: object) -> str:
    def json_value(item: object) -> object:
        if isinstance(item, BaseModel):
            return item.model_dump(mode="json")
        if isinstance(item, dict):
            return {str(key): json_value(child) for key, child in item.items()}
        if isinstance(item, tuple | list):
            return [json_value(child) for child in item]
        return item

    encoded = json.dumps(
        json_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _record_id(fields: dict[str, object]) -> str:
    return f"evd_{_canonical_digest(fields)}"


def _record(fields: dict[str, object]) -> EvidenceRecord:
    identifier = EvidenceIdentifier(evidence_id=_record_id(fields))
    return EvidenceRecord(identifier=identifier, references=(), **fields)


def _limitation(code: str, description: str, *, source: bool) -> EvidenceLimitation:
    return EvidenceLimitation(
        code=code, description=description, source_declared=source
    )


def adapt_static_analysis(source: StaticAnalysisResponse) -> EvidenceRecord:
    limitations = tuple(
        _limitation(item.code, item.description, source=True)
        for item in source.analysis_limitations
    )
    fields: dict[str, object] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "source": EvidenceSource(
            module=EvidenceSourceModule.STATIC_ANALYSIS,
            phase="02",
            source_schema_version="1.0.0",
        ),
        "provenance": EvidenceProvenance(
            source_analysis_id=source.analysis_id,
            origin_type=EvidenceOriginType.LOCALLY_DERIVED,
            origin_verified=True,
            trust_classification=EvidenceTrustClassification.INTERNAL_DERIVATION,
            synthetic=False,
            integrity_verification=EvidenceVerificationStatus.INTEGRITY_VERIFIED,
            generation_context="bounded_synchronous_static_analysis",
        ),
        "subject": EvidenceSubjectReference(
            subject_type=EvidenceSubjectType.FILE_CONTENT,
            namespace="sha256",
            value=source.fingerprint.sha256,
            identity_strength=EvidenceIdentityStrength.CONTENT,
            verified=True,
            scope="accepted_byte_stream_only",
        ),
        "observation": StaticEvidenceObservation(
            sha256=source.fingerprint.sha256,
            size_bytes=source.fingerprint.size_bytes,
            detected_format=source.fingerprint.detected_format,
            format_consistency=source.fingerprint.format_consistency,
            indicator_count=len(source.indicators),
            indicators_truncated=source.indicators_truncated,
        ),
        "classification": EvidenceClassification(
            semantics=EvidenceObservationSemantics.OBSERVED_FACT,
            factual_certainty=EvidenceVerificationStatus.INTEGRITY_VERIFIED,
        ),
        "quality": EvidenceQuality(
            overall=(
                EvidenceQualityState.INCOMPLETE
                if source.indicators_truncated
                else EvidenceQualityState.SUFFICIENT
            ),
            completeness=(
                EvidenceQualityState.INCOMPLETE
                if source.indicators_truncated
                else EvidenceQualityState.SUFFICIENT
            ),
            consistency=EvidenceQualityState.SUFFICIENT,
            temporal_precision=EvidencePrecision.EXACT,
            identity_strength=EvidenceIdentityStrength.CONTENT,
            provenance_availability=EvidenceQualityState.SUFFICIENT,
            verification_status=EvidenceVerificationStatus.INTEGRITY_VERIFIED,
        ),
        "context": EvidenceContext(
            timestamps=(
                EvidenceTimestamp(
                    meaning=EvidenceTimestampMeaning.ANALYSIS_STARTED_TIME,
                    value=source.created_at,
                    precision=EvidencePrecision.EXACT,
                ),
                EvidenceTimestamp(
                    meaning=EvidenceTimestampMeaning.ANALYSIS_COMPLETED_TIME,
                    value=source.completed_at,
                    precision=EvidencePrecision.EXACT,
                ),
            ),
            source_status=source.status,
            sensitive_fields_omitted=(
                "filename",
                "extracted_strings",
                "indicator_values",
            ),
        ),
        "limitations": limitations,
    }
    return _record(fields)


def adapt_ml_inference(source: MLInferenceResponse) -> EvidenceRecord:
    limitations = tuple(
        _limitation(item.code, item.description, source=True)
        for item in source.limitations
    ) + (
        _limitation(
            "model_version_unavailable",
            "The Phase 03 inference contract exposes model and experiment identifiers but no distinct model version.",
            source=False,
        ),
        _limitation(
            "inference_timestamp_unavailable",
            "The Phase 03 inference response does not expose a generation timestamp.",
            source=False,
        ),
    )
    fields: dict[str, object] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "source": EvidenceSource(
            module=EvidenceSourceModule.SYNTHETIC_ML,
            phase="03",
            source_schema_version="1.0.0",
        ),
        "provenance": EvidenceProvenance(
            source_analysis_id=source.inference_id,
            origin_type=EvidenceOriginType.SYNTHETIC_GENERATED,
            origin_verified=True,
            trust_classification=EvidenceTrustClassification.INTERNAL_DERIVATION,
            synthetic=True,
            integrity_verification=EvidenceVerificationStatus.STRUCTURALLY_VALID,
            generation_context=source.inference_mode,
        ),
        "subject": EvidenceSubjectReference(
            subject_type=EvidenceSubjectType.ANALYSIS,
            namespace="analysis_uuid",
            value=str(source.analysis_id),
            identity_strength=EvidenceIdentityStrength.ANALYSIS_SCOPED,
            verified=False,
            scope="phase03_input_analysis_reference",
        ),
        "observation": MLEvidenceObservation(
            model_id=source.model.model_id,
            model_version=None,
            dataset_id=source.model.dataset_id,
            dataset_integrity_digest=source.model.dataset_integrity_digest,
            output_label=source.prediction.label,
            benign_probability=source.prediction.probability_estimates.benign,
            malicious_probability=source.prediction.probability_estimates.malicious,
        ),
        "classification": EvidenceClassification(
            semantics=EvidenceObservationSemantics.EDUCATIONAL_PREDICTION,
            factual_certainty=EvidenceVerificationStatus.STRUCTURALLY_VALID,
        ),
        "quality": EvidenceQuality(
            overall=EvidenceQualityState.INCOMPLETE,
            completeness=EvidenceQualityState.INCOMPLETE,
            consistency=EvidenceQualityState.SUFFICIENT,
            temporal_precision=EvidencePrecision.NOT_AVAILABLE,
            identity_strength=EvidenceIdentityStrength.ANALYSIS_SCOPED,
            provenance_availability=EvidenceQualityState.SUFFICIENT,
            verification_status=EvidenceVerificationStatus.STRUCTURALLY_VALID,
        ),
        "context": EvidenceContext(
            timestamps=(),
            source_status=source.status,
            sensitive_fields_omitted=("input_feature_vector",),
        ),
        "limitations": limitations,
    }
    return _record(fields)


def adapt_vulnerability_intelligence(
    source: UnifiedVulnerabilityIntelligenceResponse,
) -> EvidenceRecord:
    timestamps = [
        EvidenceTimestamp(
            meaning=EvidenceTimestampMeaning.GENERATED_TIME,
            value=source.generated_at,
            precision=EvidencePrecision.EXACT,
        )
    ]
    nvd = source.sources.nvd
    if nvd.evidence is not None:
        if nvd.evidence.publication_date is not None:
            timestamps.append(
                EvidenceTimestamp(
                    meaning=EvidenceTimestampMeaning.INTELLIGENCE_PUBLICATION_TIME,
                    value=nvd.evidence.publication_date,
                    precision=EvidencePrecision.SOURCE_REPORTED,
                )
            )
        if nvd.evidence.last_modified_date is not None:
            timestamps.append(
                EvidenceTimestamp(
                    meaning=EvidenceTimestampMeaning.INTELLIGENCE_MODIFICATION_TIME,
                    value=nvd.evidence.last_modified_date,
                    precision=EvidencePrecision.SOURCE_REPORTED,
                )
            )
    retrievals = tuple(
        item
        for item in (
            source.sources.nvd.retrieved_at,
            source.sources.cisa_kev.retrieved_at,
            source.sources.first_epss.retrieved_at,
        )
        if item is not None
    )
    if retrievals:
        timestamps.append(
            EvidenceTimestamp(
                meaning=EvidenceTimestampMeaning.INTELLIGENCE_RETRIEVAL_TIME,
                value=max(retrievals),
                precision=EvidencePrecision.SOURCE_REPORTED,
            )
        )
    available = nvd.evidence
    source_limitations = (
        source.limitations
        + source.sources.nvd.limitations
        + source.sources.cisa_kev.limitations
        + source.sources.first_epss.limitations
    )
    limitations = tuple(
        _limitation(f"source_limitation_{index:02d}", item, source=True)
        for index, item in enumerate(dict.fromkeys(source_limitations), start=1)
    )
    limitations += (
        _limitation(
            "no_exploitation_claim",
            "Vulnerability intelligence does not demonstrate exploitation or compromise.",
            source=False,
        ),
        _limitation(
            "no_attack_mapping",
            "No CVE-to-ATT&CK association is inferred by evidence normalization.",
            source=False,
        ),
    )
    completeness = (
        EvidenceQualityState.SUFFICIENT
        if source.status is CorrelationStatus.COMPLETE
        else EvidenceQualityState.INCOMPLETE
    )
    fields: dict[str, object] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "source": EvidenceSource(
            module=EvidenceSourceModule.VULNERABILITY_INTELLIGENCE,
            phase="04",
            source_schema_version=source.schema_version,
        ),
        "provenance": EvidenceProvenance(
            source_analysis_id=source.correlation_id,
            origin_type=EvidenceOriginType.EXTERNAL_INTELLIGENCE,
            origin_verified=False,
            trust_classification=EvidenceTrustClassification.EXTERNAL_REPORTED,
            synthetic=False,
            integrity_verification=EvidenceVerificationStatus.ORIGIN_UNVERIFIED,
            generation_context="bounded_multi_provider_lookup",
        ),
        "subject": EvidenceSubjectReference(
            subject_type=EvidenceSubjectType.VULNERABILITY,
            namespace="cve",
            value=source.cve_id,
            identity_strength=EvidenceIdentityStrength.NAMESPACE_IDENTIFIER,
            verified=True,
            scope="public_vulnerability_identifier",
        ),
        "observation": VulnerabilityEvidenceObservation(
            cve_id=source.cve_id,
            nvd_status=source.sources.nvd.status,
            kev_status=source.sources.cisa_kev.status,
            epss_status=source.sources.first_epss.status,
            cvss_metric_count=(
                None if available is None else available.cvss_metric_count
            ),
            weakness_count=(None if available is None else available.weakness_count),
            cpe_configuration_count=(
                None if available is None else available.cpe_configuration_count
            ),
        ),
        "classification": EvidenceClassification(
            semantics=EvidenceObservationSemantics.EXTERNAL_INTELLIGENCE_REPORT,
            factual_certainty=EvidenceVerificationStatus.ORIGIN_UNVERIFIED,
        ),
        "quality": EvidenceQuality(
            overall=completeness,
            completeness=completeness,
            consistency=EvidenceQualityState.SUFFICIENT,
            temporal_precision=(
                EvidencePrecision.SOURCE_REPORTED
                if len(timestamps) > 1
                else EvidencePrecision.PARTIAL
            ),
            identity_strength=EvidenceIdentityStrength.NAMESPACE_IDENTIFIER,
            provenance_availability=EvidenceQualityState.UNVERIFIABLE_PROVENANCE,
            verification_status=EvidenceVerificationStatus.ORIGIN_UNVERIFIED,
        ),
        "context": EvidenceContext(
            timestamps=tuple(timestamps),
            source_status=source.status,
            sensitive_fields_omitted=("descriptions", "reference_urls", "cpe_values"),
        ),
        "limitations": limitations,
    }
    return _record(fields)


def adapt_behavioral_analysis(source: BehavioralAnalysisResult) -> EvidenceRecord:
    synthetic = source.source is BehavioralAnalysisSource.SYNTHETIC_SCENARIO
    origin = (
        EvidenceOriginType.SYNTHETIC_GENERATED
        if synthetic
        else EvidenceOriginType.CLIENT_DECLARED
    )
    completeness = (
        EvidenceQualityState.SUFFICIENT
        if source.status is BehavioralAnalysisStatus.COMPLETE
        else EvidenceQualityState.INCOMPLETE
    )
    limitations = tuple(
        _limitation(f"source_limitation_{index:02d}", item, source=True)
        for index, item in enumerate(dict.fromkeys(source.limitations), start=1)
    ) + (
        _limitation(
            "non_causal_temporal_relationships",
            "Temporal relationships do not establish causality.",
            source=False,
        ),
        _limitation(
            "attack_candidates_not_confirmations",
            "ATT&CK mapping candidates are not confirmed attacks.",
            source=False,
        ),
        _limitation(
            "event_times_not_reproduced",
            "Raw event timestamps and sensitive telemetry are minimized from this evidence record.",
            source=False,
        ),
    )
    fields: dict[str, object] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "source": EvidenceSource(
            module=EvidenceSourceModule.BEHAVIORAL_ANALYSIS,
            phase="05",
            source_schema_version=source.schema_version,
        ),
        "provenance": EvidenceProvenance(
            source_analysis_id=source.analysis_id,
            origin_type=origin,
            origin_verified=synthetic,
            trust_classification=EvidenceTrustClassification.DERIVED_EVIDENCE,
            synthetic=synthetic,
            integrity_verification=EvidenceVerificationStatus.STRUCTURALLY_VALID,
            generation_context=source.source,
        ),
        "subject": EvidenceSubjectReference(
            subject_type=EvidenceSubjectType.BEHAVIORAL_ANALYSIS,
            namespace="analysis_uuid",
            value=str(source.analysis_id),
            identity_strength=EvidenceIdentityStrength.ANALYSIS_SCOPED,
            verified=True,
            scope="phase05_analysis_only",
        ),
        "observation": BehavioralEvidenceObservation(
            analysis_status=source.status,
            submitted_events=source.event_summary.submitted_events,
            matched_rules=source.summary.matched_rules,
            temporal_relationships=source.summary.temporal_relationships,
            mapping_candidates=source.summary.mapping_candidates,
            unknowns=source.summary.unknowns,
        ),
        "classification": EvidenceClassification(
            semantics=EvidenceObservationSemantics.BEHAVIORAL_ASSESSMENT,
            factual_certainty=EvidenceVerificationStatus.STRUCTURALLY_VALID,
        ),
        "quality": EvidenceQuality(
            overall=completeness,
            completeness=completeness,
            consistency=(
                EvidenceQualityState.CONTRADICTORY
                if any("contradict" in item.lower() for item in source.limitations)
                else EvidenceQualityState.SUFFICIENT
            ),
            temporal_precision=EvidencePrecision.PARTIAL,
            identity_strength=EvidenceIdentityStrength.ANALYSIS_SCOPED,
            provenance_availability=EvidenceQualityState.SUFFICIENT,
            verification_status=EvidenceVerificationStatus.STRUCTURALLY_VALID,
        ),
        "context": EvidenceContext(
            timestamps=(
                EvidenceTimestamp(
                    meaning=EvidenceTimestampMeaning.GENERATED_TIME,
                    value=source.generated_at,
                    precision=EvidencePrecision.EXACT,
                ),
            ),
            source_status=source.status,
            sensitive_fields_omitted=(
                "events",
                "host_ids",
                "command_lines",
                "file_paths",
                "usernames",
                "ip_addresses",
                "configuration_targets",
            ),
        ),
        "limitations": limitations,
    }
    return _record(fields)


def create_evidence_batch(records: tuple[EvidenceRecord, ...]) -> EvidenceBatch:
    ordered = tuple(sorted(records, key=lambda item: item.identifier.evidence_id))
    identity = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "record_ids": [item.identifier.evidence_id for item in ordered],
    }
    return EvidenceBatch(batch_id=f"evb_{_canonical_digest(identity)}", records=ordered)


def get_evidence_schema_descriptor() -> EvidenceSchemaDescriptor:
    return EvidenceSchemaDescriptor(
        source_modules=tuple(EvidenceSourceModule),
        origin_types=tuple(EvidenceOriginType),
        trust_classifications=tuple(EvidenceTrustClassification),
        maximum_records_per_batch=256,
        maximum_record_bytes=32 * 1024,
        maximum_batch_bytes=1024 * 1024,
        maximum_references_per_record=16,
        maximum_nesting_depth=8,
    )


Adapter = Callable[[Any], EvidenceRecord]


def normalize_source_output(
    source_module: str | EvidenceSourceModule,
    source_schema_version: str,
    output: object,
) -> EvidenceRecord:
    try:
        module = EvidenceSourceModule(source_module)
    except ValueError as exc:
        raise UnsupportedSourceModuleError(
            f"unsupported evidence source module: {source_module}"
        ) from exc
    if source_schema_version != EVIDENCE_SCHEMA_VERSION:
        raise UnsupportedSourceSchemaError(
            f"unsupported {module.value} schema version: {source_schema_version}"
        )
    adapters: dict[EvidenceSourceModule, tuple[type[BaseModel], Adapter]] = {
        EvidenceSourceModule.STATIC_ANALYSIS: (
            StaticAnalysisResponse,
            adapt_static_analysis,
        ),
        EvidenceSourceModule.SYNTHETIC_ML: (MLInferenceResponse, adapt_ml_inference),
        EvidenceSourceModule.VULNERABILITY_INTELLIGENCE: (
            UnifiedVulnerabilityIntelligenceResponse,
            adapt_vulnerability_intelligence,
        ),
        EvidenceSourceModule.BEHAVIORAL_ANALYSIS: (
            BehavioralAnalysisResult,
            adapt_behavioral_analysis,
        ),
    }
    expected, adapter = adapters[module]
    if not isinstance(output, expected):
        raise SourceContractMismatchError(
            f"{module.value} requires {expected.__name__}, not {type(output).__name__}"
        )
    return adapter(output)
