from __future__ import annotations

import hashlib
import json

from pydantic import BaseModel, ValidationError

from app.evidence.adapters import create_evidence_batch
from app.schemas.evidence import (
    EVIDENCE_SCHEMA_VERSION,
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
from app.schemas.multilayer_analysis import (
    DeclaredMLInput,
    DeclaredStaticInput,
    DeclaredVulnerabilityInput,
    MultilayerAnalysisRequest,
    MultilayerEvidenceReference,
)


class MultilayerAdmissionError(ValueError):
    """A declared source cannot be safely normalized."""


def _canonical_digest(value: object) -> str:
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
    identifier = EvidenceIdentifier(evidence_id=f"evd_{_canonical_digest(fields)}")
    return EvidenceRecord(identifier=identifier, references=(), **fields)


def _common(
    source: DeclaredStaticInput | DeclaredVulnerabilityInput | DeclaredMLInput,
    *,
    module: EvidenceSourceModule,
    phase: str,
    subject: EvidenceSubjectReference,
    observation: object,
    semantics: EvidenceObservationSemantics,
    limitations: tuple[EvidenceLimitation, ...],
) -> EvidenceRecord:
    fields: dict[str, object] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "source": EvidenceSource(
            module=module, phase=phase, source_schema_version="1.0.0"
        ),
        "provenance": EvidenceProvenance(
            source_analysis_id=source.analysis_context_id,
            origin_type=EvidenceOriginType.CLIENT_DECLARED,
            origin_verified=False,
            trust_classification=EvidenceTrustClassification.CLIENT_DECLARED,
            synthetic=False,
            integrity_verification=EvidenceVerificationStatus.ORIGIN_UNVERIFIED,
            generation_context=f"multilayer_http_{source.input_type.value}",
        ),
        "subject": subject,
        "observation": observation,
        "classification": EvidenceClassification(
            semantics=semantics,
            factual_certainty=EvidenceVerificationStatus.ORIGIN_UNVERIFIED,
        ),
        "quality": EvidenceQuality(
            overall=EvidenceQualityState.INCOMPLETE,
            completeness=EvidenceQualityState.INCOMPLETE,
            consistency=EvidenceQualityState.SUFFICIENT,
            temporal_precision=EvidencePrecision.NOT_AVAILABLE,
            identity_strength=EvidenceIdentityStrength.DECLARED,
            provenance_availability=EvidenceQualityState.UNVERIFIABLE_PROVENANCE,
            verification_status=EvidenceVerificationStatus.ORIGIN_UNVERIFIED,
        ),
        "context": EvidenceContext(
            timestamps=(),
            source_status="client_declared",
            sensitive_fields_omitted=(
                "paths",
                "commands",
                "users",
                "hosts",
                "network_values",
                "raw_payloads",
            ),
        ),
        "limitations": limitations,
    }
    return _record(fields)


def _static(source: DeclaredStaticInput) -> EvidenceRecord:
    return _common(
        source,
        module=EvidenceSourceModule.STATIC_ANALYSIS,
        phase="02",
        subject=EvidenceSubjectReference(
            subject_type=EvidenceSubjectType.FILE_CONTENT,
            namespace="sha256",
            value=source.sha256,
            identity_strength=EvidenceIdentityStrength.DECLARED,
            verified=False,
            scope="client_declared_sha256",
        ),
        observation=StaticEvidenceObservation(
            sha256=source.sha256,
            size_bytes=source.size_bytes,
            detected_format="unknown",
            format_consistency="unknown",
            indicator_count=0,
            indicators_truncated=False,
        ),
        semantics=EvidenceObservationSemantics.OBSERVED_FACT,
        limitations=(
            EvidenceLimitation(
                code="client_declared_digest",
                description="The digest and size were declared by the client and were not computed from bytes by this endpoint.",
                source_declared=True,
            ),
            EvidenceLimitation(
                code="no_execution_or_malware_claim",
                description="Digest equality does not establish execution, origin, maliciousness, or compromise.",
                source_declared=False,
            ),
        ),
    )


def _vulnerability(source: DeclaredVulnerabilityInput) -> EvidenceRecord:
    return _common(
        source,
        module=EvidenceSourceModule.VULNERABILITY_INTELLIGENCE,
        phase="04",
        subject=EvidenceSubjectReference(
            subject_type=EvidenceSubjectType.VULNERABILITY,
            namespace="cve",
            value=source.cve_id,
            identity_strength=EvidenceIdentityStrength.DECLARED,
            verified=False,
            scope="client_declared_cve",
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
        semantics=EvidenceObservationSemantics.EXTERNAL_INTELLIGENCE_REPORT,
        limitations=(
            EvidenceLimitation(
                code="client_declared_cve",
                description="The CVE identifier was declared by the client; no intelligence provider was queried.",
                source_declared=True,
            ),
            EvidenceLimitation(
                code="no_exploitation_claim",
                description="CVE identity does not establish installation, exposure, exploitation, or compromise.",
                source_declared=False,
            ),
        ),
    )


def _ml(source: DeclaredMLInput) -> EvidenceRecord:
    return _common(
        source,
        module=EvidenceSourceModule.SYNTHETIC_ML,
        phase="03",
        subject=EvidenceSubjectReference(
            subject_type=EvidenceSubjectType.ANALYSIS,
            namespace="analysis_uuid",
            value=str(source.analysis_context_id),
            identity_strength=EvidenceIdentityStrength.DECLARED,
            verified=False,
            scope="client_declared_phase03_analysis",
        ),
        observation=MLEvidenceObservation(
            model_id=source.model_id,
            model_version=source.model_version,
            dataset_id=source.dataset_id,
            dataset_integrity_digest=source.dataset_integrity_digest,
            output_label=source.output_label,
            benign_probability=source.benign_probability,
            malicious_probability=source.malicious_probability,
        ),
        semantics=EvidenceObservationSemantics.EDUCATIONAL_PREDICTION,
        limitations=(
            EvidenceLimitation(
                code="client_declared_ml_output",
                description="The model metadata and prediction were declared by the client and were not executed by this endpoint.",
                source_declared=True,
            ),
            EvidenceLimitation(
                code="no_malware_confirmation",
                description="A declared model label is not an observed fact, malware detection, or operational validation.",
                source_declared=False,
            ),
        ),
    )


def admit_sources(
    request: MultilayerAnalysisRequest,
) -> tuple[
    EvidenceBatch,
    dict[str, str],
    tuple[MultilayerEvidenceReference, ...],
]:
    records_by_source: dict[str, EvidenceRecord] = {}
    try:
        for source in request.sources:
            if isinstance(source, DeclaredStaticInput):
                record = _static(source)
            elif isinstance(source, DeclaredVulnerabilityInput):
                record = _vulnerability(source)
            else:
                record = _ml(source)
            records_by_source[source.source_id] = record
        records = tuple(records_by_source.values())
        if len({item.identifier.evidence_id for item in records}) != len(records):
            raise MultilayerAdmissionError(
                "Declared sources must produce distinct evidence records."
            )
        batch = create_evidence_batch(records)
    except (ValidationError, ValueError) as error:
        if isinstance(error, MultilayerAdmissionError):
            raise
        raise MultilayerAdmissionError(
            "A declared source could not be normalized safely."
        ) from error
    source_to_evidence = {
        source_id: record.identifier.evidence_id
        for source_id, record in records_by_source.items()
    }
    references = tuple(
        sorted(
            (
                MultilayerEvidenceReference(
                    source_id=source_id,
                    evidence_id=record.identifier.evidence_id,
                    domain=record.observation.domain,
                )
                for source_id, record in records_by_source.items()
            ),
            key=lambda item: item.evidence_id,
        )
    )
    return batch, source_to_evidence, references
