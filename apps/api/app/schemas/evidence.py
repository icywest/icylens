from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Annotated, Literal, Self, TypeAlias
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.schemas.vulnerability import StrictContract, normalize_utc

EVIDENCE_SCHEMA_VERSION = "1.0.0"
MAX_EVIDENCE_RECORDS_PER_BATCH = 256
MAX_EVIDENCE_RECORD_BYTES = 32 * 1024
MAX_EVIDENCE_BATCH_BYTES = 1024 * 1024
MAX_EVIDENCE_REFERENCES = 16
MAX_EVIDENCE_LIMITATIONS = 32
MAX_EVIDENCE_TIMESTAMPS = 8
MAX_EVIDENCE_STRING_LENGTH = 512
MAX_EVIDENCE_NESTING_DEPTH = 8

EvidenceId: TypeAlias = Annotated[
    str, Field(pattern=r"^evd_[0-9a-f]{64}$", max_length=68)
]
EvidenceBatchId: TypeAlias = Annotated[
    str, Field(pattern=r"^evb_[0-9a-f]{64}$", max_length=68)
]


class EvidenceSchemaVersion(str, Enum):
    V1_0_0 = EVIDENCE_SCHEMA_VERSION


class EvidenceDomain(str, Enum):
    STATIC = "static"
    SYNTHETIC_ML = "synthetic_ml"
    VULNERABILITY = "vulnerability"
    BEHAVIORAL = "behavioral"


class EvidenceSourceModule(str, Enum):
    STATIC_ANALYSIS = "static_analysis"
    SYNTHETIC_ML = "synthetic_ml"
    VULNERABILITY_INTELLIGENCE = "vulnerability_intelligence"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"


class EvidenceOriginType(str, Enum):
    SYNTHETIC_GENERATED = "synthetic_generated"
    CLIENT_DECLARED = "client_declared"
    LOCALLY_DERIVED = "locally_derived"
    EXTERNAL_INTELLIGENCE = "external_intelligence"


class EvidenceTrustClassification(str, Enum):
    CLIENT_DECLARED = "client_declared"
    INTERNAL_DERIVATION = "internal_derivation"
    DERIVED_EVIDENCE = "derived_evidence"
    EXTERNAL_REPORTED = "external_reported"
    VERSIONED_KNOWLEDGE = "versioned_knowledge"


class EvidenceObservationSemantics(str, Enum):
    OBSERVED_FACT = "observed_fact"
    EDUCATIONAL_PREDICTION = "educational_prediction"
    EXTERNAL_INTELLIGENCE_REPORT = "external_intelligence_report"
    BEHAVIORAL_ASSESSMENT = "behavioral_assessment"


class EvidenceVerificationStatus(str, Enum):
    STRUCTURALLY_VALID = "structurally_valid"
    INTEGRITY_VERIFIED = "integrity_verified"
    ORIGIN_UNVERIFIED = "origin_unverified"
    PARTIAL = "partial"
    CONTRADICTORY = "contradictory"
    NOT_APPLICABLE = "not_applicable"


class EvidenceQualityState(str, Enum):
    SUFFICIENT = "sufficient"
    INCOMPLETE = "incomplete"
    CONTRADICTORY = "contradictory"
    NOT_APPLICABLE = "not_applicable"
    UNVERIFIABLE_PROVENANCE = "unverifiable_provenance"


class EvidencePrecision(str, Enum):
    EXACT = "exact"
    SOURCE_REPORTED = "source_reported"
    PARTIAL = "partial"
    NOT_AVAILABLE = "not_available"


class EvidenceIdentityStrength(str, Enum):
    CONTENT = "content"
    NAMESPACE_IDENTIFIER = "namespace_identifier"
    ANALYSIS_SCOPED = "analysis_scoped"
    DECLARED = "declared"
    MISSING = "missing"


class EvidenceSubjectType(str, Enum):
    FILE_CONTENT = "file_content"
    ANALYSIS = "analysis"
    VULNERABILITY = "vulnerability"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"


class EvidenceTimestampMeaning(str, Enum):
    EVENT_TIME = "event_time"
    OBSERVED_TIME = "observed_time"
    RECEIVED_TIME = "received_time"
    GENERATED_TIME = "generated_time"
    ANALYSIS_STARTED_TIME = "analysis_started_time"
    ANALYSIS_COMPLETED_TIME = "analysis_completed_time"
    INTELLIGENCE_PUBLICATION_TIME = "intelligence_publication_time"
    INTELLIGENCE_MODIFICATION_TIME = "intelligence_modification_time"
    INTELLIGENCE_RETRIEVAL_TIME = "intelligence_retrieval_time"


class EvidenceReferenceType(str, Enum):
    EXPLICIT_SAME_SUBJECT = "explicit_same_subject"
    EXPLICIT_DERIVATION = "explicit_derivation"


class EvidenceIdentifier(StrictContract):
    evidence_id: EvidenceId
    algorithm: Literal["sha256-canonical-json-v1"] = "sha256-canonical-json-v1"
    deterministic: Literal[True] = True


class EvidenceSource(StrictContract):
    module: EvidenceSourceModule
    phase: Literal["02", "03", "04", "05"]
    source_schema_version: Annotated[str, Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]

    @model_validator(mode="after")
    def require_phase_module_pair(self) -> Self:
        expected = {
            EvidenceSourceModule.STATIC_ANALYSIS: "02",
            EvidenceSourceModule.SYNTHETIC_ML: "03",
            EvidenceSourceModule.VULNERABILITY_INTELLIGENCE: "04",
            EvidenceSourceModule.BEHAVIORAL_ANALYSIS: "05",
        }
        if expected[self.module] != self.phase:
            raise ValueError("source module and phase are inconsistent")
        return self


class EvidenceProvenance(StrictContract):
    source_analysis_id: UUID
    origin_type: EvidenceOriginType
    origin_verified: bool
    trust_classification: EvidenceTrustClassification
    synthetic: bool
    integrity_verification: EvidenceVerificationStatus
    generation_context: Annotated[str, Field(min_length=1, max_length=128)]

    @model_validator(mode="after")
    def reject_trust_elevation(self) -> Self:
        allowed = {
            EvidenceOriginType.CLIENT_DECLARED: {
                EvidenceTrustClassification.CLIENT_DECLARED,
                EvidenceTrustClassification.DERIVED_EVIDENCE,
            },
            EvidenceOriginType.SYNTHETIC_GENERATED: {
                EvidenceTrustClassification.INTERNAL_DERIVATION,
                EvidenceTrustClassification.DERIVED_EVIDENCE,
            },
            EvidenceOriginType.LOCALLY_DERIVED: {
                EvidenceTrustClassification.INTERNAL_DERIVATION,
                EvidenceTrustClassification.DERIVED_EVIDENCE,
            },
            EvidenceOriginType.EXTERNAL_INTELLIGENCE: {
                EvidenceTrustClassification.EXTERNAL_REPORTED,
                EvidenceTrustClassification.VERSIONED_KNOWLEDGE,
            },
        }
        if self.trust_classification not in allowed[self.origin_type]:
            raise ValueError("origin cannot be elevated to the requested trust class")
        if (
            self.origin_type is EvidenceOriginType.CLIENT_DECLARED
            and self.origin_verified
        ):
            raise ValueError("client-declared origin cannot be marked verified")
        if (
            self.origin_type is EvidenceOriginType.EXTERNAL_INTELLIGENCE
            and self.origin_verified
        ):
            raise ValueError(
                "external intelligence origin is not cryptographically verified"
            )
        if self.synthetic != (
            self.origin_type is EvidenceOriginType.SYNTHETIC_GENERATED
        ):
            raise ValueError("synthetic status and origin type are inconsistent")
        return self


class EvidenceSubjectReference(StrictContract):
    subject_type: EvidenceSubjectType
    namespace: Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{1,63}$")]
    value: Annotated[str, Field(min_length=1, max_length=128)]
    identity_strength: EvidenceIdentityStrength
    verified: bool
    scope: Annotated[str, Field(min_length=1, max_length=128)]


class EvidenceTimestamp(StrictContract):
    meaning: EvidenceTimestampMeaning
    value: datetime
    precision: EvidencePrecision

    _utc = field_validator("value")(normalize_utc)


class StaticEvidenceObservation(StrictContract):
    domain: Literal[EvidenceDomain.STATIC] = EvidenceDomain.STATIC
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    size_bytes: Annotated[int, Field(gt=0)]
    detected_format: Annotated[str, Field(min_length=1, max_length=32)]
    format_consistency: Annotated[str, Field(min_length=1, max_length=32)]
    indicator_count: Annotated[int, Field(ge=0)]
    indicators_truncated: bool
    execution_observed: Literal[False] = False


class MLEvidenceObservation(StrictContract):
    domain: Literal[EvidenceDomain.SYNTHETIC_ML] = EvidenceDomain.SYNTHETIC_ML
    model_id: Annotated[str, Field(min_length=1, max_length=64)]
    model_version: Annotated[str | None, Field(default=None, max_length=64)]
    dataset_id: Annotated[str, Field(min_length=1, max_length=128)]
    dataset_integrity_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    prediction_type: Literal["binary_classification"] = "binary_classification"
    output_label: Literal["benign", "malicious"]
    benign_probability: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    malicious_probability: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    probability_calibrated: Literal[False] = False
    confirmed_fact: Literal[False] = False


class VulnerabilityEvidenceObservation(StrictContract):
    domain: Literal[EvidenceDomain.VULNERABILITY] = EvidenceDomain.VULNERABILITY
    cve_id: Annotated[str, Field(pattern=r"^CVE-(?:1999|2\d{3})-\d{4,}$")]
    nvd_status: Annotated[str, Field(min_length=1, max_length=32)]
    kev_status: Annotated[str, Field(min_length=1, max_length=32)]
    epss_status: Annotated[str, Field(min_length=1, max_length=32)]
    cvss_metric_count: Annotated[int | None, Field(default=None, ge=0)]
    weakness_count: Annotated[int | None, Field(default=None, ge=0)]
    cpe_configuration_count: Annotated[int | None, Field(default=None, ge=0)]
    exploitation_observed: Literal[False] = False
    attack_mapping_performed: Literal[False] = False


class BehavioralEvidenceObservation(StrictContract):
    domain: Literal[EvidenceDomain.BEHAVIORAL] = EvidenceDomain.BEHAVIORAL
    analysis_status: Annotated[str, Field(min_length=1, max_length=32)]
    submitted_events: Annotated[int, Field(ge=0)]
    matched_rules: Annotated[int, Field(ge=0)]
    temporal_relationships: Annotated[int, Field(ge=0)]
    mapping_candidates: Annotated[int, Field(ge=0)]
    unknowns: Annotated[int, Field(ge=0)]
    attack_confirmed: Literal[False] = False
    malware_detected: Literal[False] = False
    causal_inference_performed: Literal[False] = False


EvidenceObservation: TypeAlias = Annotated[
    StaticEvidenceObservation
    | MLEvidenceObservation
    | VulnerabilityEvidenceObservation
    | BehavioralEvidenceObservation,
    Field(discriminator="domain"),
]


class EvidenceClassification(StrictContract):
    semantics: EvidenceObservationSemantics
    factual_certainty: EvidenceVerificationStatus
    threat_verdict: Literal[False] = False
    operational_detection: Literal[False] = False


class EvidenceLimitation(StrictContract):
    code: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")]
    description: Annotated[
        str, Field(min_length=1, max_length=MAX_EVIDENCE_STRING_LENGTH)
    ]
    source_declared: bool


class EvidenceQuality(StrictContract):
    overall: EvidenceQualityState
    completeness: EvidenceQualityState
    consistency: EvidenceQualityState
    temporal_precision: EvidencePrecision
    identity_strength: EvidenceIdentityStrength
    provenance_availability: EvidenceQualityState
    verification_status: EvidenceVerificationStatus


class EvidenceContext(StrictContract):
    timestamps: Annotated[
        tuple[EvidenceTimestamp, ...], Field(max_length=MAX_EVIDENCE_TIMESTAMPS)
    ]
    source_status: Annotated[str, Field(min_length=1, max_length=64)]
    sensitive_fields_omitted: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=64)], ...],
        Field(max_length=16),
    ]

    @model_validator(mode="after")
    def reject_duplicate_clock_meanings(self) -> Self:
        meanings = [item.meaning for item in self.timestamps]
        if len(meanings) != len(set(meanings)):
            raise ValueError("timestamp meanings must be unique")
        return self


class EvidenceReferenceProvenance(StrictContract):
    established_by: Literal["explicit_source_contract", "backend_validation"]
    origin_type: EvidenceOriginType
    description: Annotated[str, Field(min_length=1, max_length=256)]


class EvidenceReference(StrictContract):
    source_evidence_id: EvidenceId
    referenced_evidence_id: EvidenceId
    reference_type: EvidenceReferenceType
    provenance: EvidenceReferenceProvenance
    identity_assumptions: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...],
        Field(min_length=1, max_length=8),
    ]
    verification_status: EvidenceVerificationStatus

    @model_validator(mode="after")
    def reject_self_reference(self) -> Self:
        if self.source_evidence_id == self.referenced_evidence_id:
            raise ValueError("evidence cannot reference itself")
        return self


class EvidenceRecord(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    identifier: EvidenceIdentifier
    source: EvidenceSource
    provenance: EvidenceProvenance
    subject: EvidenceSubjectReference
    observation: EvidenceObservation
    classification: EvidenceClassification
    quality: EvidenceQuality
    context: EvidenceContext
    limitations: Annotated[
        tuple[EvidenceLimitation, ...], Field(max_length=MAX_EVIDENCE_LIMITATIONS)
    ]
    references: Annotated[
        tuple[EvidenceReference, ...], Field(max_length=MAX_EVIDENCE_REFERENCES)
    ] = ()

    @model_validator(mode="after")
    def enforce_domain_and_size(self) -> Self:
        expected = {
            EvidenceSourceModule.STATIC_ANALYSIS: EvidenceDomain.STATIC,
            EvidenceSourceModule.SYNTHETIC_ML: EvidenceDomain.SYNTHETIC_ML,
            EvidenceSourceModule.VULNERABILITY_INTELLIGENCE: EvidenceDomain.VULNERABILITY,
            EvidenceSourceModule.BEHAVIORAL_ANALYSIS: EvidenceDomain.BEHAVIORAL,
        }
        if self.observation.domain is not expected[self.source.module]:
            raise ValueError("source module and observation domain are inconsistent")
        if any(
            item.source_evidence_id != self.identifier.evidence_id
            for item in self.references
        ):
            raise ValueError("reference source must equal its containing evidence ID")
        identity_payload = self.model_dump(
            mode="json", exclude={"identifier", "references"}
        )
        canonical = json.dumps(
            identity_payload, sort_keys=True, separators=(",", ":")
        ).encode()
        expected_id = f"evd_{hashlib.sha256(canonical).hexdigest()}"
        if self.identifier.evidence_id != expected_id:
            raise ValueError("evidence ID does not match canonical record content")
        encoded = json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
        if len(encoded) > MAX_EVIDENCE_RECORD_BYTES:
            raise ValueError("evidence record exceeds the serialized size limit")
        return self


class EvidenceBatch(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    batch_id: EvidenceBatchId
    records: Annotated[
        tuple[EvidenceRecord, ...],
        Field(min_length=1, max_length=MAX_EVIDENCE_RECORDS_PER_BATCH),
    ]
    deterministic_ordering: Literal["evidence_id_ascending"] = "evidence_id_ascending"
    persisted: Literal[False] = False
    correlation_performed: Literal[False] = False
    assessment_performed: Literal[False] = False

    @model_validator(mode="after")
    def enforce_batch_invariants(self) -> Self:
        identifiers = [item.identifier.evidence_id for item in self.records]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("evidence IDs must be unique within a batch")
        if identifiers != sorted(identifiers):
            raise ValueError("evidence records must use deterministic ID ordering")
        known = set(identifiers)
        graph: dict[str, tuple[str, ...]] = {}
        subjects = {item.identifier.evidence_id: item.subject for item in self.records}
        for record in self.records:
            identity_payload = record.model_dump(
                mode="json", exclude={"identifier", "references"}
            )
            canonical_record = json.dumps(
                identity_payload, sort_keys=True, separators=(",", ":")
            ).encode()
            expected_record_id = f"evd_{hashlib.sha256(canonical_record).hexdigest()}"
            if record.identifier.evidence_id != expected_record_id:
                raise ValueError(
                    "batch record ID does not match canonical record content"
                )
            encoded_record = json.dumps(
                record.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            if len(encoded_record) > MAX_EVIDENCE_RECORD_BYTES:
                raise ValueError("batch contains an oversized evidence record")
            targets = tuple(item.referenced_evidence_id for item in record.references)
            if not set(targets).issubset(known):
                raise ValueError("references must resolve inside the evidence batch")
            graph[record.identifier.evidence_id] = targets
            for reference in record.references:
                if (
                    reference.reference_type
                    is EvidenceReferenceType.EXPLICIT_SAME_SUBJECT
                    and subjects[record.identifier.evidence_id]
                    != subjects[reference.referenced_evidence_id]
                ):
                    raise ValueError("same-subject reference has an identity mismatch")
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node: str) -> None:
            if node in visiting:
                raise ValueError("circular evidence references are not allowed")
            if node in visited:
                return
            visiting.add(node)
            for target in graph[node]:
                visit(target)
            visiting.remove(node)
            visited.add(node)

        for identifier in identifiers:
            visit(identifier)
        canonical = json.dumps(
            {
                "schema_version": self.schema_version,
                "record_ids": identifiers,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        expected_batch_id = f"evb_{hashlib.sha256(canonical).hexdigest()}"
        if self.batch_id != expected_batch_id:
            raise ValueError("batch ID does not match canonical record identities")
        encoded = json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
        if len(encoded) > MAX_EVIDENCE_BATCH_BYTES:
            raise ValueError("evidence batch exceeds the serialized size limit")
        return self


class EvidenceSchemaDescriptor(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    source_modules: tuple[EvidenceSourceModule, ...]
    origin_types: tuple[EvidenceOriginType, ...]
    trust_classifications: tuple[EvidenceTrustClassification, ...]
    maximum_records_per_batch: int
    maximum_record_bytes: int
    maximum_batch_bytes: int
    maximum_references_per_record: int
    maximum_nesting_depth: int
    persistence: Literal[False] = False
    correlation: Literal[False] = False
    inferred_references: Literal[False] = False
