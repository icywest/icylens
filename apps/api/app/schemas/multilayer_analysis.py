from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Annotated, Literal, Self, TypeAlias
from uuid import UUID

from pydantic import Field, model_validator

from app.schemas.correlation import (
    CorrelationRelationshipType,
    CorrelationStatus,
    CorrelationSummary,
)
from app.schemas.evidence import (
    EvidenceDomain,
    EvidenceId,
    EvidenceOriginType,
    EvidenceTrustClassification,
)
from app.schemas.explainability import DecisionTrace
from app.schemas.identity import IdentityResolutionSummary
from app.schemas.sufficiency import SufficiencyState, SufficiencySummary
from app.schemas.vulnerability import StrictContract, normalize_cve_id

MULTILAYER_ANALYSIS_SCHEMA_VERSION = "1.0.0"
MAX_MULTILAYER_REQUEST_BYTES = 256 * 1024
MAX_MULTILAYER_RESPONSE_BYTES = 1024 * 1024
MAX_MULTILAYER_SOURCES = 16
MAX_MULTILAYER_ASSERTIONS = 32
MULTILAYER_OPERATION_TIMEOUT_SECONDS = 4.0
MULTILAYER_MAX_CONCURRENCY = 4

SourceId: TypeAlias = Annotated[
    str, Field(pattern=r"^src_[a-z0-9][a-z0-9_-]{0,47}$", max_length=52)
]


def multilayer_content_id(prefix: str, value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return f"{prefix}_{hashlib.sha256(encoded).hexdigest()}"


class MultilayerInputType(str, Enum):
    DECLARED_STATIC = "declared_static"
    DECLARED_VULNERABILITY = "declared_vulnerability"
    DECLARED_ML = "declared_ml"


class MultilayerResponseMode(str, Enum):
    EXPLAINABLE = "explainable"


class DeclaredStaticInput(StrictContract):
    input_type: Literal[MultilayerInputType.DECLARED_STATIC] = (
        MultilayerInputType.DECLARED_STATIC
    )
    source_id: SourceId
    analysis_context_id: UUID
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    size_bytes: Annotated[int, Field(gt=0, le=1024 * 1024 * 1024)]


class DeclaredVulnerabilityInput(StrictContract):
    input_type: Literal[MultilayerInputType.DECLARED_VULNERABILITY] = (
        MultilayerInputType.DECLARED_VULNERABILITY
    )
    source_id: SourceId
    analysis_context_id: UUID
    cve_id: Annotated[str, Field(pattern=r"^CVE-(?:1999|2\d{3})-\d{4,}$")]

    @model_validator(mode="after")
    def normalize_identifier(self) -> Self:
        if self.cve_id != normalize_cve_id(self.cve_id):
            raise ValueError("CVE ID must use canonical uppercase form")
        return self


class DeclaredMLInput(StrictContract):
    input_type: Literal[MultilayerInputType.DECLARED_ML] = (
        MultilayerInputType.DECLARED_ML
    )
    source_id: SourceId
    analysis_context_id: UUID
    model_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
    model_version: Annotated[str | None, Field(default=None, max_length=64)]
    dataset_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")]
    dataset_integrity_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    output_label: Literal["benign", "malicious"]
    benign_probability: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    malicious_probability: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]

    @model_validator(mode="after")
    def validate_probability_pair(self) -> Self:
        if abs(self.benign_probability + self.malicious_probability - 1.0) > 1e-9:
            raise ValueError("declared probability values must sum to one")
        return self


MultilayerInputSource: TypeAlias = Annotated[
    DeclaredStaticInput | DeclaredVulnerabilityInput | DeclaredMLInput,
    Field(discriminator="input_type"),
]


class MultilayerAnalysisOptions(StrictContract):
    response_mode: Literal[MultilayerResponseMode.EXPLAINABLE] = (
        MultilayerResponseMode.EXPLAINABLE
    )


class MultilayerAssertionSelection(StrictContract):
    assertion_id: Annotated[str, Field(pattern=r"^AS-[A-Z]+-[0-9]{3}$")]
    source_ids: Annotated[
        tuple[SourceId, ...], Field(min_length=1, max_length=MAX_MULTILAYER_SOURCES)
    ]

    @model_validator(mode="after")
    def reject_duplicate_sources(self) -> Self:
        if len(self.source_ids) != len(set(self.source_ids)):
            raise ValueError("assertion source IDs must be unique")
        return self


class MultilayerAnalysisContext(StrictContract):
    scope: Literal["educational_local"] = "educational_local"
    client_inputs_are_declared: Literal[True] = True
    origin_authentication_provided: Literal[False] = False


class MultilayerAnalysisRequest(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    sources: Annotated[
        tuple[MultilayerInputSource, ...],
        Field(min_length=1, max_length=MAX_MULTILAYER_SOURCES),
    ]
    assertions: Annotated[
        tuple[MultilayerAssertionSelection, ...],
        Field(min_length=1, max_length=MAX_MULTILAYER_ASSERTIONS),
    ]
    options: MultilayerAnalysisOptions = MultilayerAnalysisOptions()
    context: MultilayerAnalysisContext = MultilayerAnalysisContext()

    @model_validator(mode="after")
    def enforce_uniqueness(self) -> Self:
        source_ids = tuple(item.source_id for item in self.sources)
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("multilayer source IDs must be unique")
        selections = tuple(
            (item.assertion_id, tuple(sorted(item.source_ids)))
            for item in self.assertions
        )
        if len(selections) != len(set(selections)):
            raise ValueError("multilayer assertion selections must be unique")
        return self


class MultilayerEvidenceReference(StrictContract):
    source_id: SourceId
    evidence_id: EvidenceId
    domain: EvidenceDomain
    origin_type: Literal[EvidenceOriginType.CLIENT_DECLARED] = (
        EvidenceOriginType.CLIENT_DECLARED
    )
    trust_classification: Literal[EvidenceTrustClassification.CLIENT_DECLARED] = (
        EvidenceTrustClassification.CLIENT_DECLARED
    )
    origin_verified: Literal[False] = False
    synthetic: Literal[False] = False


class MultilayerEvidenceSummary(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    record_count: Annotated[int, Field(ge=1, le=MAX_MULTILAYER_SOURCES)]
    records: Annotated[
        tuple[MultilayerEvidenceReference, ...],
        Field(min_length=1, max_length=MAX_MULTILAYER_SOURCES),
    ]


class MultilayerIdentitySummary(StrictContract):
    rules_version: Literal["identity-rules/1.0.0"] = "identity-rules/1.0.0"
    summary: IdentityResolutionSummary
    reference_ids: Annotated[tuple[str, ...], Field(max_length=512)]


class MultilayerCorrelationReference(StrictContract):
    relationship_id: Annotated[str, Field(pattern=r"^crr_[0-9a-f]{64}$")]
    relationship_type: CorrelationRelationshipType
    status: Literal[CorrelationStatus.SUPPORTED] = CorrelationStatus.SUPPORTED
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=2, max_length=256)]


class MultilayerCorrelationSummary(StrictContract):
    rules_version: Literal["correlation-rules/1.0.0"] = "correlation-rules/1.0.0"
    summary: CorrelationSummary
    reference_ids: Annotated[tuple[str, ...], Field(max_length=1024)]
    relationships: Annotated[
        tuple[MultilayerCorrelationReference, ...], Field(max_length=512)
    ]


class MultilayerAssessmentReference(StrictContract):
    assessment_id: Annotated[str, Field(pattern=r"^sas_[0-9a-f]{64}$")]
    assertion_id: Annotated[str, Field(pattern=r"^AS-[A-Z]+-[0-9]{3}$")]
    status: SufficiencyState
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(max_length=16)]


class MultilayerSufficiencySummary(StrictContract):
    policy_version: Literal["sufficiency-assertions/1.0.0"] = (
        "sufficiency-assertions/1.0.0"
    )
    summary: SufficiencySummary
    assessments: Annotated[
        tuple[MultilayerAssessmentReference, ...],
        Field(min_length=1, max_length=MAX_MULTILAYER_ASSERTIONS),
    ]


class MultilayerExplanationSummary(StrictContract):
    trace_version: Literal["decision-trace/1.0.0"] = "decision-trace/1.0.0"
    trace_count: Annotated[int, Field(ge=1, le=MAX_MULTILAYER_ASSERTIONS)]
    trace_ids: Annotated[
        tuple[Annotated[str, Field(pattern=r"^dtr_[0-9a-f]{64}$")], ...],
        Field(min_length=1, max_length=MAX_MULTILAYER_ASSERTIONS),
    ]
    traces: Annotated[
        tuple[DecisionTrace, ...],
        Field(min_length=1, max_length=MAX_MULTILAYER_ASSERTIONS),
    ]


class MultilayerLimitations(StrictContract):
    trust: Annotated[tuple[str, ...], Field(min_length=1, max_length=8)]
    scientific: Annotated[tuple[str, ...], Field(min_length=1, max_length=16)]
    operational: Annotated[tuple[str, ...], Field(min_length=1, max_length=8)]


class MultilayerAnalysisResponse(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    analysis_id: Annotated[str, Field(pattern=r"^mla_[0-9a-f]{64}$")]
    batch_id: Annotated[str, Field(pattern=r"^evb_[0-9a-f]{64}$")]
    response_mode: Literal[MultilayerResponseMode.EXPLAINABLE] = (
        MultilayerResponseMode.EXPLAINABLE
    )
    evidence: MultilayerEvidenceSummary
    identity: MultilayerIdentitySummary
    correlation: MultilayerCorrelationSummary
    sufficiency: MultilayerSufficiencySummary
    explanation: MultilayerExplanationSummary
    limitations: MultilayerLimitations
    persistence_performed: Literal[False] = False
    external_io_performed: Literal[False] = False
    dynamic_rule_execution_performed: Literal[False] = False
    scoring_performed: Literal[False] = False
    threat_verdict_generated: Literal[False] = False
    malware_confirmed: Literal[False] = False
    exploitation_inferred: Literal[False] = False
    attack_execution_confirmed: Literal[False] = False
    causal_inference_performed: Literal[False] = False
    response_action_performed: Literal[False] = False

    @model_validator(mode="after")
    def enforce_consistency_and_size(self) -> Self:
        if self.evidence.record_count != len(self.evidence.records):
            raise ValueError("multilayer evidence summary is inconsistent")
        evidence_ids = {item.evidence_id for item in self.evidence.records}
        if any(
            not set(item.evidence_ids).issubset(evidence_ids)
            for item in self.correlation.relationships
        ) or any(
            not set(item.evidence_ids).issubset(evidence_ids)
            for item in self.sufficiency.assessments
        ):
            raise ValueError("multilayer response references unknown evidence")
        traces = self.explanation.traces
        if any(
            not {item.evidence_id for item in trace.evidence_references}.issubset(
                evidence_ids
            )
            for trace in traces
        ):
            raise ValueError("decision traces reference unpublished evidence")
        identity_ids = set(self.identity.reference_ids)
        correlation_ids = set(self.correlation.reference_ids)
        if any(
            not {
                item.identity_object_id for item in trace.identity_references
            }.issubset(identity_ids)
            or not {
                item.correlation_object_id for item in trace.correlation_references
            }.issubset(correlation_ids)
            for trace in traces
        ):
            raise ValueError("decision traces reference unpublished prerequisites")
        trace_ids = tuple(item.identifier.trace_id for item in traces)
        if (
            self.explanation.trace_count != len(traces)
            or self.explanation.trace_ids != trace_ids
        ):
            raise ValueError("multilayer explanation summary is inconsistent")
        assessment_ids = {item.assessment_id for item in self.sufficiency.assessments}
        if {item.identifier.source_assessment_id for item in traces} != assessment_ids:
            raise ValueError("decision traces do not cover the published assessments")
        material = {
            "batch_id": self.batch_id,
            "assessment_ids": tuple(
                item.assessment_id for item in self.sufficiency.assessments
            ),
            "trace_ids": self.explanation.trace_ids,
        }
        if self.analysis_id != multilayer_content_id("mla", material):
            raise ValueError("multilayer analysis ID does not match canonical content")
        encoded = json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
        if len(encoded) > MAX_MULTILAYER_RESPONSE_BYTES:
            raise ValueError("multilayer response exceeds the byte limit")
        return self


class MultilayerResourceLimits(StrictContract):
    maximum_request_bytes: Literal[262144] = 262144
    maximum_response_bytes: Literal[1048576] = 1048576
    maximum_sources: Literal[16] = 16
    maximum_assertions: Literal[32] = 32
    maximum_concurrency: Literal[4] = 4
    operation_timeout_seconds: Annotated[float, Field(ge=4.0, le=4.0)] = 4.0


class MultilayerSchemaDescriptor(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    endpoint: Literal["POST /api/v1/multilayer/analyze"] = (
        "POST /api/v1/multilayer/analyze"
    )
    response_contract: Literal["MultilayerAnalysisResponse/1.0.0"] = (
        "MultilayerAnalysisResponse/1.0.0"
    )
    input_modes: tuple[MultilayerInputType, ...]
    response_modes: tuple[MultilayerResponseMode, ...]
    supported_assertion_ids: tuple[str, ...]
    supported_domains: tuple[EvidenceDomain, ...]
    limits: MultilayerResourceLimits
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(min_length=1, max_length=16),
    ]
    accepts_evidence_batches: Literal[False] = False
    accepts_precomputed_results: Literal[False] = False
    authenticates_client_origin: Literal[False] = False
    persistence: Literal[False] = False
