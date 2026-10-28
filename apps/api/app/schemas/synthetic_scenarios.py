from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Annotated, Literal, Self, TypeAlias
from uuid import UUID

from pydantic import Field, model_validator

from app.schemas.correlation import CorrelationRelationshipType
from app.schemas.evidence import (
    EvidenceDomain,
    EvidenceId,
    EvidenceOriginType,
    EvidenceTrustClassification,
)
from app.schemas.sufficiency import (
    EvidenceGapCategory,
    SufficiencyState,
    UncertaintyCategory,
)
from app.schemas.vulnerability import StrictContract, normalize_cve_id

SYNTHETIC_SCENARIO_SCHEMA_VERSION = "1.0.0"
SYNTHETIC_SCENARIO_REGISTRY_VERSION = "synthetic-scenarios/1.0.0"
MAX_SYNTHETIC_SCENARIOS = 16
MAX_SYNTHETIC_EVIDENCE = 8
MAX_SYNTHETIC_EXPECTATIONS = 8
MAX_SYNTHETIC_TRACE_REFERENCES = 32
MAX_SYNTHETIC_OUTPUT_BYTES = 512 * 1024

ScenarioId: TypeAlias = Annotated[
    str, Field(pattern=r"^scenario_[a-z0-9][a-z0-9_]{2,63}$", max_length=73)
]
ScenarioSourceId: TypeAlias = Annotated[
    str, Field(pattern=r"^fixture_[a-z0-9][a-z0-9_]{1,47}$", max_length=56)
]


def scenario_content_id(prefix: str, value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return f"{prefix}_{hashlib.sha256(encoded).hexdigest()}"


class SyntheticDataClassification(str, Enum):
    BACKEND_EDUCATIONAL = "backend_generated_educational"


class SyntheticSourceType(str, Enum):
    STATIC = "synthetic_static"
    VULNERABILITY = "synthetic_vulnerability"
    ML = "synthetic_ml"
    BEHAVIORAL = "synthetic_behavioral"


class ScenarioValidationStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"


class SyntheticScenarioLearningObjective(StrictContract):
    objective_id: Annotated[str, Field(pattern=r"^LO-[0-9]{3}$")]
    statement: Annotated[str, Field(min_length=1, max_length=256)]


class SyntheticScenarioIdentifier(StrictContract):
    scenario_id: ScenarioId
    version: Literal["1.0.0"] = "1.0.0"


class SyntheticScenarioMetadata(StrictContract):
    identifier: SyntheticScenarioIdentifier
    title: Annotated[str, Field(min_length=1, max_length=128)]
    objective: SyntheticScenarioLearningObjective
    domains: Annotated[tuple[EvidenceDomain, ...], Field(min_length=1, max_length=4)]
    data_classification: Literal[SyntheticDataClassification.BACKEND_EDUCATIONAL] = (
        SyntheticDataClassification.BACKEND_EDUCATIONAL
    )
    scientific_boundaries: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...],
        Field(min_length=1, max_length=8),
    ]


class _SyntheticSourceBase(StrictContract):
    source_id: ScenarioSourceId
    source_analysis_id: UUID
    explicit_derivation_of: ScenarioSourceId | None = None


class SyntheticStaticSource(_SyntheticSourceBase):
    source_type: Literal[SyntheticSourceType.STATIC] = SyntheticSourceType.STATIC
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    size_bytes: Annotated[int, Field(gt=0, le=1024 * 1024)] = 256
    scope: Annotated[str, Field(min_length=1, max_length=64)] = (
        "synthetic_content_identity"
    )


class SyntheticVulnerabilitySource(_SyntheticSourceBase):
    source_type: Literal[SyntheticSourceType.VULNERABILITY] = (
        SyntheticSourceType.VULNERABILITY
    )
    cve_id: Annotated[str, Field(pattern=r"^CVE-(?:1999|2\d{3})-\d{4,}$")]
    scope: Annotated[str, Field(min_length=1, max_length=64)] = (
        "synthetic_vulnerability_identity"
    )

    @model_validator(mode="after")
    def require_canonical_cve(self) -> Self:
        if self.cve_id != normalize_cve_id(self.cve_id):
            raise ValueError("synthetic CVE identifier must be canonical")
        return self


class SyntheticMLSource(_SyntheticSourceBase):
    source_type: Literal[SyntheticSourceType.ML] = SyntheticSourceType.ML
    analysis_context_id: UUID
    scope: Annotated[str, Field(min_length=1, max_length=64)] = (
        "synthetic_analysis_context"
    )
    output_label: Literal["benign", "malicious"] = "benign"


class SyntheticBehavioralSource(_SyntheticSourceBase):
    source_type: Literal[SyntheticSourceType.BEHAVIORAL] = (
        SyntheticSourceType.BEHAVIORAL
    )
    analysis_context_id: UUID
    scope: Annotated[str, Field(min_length=1, max_length=64)] = (
        "synthetic_analysis_context"
    )


SyntheticEvidenceSource: TypeAlias = Annotated[
    SyntheticStaticSource
    | SyntheticVulnerabilitySource
    | SyntheticMLSource
    | SyntheticBehavioralSource,
    Field(discriminator="source_type"),
]


class SyntheticAssertionSelection(StrictContract):
    assertion_id: Annotated[str, Field(pattern=r"^AS-[A-Z]+-[0-9]{3}$")]
    source_ids: Annotated[
        tuple[ScenarioSourceId, ...],
        Field(min_length=1, max_length=MAX_SYNTHETIC_EVIDENCE),
    ]

    @model_validator(mode="after")
    def require_unique_sources(self) -> Self:
        if self.source_ids != tuple(sorted(set(self.source_ids))):
            raise ValueError("scenario assertion source IDs must be sorted and unique")
        return self


class SyntheticExpectedAssessment(StrictContract):
    assertion_id: Annotated[str, Field(pattern=r"^AS-[A-Z]+-[0-9]{3}$")]
    status: SufficiencyState


class SyntheticScenarioExpectation(StrictContract):
    assessments: Annotated[
        tuple[SyntheticExpectedAssessment, ...],
        Field(min_length=1, max_length=MAX_SYNTHETIC_EXPECTATIONS),
    ]
    relationship_types: Annotated[
        tuple[CorrelationRelationshipType, ...],
        Field(max_length=MAX_SYNTHETIC_EXPECTATIONS),
    ] = ()
    relevant_conflicts: Annotated[int, Field(ge=0, le=32)] = 0
    missing_requirement_categories: Annotated[
        tuple[EvidenceGapCategory, ...], Field(max_length=16)
    ] = ()
    uncertainty_categories: Annotated[
        tuple[UncertaintyCategory, ...], Field(max_length=16)
    ] = ()
    positive_relationships_absent: bool = False
    unsupported_conclusions_absent: Literal[True] = True


class SyntheticScenarioDefinition(StrictContract):
    metadata: SyntheticScenarioMetadata
    sources: Annotated[
        tuple[SyntheticEvidenceSource, ...],
        Field(min_length=1, max_length=MAX_SYNTHETIC_EVIDENCE),
    ]
    assertions: Annotated[
        tuple[SyntheticAssertionSelection, ...],
        Field(min_length=1, max_length=MAX_SYNTHETIC_EXPECTATIONS),
    ]
    expectation: SyntheticScenarioExpectation
    external_effects_allowed: Literal[False] = False
    executable_content_allowed: Literal[False] = False
    arbitrary_seed_allowed: Literal[False] = False

    @model_validator(mode="after")
    def validate_closed_definition(self) -> Self:
        source_ids = tuple(item.source_id for item in self.sources)
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("scenario source identifiers must be unique")
        known = set(source_ids)
        if any(not set(item.source_ids).issubset(known) for item in self.assertions):
            raise ValueError("scenario assertion references an unknown source")
        if any(
            item.explicit_derivation_of is not None
            and item.explicit_derivation_of not in known
            for item in self.sources
        ):
            raise ValueError("scenario source references an unknown fixture")
        if tuple(item.assertion_id for item in self.assertions) != tuple(
            item.assertion_id for item in self.expectation.assessments
        ):
            raise ValueError("scenario expectations must cover assertions in order")
        return self


class SyntheticScenario(StrictContract):
    registry_version: Literal["synthetic-scenarios/1.0.0"] = "synthetic-scenarios/1.0.0"
    definition: SyntheticScenarioDefinition


class SyntheticScenarioExecutionRequest(StrictContract):
    scenario_id: ScenarioId
    scenario_version: Literal["1.0.0"] = "1.0.0"


class SyntheticScenarioSummary(StrictContract):
    identifier: SyntheticScenarioIdentifier
    title: Annotated[str, Field(min_length=1, max_length=128)]
    objective: SyntheticScenarioLearningObjective
    domains: tuple[EvidenceDomain, ...]


class SyntheticEvidenceSummary(StrictContract):
    batch_id: Annotated[str, Field(pattern=r"^evb_[0-9a-f]{64}$")]
    evidence_ids: Annotated[
        tuple[EvidenceId, ...], Field(min_length=1, max_length=MAX_SYNTHETIC_EVIDENCE)
    ]
    domains: tuple[EvidenceDomain, ...]
    origin_type: Literal[EvidenceOriginType.SYNTHETIC_GENERATED] = (
        EvidenceOriginType.SYNTHETIC_GENERATED
    )
    trust_classification: Literal[EvidenceTrustClassification.INTERNAL_DERIVATION] = (
        EvidenceTrustClassification.INTERNAL_DERIVATION
    )
    synthetic: Literal[True] = True
    external_telemetry_authenticated: Literal[False] = False


class SyntheticObservedOutcome(StrictContract):
    assessment_statuses: tuple[SyntheticExpectedAssessment, ...]
    relationship_types: tuple[CorrelationRelationshipType, ...]
    relevant_conflicts: Annotated[int, Field(ge=0)]
    missing_requirement_categories: tuple[EvidenceGapCategory, ...]
    uncertainty_categories: tuple[UncertaintyCategory, ...]
    identity_reference_ids: Annotated[tuple[str, ...], Field(max_length=64)]
    relationship_ids: Annotated[tuple[str, ...], Field(max_length=64)]
    assessment_ids: Annotated[tuple[str, ...], Field(max_length=32)]
    decision_trace_ids: Annotated[
        tuple[str, ...], Field(max_length=MAX_SYNTHETIC_TRACE_REFERENCES)
    ]
    threat_verdict_generated: Literal[False] = False
    malware_confirmed: Literal[False] = False
    exploitation_inferred: Literal[False] = False
    causal_inference_performed: Literal[False] = False


class SyntheticScenarioValidation(StrictContract):
    status: ScenarioValidationStatus
    assessment_statuses_match: bool
    relationship_types_match: bool
    relevant_conflicts_match: bool
    missing_categories_match: bool
    uncertainty_categories_present: bool
    unsupported_conclusions_absent: bool
    discrepancies: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...],
        Field(max_length=16),
    ] = ()

    @model_validator(mode="after")
    def enforce_status(self) -> Self:
        checks = (
            self.assessment_statuses_match,
            self.relationship_types_match,
            self.relevant_conflicts_match,
            self.missing_categories_match,
            self.uncertainty_categories_present,
            self.unsupported_conclusions_absent,
        )
        if (self.status is ScenarioValidationStatus.PASSED) != all(checks):
            raise ValueError("scenario validation status does not match checks")
        if bool(self.discrepancies) == all(checks):
            raise ValueError("scenario discrepancies do not match validation checks")
        return self


class SyntheticScenarioExecutionResult(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    execution_id: Annotated[str, Field(pattern=r"^sce_[0-9a-f]{64}$")]
    scenario: SyntheticScenarioSummary
    evidence: SyntheticEvidenceSummary
    expected: SyntheticScenarioExpectation
    observed: SyntheticObservedOutcome
    validation: SyntheticScenarioValidation
    scientific_limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...],
        Field(min_length=1, max_length=8),
    ]
    persistence_performed: Literal[False] = False
    external_io_performed: Literal[False] = False
    subprocess_execution_performed: Literal[False] = False
    model_execution_performed: Literal[False] = False
    dynamic_rule_execution_performed: Literal[False] = False

    @model_validator(mode="after")
    def enforce_identifier_and_size(self) -> Self:
        material = {
            "scenario": self.scenario.identifier.model_dump(mode="json"),
            "batch_id": self.evidence.batch_id,
            "assessment_ids": self.observed.assessment_ids,
            "trace_ids": self.observed.decision_trace_ids,
            "validation": self.validation.model_dump(mode="json"),
        }
        if self.execution_id != scenario_content_id("sce", material):
            raise ValueError("scenario execution ID does not match canonical content")
        encoded = json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
        if len(encoded) > MAX_SYNTHETIC_OUTPUT_BYTES:
            raise ValueError("scenario output exceeds the byte limit")
        return self
