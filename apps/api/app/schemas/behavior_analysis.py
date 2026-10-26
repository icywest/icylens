from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.schemas.attack_mapping import (
    MAX_MAPPING_EVALUATIONS,
    AttackMappingPolicyIdentifier,
    AttackMappingSummary,
    MappingEvaluation,
)
from app.schemas.behavior import (
    EventBatch,
    EventNature,
    EventValidationResult,
    SyntheticScenarioKind,
    SyntheticScenarioRequest,
    ValidationSeverity,
    _utc,
)
from app.schemas.behavior_correlation import (
    MAX_CORRELATION_EDGES,
    MAX_TEMPORAL_SEQUENCES,
    CorrelationPolicy,
    CorrelationSummary,
    EventRelationship,
    TemporalSequence,
)
from app.schemas.behavior_rules import (
    MAX_FINDINGS_PER_EVALUATION,
    MAX_RULES_PER_EVALUATION,
    RuleEvaluationSummary,
    RuleEventFamily,
    RuleIdentifier,
    RuleMatchStatus,
)
from app.schemas.vulnerability import StrictContract

BEHAVIORAL_ANALYSIS_SCHEMA_VERSION = "1.0.0"
MAX_UNIFIED_ANALYSIS_OUTPUT_BYTES = 1024 * 1024
UNIFIED_ANALYSIS_DEADLINE_SECONDS = 3.0
UNIFIED_ANALYSIS_OPERATION_TIMEOUT_SECONDS = 4.0
UNIFIED_ANALYSIS_MAX_CONCURRENCY = 4


class BehavioralAnalysisSource(str, Enum):
    DECLARED_BATCH = "declared_batch"
    SYNTHETIC_SCENARIO = "synthetic_scenario"


class BehavioralAnalysisStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


class BehavioralAnalysisStageName(str, Enum):
    VALIDATION = "validation"
    RULES = "rules"
    TEMPORAL_CORRELATION = "temporal_correlation"
    ATTACK_MAPPING = "attack_mapping"
    EXPLAINABILITY = "explainability"


class BehavioralAnalysisStageStatus(str, Enum):
    COMPLETED = "completed"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"


class BehavioralAnalysisOptions(StrictContract):
    rule_ids: Annotated[
        tuple[RuleIdentifier, ...] | None,
        Field(default=None, min_length=1, max_length=MAX_RULES_PER_EVALUATION),
    ]
    mapping_policy_ids: Annotated[
        tuple[AttackMappingPolicyIdentifier, ...] | None,
        Field(default=None, min_length=1, max_length=MAX_MAPPING_EVALUATIONS),
    ]
    correlation_policy: CorrelationPolicy = Field(default_factory=CorrelationPolicy)

    @model_validator(mode="after")
    def reject_duplicates(self) -> Self:
        if self.rule_ids is not None and len(set(self.rule_ids)) != len(self.rule_ids):
            raise ValueError("rule_ids must not contain duplicates")
        if self.mapping_policy_ids is not None and len(
            set(self.mapping_policy_ids)
        ) != len(self.mapping_policy_ids):
            raise ValueError("mapping_policy_ids must not contain duplicates")
        return self


class BehavioralAnalysisRequest(StrictContract):
    batch: EventBatch
    options: BehavioralAnalysisOptions = BehavioralAnalysisOptions(
        rule_ids=None, mapping_policy_ids=None
    )


class SyntheticAnalysisRequest(StrictContract):
    scenario: SyntheticScenarioRequest
    options: BehavioralAnalysisOptions = BehavioralAnalysisOptions(
        rule_ids=None, mapping_policy_ids=None
    )


class BehavioralAnalysisStage(StrictContract):
    stage: BehavioralAnalysisStageName
    status: BehavioralAnalysisStageStatus
    item_count: Annotated[int, Field(ge=0)]
    detail: Annotated[str, Field(min_length=1, max_length=512)]


class BehavioralAnalysisIssue(StrictContract):
    stage: BehavioralAnalysisStageName
    code: Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")]
    severity: ValidationSeverity
    message: Annotated[str, Field(min_length=1, max_length=512)]
    event_ids: Annotated[tuple[UUID, ...], Field(max_length=16)]


class BehavioralAnalysisProvenance(StrictContract):
    source: BehavioralAnalysisSource
    event_natures: Annotated[tuple[EventNature, ...], Field(min_length=1, max_length=2)]
    scenario_id: Annotated[str | None, Field(default=None, max_length=128)]
    scenario_kind: SyntheticScenarioKind | None
    scenario_seed: int | None
    validation_recomputed: Literal[True] = True
    rule_findings_backend_generated: Literal[True] = True
    temporal_graph_backend_generated: Literal[True] = True
    attack_mapping_backend_generated: Literal[True] = True
    events_returned: Literal[False] = False


class BehavioralEventSummary(StrictContract):
    submitted_events: int
    unique_event_ids: int
    declared_events: int
    synthetic_events: int
    process_events: int
    file_events: int
    network_events: int
    configuration_events: int


class BehavioralAnalysisSummary(StrictContract):
    valid_events: int
    validation_errors: int
    validation_warnings: int
    evaluated_rules: int
    matched_rules: int
    temporal_relationships: int
    strong_relationships: int
    weak_relationships: int
    mapping_policies: int
    mapping_candidates: int
    insufficient_mappings: int
    unknowns: int


class BehavioralRuleFindingSummary(StrictContract):
    rule_id: RuleIdentifier
    rule_version: str
    rule_name: Annotated[str, Field(min_length=1, max_length=256)]
    family: RuleEventFamily
    result: RuleMatchStatus
    event_ids: Annotated[tuple[UUID, ...], Field(max_length=8)]
    satisfied_conditions: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(max_length=16),
    ]
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(max_length=16),
    ]
    raw_evidence_returned: Literal[False] = False


class BehavioralAnalysisExplanation(StrictContract):
    template_id: Literal["unified_behavioral_assessment_v1"] = (
        "unified_behavioral_assessment_v1"
    )
    input_statement: Annotated[str, Field(min_length=1, max_length=512)]
    validation_statement: Annotated[str, Field(min_length=1, max_length=512)]
    rule_statement: Annotated[str, Field(min_length=1, max_length=512)]
    temporal_statement: Annotated[str, Field(min_length=1, max_length=512)]
    mapping_statement: Annotated[str, Field(min_length=1, max_length=512)]
    unknowns: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(max_length=16),
    ]
    scientific_boundary: Literal[
        "This educational assessment is not a SOC verdict, malware detection, attack confirmation, causal reconstruction, or attribution."
    ] = "This educational assessment is not a SOC verdict, malware detection, attack confirmation, causal reconstruction, or attribution."


class BehavioralAnalysisResult(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    analysis_id: UUID
    status: BehavioralAnalysisStatus
    generated_at: datetime
    source: BehavioralAnalysisSource
    provenance: BehavioralAnalysisProvenance
    event_summary: BehavioralEventSummary
    validation: EventValidationResult
    rule_findings: Annotated[
        tuple[BehavioralRuleFindingSummary, ...],
        Field(max_length=MAX_FINDINGS_PER_EVALUATION),
    ]
    rule_summary: RuleEvaluationSummary | None
    temporal_relationships: Annotated[
        tuple[EventRelationship, ...], Field(max_length=MAX_CORRELATION_EDGES)
    ]
    temporal_sequences: Annotated[
        tuple[TemporalSequence, ...], Field(max_length=MAX_TEMPORAL_SEQUENCES)
    ]
    temporal_summary: CorrelationSummary | None
    attack_mapping_evaluations: Annotated[
        tuple[MappingEvaluation, ...], Field(max_length=MAX_MAPPING_EVALUATIONS)
    ]
    attack_mapping_summary: AttackMappingSummary | None
    catalog_version: str | None
    stages: Annotated[
        tuple[BehavioralAnalysisStage, ...], Field(min_length=5, max_length=5)
    ]
    issues: Annotated[tuple[BehavioralAnalysisIssue, ...], Field(max_length=512)]
    summary: BehavioralAnalysisSummary
    explanation: BehavioralAnalysisExplanation
    limitations: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...]
    attack_confirmed: Literal[False] = False
    malware_detected: Literal[False] = False
    causal_inference_performed: Literal[False] = False
    ml_inference_performed: Literal[False] = False
    vulnerability_mapping_performed: Literal[False] = False
    persisted: Literal[False] = False

    _generated_utc = field_validator("generated_at")(_utc)


class BehavioralAnalysisSchemaDescriptor(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    sources: tuple[BehavioralAnalysisSource, ...]
    statuses: tuple[BehavioralAnalysisStatus, ...]
    stage_statuses: tuple[BehavioralAnalysisStageStatus, ...]
    maximum_declared_events: int
    maximum_synthetic_events: int
    maximum_request_bytes: int
    maximum_response_bytes: int
    maximum_concurrency: int
    persistence: Literal[False] = False
    attack_confirmation: Literal[False] = False
    malware_detection: Literal[False] = False
