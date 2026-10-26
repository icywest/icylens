from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal, Self, TypeAlias
from uuid import UUID

from pydantic import Field, model_validator

from app.schemas.behavior import EventBatch, EventNature, EventValidationResult
from app.schemas.vulnerability import StrictContract

MAX_RULES_PER_EVALUATION = 32
MAX_FINDINGS_PER_EVALUATION = 32
MAX_EVIDENCE_PER_FINDING = 8
MAX_EVIDENCE_FIELDS = 12
MAX_EVIDENCE_VALUE_LENGTH = 256
MAX_RULE_OUTPUT_BYTES = 256 * 1024
RULE_EVALUATION_DEADLINE_SECONDS = 1.0

RuleIdentifier = Annotated[
    str, Field(pattern=r"^BR-(?:PROC|FILE|NET|CONF)-[0-9]{3}$", max_length=16)
]
EvidenceScalar: TypeAlias = (
    Annotated[str, Field(max_length=MAX_EVIDENCE_VALUE_LENGTH)] | int | bool | None
)


class RuleEventFamily(str, Enum):
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"
    CONFIGURATION = "configuration"


class RuleConditionOperator(str, Enum):
    EQUALS = "equals"
    PRESENT = "present"
    ABSENT = "absent"
    PRECEDES = "precedes"
    NO_LATER_STATE = "no_later_state"


class RuleCondition(StrictContract):
    field: Annotated[str, Field(min_length=1, max_length=128)]
    operator: RuleConditionOperator
    expected: EvidenceScalar = None
    description: Annotated[str, Field(min_length=1, max_length=512)]


class BehavioralRule(StrictContract):
    rule_id: RuleIdentifier
    version: Annotated[
        str, Field(pattern=r"^[1-9][0-9]*\.[0-9]+\.[0-9]+$", max_length=32)
    ]
    name: Annotated[str, Field(min_length=1, max_length=256)]
    description: Annotated[str, Field(min_length=1, max_length=2048)]
    family: RuleEventFamily
    conditions: Annotated[tuple[RuleCondition, ...], Field(min_length=1, max_length=16)]
    required_evidence_fields: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=128)], ...],
        Field(min_length=1, max_length=16),
    ]
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(min_length=1, max_length=16),
    ]
    enabled: bool = True


class RuleMatchStatus(str, Enum):
    MATCHED = "matched"
    NOT_MATCHED = "not_matched"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    NOT_APPLICABLE = "not_applicable"


class EvidenceField(StrictContract):
    field: Annotated[str, Field(min_length=1, max_length=128)]
    value: EvidenceScalar
    redacted: bool = False


class RuleEvidence(StrictContract):
    event_id: UUID
    source_id: Annotated[str, Field(min_length=1, max_length=256)]
    nature: EventNature
    fields: Annotated[
        tuple[EvidenceField, ...], Field(min_length=1, max_length=MAX_EVIDENCE_FIELDS)
    ]


class RuleFinding(StrictContract):
    rule_id: RuleIdentifier
    rule_version: Annotated[str, Field(pattern=r"^[1-9][0-9]*\.[0-9]+\.[0-9]+$")]
    rule_name: Annotated[str, Field(min_length=1, max_length=256)]
    family: RuleEventFamily
    result: RuleMatchStatus
    event_ids: tuple[UUID, ...]
    satisfied_conditions: tuple[
        Annotated[str, Field(min_length=1, max_length=512)], ...
    ]
    evidence: Annotated[
        tuple[RuleEvidence, ...], Field(max_length=MAX_EVIDENCE_PER_FINDING)
    ]
    event_sources: tuple[Annotated[str, Field(min_length=1, max_length=256)], ...]
    event_natures: tuple[EventNature, ...]
    limitations: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...]
    security_interpretation: Literal[
        "A rule condition was evaluated; this is not confirmation of malicious activity."
    ] = "A rule condition was evaluated; this is not confirmation of malicious activity."


class RuleEvaluationSummary(StrictContract):
    evaluated_rules: int
    matched: int
    not_matched: int
    insufficient_evidence: int
    not_applicable: int
    findings_truncated: bool


class RuleEvaluationRequest(StrictContract):
    batch: EventBatch
    rule_ids: Annotated[
        tuple[RuleIdentifier, ...] | None,
        Field(default=None, min_length=1, max_length=MAX_RULES_PER_EVALUATION),
    ]

    @model_validator(mode="after")
    def reject_duplicate_rule_ids(self) -> Self:
        if self.rule_ids is not None and len(set(self.rule_ids)) != len(self.rule_ids):
            raise ValueError("rule_ids must not contain duplicates")
        return self


class RuleEvaluationResult(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    batch_validation: EventValidationResult
    findings: Annotated[
        tuple[RuleFinding, ...], Field(max_length=MAX_FINDINGS_PER_EVALUATION)
    ]
    summary: RuleEvaluationSummary
    limitations: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...]
    attack_mapping_performed: Literal[False] = False
    malware_classification_performed: Literal[False] = False
    persisted: Literal[False] = False


class RuleRegistryResponse(StrictContract):
    rules: tuple[BehavioralRule, ...]
    count: int
    mutable_from_http: Literal[False] = False
    external_plugins_loaded: Literal[False] = False
