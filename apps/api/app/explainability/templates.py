from __future__ import annotations

from app.schemas.explainability import (
    EXPLANATION_MESSAGES,
    ExplanationStatement,
    ExplanationTemplateId,
    trace_content_id,
)
from app.schemas.sufficiency import RequirementState, SufficiencyState

_DECISION_TEMPLATES = {
    SufficiencyState.SUFFICIENT: ExplanationTemplateId.DECISION_SUFFICIENT,
    SufficiencyState.INSUFFICIENT_EVIDENCE: ExplanationTemplateId.DECISION_INSUFFICIENT,
    SufficiencyState.CONFLICTING_EVIDENCE: ExplanationTemplateId.DECISION_CONFLICTING,
    SufficiencyState.NOT_APPLICABLE: ExplanationTemplateId.DECISION_NOT_APPLICABLE,
    SufficiencyState.UNSUPPORTED_ASSERTION: ExplanationTemplateId.DECISION_UNSUPPORTED,
}

_REQUIREMENT_TEMPLATES = {
    RequirementState.SATISFIED: ExplanationTemplateId.REQUIREMENT_SATISFIED,
    RequirementState.MISSING: ExplanationTemplateId.REQUIREMENT_MISSING,
    RequirementState.CONFLICTING: ExplanationTemplateId.REQUIREMENT_CONFLICTING,
    RequirementState.NOT_APPLICABLE: ExplanationTemplateId.REQUIREMENT_NOT_APPLICABLE,
}


def explanation_statement(
    template_id: ExplanationTemplateId, source_reference_id: str
) -> ExplanationStatement:
    material = {
        "template_id": template_id.value,
        "template_version": "1.0.0",
        "source_reference_id": source_reference_id,
    }
    return ExplanationStatement(
        statement_id=trace_content_id("tst", material),
        template_id=template_id,
        source_reference_id=source_reference_id,
        message=EXPLANATION_MESSAGES[template_id],
    )


def decision_statement(
    state: SufficiencyState, assessment_id: str
) -> ExplanationStatement:
    return explanation_statement(_DECISION_TEMPLATES[state], assessment_id)


def requirement_statement(
    state: RequirementState, evaluation_id: str
) -> ExplanationStatement:
    return explanation_statement(_REQUIREMENT_TEMPLATES[state], evaluation_id)
