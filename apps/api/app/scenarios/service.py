from __future__ import annotations

from app.correlation.service import correlate_evidence_with_identity
from app.explainability.service import explain_decisions_with_context
from app.identity.resolution import resolve_identities
from app.scenarios.generator import generate_synthetic_evidence
from app.scenarios.registry import (
    DEFAULT_SYNTHETIC_SCENARIO_REGISTRY,
    SyntheticScenarioRegistry,
)
from app.schemas.correlation import MultilayerCorrelationRequest
from app.schemas.explainability import DecisionTraceRequest
from app.schemas.identity import IdentityResolutionRequest
from app.schemas.sufficiency import AssertionSelection, SufficiencyAssessmentRequest
from app.schemas.synthetic_scenarios import (
    ScenarioValidationStatus,
    SyntheticEvidenceSummary,
    SyntheticExpectedAssessment,
    SyntheticObservedOutcome,
    SyntheticScenarioExecutionRequest,
    SyntheticScenarioExecutionResult,
    SyntheticScenarioExpectation,
    SyntheticScenarioSummary,
    SyntheticScenarioValidation,
    scenario_content_id,
)
from app.sufficiency.service import assess_evidence_sufficiency_with_context


def _validation(
    expected: SyntheticScenarioExpectation, observed: SyntheticObservedOutcome
) -> SyntheticScenarioValidation:
    assessments_match = expected.assessments == observed.assessment_statuses
    relationships_match = expected.relationship_types == observed.relationship_types
    conflicts_match = expected.relevant_conflicts == observed.relevant_conflicts
    missing_match = (
        expected.missing_requirement_categories
        == observed.missing_requirement_categories
    )
    uncertainty_present = set(expected.uncertainty_categories).issubset(
        observed.uncertainty_categories
    )
    unsupported_absent = (
        not observed.threat_verdict_generated
        and not observed.malware_confirmed
        and not observed.exploitation_inferred
        and not observed.causal_inference_performed
    )
    checks = {
        "assessment statuses": assessments_match,
        "relationship types": relationships_match,
        "relevant conflicts": conflicts_match,
        "missing requirement categories": missing_match,
        "uncertainty categories": uncertainty_present,
        "unsupported conclusions": unsupported_absent,
    }
    discrepancies = tuple(
        f"Expected and observed {name} differ."
        for name, matches in checks.items()
        if not matches
    )
    return SyntheticScenarioValidation(
        status=(
            ScenarioValidationStatus.PASSED
            if not discrepancies
            else ScenarioValidationStatus.FAILED
        ),
        assessment_statuses_match=assessments_match,
        relationship_types_match=relationships_match,
        relevant_conflicts_match=conflicts_match,
        missing_categories_match=missing_match,
        uncertainty_categories_present=uncertainty_present,
        unsupported_conclusions_absent=unsupported_absent,
        discrepancies=discrepancies,
    )


def execute_synthetic_scenario(
    scenario_id: str,
    *,
    scenario_version: str = "1.0.0",
    registry: SyntheticScenarioRegistry = DEFAULT_SYNTHETIC_SCENARIO_REGISTRY,
) -> SyntheticScenarioExecutionResult:
    request = SyntheticScenarioExecutionRequest(
        scenario_id=scenario_id, scenario_version=scenario_version
    )
    scenario = registry.get(request.scenario_id, request.scenario_version)
    batch, source_to_evidence = generate_synthetic_evidence(scenario)
    selections = tuple(
        AssertionSelection(
            assertion_id=item.assertion_id,
            evidence_ids=tuple(
                sorted(source_to_evidence[source_id] for source_id in item.source_ids)
            ),
        )
        for item in scenario.definition.assertions
    )
    identity = resolve_identities(IdentityResolutionRequest(batch=batch))
    correlation = correlate_evidence_with_identity(
        MultilayerCorrelationRequest(batch=batch), identity
    )
    sufficiency_request = SufficiencyAssessmentRequest(
        batch=batch, assertions=selections
    )
    sufficiency = assess_evidence_sufficiency_with_context(
        sufficiency_request, identity, correlation
    )
    explanation = explain_decisions_with_context(
        DecisionTraceRequest(batch=batch, assertions=selections),
        identity,
        correlation,
        sufficiency,
    )
    assessments = tuple(
        SyntheticExpectedAssessment(assertion_id=item.assertion_id, status=item.state)
        for item in sufficiency.assessments
    )
    relationship_types = tuple(
        sorted(
            {item.relationship_type for item in correlation.relationships},
            key=lambda item: item.value,
        )
    )
    gaps = tuple(
        sorted(
            {
                gap.category
                for assessment in sufficiency.assessments
                for gap in assessment.gaps
            },
            key=lambda item: item.value,
        )
    )
    uncertainties = tuple(
        sorted(
            {
                reason.category
                for assessment in sufficiency.assessments
                for reason in assessment.uncertainty_reasons
            },
            key=lambda item: item.value,
        )
    )
    observed = SyntheticObservedOutcome(
        assessment_statuses=assessments,
        relationship_types=relationship_types,
        relevant_conflicts=sum(
            len(item.contradictions) for item in sufficiency.assessments
        ),
        missing_requirement_categories=gaps,
        uncertainty_categories=uncertainties,
        identity_reference_ids=tuple(
            sorted(
                (
                    *(item.match_id for item in identity.matches),
                    *(item.group_id for item in identity.groups),
                )
            )
        ),
        relationship_ids=tuple(
            item.relationship_id for item in correlation.relationships
        ),
        assessment_ids=tuple(item.assessment_id for item in sufficiency.assessments),
        decision_trace_ids=tuple(
            item.identifier.trace_id for item in explanation.traces
        ),
    )
    expected = scenario.definition.expectation
    validation = _validation(expected, observed)
    metadata = scenario.definition.metadata
    summary = SyntheticScenarioSummary(
        identifier=metadata.identifier,
        title=metadata.title,
        objective=metadata.objective,
        domains=metadata.domains,
    )
    evidence = SyntheticEvidenceSummary(
        batch_id=batch.batch_id,
        evidence_ids=tuple(item.identifier.evidence_id for item in batch.records),
        domains=tuple(
            sorted(
                {item.observation.domain for item in batch.records},
                key=lambda item: item.value,
            )
        ),
    )
    material = {
        "scenario": summary.identifier.model_dump(mode="json"),
        "batch_id": evidence.batch_id,
        "assessment_ids": observed.assessment_ids,
        "trace_ids": observed.decision_trace_ids,
        "validation": validation.model_dump(mode="json"),
    }
    return SyntheticScenarioExecutionResult(
        execution_id=scenario_content_id("sce", material),
        scenario=summary,
        evidence=evidence,
        expected=expected,
        observed=observed,
        validation=validation,
        scientific_limitations=metadata.scientific_boundaries,
    )
