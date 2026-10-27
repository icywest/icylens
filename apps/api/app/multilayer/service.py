from __future__ import annotations

import asyncio
from collections.abc import Callable

from app.correlation.service import correlate_evidence_with_identity
from app.explainability.service import explain_decisions_with_context
from app.identity.resolution import resolve_identities
from app.multilayer.admission import MultilayerAdmissionError, admit_sources
from app.schemas.correlation import MultilayerCorrelationRequest
from app.schemas.explainability import DecisionTraceRequest
from app.schemas.identity import IdentityResolutionRequest
from app.schemas.multilayer_analysis import (
    MULTILAYER_OPERATION_TIMEOUT_SECONDS,
    MultilayerAnalysisRequest,
    MultilayerAnalysisResponse,
    MultilayerAssessmentReference,
    MultilayerCorrelationReference,
    MultilayerCorrelationSummary,
    MultilayerEvidenceSummary,
    MultilayerExplanationSummary,
    MultilayerIdentitySummary,
    MultilayerLimitations,
    MultilayerSufficiencySummary,
    multilayer_content_id,
)
from app.schemas.sufficiency import AssertionSelection, SufficiencyAssessmentRequest
from app.services.synchronous_workers import SynchronousWorkerManager
from app.sufficiency.service import assess_evidence_sufficiency_with_context


class MultilayerAnalysisCapacityError(RuntimeError):
    pass


class MultilayerAnalysisTimeoutError(RuntimeError):
    pass


class MultilayerAnalysisLimitError(RuntimeError):
    pass


class MultilayerAnalysisConsistencyError(RuntimeError):
    pass


_LIMITATIONS = MultilayerLimitations(
    trust=(
        "All enabled HTTP input modes are client-declared and origin-unverified.",
        "Schema validation and deterministic hashes do not authenticate the producer or factual truth of client claims.",
    ),
    scientific=(
        "A sufficient result supports only its registered assertion and is not a global truth or threat verdict.",
        "Digest equality does not establish execution or malware.",
        "CVE identity does not establish installation, exposure, exploitation, or compromise.",
        "A declared ML output is not server-executed inference or confirmed malware detection.",
        "Correlation is not causality and no ATT&CK execution is confirmed.",
    ),
    operational=(
        "The API has educational local scope and performs no persistence, external provider lookup, alerting, or response action.",
        "Deterministic identifiers are correlatable and are not anonymous.",
    ),
)


class MultilayerAnalysisService:
    def analyze(self, request: MultilayerAnalysisRequest) -> MultilayerAnalysisResponse:
        batch, source_to_evidence, evidence_references = admit_sources(request)
        selections = []
        for requested in request.assertions:
            try:
                evidence_ids = tuple(
                    sorted(source_to_evidence[item] for item in requested.source_ids)
                )
            except KeyError as error:
                raise MultilayerAdmissionError(
                    "An assertion references an unknown declared source."
                ) from error
            selections.append(
                AssertionSelection(
                    assertion_id=requested.assertion_id,
                    evidence_ids=evidence_ids,
                )
            )
        assertion_selections = tuple(
            sorted(
                selections,
                key=lambda item: (item.assertion_id, item.evidence_ids),
            )
        )
        identity = resolve_identities(IdentityResolutionRequest(batch=batch))
        correlation = correlate_evidence_with_identity(
            MultilayerCorrelationRequest(batch=batch), identity
        )
        sufficiency_request = SufficiencyAssessmentRequest(
            batch=batch, assertions=assertion_selections
        )
        sufficiency = assess_evidence_sufficiency_with_context(
            sufficiency_request, identity, correlation
        )
        trace_request = DecisionTraceRequest(
            batch=batch, assertions=assertion_selections
        )
        explanation = explain_decisions_with_context(
            trace_request, identity, correlation, sufficiency
        )
        identity_reference_ids = tuple(
            sorted(
                (
                    *(item.match_id for item in identity.matches),
                    *(item.group_id for item in identity.groups),
                )
            )
        )
        assessment_references = tuple(
            MultilayerAssessmentReference(
                assessment_id=item.assessment_id,
                assertion_id=item.assertion_id,
                status=item.state,
                evidence_ids=item.evidence_ids,
            )
            for item in sufficiency.assessments
        )
        trace_ids = tuple(item.identifier.trace_id for item in explanation.traces)
        material = {
            "batch_id": batch.batch_id,
            "assessment_ids": tuple(
                item.assessment_id for item in assessment_references
            ),
            "trace_ids": trace_ids,
        }
        try:
            return MultilayerAnalysisResponse(
                analysis_id=multilayer_content_id("mla", material),
                batch_id=batch.batch_id,
                evidence=MultilayerEvidenceSummary(
                    record_count=len(evidence_references),
                    records=evidence_references,
                ),
                identity=MultilayerIdentitySummary(
                    summary=identity.summary,
                    reference_ids=identity_reference_ids,
                ),
                correlation=MultilayerCorrelationSummary(
                    summary=correlation.summary,
                    reference_ids=tuple(
                        sorted(
                            (
                                *(
                                    item.evaluation_id
                                    for item in correlation.evaluations
                                ),
                                *(
                                    item.relationship_id
                                    for item in correlation.relationships
                                ),
                            )
                        )
                    ),
                    relationships=tuple(
                        MultilayerCorrelationReference(
                            relationship_id=item.relationship_id,
                            relationship_type=item.relationship_type,
                            evidence_ids=item.evidence_ids,
                        )
                        for item in correlation.relationships
                    ),
                ),
                sufficiency=MultilayerSufficiencySummary(
                    summary=sufficiency.summary,
                    assessments=assessment_references,
                ),
                explanation=MultilayerExplanationSummary(
                    trace_count=len(explanation.traces),
                    trace_ids=trace_ids,
                    traces=explanation.traces,
                ),
                limitations=_LIMITATIONS,
            )
        except ValueError as error:
            if "byte limit" in str(error):
                raise MultilayerAnalysisLimitError(
                    "Multilayer output exceeded its resource limit."
                ) from error
            raise MultilayerAnalysisConsistencyError(
                "Multilayer results failed internal consistency validation."
            ) from error


async def execute_multilayer_analysis(
    operation: Callable[[], MultilayerAnalysisResponse],
    capacity: SynchronousWorkerManager,
) -> MultilayerAnalysisResponse:
    worker = capacity.try_submit(operation)
    if worker is None:
        raise MultilayerAnalysisCapacityError("Multilayer capacity is exhausted")
    try:
        return await capacity.wait(
            worker,
            timeout=MULTILAYER_OPERATION_TIMEOUT_SECONDS,
        )
    except TimeoutError as error:
        raise MultilayerAnalysisTimeoutError(
            "Multilayer analysis operation timed out"
        ) from error
    except asyncio.CancelledError:
        raise
