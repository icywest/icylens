from __future__ import annotations

from app.schemas.evidence import (
    EvidenceOriginType,
    EvidenceQualityState,
    MLEvidenceObservation,
)
from app.schemas.sufficiency import (
    AssertionSelection,
    SufficiencyAssertion,
    UncertaintyCategory,
    UncertaintyReason,
    sufficiency_content_id,
)
from app.sufficiency.resolver import (
    AssessmentContext,
    has_unsupported_relation,
    has_weak_context_match,
    selected_records,
)

_EXPLANATIONS = {
    UncertaintyCategory.MISSING_IDENTITY: "The required exact identity is unavailable; absence does not prove the assertion false.",
    UncertaintyCategory.UNVERIFIED_PROVENANCE: "At least one selected record has origin that is declared or externally reported rather than cryptographically authenticated.",
    UncertaintyCategory.SYNTHETIC_ORIGIN: "Synthetic evidence remains educational and is not promoted to an operational observation.",
    UncertaintyCategory.DECLARED_CONTEXT: "At least one context is client declared and remains explicitly unverified.",
    UncertaintyCategory.MISSING_MODEL_VERSION: "Current ML evidence lacks an independent model version.",
    UncertaintyCategory.MISSING_TEMPORAL_CONTEXT: "At least one selected record lacks a semantic timestamp; this is not evidence of non-occurrence.",
    UncertaintyCategory.WEAK_CONTEXTUAL_ASSOCIATION: "Only compatible context is available; compatibility is not identity or a transitive relationship.",
    UncertaintyCategory.UNSUPPORTED_CROSS_MODULE_RELATION: "The available cross-module association has no supported 06.03 relationship rule.",
    UncertaintyCategory.CONFLICTING_CLAIMS: "Relevant retained claims conflict and are not resolved by source precedence.",
    UncertaintyCategory.INCOMPLETE_SOURCE_METADATA: "At least one source reports incomplete or partial metadata.",
}


def _reason(
    category: UncertaintyCategory,
    selection: AssertionSelection,
    evidence_ids: tuple[str, ...],
    *,
    affects_sufficiency: bool,
) -> UncertaintyReason:
    ordered = tuple(sorted(set(evidence_ids)))
    material = {
        "category": category.value,
        "assertion_id": selection.assertion_id,
        "evidence_ids": ordered,
        "affects_sufficiency": affects_sufficiency,
    }
    return UncertaintyReason(
        uncertainty_id=sufficiency_content_id("sur", material),
        category=category,
        assertion_id=selection.assertion_id,
        evidence_ids=ordered,
        explanation=_EXPLANATIONS[category],
        affects_sufficiency=affects_sufficiency,
    )


def classify_uncertainty(
    context: AssessmentContext,
    selection: AssertionSelection,
    policy: SufficiencyAssertion | None,
    *,
    identity_missing: bool,
    has_contradictions: bool,
) -> tuple[UncertaintyReason, ...]:
    records, missing_ids = selected_records(context, selection)
    reasons: list[UncertaintyReason] = []

    def add(
        category: UncertaintyCategory,
        ids: tuple[str, ...],
        *,
        affects: bool,
    ) -> None:
        if ids:
            reasons.append(
                _reason(category, selection, ids, affects_sufficiency=affects)
            )

    if (
        identity_missing
        and policy is not None
        and policy.required_identity_type is not None
    ):
        add(UncertaintyCategory.MISSING_IDENTITY, selection.evidence_ids, affects=True)
    unverified = tuple(
        item.identifier.evidence_id
        for item in records
        if not item.provenance.origin_verified
    )
    add(UncertaintyCategory.UNVERIFIED_PROVENANCE, unverified, affects=False)
    synthetic = tuple(
        item.identifier.evidence_id for item in records if item.provenance.synthetic
    )
    add(UncertaintyCategory.SYNTHETIC_ORIGIN, synthetic, affects=False)
    declared = tuple(
        item.identifier.evidence_id
        for item in records
        if item.provenance.origin_type is EvidenceOriginType.CLIENT_DECLARED
    )
    add(UncertaintyCategory.DECLARED_CONTEXT, declared, affects=False)
    missing_model = tuple(
        item.identifier.evidence_id
        for item in records
        if isinstance(item.observation, MLEvidenceObservation)
        and item.observation.model_version is None
    )
    add(UncertaintyCategory.MISSING_MODEL_VERSION, missing_model, affects=False)
    missing_time = tuple(
        item.identifier.evidence_id for item in records if not item.context.timestamps
    )
    add(UncertaintyCategory.MISSING_TEMPORAL_CONTEXT, missing_time, affects=False)
    if has_weak_context_match(context, selection):
        add(
            UncertaintyCategory.WEAK_CONTEXTUAL_ASSOCIATION,
            selection.evidence_ids,
            affects=True,
        )
    if has_unsupported_relation(context, selection):
        add(
            UncertaintyCategory.UNSUPPORTED_CROSS_MODULE_RELATION,
            selection.evidence_ids,
            affects=True,
        )
    if has_contradictions:
        add(
            UncertaintyCategory.CONFLICTING_CLAIMS, selection.evidence_ids, affects=True
        )
    incomplete = tuple(
        item.identifier.evidence_id
        for item in records
        if item.quality.completeness is not EvidenceQualityState.SUFFICIENT
    )
    add(UncertaintyCategory.INCOMPLETE_SOURCE_METADATA, incomplete, affects=False)
    if missing_ids:
        add(UncertaintyCategory.MISSING_IDENTITY, missing_ids, affects=True)
    unique = {item.uncertainty_id: item for item in reasons}
    return tuple(sorted(unique.values(), key=lambda item: item.uncertainty_id))[:8]
