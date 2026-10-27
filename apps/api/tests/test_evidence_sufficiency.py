from __future__ import annotations

import inspect

import pytest
from pydantic import ValidationError

from app.evidence.adapters import (
    adapt_behavioral_analysis,
    adapt_ml_inference,
    adapt_static_analysis,
    adapt_vulnerability_intelligence,
    create_evidence_batch,
)
from app.schemas.evidence import (
    EvidenceBatch,
    EvidenceContext,
    EvidenceIdentityStrength,
    EvidenceOriginType,
    EvidenceProvenance,
    EvidenceTrustClassification,
)
from app.schemas.sufficiency import (
    MAX_ASSERTIONS_PER_REQUEST,
    MAX_REQUIREMENTS_PER_ASSERTION,
    AssertionSelection,
    EvidenceContradiction,
    EvidenceGap,
    EvidenceRequirement,
    RequirementEvaluation,
    RequirementKind,
    RequirementState,
    SufficiencyAssertion,
    SufficiencyAssessmentRequest,
    SufficiencyAssessmentResult,
    SufficiencyState,
    UncertaintyCategory,
    UncertaintyReason,
)
from app.sufficiency import assess_evidence_sufficiency
from app.sufficiency.rules import (
    BUILTIN_SUFFICIENCY_ASSERTIONS,
    DEFAULT_SUFFICIENCY_POLICY_REGISTRY,
    SufficiencyPolicyRegistry,
    SufficiencyPolicyRegistryError,
)
from tests.test_identity_resolution import (
    _rebuild_record,
    _second_static,
    _second_vulnerability,
)
from tests.test_multilayer_correlation import _reference, _second_ml
from tests.test_unified_evidence import (
    behavioral_source,
    ml_source,
    static_source,
    vulnerability_source,
)


def _request(
    assertion_id: str, *records: object, evidence_ids: tuple[str, ...] | None = None
) -> SufficiencyAssessmentResult:
    batch = create_evidence_batch(tuple(records))  # type: ignore[arg-type]
    selected = (
        tuple(item.identifier.evidence_id for item in batch.records)
        if evidence_ids is None
        else tuple(sorted(evidence_ids))
    )
    return assess_evidence_sufficiency(
        SufficiencyAssessmentRequest(
            batch=batch,
            assertions=(
                AssertionSelection(assertion_id=assertion_id, evidence_ids=selected),
            ),
        )
    )


def _assessment(
    assertion_id: str, *records: object, evidence_ids: tuple[str, ...] | None = None
):
    return _request(assertion_id, *records, evidence_ids=evidence_ids).assessments[0]


@pytest.mark.parametrize(
    ("assertion_id", "records"),
    [
        (
            "AS-CONTENT-001",
            (adapt_static_analysis(static_source()), _second_static()),
        ),
        (
            "AS-VULN-001",
            (
                adapt_vulnerability_intelligence(vulnerability_source()),
                _second_vulnerability(),
            ),
        ),
        (
            "AS-ANALYSIS-001",
            (adapt_ml_inference(ml_source()), _second_ml()),
        ),
    ],
)
def test_exact_supported_assertions_are_sufficient_only_for_their_statement(
    assertion_id: str, records: tuple[object, ...]
) -> None:
    result = _request(assertion_id, *records)
    assessment = result.assessments[0]
    assert assessment.state is SufficiencyState.SUFFICIENT
    assert all(
        item.state is RequirementState.SATISFIED
        for item in assessment.requirement_evaluations
    )
    assert not assessment.gaps
    assert not assessment.contradictions
    assert result.threat_confirmed is False
    assert result.exploitation_inferred is False
    assert result.file_executed is False


def test_explicit_reference_is_sufficient_only_for_declared_link() -> None:
    static = adapt_static_analysis(static_source())
    ml = _reference(adapt_ml_inference(ml_source()), static)
    result = _request("AS-REF-001", static, ml)
    assessment = result.assessments[0]
    assert assessment.state == "sufficient"
    assert "causality" in " ".join(assessment.limitations)
    assert result.causal_inference_performed is False


def test_different_hashes_are_insufficient_not_false() -> None:
    assessment = _assessment(
        "AS-CONTENT-001",
        adapt_static_analysis(static_source()),
        _second_static(sha256="b" * 64),
    )
    assert assessment.state == "insufficient_evidence"
    assert any(item.category == "missing_identity" for item in assessment.gaps)
    assert all(item.assertion_proven_false is False for item in assessment.gaps)


def test_relevant_content_conflict_prevents_sufficient() -> None:
    first = adapt_static_analysis(static_source())
    second = adapt_static_analysis(
        static_source().model_copy(
            update={
                "fingerprint": static_source().fingerprint.model_copy(
                    update={"sha256": "b" * 64}
                )
            }
        )
    )
    assessment = _assessment("AS-CONTENT-001", first, second)
    assert assessment.state == "conflicting_evidence"
    assert assessment.contradictions
    assert any(
        item.category == "conflicting_claims" for item in assessment.uncertainty_reasons
    )


def test_irrelevant_conflict_does_not_block_independent_cve_assertion() -> None:
    first_static = adapt_static_analysis(static_source())
    second_static = adapt_static_analysis(
        static_source().model_copy(
            update={
                "fingerprint": static_source().fingerprint.model_copy(
                    update={"sha256": "b" * 64}
                )
            }
        )
    )
    first_cve = adapt_vulnerability_intelligence(vulnerability_source())
    second_cve = _second_vulnerability()
    selected = tuple(
        sorted((first_cve.identifier.evidence_id, second_cve.identifier.evidence_id))
    )
    assessment = _assessment(
        "AS-VULN-001",
        first_static,
        second_static,
        first_cve,
        second_cve,
        evidence_ids=selected,
    )
    assert assessment.state == "sufficient"
    assert not assessment.contradictions


def test_duplicate_reference_is_a_relevant_correlation_contradiction() -> None:
    static = adapt_static_analysis(static_source())
    ml = _reference(adapt_ml_inference(ml_source()), static)
    duplicated = ml.model_copy(update={"references": ml.references * 2})
    assessment = _assessment("AS-REF-001", static, duplicated)
    assert assessment.state == "conflicting_evidence"
    assert any(
        item.category == "duplicate_reference" for item in assessment.contradictions
    )


def test_missing_reference_is_insufficient() -> None:
    assessment = _assessment(
        "AS-REF-001",
        adapt_static_analysis(static_source()),
        adapt_ml_inference(ml_source()),
    )
    assert assessment.state == "insufficient_evidence"
    assert any(item.category == "missing_relationship" for item in assessment.gaps)


@pytest.mark.parametrize(
    "assertion_id",
    [
        "AS-MALWARE-001",
        "AS-ATTACK-001",
        "AS-COMPROMISE-001",
        "AS-EXPLOIT-001",
        "AS-EXECUTION-001",
        "AS-PERSISTENCE-001",
        "AS-CONTROL-001",
        "AS-MLVALID-001",
        "AS-DEVICE-001",
    ],
)
def test_negative_assertion_matrix_is_unsupported(assertion_id: str) -> None:
    result = _request(assertion_id, adapt_ml_inference(ml_source()))
    assessment = result.assessments[0]
    assert assessment.state is SufficiencyState.UNSUPPORTED_ASSERTION
    assert not assessment.requirement_evaluations
    assert result.threat_confirmed is False
    assert result.probability_generated is False


def test_wrong_domain_is_not_applicable() -> None:
    assessment = _assessment(
        "AS-CONTENT-001",
        adapt_vulnerability_intelligence(vulnerability_source()),
        _second_vulnerability(),
    )
    assert assessment.state == "not_applicable"
    assert any(item.category == "inapplicable_domain" for item in assessment.gaps)


def test_context_compatibility_without_identity_is_not_positive() -> None:
    static = adapt_static_analysis(static_source())
    ml = _reference(adapt_ml_inference(ml_source()), static)
    assessment = _assessment("AS-ANALYSIS-001", static, ml)
    assert assessment.state == "not_applicable"
    assert any(
        item.category == UncertaintyCategory.WEAK_CONTEXTUAL_ASSOCIATION
        for item in assessment.uncertainty_reasons
    )


def test_equal_uuid_across_source_modules_is_insufficient() -> None:
    assessment = _assessment(
        "AS-ANALYSIS-001",
        adapt_ml_inference(ml_source()),
        adapt_behavioral_analysis(behavioral_source()),
    )
    assert assessment.state == "insufficient_evidence"
    assert any(
        item.category == "missing_identity" for item in assessment.uncertainty_reasons
    )


def test_synthetic_provenance_and_missing_model_version_are_preserved() -> None:
    assessment = _assessment(
        "AS-ANALYSIS-001", adapt_ml_inference(ml_source()), _second_ml()
    )
    categories = {item.category for item in assessment.uncertainty_reasons}
    assert UncertaintyCategory.SYNTHETIC_ORIGIN in categories
    assert UncertaintyCategory.MISSING_MODEL_VERSION in categories
    assert assessment.state == "sufficient"
    assert all(item.synthetic for item in assessment.support_references)


def test_declared_and_authenticated_origins_remain_distinct() -> None:
    local = adapt_static_analysis(static_source())
    declared_base = _second_static()
    declared = _rebuild_record(
        declared_base,
        provenance=EvidenceProvenance(
            source_analysis_id=declared_base.provenance.source_analysis_id,
            origin_type=EvidenceOriginType.CLIENT_DECLARED,
            origin_verified=False,
            trust_classification=EvidenceTrustClassification.CLIENT_DECLARED,
            synthetic=False,
            integrity_verification=declared_base.provenance.integrity_verification,
            generation_context="declared_test_context",
        ),
    )
    assessment = _assessment("AS-CONTENT-001", local, declared)
    assert assessment.state == "sufficient"
    categories = {item.category for item in assessment.uncertainty_reasons}
    assert UncertaintyCategory.DECLARED_CONTEXT in categories
    assert UncertaintyCategory.UNVERIFIED_PROVENANCE in categories
    assert len({item.origin_type for item in assessment.support_references}) == 2


def test_missing_temporal_context_is_uncertainty_not_nonoccurrence() -> None:
    first = adapt_static_analysis(static_source())
    second = _second_static()
    empty = EvidenceContext(
        timestamps=(),
        source_status=first.context.source_status,
        sensitive_fields_omitted=first.context.sensitive_fields_omitted,
    )
    first = _rebuild_record(first, context=empty)
    assessment = _assessment("AS-CONTENT-001", first, second)
    assert assessment.state == "sufficient"
    reason = next(
        item
        for item in assessment.uncertainty_reasons
        if item.category == "missing_temporal_context"
    )
    assert reason.affects_sufficiency is False
    assert "non-occurrence" in reason.explanation


def test_missing_selected_record_stays_explicit() -> None:
    record = adapt_static_analysis(static_source())
    missing = "evd_" + "0" * 64
    assessment = _assessment(
        "AS-CONTENT-001",
        record,
        evidence_ids=tuple(sorted((record.identifier.evidence_id, missing))),
    )
    assert assessment.state == "insufficient_evidence"
    gap = next(item for item in assessment.gaps if item.category == "missing_record")
    assert gap.missing_evidence_ids == (missing,)


@pytest.mark.parametrize(
    "field",
    [
        "persistence_performed",
        "causal_inference_performed",
        "temporal_sequence_inferred",
        "threat_confirmed",
        "malware_detected",
        "host_compromised",
        "exploitation_inferred",
        "attack_technique_executed",
        "file_executed",
        "risk_score_generated",
        "probability_generated",
        "trust_promoted",
    ],
)
def test_operational_and_numeric_promotions_are_hard_false(field: str) -> None:
    result = _request(
        "AS-CONTENT-001",
        adapt_static_analysis(static_source()),
        _second_static(),
    )
    assert getattr(result, field) is False


def test_uncertainty_has_no_numeric_confidence() -> None:
    result = _request("AS-ANALYSIS-001", adapt_ml_inference(ml_source()), _second_ml())
    assert all(
        item.numeric_confidence is None
        for item in result.assessments[0].uncertainty_reasons
    )
    encoded = result.model_dump_json()
    assert "attack_probability" not in encoded
    assert "malware_probability" not in encoded


def test_determinism_and_input_permutation() -> None:
    records = (adapt_static_analysis(static_source()), _second_static())
    left = _request("AS-CONTENT-001", *records)
    right = _request("AS-CONTENT-001", *reversed(records))
    assert left.model_dump_json() == right.model_dump_json()


def test_assertion_selection_permutation_is_deterministic() -> None:
    records = (adapt_static_analysis(static_source()), _second_static())
    batch = create_evidence_batch(records)
    ids = tuple(item.identifier.evidence_id for item in batch.records)
    selections = (
        AssertionSelection(assertion_id="AS-CONTENT-001", evidence_ids=ids),
        AssertionSelection(assertion_id="AS-EXECUTION-001", evidence_ids=ids),
    )
    left = assess_evidence_sufficiency(
        SufficiencyAssessmentRequest(batch=batch, assertions=selections)
    )
    right = assess_evidence_sufficiency(
        SufficiencyAssessmentRequest(
            batch=batch, assertions=tuple(reversed(selections))
        )
    )
    assert left.model_dump_json() == right.model_dump_json()


def test_untrusted_precomputed_results_are_not_request_fields() -> None:
    assert set(SufficiencyAssessmentRequest.model_fields) == {
        "schema_version",
        "batch",
        "assertions",
    }
    source = inspect.getsource(assess_evidence_sufficiency)
    assert "resolve_identities" in source
    assert "correlate_evidence" in source
    batch = create_evidence_batch((adapt_static_analysis(static_source()),))
    with pytest.raises(ValidationError):
        SufficiencyAssessmentRequest.model_validate(
            {
                "batch": batch.model_dump(),
                "assertions": [
                    {
                        "assertion_id": "AS-CONTENT-001",
                        "evidence_ids": [batch.records[0].identifier.evidence_id],
                    }
                ],
                "trusted": True,
                "correlation_result": {},
            }
        )


def test_manipulated_evidence_identifier_is_rejected_by_0601() -> None:
    record = adapt_static_analysis(static_source())
    with pytest.raises(ValidationError):
        EvidenceBatch.model_validate(
            {
                **create_evidence_batch((record,)).model_dump(),
                "records": [
                    {
                        **record.model_dump(),
                        "identifier": {"evidence_id": "evd_" + "0" * 64},
                    }
                ],
            }
        )


def test_excessive_assertions_and_duplicate_selections_are_rejected() -> None:
    record = adapt_static_analysis(static_source())
    batch = create_evidence_batch((record,))
    evidence_ids = (record.identifier.evidence_id,)
    selections = tuple(
        AssertionSelection(
            assertion_id=f"AS-OVER-{index:03d}", evidence_ids=evidence_ids
        )
        for index in range(MAX_ASSERTIONS_PER_REQUEST + 1)
    )
    with pytest.raises(ValidationError):
        SufficiencyAssessmentRequest(batch=batch, assertions=selections)
    duplicate = AssertionSelection(
        assertion_id="AS-CONTENT-001", evidence_ids=evidence_ids
    )
    with pytest.raises(ValidationError, match="unique"):
        SufficiencyAssessmentRequest(batch=batch, assertions=(duplicate, duplicate))


def test_excessive_requirements_and_dynamic_policy_are_rejected() -> None:
    policy = BUILTIN_SUFFICIENCY_ASSERTIONS[0]
    requirement = EvidenceRequirement(
        requirement_id="extra_requirement",
        kind=RequirementKind.PROVENANCE_AVAILABLE,
        description="Extra bounded requirement.",
        required=True,
    )
    with pytest.raises(ValidationError):
        SufficiencyAssertion.model_validate(
            {
                **policy.model_dump(),
                "requirements": [
                    *policy.requirements,
                    *([requirement] * (MAX_REQUIREMENTS_PER_ASSERTION + 1)),
                ],
            }
        )
    with pytest.raises(ValidationError):
        SufficiencyAssertion.model_validate(
            {**policy.model_dump(), "executable_expression": True}
        )


def test_registry_is_static_sorted_and_rejects_duplicates() -> None:
    assert DEFAULT_SUFFICIENCY_POLICY_REGISTRY.assertions == tuple(
        sorted(BUILTIN_SUFFICIENCY_ASSERTIONS, key=lambda item: item.assertion_id)
    )
    assert len(BUILTIN_SUFFICIENCY_ASSERTIONS) == 4
    with pytest.raises(SufficiencyPolicyRegistryError):
        SufficiencyPolicyRegistry((BUILTIN_SUFFICIENCY_ASSERTIONS[0],) * 2)
    with pytest.raises(SufficiencyPolicyRegistryError):
        SufficiencyPolicyRegistry(())
    with pytest.raises(SufficiencyPolicyRegistryError):
        DEFAULT_SUFFICIENCY_POLICY_REGISTRY.get("AS-NOPE-999")


def test_result_rejects_tampered_summary_and_assessment_id() -> None:
    result = _request(
        "AS-CONTENT-001",
        adapt_static_analysis(static_source()),
        _second_static(),
    )
    assessment = result.assessments[0]
    with pytest.raises(ValidationError):
        type(assessment).model_validate(
            {**assessment.model_dump(), "assessment_id": "sas_" + "0" * 64}
        )
    with pytest.raises(ValidationError):
        SufficiencyAssessmentResult.model_validate(
            {
                **result.model_dump(),
                "summary": result.summary.model_copy(
                    update={"sufficient": 0}
                ).model_dump(),
            }
        )


def test_nested_contract_identifiers_and_policy_invariants_are_verified() -> None:
    sufficient = _request(
        "AS-CONTENT-001",
        adapt_static_analysis(static_source()),
        _second_static(),
    ).assessments[0]
    conflicting_first = adapt_static_analysis(static_source())
    conflicting_second = adapt_static_analysis(
        static_source().model_copy(
            update={
                "fingerprint": static_source().fingerprint.model_copy(
                    update={"sha256": "b" * 64}
                )
            }
        )
    )
    conflicting = _assessment("AS-CONTENT-001", conflicting_first, conflicting_second)
    insufficient = _assessment(
        "AS-CONTENT-001",
        adapt_static_analysis(static_source()),
        _second_static(sha256="b" * 64),
    )
    uncertainty = _assessment(
        "AS-ANALYSIS-001", adapt_ml_inference(ml_source()), _second_ml()
    ).uncertainty_reasons[0]
    cases = (
        (
            RequirementEvaluation,
            sufficient.requirement_evaluations[0].model_dump(),
            "evaluation_id",
            "sre_",
        ),
        (
            EvidenceContradiction,
            conflicting.contradictions[0].model_dump(),
            "contradiction_id",
            "sct_",
        ),
        (EvidenceGap, insufficient.gaps[0].model_dump(), "gap_id", "sgp_"),
        (
            UncertaintyReason,
            uncertainty.model_dump(),
            "uncertainty_id",
            "sur_",
        ),
    )
    for model, payload, field, prefix in cases:
        with pytest.raises(ValidationError):
            model.model_validate({**payload, field: prefix + "0" * 64})

    policy = BUILTIN_SUFFICIENCY_ASSERTIONS[0]
    with pytest.raises(ValidationError, match="unique"):
        SufficiencyAssertion.model_validate(
            {**policy.model_dump(), "requirements": (policy.requirements[0],) * 2}
        )
    with pytest.raises(ValidationError, match="together"):
        SufficiencyAssertion.model_validate(
            {**policy.model_dump(), "required_identity_namespace": None}
        )


def test_selection_and_result_ordering_are_contractually_enforced() -> None:
    records = (adapt_static_analysis(static_source()), _second_static())
    batch = create_evidence_batch(records)
    evidence_ids = tuple(item.identifier.evidence_id for item in batch.records)
    with pytest.raises(ValidationError, match="sorted"):
        AssertionSelection(
            assertion_id="AS-CONTENT-001",
            evidence_ids=tuple(reversed(evidence_ids)),
        )
    selections = (
        AssertionSelection(assertion_id="AS-CONTENT-001", evidence_ids=evidence_ids),
        AssertionSelection(assertion_id="AS-EXECUTION-001", evidence_ids=evidence_ids),
    )
    result = assess_evidence_sufficiency(
        SufficiencyAssessmentRequest(batch=batch, assertions=selections)
    )
    with pytest.raises(ValidationError, match="ordered"):
        SufficiencyAssessmentResult.model_validate(
            {**result.model_dump(), "assessments": tuple(reversed(result.assessments))}
        )


def test_single_record_and_unsupported_namespace_cannot_satisfy_identity() -> None:
    record = adapt_static_analysis(static_source())
    single = _assessment("AS-CONTENT-001", record)
    assert single.state == "insufficient_evidence"
    altered = _rebuild_record(
        record,
        subject=record.subject.model_copy(
            update={
                "namespace": "sha1",
                "value": "b" * 40,
                "identity_strength": EvidenceIdentityStrength.DECLARED,
                "verified": False,
            }
        ),
    )
    unresolved = _assessment("AS-CONTENT-001", altered, _second_static())
    assert unresolved.state == "insufficient_evidence"
    assert not unresolved.contradictions


def test_privacy_canaries_and_raw_values_are_absent() -> None:
    result = _request(
        "AS-CONTENT-001",
        adapt_static_analysis(static_source()),
        _second_static(),
    )
    encoded = result.model_dump_json()
    assert "secret-user-path.exe" not in encoded
    assert "a" * 64 not in encoded
    assert all(
        not item.raw_value_disclosed
        for assessment in result.assessments
        for item in assessment.support_references
    )


def test_sufficiency_modules_have_no_external_effects_or_model_execution() -> None:
    import app.sufficiency.contradictions as contradictions_module
    import app.sufficiency.evaluation as evaluation_module
    import app.sufficiency.resolver as resolver_module
    import app.sufficiency.service as service_module
    import app.sufficiency.uncertainty as uncertainty_module

    source = "\n".join(
        inspect.getsource(module)
        for module in (
            contradictions_module,
            evaluation_module,
            resolver_module,
            service_module,
            uncertainty_module,
        )
    )
    forbidden = (
        "requests.",
        "httpx.",
        "socket.",
        "subprocess.",
        "open(",
        "eval(",
        "exec(",
        "sqlite",
        "redis",
        "predict(",
        "completion",
        "plugin",
    )
    assert not any(token in source for token in forbidden)


def test_json_round_trip_and_resource_contracts() -> None:
    result = _request(
        "AS-VULN-001",
        adapt_vulnerability_intelligence(vulnerability_source()),
        _second_vulnerability(),
    )
    assert (
        SufficiencyAssessmentResult.model_validate_json(result.model_dump_json())
        == result
    )
    assert result.summary.requested_assertions == 1
    assert len(result.model_dump_json()) < 1024 * 1024
