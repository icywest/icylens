from __future__ import annotations

import hashlib
import inspect
import json
from datetime import UTC
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.evidence.adapters import (
    adapt_behavioral_analysis,
    adapt_ml_inference,
    adapt_static_analysis,
    adapt_vulnerability_intelligence,
    create_evidence_batch,
)
from app.identity.resolution import resolve_identities
from app.identity.rules import (
    DEFAULT_IDENTITY_RULE_REGISTRY,
    IdentityRuleRegistry,
    IdentityRuleRegistryError,
)
from app.schemas.behavior_analysis import BehavioralAnalysisSource
from app.schemas.evidence import (
    EvidenceIdentifier,
    EvidenceRecord,
    EvidenceReference,
    EvidenceReferenceProvenance,
    EvidenceReferenceType,
    EvidenceSubjectReference,
    EvidenceVerificationStatus,
)
from app.schemas.identity import (
    MAX_IDENTITY_CLAIMS,
    IdentityClaim,
    IdentityClaimAvailability,
    IdentityNamespace,
    IdentityResolutionRequest,
    IdentityResolutionResult,
    IdentityResolutionStatus,
    IdentityType,
)
from tests.test_unified_evidence import (
    behavioral_source,
    ml_source,
    static_source,
    vulnerability_source,
)


def _resolve(*records: EvidenceRecord) -> IdentityResolutionResult:
    return resolve_identities(
        IdentityResolutionRequest(batch=create_evidence_batch(tuple(records)))
    )


def _replace_subject(
    record: EvidenceRecord, subject: EvidenceSubjectReference
) -> EvidenceRecord:
    return _rebuild_record(record, subject=subject)


def _rebuild_record(record: EvidenceRecord, **updates: object) -> EvidenceRecord:
    candidate = record.model_copy(update={**updates, "references": ()})
    canonical = json.dumps(
        candidate.model_dump(mode="json", exclude={"identifier", "references"}),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    fields = candidate.model_dump()
    fields["identifier"] = EvidenceIdentifier(
        evidence_id=f"evd_{hashlib.sha256(canonical).hexdigest()}"
    )
    return EvidenceRecord.model_validate(fields)


def _second_static(*, sha256: str = "a" * 64) -> EvidenceRecord:
    source = static_source().model_copy(
        update={
            "analysis_id": UUID("30000000-0000-4000-8000-000000000003"),
            "fingerprint": static_source().fingerprint.model_copy(
                update={"sha256": sha256}
            ),
        }
    )
    return adapt_static_analysis(source)


def _second_vulnerability() -> EvidenceRecord:
    source = vulnerability_source().model_copy(
        update={"correlation_id": UUID("40000000-0000-4000-8000-000000000004")}
    )
    return adapt_vulnerability_intelligence(source)


def _explicit_derivation(
    source: EvidenceRecord, target: EvidenceRecord
) -> EvidenceRecord:
    reference = EvidenceReference(
        source_evidence_id=source.identifier.evidence_id,
        referenced_evidence_id=target.identifier.evidence_id,
        reference_type=EvidenceReferenceType.EXPLICIT_DERIVATION,
        provenance=EvidenceReferenceProvenance(
            established_by="explicit_source_contract",
            origin_type=source.provenance.origin_type,
            description="Explicit source-contract derivation reference.",
        ),
        identity_assumptions=(
            "The reference supplies context only and does not assert subject equality.",
        ),
        verification_status=EvidenceVerificationStatus.STRUCTURALLY_VALID,
    )
    return source.model_copy(update={"references": (reference,)})


def test_same_sha256_resolves_content_identity_without_execution_claim() -> None:
    result = _resolve(adapt_static_analysis(static_source()), _second_static())
    groups = [item for item in result.groups if item.identity_type == "file_content"]
    assert len(groups) == 1
    assert groups[0].namespace == IdentityNamespace.SHA256
    match = next(item for item in result.matches if item.status == "same_identity")
    assert match.execution_confirmed is False
    assert result.attack_finding_generated is False
    assert "a" * 64 not in result.model_dump_json()


def test_different_content_hashes_do_not_group_or_imply_malware() -> None:
    result = _resolve(
        adapt_static_analysis(static_source()), _second_static(sha256="b" * 64)
    )
    assert not [item for item in result.groups if item.identity_type == "file_content"]
    assert result.threat_correlation_performed is False
    assert result.risk_score_generated is False


@pytest.mark.parametrize(
    ("namespace", "value"),
    [("sha1", "b" * 40), ("sha256", "not-a-valid-hash")],
)
def test_unsupported_or_invalid_hash_is_unresolved(namespace: str, value: str) -> None:
    record = adapt_static_analysis(static_source())
    altered = _replace_subject(
        record,
        EvidenceSubjectReference(
            subject_type="file_content",
            namespace=namespace,
            value=value,
            identity_strength="declared",
            verified=False,
            scope="accepted_byte_stream_only",
        ),
    )
    result = _resolve(altered)
    claim = next(item for item in result.claims if item.identity_type == "file_content")
    assert claim.availability == IdentityClaimAvailability.UNRESOLVED
    assert any(item.code == "unsupported_namespace" for item in result.conflicts)


def test_missing_hash_is_rejected_by_evidence_contract() -> None:
    with pytest.raises(ValidationError):
        EvidenceSubjectReference(
            subject_type="file_content",
            namespace="sha256",
            value="",
            identity_strength="missing",
            verified=False,
            scope="accepted_byte_stream_only",
        )


def test_same_cve_resolves_vulnerability_not_installation_or_exploitation() -> None:
    first = adapt_vulnerability_intelligence(vulnerability_source())
    result = _resolve(first, _second_vulnerability())
    group = next(
        item for item in result.groups if item.identity_type == "vulnerability"
    )
    assert group.namespace == IdentityNamespace.CVE
    assert result.exploitation_inferred is False
    assert "installed software" in " ".join(group.limitations)


def test_ml_model_identity_stays_unresolved_without_version() -> None:
    result = _resolve(adapt_ml_inference(ml_source()))
    model_claim = next(
        item for item in result.claims if item.identity_type == "ml_model"
    )
    assert model_claim.availability == "unresolved"
    assert model_claim.missing_attributes == ("model_version",)
    assert result.ml_promoted_to_observation is False


def test_versioned_ml_model_identity_uses_all_required_attributes() -> None:
    first = adapt_ml_inference(ml_source())
    second_source = ml_source().model_copy(
        update={"inference_id": UUID("60000000-0000-4000-8000-000000000006")}
    )
    second = adapt_ml_inference(second_source)
    first = _rebuild_record(
        first,
        observation=first.observation.model_copy(update={"model_version": "1.0.0"}),
    )
    second = _rebuild_record(
        second,
        observation=second.observation.model_copy(update={"model_version": "1.0.0"}),
    )
    result = _resolve(first, second)
    group = next(item for item in result.groups if item.identity_type == "ml_model")
    assert group.namespace == IdentityNamespace.MODEL_ID_VERSION
    assert result.ml_promoted_to_observation is False


def test_analysis_uuid_is_source_scoped_across_ml_and_behavior() -> None:
    ml = adapt_ml_inference(ml_source())
    behavior = adapt_behavioral_analysis(behavioral_source())
    result = _resolve(ml, behavior)
    assert not [item for item in result.groups if item.identity_type == "analysis"]
    assert any(item.status == "not_comparable" for item in result.matches)


def test_static_to_ml_requires_explicit_reference_for_compatible_context() -> None:
    static = adapt_static_analysis(static_source())
    ml = adapt_ml_inference(ml_source())
    without_reference = _resolve(static, ml)
    assert any(item.status == "not_comparable" for item in without_reference.matches)

    with_reference = _resolve(static, _explicit_derivation(ml, static))
    compatible = [
        item
        for item in with_reference.matches
        if item.status == IdentityResolutionStatus.COMPATIBLE_CONTEXT
    ]
    assert len(compatible) == 1
    assert compatible[0].identity_confirmed is False
    assert not with_reference.groups


def test_context_compatibility_is_not_transitive() -> None:
    static = adapt_static_analysis(static_source())
    ml = adapt_ml_inference(ml_source())
    behavior = adapt_behavioral_analysis(behavioral_source())
    ml = _explicit_derivation(ml, static)
    behavior = _explicit_derivation(behavior, ml)
    result = _resolve(static, ml, behavior)
    assert result.summary.compatible_context_matches == 2
    assert not result.groups


def test_conflicting_subjects_for_one_analysis_are_visible_and_not_grouped() -> None:
    first = adapt_static_analysis(static_source())
    conflicting_source = static_source().model_copy(
        update={
            "fingerprint": static_source().fingerprint.model_copy(
                update={"sha256": "b" * 64}
            )
        }
    )
    second = adapt_static_analysis(conflicting_source)
    result = _resolve(first, second)
    assert any(item.code == "conflicting_analysis_subject" for item in result.conflicts)
    assert any(item.status == "conflicting_identity" for item in result.matches)
    assert not result.groups


def test_exact_subset_is_not_grouped_when_analysis_has_third_conflicting_claim() -> (
    None
):
    first = adapt_static_analysis(static_source())
    same_hash_later = static_source().model_copy(
        update={"completed_at": static_source().completed_at.replace(microsecond=1)}
    )
    second = adapt_static_analysis(same_hash_later)
    different = adapt_static_analysis(
        static_source().model_copy(
            update={
                "fingerprint": static_source().fingerprint.model_copy(
                    update={"sha256": "b" * 64}
                )
            }
        )
    )
    result = _resolve(first, second, different)
    assert result.summary.same_identity_matches == 1
    assert result.summary.conflicts == 1
    assert not result.groups


def test_duplicate_explicit_reference_is_reported_without_duplicate_match() -> None:
    static = adapt_static_analysis(static_source())
    ml = _explicit_derivation(adapt_ml_inference(ml_source()), static)
    ml = ml.model_copy(update={"references": ml.references * 2})
    result = _resolve(static, ml)
    assert any(item.code == "duplicate_evidence_reference" for item in result.conflicts)
    assert result.summary.compatible_context_matches == 1


def test_process_and_attack_identity_remain_unresolved_without_source_attributes() -> (
    None
):
    result = _resolve(adapt_behavioral_analysis(behavioral_source()))
    assert not any(
        item.identity_type == IdentityType.PROCESS_INSTANCE for item in result.claims
    )
    assert not any(
        item.identity_type == IdentityType.ATTACK_TECHNIQUE for item in result.claims
    )
    limitations = " ".join(result.limitations)
    assert "process-instance" in limitations
    assert "ATT&CK" in limitations
    process_rule = DEFAULT_IDENTITY_RULE_REGISTRY.get("IR-PROC-001")
    assert "host_scope" in process_rule.required_attributes
    assert "process_instance_id" in process_rule.required_attributes
    attack_rule = DEFAULT_IDENTITY_RULE_REGISTRY.get("IR-ATTACK-001")
    assert attack_rule.required_attributes == (
        "technique_id",
        "stix_id",
        "domain",
        "catalog_version",
    )


def test_synthetic_and_client_declared_provenance_are_preserved() -> None:
    declared = adapt_behavioral_analysis(behavioral_source())
    synthetic_source = behavioral_source().model_copy(
        update={
            "analysis_id": UUID("50000000-0000-4000-8000-000000000005"),
            "source": BehavioralAnalysisSource.SYNTHETIC_SCENARIO,
        }
    )
    synthetic = adapt_behavioral_analysis(synthetic_source)
    result = _resolve(declared, synthetic)
    contexts = {item.evidence_id: item for item in result.contexts}
    assert contexts[declared.identifier.evidence_id].origin_type == "client_declared"
    assert contexts[declared.identifier.evidence_id].synthetic is False
    assert (
        contexts[synthetic.identifier.evidence_id].origin_type == "synthetic_generated"
    )
    assert contexts[synthetic.identifier.evidence_id].synthetic is True


def test_timestamp_meanings_and_utc_are_preserved_without_temporal_matching() -> None:
    result = _resolve(adapt_static_analysis(static_source()))
    timestamps = result.contexts[0].temporal_context
    assert [item.meaning for item in timestamps] == [
        "analysis_started_time",
        "analysis_completed_time",
    ]
    assert all(item.value.tzinfo == UTC for item in timestamps)
    assert not result.groups


def test_input_permutation_has_identical_deterministic_output() -> None:
    first = adapt_static_analysis(static_source())
    second = _second_static()
    left = resolve_identities(
        IdentityResolutionRequest(batch=create_evidence_batch((first, second)))
    )
    right = resolve_identities(
        IdentityResolutionRequest(batch=create_evidence_batch((second, first)))
    )
    assert left == right


def test_invalid_request_version_unknown_domain_and_excess_claims_are_rejected() -> (
    None
):
    batch = create_evidence_batch((adapt_static_analysis(static_source()),))
    with pytest.raises(ValidationError):
        IdentityResolutionRequest.model_validate(
            {"schema_version": "9.9.9", "batch": batch}
        )
    with pytest.raises(ValidationError):
        EvidenceSubjectReference(
            subject_type="unknown_domain",
            namespace="unknown",
            value="value",
            identity_strength="declared",
            verified=False,
            scope="unknown",
        )
    sample = IdentityClaim.model_construct(
        claim_id="idc_" + "0" * 64,
        evidence_id="evd_" + "0" * 64,
        identity_type=IdentityType.FILE_CONTENT,
        availability=IdentityClaimAvailability.UNRESOLVED,
        reference=None,
        required_attributes=("digest",),
        missing_attributes=("digest",),
        source_module="static_analysis",
        verification_status="partial",
        limitations=("Missing.",),
    )
    result = _resolve(adapt_static_analysis(static_source())).model_dump()
    result["claims"] = (sample,) * (MAX_IDENTITY_CLAIMS + 1)
    with pytest.raises(ValidationError):
        IdentityResolutionResult.model_validate(result)


def test_output_rejects_tampered_content_ids_and_summary() -> None:
    result = _resolve(adapt_static_analysis(static_source()), _second_static())
    payload = result.model_dump()
    payload["claims"][0]["claim_id"] = "idc_" + "0" * 64
    with pytest.raises(ValidationError, match="canonical claim content"):
        IdentityResolutionResult.model_validate(payload)

    payload = result.model_dump()
    payload["summary"]["groups"] = 0
    with pytest.raises(ValidationError, match="summary is inconsistent"):
        IdentityResolutionResult.model_validate(payload)

    payload = result.model_dump()
    payload["matches"][0]["match_id"] = "idm_" + "0" * 64
    with pytest.raises(ValidationError, match="canonical match content"):
        IdentityResolutionResult.model_validate(payload)

    payload = result.model_dump()
    payload["groups"][0]["group_id"] = "idg_" + "0" * 64
    with pytest.raises(ValidationError, match="canonical group content"):
        IdentityResolutionResult.model_validate(payload)


def test_output_rejects_tampered_conflict_id_and_nondeterministic_order() -> None:
    conflict_result = _resolve(
        adapt_static_analysis(static_source()),
        adapt_static_analysis(
            static_source().model_copy(
                update={
                    "fingerprint": static_source().fingerprint.model_copy(
                        update={"sha256": "b" * 64}
                    )
                }
            )
        ),
    )
    payload = conflict_result.model_dump()
    payload["conflicts"][0]["conflict_id"] = "idf_" + "0" * 64
    with pytest.raises(ValidationError, match="canonical conflict content"):
        IdentityResolutionResult.model_validate(payload)

    ordered = _resolve(adapt_static_analysis(static_source()), _second_static())
    payload = ordered.model_dump()
    payload["contexts"] = tuple(reversed(payload["contexts"]))
    with pytest.raises(ValidationError, match="contexts must be"):
        IdentityResolutionResult.model_validate(payload)


def test_claim_and_match_semantics_reject_inconsistent_promotions() -> None:
    result = _resolve(adapt_static_analysis(static_source()))
    claim = result.claims[0].model_dump()
    claim["missing_attributes"] = ("digest",)
    with pytest.raises(ValidationError, match="available identity claim"):
        IdentityClaim.model_validate(claim)

    match_result = _resolve(adapt_static_analysis(static_source()), _second_static())
    match = match_result.matches[0].model_dump()
    match["identity_confirmed"] = False
    with pytest.raises(ValidationError, match="multiple confirmed"):
        type(match_result.matches[0]).model_validate(match)


def test_rule_registry_is_static_and_rejects_duplicates_or_unknown_rules() -> None:
    rules = DEFAULT_IDENTITY_RULE_REGISTRY.rules
    assert rules == tuple(sorted(rules, key=lambda item: item.rule_id))
    assert all(rule.dynamic_expression is False for rule in rules)
    with pytest.raises(IdentityRuleRegistryError, match="duplicate"):
        IdentityRuleRegistry((rules[0], rules[0]))
    with pytest.raises(IdentityRuleRegistryError, match="unknown"):
        DEFAULT_IDENTITY_RULE_REGISTRY.get("IR-NONE-999")
    with pytest.raises(IdentityRuleRegistryError, match="must not be empty"):
        IdentityRuleRegistry(())


def test_output_is_privacy_minimized_and_has_no_correlation_findings() -> None:
    record = adapt_static_analysis(static_source())
    result = _resolve(record)
    serialized = result.model_dump_json()
    assert "secret-user-path.exe" not in serialized
    assert record.subject.value not in serialized
    assert result.persistence_performed is False
    assert result.threat_correlation_performed is False
    assert result.attack_finding_generated is False


def test_resolution_module_has_no_io_network_persistence_or_dynamic_execution() -> None:
    import app.identity.resolution as resolution

    source = inspect.getsource(resolution)
    forbidden = (
        "requests",
        "httpx",
        "socket",
        "subprocess",
        "pathlib",
        "open(",
        "eval(",
        "exec(",
        "database",
    )
    assert all(token not in source for token in forbidden)
