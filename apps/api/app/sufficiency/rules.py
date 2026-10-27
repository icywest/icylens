from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType

from app.schemas.correlation import CorrelationRelationshipType
from app.schemas.evidence import EvidenceDomain
from app.schemas.identity import (
    IdentityNamespace,
    IdentityResolutionStatus,
    IdentityType,
)
from app.schemas.sufficiency import (
    AssertionCategory,
    EvidenceRequirement,
    RequirementKind,
    SufficiencyAssertion,
)

_RECORDS = EvidenceRequirement(
    requirement_id="selected_records_exist",
    kind=RequirementKind.EVIDENCE_RECORD_EXISTS,
    description="Every selected evidence identifier resolves inside the validated batch.",
    required=True,
)
_PROVENANCE = EvidenceRequirement(
    requirement_id="provenance_available",
    kind=RequirementKind.PROVENANCE_AVAILABLE,
    description="Each selected record retains structured provenance.",
    required=True,
)
_IDENTITY = EvidenceRequirement(
    requirement_id="required_identity_satisfied",
    kind=RequirementKind.IDENTITY_SATISFIED,
    description="Checkpoint 06.02 establishes the exact typed identity required by this assertion.",
    required=True,
)
_RELATIONSHIP = EvidenceRequirement(
    requirement_id="required_correlation_supported",
    kind=RequirementKind.CORRELATION_SUPPORTED,
    description="Checkpoint 06.03 emits the exact supported relationship required by this assertion.",
    required=True,
)
_NO_CONFLICT = EvidenceRequirement(
    requirement_id="no_relevant_conflict",
    kind=RequirementKind.NO_RELEVANT_CONFLICT,
    description="No retained identity or correlation conflict contradicts the required property.",
    required=True,
)

BUILTIN_SUFFICIENCY_ASSERTIONS = (
    SufficiencyAssertion(
        assertion_id="AS-ANALYSIS-001",
        category=AssertionCategory.ANALYSIS_CONTEXT,
        statement="The selected records share one exact source-scoped analysis context.",
        applicable_domains=(EvidenceDomain.SYNTHETIC_ML, EvidenceDomain.BEHAVIORAL),
        required_evidence_types=(
            "unified_evidence_record",
            "resolved_analysis_identity",
        ),
        required_identity_type=IdentityType.ANALYSIS,
        required_identity_namespace=IdentityNamespace.ANALYSIS_UUID,
        required_identity_status=IdentityResolutionStatus.SAME_IDENTITY,
        required_relationship_type=CorrelationRelationshipType.SHARED_ANALYSIS_CONTEXT,
        requirements=(_RECORDS, _PROVENANCE, _IDENTITY, _RELATIONSHIP, _NO_CONFLICT),
        contradiction_conditions=(
            "A conflicting source-scoped analysis identity affects a selected record.",
        ),
        limitations=(
            "Shared analysis context is not shared device, sample, session, investigation, tenant, execution, or causality.",
        ),
        safe_explanation_template="The selected evidence is sufficient only for exact source-scoped analysis context equality.",
    ),
    SufficiencyAssertion(
        assertion_id="AS-CONTENT-001",
        category=AssertionCategory.CONTENT_IDENTITY,
        statement="The selected records share one comparable SHA-256 content identity.",
        applicable_domains=(EvidenceDomain.STATIC,),
        required_evidence_types=("unified_evidence_record", "resolved_sha256_identity"),
        required_identity_type=IdentityType.FILE_CONTENT,
        required_identity_namespace=IdentityNamespace.SHA256,
        required_identity_status=IdentityResolutionStatus.SAME_IDENTITY,
        required_relationship_type=CorrelationRelationshipType.SHARED_CONTENT_IDENTITY,
        requirements=(_RECORDS, _PROVENANCE, _IDENTITY, _RELATIONSHIP, _NO_CONFLICT),
        contradiction_conditions=(
            "A conflicting content identity affects a selected record.",
        ),
        limitations=(
            "Content identity does not establish a physical file, path, host, execution, origin, maliciousness, or causality.",
        ),
        safe_explanation_template="The selected evidence is sufficient only for comparable SHA-256 content equality.",
    ),
    SufficiencyAssertion(
        assertion_id="AS-REF-001",
        category=AssertionCategory.EXPLICIT_REFERENCE,
        statement="A validated explicit evidence reference links the selected records.",
        applicable_domains=tuple(EvidenceDomain),
        required_evidence_types=(
            "unified_evidence_record",
            "validated_explicit_reference",
        ),
        required_identity_type=None,
        required_identity_namespace=None,
        required_identity_status=None,
        required_relationship_type=CorrelationRelationshipType.EXPLICIT_EVIDENCE_REFERENCE,
        requirements=(_RECORDS, _PROVENANCE, _RELATIONSHIP, _NO_CONFLICT),
        contradiction_conditions=(
            "A duplicate or contradictory explicit reference affects the selected records.",
        ),
        limitations=(
            "An explicit reference proves only the validated declaration; it does not establish identity, causality, time order, execution, or maliciousness.",
        ),
        safe_explanation_template="The selected evidence is sufficient only to establish that a validated explicit reference exists.",
    ),
    SufficiencyAssertion(
        assertion_id="AS-VULN-001",
        category=AssertionCategory.VULNERABILITY_IDENTITY,
        statement="The selected records refer to one exact canonical CVE identity.",
        applicable_domains=(EvidenceDomain.VULNERABILITY,),
        required_evidence_types=("unified_evidence_record", "resolved_cve_identity"),
        required_identity_type=IdentityType.VULNERABILITY,
        required_identity_namespace=IdentityNamespace.CVE,
        required_identity_status=IdentityResolutionStatus.SAME_IDENTITY,
        required_relationship_type=CorrelationRelationshipType.SHARED_VULNERABILITY_IDENTITY,
        requirements=(_RECORDS, _PROVENANCE, _IDENTITY, _RELATIONSHIP, _NO_CONFLICT),
        contradiction_conditions=(
            "A conflicting vulnerability identity affects a selected record.",
        ),
        limitations=(
            "CVE identity does not establish installation, applicability, exposure, exploitation, compromise, or causality.",
        ),
        safe_explanation_template="The selected evidence is sufficient only for canonical CVE subject equality.",
    ),
)


class SufficiencyPolicyRegistryError(RuntimeError):
    pass


class SufficiencyPolicyRegistry:
    def __init__(
        self,
        assertions: Iterable[SufficiencyAssertion] = BUILTIN_SUFFICIENCY_ASSERTIONS,
    ) -> None:
        ordered = tuple(sorted(assertions, key=lambda item: item.assertion_id))
        by_id: dict[str, SufficiencyAssertion] = {}
        for assertion in ordered:
            if assertion.assertion_id in by_id:
                raise SufficiencyPolicyRegistryError("duplicate assertion identifier")
            by_id[assertion.assertion_id] = assertion
        if not by_id:
            raise SufficiencyPolicyRegistryError("assertion registry must not be empty")
        self._assertions = ordered
        self._by_id: Mapping[str, SufficiencyAssertion] = MappingProxyType(by_id)

    @property
    def assertions(self) -> tuple[SufficiencyAssertion, ...]:
        return self._assertions

    def find(self, assertion_id: str) -> SufficiencyAssertion | None:
        return self._by_id.get(assertion_id)

    def get(self, assertion_id: str) -> SufficiencyAssertion:
        assertion = self.find(assertion_id)
        if assertion is None:
            raise SufficiencyPolicyRegistryError("unknown assertion identifier")
        return assertion


DEFAULT_SUFFICIENCY_POLICY_REGISTRY = SufficiencyPolicyRegistry()
