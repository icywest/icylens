from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType

from app.schemas.correlation import (
    CorrelationCandidateSource,
    CorrelationRelationshipType,
    CorrelationRequirement,
    CorrelationRequirementKind,
    CorrelationRule,
)
from app.schemas.identity import IdentityNamespace, IdentityType

_NO_CONFLICT = CorrelationRequirement(
    requirement_id="no_identity_conflict",
    kind=CorrelationRequirementKind.NO_IDENTITY_CONFLICT,
    description="No retained identity conflict may contradict the candidate.",
    required=True,
)
_PROVENANCE = CorrelationRequirement(
    requirement_id="provenance_preserved",
    kind=CorrelationRequirementKind.PROVENANCE_PRESERVED,
    description="Each supporting record keeps its original provenance classification.",
    required=True,
)

BUILTIN_CORRELATION_RULES = (
    CorrelationRule(
        rule_id="CR-ANALYSIS-001",
        relationship_type=CorrelationRelationshipType.SHARED_ANALYSIS_CONTEXT,
        identity_type=IdentityType.ANALYSIS,
        allowed_namespaces=(IdentityNamespace.ANALYSIS_UUID,),
        applicable_candidate_sources=(CorrelationCandidateSource.IDENTITY_GROUP,),
        requirements=(
            CorrelationRequirement(
                requirement_id="source_scoped_analysis_group",
                kind=CorrelationRequirementKind.IDENTITY_GROUP,
                description="A 06.02 group must establish an exact source-scoped analysis identity.",
                required=True,
            ),
            _NO_CONFLICT,
            _PROVENANCE,
        ),
        explanation_template="The records share one exact source-scoped analysis identity resolved by checkpoint 06.02.",
        limitations=(
            "Shared analysis context is not shared device, sample, session, investigation, tenant, or causality.",
        ),
    ),
    CorrelationRule(
        rule_id="CR-CONTENT-001",
        relationship_type=CorrelationRelationshipType.SHARED_CONTENT_IDENTITY,
        identity_type=IdentityType.FILE_CONTENT,
        allowed_namespaces=(IdentityNamespace.SHA256,),
        applicable_candidate_sources=(CorrelationCandidateSource.IDENTITY_GROUP,),
        requirements=(
            CorrelationRequirement(
                requirement_id="sha256_identity_group",
                kind=CorrelationRequirementKind.IDENTITY_GROUP,
                description="A 06.02 group must establish exact SHA-256 content identity.",
                required=True,
            ),
            _NO_CONFLICT,
            _PROVENANCE,
        ),
        explanation_template="The records share exact SHA-256 content identity resolved by checkpoint 06.02.",
        limitations=(
            "Shared content does not establish path, host, user, execution, origin, maliciousness, or causality.",
        ),
    ),
    CorrelationRule(
        rule_id="CR-CONTEXT-001",
        relationship_type=None,
        identity_type=None,
        allowed_namespaces=(),
        applicable_candidate_sources=(CorrelationCandidateSource.IDENTITY_MATCH,),
        requirements=(
            CorrelationRequirement(
                requirement_id="exact_identity_required",
                kind=CorrelationRequirementKind.IDENTITY_GROUP,
                description="Context compatibility alone cannot create a relationship.",
                required=True,
            ),
            _PROVENANCE,
        ),
        explanation_template="Compatible context is retained as auxiliary evidence and cannot form an edge.",
        limitations=(
            "Compatibility is neither identity nor a positive, causal, temporal, or transitive relationship.",
        ),
    ),
    CorrelationRule(
        rule_id="CR-REF-001",
        relationship_type=CorrelationRelationshipType.EXPLICIT_EVIDENCE_REFERENCE,
        identity_type=None,
        allowed_namespaces=(),
        applicable_candidate_sources=(CorrelationCandidateSource.EXPLICIT_REFERENCE,),
        requirements=(
            CorrelationRequirement(
                requirement_id="validated_explicit_reference",
                kind=CorrelationRequirementKind.EXPLICIT_REFERENCE,
                description="The immutable 06.01 batch must contain the explicit internal reference.",
                required=True,
            ),
            _NO_CONFLICT,
            _PROVENANCE,
        ),
        explanation_template="A validated source contract explicitly references another record in this evidence batch.",
        limitations=(
            "An explicit evidence reference reports only the declared link type; it does not prove identity, causality, execution, or maliciousness.",
        ),
    ),
    CorrelationRule(
        rule_id="CR-UNSUPPORTED-001",
        relationship_type=None,
        identity_type=None,
        allowed_namespaces=(),
        applicable_candidate_sources=(
            CorrelationCandidateSource.IDENTITY_GROUP,
            CorrelationCandidateSource.IDENTITY_MATCH,
        ),
        requirements=(
            CorrelationRequirement(
                requirement_id="supported_relation_rule",
                kind=CorrelationRequirementKind.IDENTITY_GROUP,
                description="The available identity evidence must map to a supported 06.03 relationship family.",
                required=True,
            ),
            _PROVENANCE,
        ),
        explanation_template="No checkpoint 06.03 relationship rule supports the available evidence.",
        limitations=(
            "Common batch membership, labels, time proximity, predictions, ATT&CK candidates, and provider values do not create relationships.",
        ),
    ),
    CorrelationRule(
        rule_id="CR-VULN-001",
        relationship_type=CorrelationRelationshipType.SHARED_VULNERABILITY_IDENTITY,
        identity_type=IdentityType.VULNERABILITY,
        allowed_namespaces=(IdentityNamespace.CVE,),
        applicable_candidate_sources=(CorrelationCandidateSource.IDENTITY_GROUP,),
        requirements=(
            CorrelationRequirement(
                requirement_id="cve_identity_group",
                kind=CorrelationRequirementKind.IDENTITY_GROUP,
                description="A 06.02 group must establish exact canonical CVE identity.",
                required=True,
            ),
            _NO_CONFLICT,
            _PROVENANCE,
        ),
        explanation_template="The records share exact CVE identity resolved by checkpoint 06.02.",
        limitations=(
            "Shared CVE identity does not establish installation, applicability, exposure, exploitation, compromise, or causality.",
        ),
    ),
)


class CorrelationRuleRegistryError(RuntimeError):
    pass


class CorrelationRuleRegistry:
    def __init__(
        self, rules: Iterable[CorrelationRule] = BUILTIN_CORRELATION_RULES
    ) -> None:
        ordered = tuple(sorted(rules, key=lambda item: item.rule_id))
        by_id: dict[str, CorrelationRule] = {}
        for rule in ordered:
            if rule.rule_id in by_id:
                raise CorrelationRuleRegistryError(
                    "duplicate correlation rule identifier"
                )
            by_id[rule.rule_id] = rule
        if not by_id:
            raise CorrelationRuleRegistryError(
                "correlation rule registry must not be empty"
            )
        self._rules = ordered
        self._by_id: Mapping[str, CorrelationRule] = MappingProxyType(by_id)

    @property
    def rules(self) -> tuple[CorrelationRule, ...]:
        return self._rules

    def get(self, rule_id: str) -> CorrelationRule:
        rule = self._by_id.get(rule_id)
        if rule is None:
            raise CorrelationRuleRegistryError("unknown correlation rule identifier")
        return rule


DEFAULT_CORRELATION_RULE_REGISTRY = CorrelationRuleRegistry()
