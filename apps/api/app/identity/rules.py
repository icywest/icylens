from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType

from app.schemas.identity import (
    IdentityNamespace,
    IdentityResolutionRule,
    IdentityType,
)

BUILTIN_IDENTITY_RULES = (
    IdentityResolutionRule(
        rule_id="IR-FILE-001",
        identity_type=IdentityType.FILE_CONTENT,
        applicable_subject_types=("file_content",),
        required_attributes=("algorithm", "digest", "scope"),
        allowed_namespaces=(IdentityNamespace.SHA256,),
        context_constraints=(
            "Only the accepted byte-stream content scope is comparable.",
        ),
        conflict_conditions=(
            "A different digest is a different content identity under SHA-256.",
            "Different or unsupported algorithms are not interchangeable.",
        ),
        explanation_template=(
            "Canonical SHA-256 equality supports equality of content digests only."
        ),
        limitations=(
            "Content identity does not establish a physical file, path, host, user, execution, or maliciousness.",
        ),
    ),
    IdentityResolutionRule(
        rule_id="IR-CVE-001",
        identity_type=IdentityType.VULNERABILITY,
        applicable_subject_types=("vulnerability",),
        required_attributes=("cve_id", "namespace"),
        allowed_namespaces=(IdentityNamespace.CVE,),
        context_constraints=("CVE identifiers use their validated public namespace.",),
        conflict_conditions=(
            "Different canonical CVE IDs are different vulnerabilities.",
        ),
        explanation_template="Canonical CVE equality identifies the same vulnerability record subject.",
        limitations=(
            "CVE identity does not establish installed software, exposure, exploitation, or compromise.",
        ),
    ),
    IdentityResolutionRule(
        rule_id="IR-ANALYSIS-001",
        identity_type=IdentityType.ANALYSIS,
        applicable_subject_types=("analysis", "behavioral_analysis"),
        required_attributes=("analysis_uuid", "source_module", "scope"),
        allowed_namespaces=(IdentityNamespace.ANALYSIS_UUID,),
        context_constraints=(
            "Analysis UUID equality is comparable only within the same source module and declared scope.",
        ),
        conflict_conditions=(
            "Equal UUID text across different source modules does not establish shared analysis identity.",
        ),
        explanation_template="The source-scoped analysis identifier is exactly equal.",
        limitations=(
            "Analysis identity is not device, sample, session, investigation, or tenant identity.",
        ),
    ),
    IdentityResolutionRule(
        rule_id="IR-MODEL-001",
        identity_type=IdentityType.ML_MODEL,
        applicable_subject_types=("analysis",),
        required_attributes=("model_id", "model_version", "dataset_integrity_digest"),
        allowed_namespaces=(IdentityNamespace.MODEL_ID_VERSION,),
        context_constraints=(
            "Model identity requires the model identifier, an independent version, and dataset integrity context.",
        ),
        conflict_conditions=(
            "Missing model version prevents versioned model identity.",
        ),
        explanation_template="Versioned model metadata is required for model identity.",
        limitations=(
            "Model identity does not make a prediction an observed fact or security verdict.",
        ),
    ),
    IdentityResolutionRule(
        rule_id="IR-PROC-001",
        identity_type=IdentityType.PROCESS_INSTANCE,
        applicable_subject_types=("process_instance",),
        required_attributes=("host_scope", "process_instance_id", "temporal_context"),
        allowed_namespaces=(IdentityNamespace.PROCESS_INSTANCE_HOST,),
        context_constraints=(
            "PID alone is insufficient and process instances are host scoped.",
        ),
        conflict_conditions=(
            "Different host scopes or explicit process instance IDs conflict.",
        ),
        explanation_template="Host-scoped process instance identity is exact.",
        limitations=(
            "Checkpoint 06.01 does not retain process or host identity in unified evidence.",
        ),
    ),
    IdentityResolutionRule(
        rule_id="IR-ATTACK-001",
        identity_type=IdentityType.ATTACK_TECHNIQUE,
        applicable_subject_types=("attack_technique",),
        required_attributes=("technique_id", "stix_id", "domain", "catalog_version"),
        allowed_namespaces=(IdentityNamespace.ATTACK_STIX_CATALOG,),
        context_constraints=(
            "ATT&CK identity requires technique, STIX, domain, and pinned catalog version.",
        ),
        conflict_conditions=(
            "Technique labels without catalog identity are insufficient.",
        ),
        explanation_template="Pinned ATT&CK catalog identifiers are exactly equal.",
        limitations=(
            "Technique identity does not confirm execution, an attack, maliciousness, or attribution.",
            "Checkpoint 06.01 behavioral evidence retains candidate counts but not technique identities.",
        ),
    ),
    IdentityResolutionRule(
        rule_id="IR-REF-001",
        identity_type=None,
        applicable_subject_types=("explicit_evidence_reference",),
        required_attributes=(
            "source_evidence_id",
            "referenced_evidence_id",
            "reference_type",
        ),
        allowed_namespaces=(),
        context_constraints=(
            "Only references already validated inside the immutable evidence batch are evaluated.",
        ),
        conflict_conditions=(
            "Duplicate explicit references are reported as conflicts.",
        ),
        explanation_template="An explicit derivation reference supports context compatibility only.",
        limitations=(
            "An explicit derivation does not by itself prove subject identity.",
        ),
    ),
    IdentityResolutionRule(
        rule_id="IR-DOMAIN-001",
        identity_type=None,
        applicable_subject_types=("cross_domain",),
        required_attributes=("supported_identity_rule",),
        allowed_namespaces=(),
        context_constraints=("A common batch is not a common operational context.",),
        conflict_conditions=(),
        explanation_template="The domains have no supported identity rule for the available attributes.",
        limitations=(
            "No relationship is inferred from co-membership, labels, or temporal proximity.",
        ),
    ),
)


class IdentityRuleRegistryError(RuntimeError):
    pass


class IdentityRuleRegistry:
    def __init__(
        self, rules: Iterable[IdentityResolutionRule] = BUILTIN_IDENTITY_RULES
    ) -> None:
        ordered = tuple(sorted(rules, key=lambda item: item.rule_id))
        by_id: dict[str, IdentityResolutionRule] = {}
        for rule in ordered:
            if rule.rule_id in by_id:
                raise IdentityRuleRegistryError("duplicate identity rule identifier")
            by_id[rule.rule_id] = rule
        if not by_id:
            raise IdentityRuleRegistryError("identity rule registry must not be empty")
        self._rules = ordered
        self._by_id: Mapping[str, IdentityResolutionRule] = MappingProxyType(by_id)

    @property
    def rules(self) -> tuple[IdentityResolutionRule, ...]:
        return self._rules

    def get(self, rule_id: str) -> IdentityResolutionRule:
        rule = self._by_id.get(rule_id)
        if rule is None:
            raise IdentityRuleRegistryError("unknown identity rule identifier")
        return rule


DEFAULT_IDENTITY_RULE_REGISTRY = IdentityRuleRegistry()
