from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from itertools import combinations
from uuid import UUID

from app.identity.rules import DEFAULT_IDENTITY_RULE_REGISTRY, IdentityRuleRegistry
from app.schemas.evidence import (
    BehavioralEvidenceObservation,
    EvidenceRecord,
    EvidenceReferenceType,
    EvidenceSubjectType,
    MLEvidenceObservation,
    StaticEvidenceObservation,
    VulnerabilityEvidenceObservation,
)
from app.schemas.identity import (
    MAX_IDENTITY_CONFLICTS,
    MAX_IDENTITY_GROUPS,
    MAX_IDENTITY_MATCHES,
    IdentityClaim,
    IdentityClaimAvailability,
    IdentityConflict,
    IdentityConflictCode,
    IdentityContext,
    IdentityMatchEvidence,
    IdentityNamespace,
    IdentityReference,
    IdentityResolutionRequest,
    IdentityResolutionResult,
    IdentityResolutionStatus,
    IdentityResolutionSummary,
    IdentityType,
    ResolvedIdentityGroup,
)


@dataclass(frozen=True)
class _ExtractedClaim:
    output: IdentityClaim
    canonical_key: tuple[IdentityType, IdentityNamespace, str, str] | None


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _prefixed_id(prefix: str, value: object) -> str:
    return f"{prefix}_{_canonical_digest(value)}"


def _claim(
    record: EvidenceRecord,
    identity_type: IdentityType,
    namespace: IdentityNamespace | None,
    canonical_value: str | None,
    scope: str,
    required: tuple[str, ...],
    missing: tuple[str, ...],
    limitations: tuple[str, ...],
) -> _ExtractedClaim:
    available = namespace is not None and canonical_value is not None and not missing
    reference = None
    key = None
    if available:
        assert namespace is not None
        assert canonical_value is not None
        reference = IdentityReference(
            identity_type=identity_type,
            namespace=namespace,
            reference_digest=_canonical_digest(
                {
                    "identity_type": identity_type.value,
                    "namespace": namespace.value,
                    "scope": scope,
                    "value": canonical_value,
                }
            ),
            scope_category=scope,
        )
        key = (identity_type, namespace, scope, canonical_value)
    claim_material = {
        "evidence_id": record.identifier.evidence_id,
        "identity_type": identity_type.value,
        "namespace": None if namespace is None else namespace.value,
        "reference_digest": None if reference is None else reference.reference_digest,
        "required": required,
        "missing": missing,
    }
    output = IdentityClaim(
        claim_id=_prefixed_id("idc", claim_material),
        evidence_id=record.identifier.evidence_id,
        identity_type=identity_type,
        availability=(
            IdentityClaimAvailability.AVAILABLE
            if available
            else IdentityClaimAvailability.UNRESOLVED
        ),
        reference=reference,
        required_attributes=required,
        missing_attributes=missing,
        source_module=record.source.module,
        verification_status=record.provenance.integrity_verification,
        limitations=limitations,
    )
    return _ExtractedClaim(output=output, canonical_key=key)


def _extract_claims(record: EvidenceRecord) -> tuple[_ExtractedClaim, ...]:
    subject = record.subject
    observation = record.observation
    if isinstance(observation, StaticEvidenceObservation):
        valid = (
            subject.subject_type is EvidenceSubjectType.FILE_CONTENT
            and subject.namespace == IdentityNamespace.SHA256.value
            and re.fullmatch(r"[0-9a-f]{64}", subject.value) is not None
            and subject.value == observation.sha256
        )
        if valid:
            return (
                _claim(
                    record,
                    IdentityType.FILE_CONTENT,
                    IdentityNamespace.SHA256,
                    subject.value,
                    subject.scope,
                    ("algorithm", "digest", "scope"),
                    (),
                    (
                        "SHA-256 equality identifies content digest equality only; it does not establish execution, host, path, user, or maliciousness.",
                    ),
                ),
            )
        return (
            _claim(
                record,
                IdentityType.FILE_CONTENT,
                None,
                None,
                subject.scope,
                ("algorithm", "digest", "scope"),
                ("supported_sha256_identity",),
                (
                    "The static subject lacks a supported, internally consistent SHA-256 identity.",
                ),
            ),
        )
    if isinstance(observation, VulnerabilityEvidenceObservation):
        valid = (
            subject.subject_type is EvidenceSubjectType.VULNERABILITY
            and subject.namespace == IdentityNamespace.CVE.value
            and subject.value == observation.cve_id
        )
        if valid:
            return (
                _claim(
                    record,
                    IdentityType.VULNERABILITY,
                    IdentityNamespace.CVE,
                    subject.value.upper(),
                    subject.scope,
                    ("cve_id", "namespace"),
                    (),
                    (
                        "CVE identity does not establish installed software, exposure, exploitation, or compromise.",
                    ),
                ),
            )
        return (
            _claim(
                record,
                IdentityType.VULNERABILITY,
                None,
                None,
                subject.scope,
                ("cve_id", "namespace"),
                ("validated_cve_identity",),
                ("The vulnerability subject and observation do not agree.",),
            ),
        )
    if isinstance(observation, MLEvidenceObservation):
        claims = [
            _analysis_claim(record, IdentityType.ANALYSIS),
        ]
        if observation.model_version is None:
            claims.append(
                _claim(
                    record,
                    IdentityType.ML_MODEL,
                    None,
                    None,
                    "phase03_model_metadata",
                    ("model_id", "model_version", "dataset_integrity_digest"),
                    ("model_version",),
                    (
                        "Phase 03 exposes no independent model version, so versioned model identity remains unresolved.",
                    ),
                )
            )
        else:
            claims.append(
                _claim(
                    record,
                    IdentityType.ML_MODEL,
                    IdentityNamespace.MODEL_ID_VERSION,
                    "|".join(
                        (
                            observation.model_id,
                            observation.model_version,
                            observation.dataset_integrity_digest,
                        )
                    ),
                    "phase03_model_metadata",
                    ("model_id", "model_version", "dataset_integrity_digest"),
                    (),
                    (
                        "Model identity does not make a prediction an observed fact or security verdict.",
                    ),
                )
            )
        return tuple(claims)
    if isinstance(observation, BehavioralEvidenceObservation):
        return (_analysis_claim(record, IdentityType.ANALYSIS),)
    raise TypeError("unsupported unified evidence observation")


def _analysis_claim(
    record: EvidenceRecord, identity_type: IdentityType
) -> _ExtractedClaim:
    subject = record.subject
    valid_type = subject.subject_type in {
        EvidenceSubjectType.ANALYSIS,
        EvidenceSubjectType.BEHAVIORAL_ANALYSIS,
    }
    try:
        UUID(subject.value)
        valid_uuid = True
    except ValueError:
        valid_uuid = False
    valid = (
        valid_type
        and subject.namespace == IdentityNamespace.ANALYSIS_UUID.value
        and valid_uuid
    )
    if not valid:
        return _claim(
            record,
            identity_type,
            None,
            None,
            subject.scope,
            ("analysis_uuid", "source_module", "scope"),
            ("valid_source_scoped_analysis_uuid",),
            ("The analysis identity is incomplete or uses an unsupported namespace.",),
        )
    canonical = f"{record.source.module.value}|{subject.scope}|{subject.value.lower()}"
    return _claim(
        record,
        identity_type,
        IdentityNamespace.ANALYSIS_UUID,
        canonical,
        subject.scope,
        ("analysis_uuid", "source_module", "scope"),
        (),
        (
            "Analysis identity is source scoped and is not device, sample, session, investigation, or tenant identity.",
        ),
    )


def _context(record: EvidenceRecord) -> IdentityContext:
    return IdentityContext(
        evidence_id=record.identifier.evidence_id,
        source_module=record.source.module,
        source_phase=record.source.phase,
        source_analysis_id=record.provenance.source_analysis_id,
        subject_type=record.subject.subject_type,
        temporal_context=record.context.timestamps,
        environment_scope=record.subject.scope,
        origin_type=record.provenance.origin_type,
        trust_classification=record.provenance.trust_classification,
        synthetic=record.provenance.synthetic,
        verification_status=record.provenance.integrity_verification,
    )


def _match(
    rule_id: str,
    status: IdentityResolutionStatus,
    evidence_ids: tuple[str, ...],
    explanation: str,
    limitations: tuple[str, ...],
    *,
    identity_type: IdentityType | None = None,
    namespace: IdentityNamespace | None = None,
    attributes: tuple[str, ...] = (),
) -> IdentityMatchEvidence:
    ordered_ids = tuple(sorted(evidence_ids))
    material = {
        "rule_id": rule_id,
        "status": status.value,
        "identity_type": None if identity_type is None else identity_type.value,
        "namespace": None if namespace is None else namespace.value,
        "evidence_ids": ordered_ids,
        "attributes": attributes,
    }
    return IdentityMatchEvidence(
        match_id=_prefixed_id("idm", material),
        rule_id=rule_id,
        status=status,
        identity_type=identity_type,
        namespace=namespace,
        evidence_ids=ordered_ids,
        matching_attributes=attributes,
        explanation=explanation,
        explanation_references=ordered_ids[:16],
        limitations=limitations,
        identity_confirmed=status is IdentityResolutionStatus.SAME_IDENTITY,
    )


def _conflict(
    code: IdentityConflictCode,
    evidence_ids: tuple[str, ...],
    explanation: str,
    fields: tuple[str, ...],
    *,
    identity_type: IdentityType | None = None,
    namespace: IdentityNamespace | None = None,
) -> IdentityConflict:
    ordered_ids = tuple(sorted(set(evidence_ids)))
    material = {
        "code": code.value,
        "evidence_ids": ordered_ids,
        "identity_type": None if identity_type is None else identity_type.value,
        "namespace": None if namespace is None else namespace.value,
        "fields": fields,
    }
    return IdentityConflict(
        conflict_id=_prefixed_id("idf", material),
        code=code,
        identity_type=identity_type,
        namespace=namespace,
        evidence_ids=ordered_ids,
        field_categories=fields,
        explanation=explanation,
    )


def resolve_identities(
    request: IdentityResolutionRequest,
    *,
    registry: IdentityRuleRegistry = DEFAULT_IDENTITY_RULE_REGISTRY,
) -> IdentityResolutionResult:
    records = request.batch.records
    contexts = tuple(
        sorted((_context(item) for item in records), key=lambda x: x.evidence_id)
    )
    extracted = tuple(claim for record in records for claim in _extract_claims(record))
    claims = tuple(
        sorted((item.output for item in extracted), key=lambda x: x.claim_id)
    )

    matches: list[IdentityMatchEvidence] = []
    conflicts: list[IdentityConflict] = []
    key_index: dict[
        tuple[IdentityType, IdentityNamespace, str, str], list[IdentityClaim]
    ] = defaultdict(list)
    for item in extracted:
        if item.canonical_key is None:
            rule_id = (
                "IR-MODEL-001"
                if item.output.identity_type is IdentityType.ML_MODEL
                else "IR-DOMAIN-001"
            )
            matches.append(
                _match(
                    rule_id,
                    IdentityResolutionStatus.INSUFFICIENT_EVIDENCE,
                    (item.output.evidence_id,),
                    "Required identity attributes are absent from the unified evidence contract.",
                    item.output.limitations,
                    identity_type=item.output.identity_type,
                )
            )
            if item.output.identity_type in {
                IdentityType.FILE_CONTENT,
                IdentityType.VULNERABILITY,
                IdentityType.ANALYSIS,
            }:
                conflicts.append(
                    _conflict(
                        IdentityConflictCode.UNSUPPORTED_NAMESPACE,
                        (item.output.evidence_id,),
                        "The evidence subject does not provide a valid supported namespace and canonical identifier for this identity type.",
                        ("subject_type", "namespace", "identifier"),
                        identity_type=item.output.identity_type,
                    )
                )
        else:
            key_index[item.canonical_key].append(item.output)

    same_matches_by_key: dict[
        tuple[IdentityType, IdentityNamespace, str, str], IdentityMatchEvidence
    ] = {}
    rule_for_type = {
        IdentityType.FILE_CONTENT: "IR-FILE-001",
        IdentityType.VULNERABILITY: "IR-CVE-001",
        IdentityType.ANALYSIS: "IR-ANALYSIS-001",
        IdentityType.ML_MODEL: "IR-MODEL-001",
    }
    for key, indexed_claims in sorted(
        key_index.items(), key=lambda item: tuple(str(part) for part in item[0])
    ):
        if len(indexed_claims) < 2:
            continue
        identity_type, namespace, _scope, _value = key
        rule = registry.get(rule_for_type[identity_type])
        match = _match(
            rule.rule_id,
            IdentityResolutionStatus.SAME_IDENTITY,
            tuple(item.evidence_id for item in indexed_claims),
            rule.explanation_template,
            rule.limitations,
            identity_type=identity_type,
            namespace=namespace,
            attributes=rule.required_attributes,
        )
        matches.append(match)
        same_matches_by_key[key] = match

    record_by_id = {item.identifier.evidence_id: item for item in records}
    seen_references: set[tuple[str, str, str]] = set()
    explicit_domain_pairs: set[tuple[str, str]] = set()
    for record in records:
        for reference in sorted(
            record.references,
            key=lambda item: (
                item.source_evidence_id,
                item.referenced_evidence_id,
                item.reference_type.value,
            ),
        ):
            reference_key = (
                reference.source_evidence_id,
                reference.referenced_evidence_id,
                reference.reference_type.value,
            )
            if reference_key in seen_references:
                conflicts.append(
                    _conflict(
                        IdentityConflictCode.DUPLICATE_EVIDENCE_REFERENCE,
                        (
                            reference.source_evidence_id,
                            reference.referenced_evidence_id,
                        ),
                        "The same explicit evidence reference occurs more than once.",
                        (
                            "source_evidence_id",
                            "referenced_evidence_id",
                            "reference_type",
                        ),
                    )
                )
                continue
            seen_references.add(reference_key)
            target = record_by_id[reference.referenced_evidence_id]
            domain_values = sorted(
                (record.observation.domain.value, target.observation.domain.value)
            )
            domain_pair = (domain_values[0], domain_values[1])
            explicit_domain_pairs.add(domain_pair)
            if reference.reference_type is EvidenceReferenceType.EXPLICIT_DERIVATION:
                rule = registry.get("IR-REF-001")
                matches.append(
                    _match(
                        rule.rule_id,
                        IdentityResolutionStatus.COMPATIBLE_CONTEXT,
                        (record.identifier.evidence_id, target.identifier.evidence_id),
                        rule.explanation_template,
                        rule.limitations,
                        attributes=("explicit_derivation_reference",),
                    )
                )

    analysis_index: dict[tuple[str, str, IdentityType], list[_ExtractedClaim]] = (
        defaultdict(list)
    )
    for item in extracted:
        if item.canonical_key is not None:
            record = record_by_id[item.output.evidence_id]
            analysis_index[
                (
                    record.source.module.value,
                    str(record.provenance.source_analysis_id),
                    item.output.identity_type,
                )
            ].append(item)
    conflicted_evidence_ids: set[str] = set()
    for indexed in analysis_index.values():
        distinct = {item.canonical_key for item in indexed}
        if len(distinct) < 2:
            continue
        evidence_ids = tuple(item.output.evidence_id for item in indexed)
        conflicted_evidence_ids.update(evidence_ids)
        identity_type = indexed[0].output.identity_type
        conflict = _conflict(
            IdentityConflictCode.CONFLICTING_ANALYSIS_SUBJECT,
            evidence_ids,
            "One source analysis identifier is associated with different explicit subject identities; no source is selected as authoritative.",
            ("source_analysis_id", "subject_identity"),
            identity_type=identity_type,
        )
        conflicts.append(conflict)
        matches.append(
            _match(
                rule_for_type.get(identity_type, "IR-DOMAIN-001"),
                IdentityResolutionStatus.CONFLICTING_IDENTITY,
                evidence_ids,
                conflict.explanation,
                ("Conflicting claims are retained and excluded from identity groups.",),
                identity_type=identity_type,
                attributes=conflict.field_categories,
            )
        )

    domains: dict[str, list[str]] = defaultdict(list)
    for record in records:
        domains[record.observation.domain.value].append(record.identifier.evidence_id)
    for left, right in combinations(sorted(domains), 2):
        if (left, right) in explicit_domain_pairs:
            continue
        matches.append(
            _match(
                "IR-DOMAIN-001",
                IdentityResolutionStatus.NOT_COMPARABLE,
                (min(domains[left]), min(domains[right])),
                "The represented domains have no supported identity rule for the attributes preserved by checkpoint 06.01.",
                (
                    "Co-membership in an EvidenceBatch and temporal proximity do not establish identity or a common investigation.",
                ),
                attributes=("source_domain",),
            )
        )

    groups: list[ResolvedIdentityGroup] = []
    for key, match in same_matches_by_key.items():
        members = tuple(
            item for item in match.evidence_ids if item not in conflicted_evidence_ids
        )
        if len(members) < 2:
            continue
        identity_type, namespace, _scope, _value = key
        material = {
            "identity_type": identity_type.value,
            "namespace": namespace.value,
            "members": members,
            "matches": (match.match_id,),
        }
        groups.append(
            ResolvedIdentityGroup(
                group_id=_prefixed_id("idg", material),
                identity_type=identity_type,
                namespace=namespace,
                member_evidence_ids=members,
                supporting_match_ids=(match.match_id,),
                limitations=match.limitations,
            )
        )

    matches_truncated = len(matches) > MAX_IDENTITY_MATCHES
    ordered_matches = tuple(sorted(matches, key=lambda item: item.match_id))[
        :MAX_IDENTITY_MATCHES
    ]
    ordered_conflicts = tuple(sorted(conflicts, key=lambda item: item.conflict_id))[
        :MAX_IDENTITY_CONFLICTS
    ]
    published_match_ids = {item.match_id for item in ordered_matches}
    publishable_groups = [
        item
        for item in groups
        if set(item.supporting_match_ids).issubset(published_match_ids)
    ]
    ordered_groups = tuple(sorted(publishable_groups, key=lambda item: item.group_id))[
        :MAX_IDENTITY_GROUPS
    ]
    counts = {status: 0 for status in IdentityResolutionStatus}
    for matched_item in ordered_matches:
        counts[matched_item.status] += 1
    summary = IdentityResolutionSummary(
        evidence_records=len(records),
        claims=len(claims),
        resolved_claims=sum(
            item.availability is IdentityClaimAvailability.AVAILABLE for item in claims
        ),
        unresolved_claims=sum(
            item.availability is IdentityClaimAvailability.UNRESOLVED for item in claims
        ),
        same_identity_matches=counts[IdentityResolutionStatus.SAME_IDENTITY],
        compatible_context_matches=counts[IdentityResolutionStatus.COMPATIBLE_CONTEXT],
        insufficient_evidence_matches=counts[
            IdentityResolutionStatus.INSUFFICIENT_EVIDENCE
        ],
        conflicting_identity_matches=counts[
            IdentityResolutionStatus.CONFLICTING_IDENTITY
        ],
        not_comparable_matches=counts[IdentityResolutionStatus.NOT_COMPARABLE],
        groups=len(ordered_groups),
        conflicts=len(ordered_conflicts),
        comparisons_truncated=(
            matches_truncated
            or len(conflicts) > MAX_IDENTITY_CONFLICTS
            or len(publishable_groups) > MAX_IDENTITY_GROUPS
            or len(publishable_groups) != len(groups)
        ),
    )
    return IdentityResolutionResult(
        batch_id=request.batch.batch_id,
        claims=claims,
        contexts=contexts,
        matches=ordered_matches,
        conflicts=ordered_conflicts,
        groups=ordered_groups,
        summary=summary,
        limitations=(
            "Resolution uses exact typed attributes and explicit references only; it performs no fuzzy, probabilistic, ML, LLM, or threat correlation.",
            "An EvidenceBatch is a processing unit and is not assumed to be an investigation, host, session, tenant, or operational context.",
            "Checkpoint 06.01 does not preserve process-instance or host identity, so PID reuse and cross-host process identity remain unresolved.",
            "Checkpoint 06.01 does not preserve ATT&CK technique/STIX identities, so technique identity remains unresolved.",
            "Phase 03 does not expose an independent model version; model identity remains unresolved for current ML evidence.",
            "Identity output uses deterministic digests and field categories; those digests remain correlatable and are not anonymous.",
        ),
    )
