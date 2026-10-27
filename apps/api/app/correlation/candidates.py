from __future__ import annotations

from dataclasses import dataclass

from app.schemas.correlation import (
    MAX_CORRELATION_CANDIDATES,
    CorrelationCandidate,
    CorrelationCandidateSource,
    correlation_content_id,
)
from app.schemas.evidence import EvidenceBatch
from app.schemas.identity import (
    IdentityNamespace,
    IdentityResolutionResult,
    IdentityResolutionStatus,
    IdentityType,
)

_GROUP_RULES = {
    IdentityType.FILE_CONTENT: "CR-CONTENT-001",
    IdentityType.VULNERABILITY: "CR-VULN-001",
    IdentityType.ANALYSIS: "CR-ANALYSIS-001",
}


@dataclass(frozen=True, slots=True)
class CandidateSelection:
    candidates: tuple[CorrelationCandidate, ...]
    truncated: bool


def _candidate(
    *,
    rule_id: str,
    source: CorrelationCandidateSource,
    evidence_ids: tuple[str, ...],
    identity_type: IdentityType | None = None,
    namespace: IdentityNamespace | None = None,
    identity_group_id: str | None = None,
    identity_match_id: str | None = None,
    reference_source_id: str | None = None,
    reference_target_id: str | None = None,
    reference_type: str | None = None,
) -> CorrelationCandidate:
    material = {
        "rule_id": rule_id,
        "source": source.value,
        "evidence_ids": evidence_ids,
        "identity_type": None if identity_type is None else identity_type.value,
        "namespace": None if namespace is None else namespace.value,
        "identity_group_id": identity_group_id,
        "identity_match_id": identity_match_id,
        "reference_source_id": reference_source_id,
        "reference_target_id": reference_target_id,
        "reference_type": reference_type,
    }
    return CorrelationCandidate(
        candidate_id=correlation_content_id("crc", material),
        rule_id=rule_id,
        source=source,
        evidence_ids=evidence_ids,
        identity_type=identity_type,
        namespace=namespace,
        identity_group_id=identity_group_id,
        identity_match_id=identity_match_id,
        reference_source_id=reference_source_id,
        reference_target_id=reference_target_id,
        reference_type=reference_type,
    )


def select_candidates(
    batch: EvidenceBatch, identity: IdentityResolutionResult
) -> CandidateSelection:
    selected: dict[str, CorrelationCandidate] = {}
    for group in identity.groups:
        rule_id = _GROUP_RULES.get(group.identity_type, "CR-UNSUPPORTED-001")
        item = _candidate(
            rule_id=rule_id,
            source=CorrelationCandidateSource.IDENTITY_GROUP,
            evidence_ids=group.member_evidence_ids,
            identity_type=group.identity_type,
            namespace=group.namespace,
            identity_group_id=group.group_id,
        )
        selected[item.candidate_id] = item

    for match in identity.matches:
        if match.status is IdentityResolutionStatus.SAME_IDENTITY:
            continue
        rule_id = (
            "CR-CONTEXT-001"
            if match.status is IdentityResolutionStatus.COMPATIBLE_CONTEXT
            else "CR-UNSUPPORTED-001"
        )
        item = _candidate(
            rule_id=rule_id,
            source=CorrelationCandidateSource.IDENTITY_MATCH,
            evidence_ids=match.evidence_ids,
            identity_type=match.identity_type,
            namespace=match.namespace,
            identity_match_id=match.match_id,
        )
        selected[item.candidate_id] = item

    for record in batch.records:
        for reference in record.references:
            evidence_ids = tuple(
                sorted(
                    (
                        reference.source_evidence_id,
                        reference.referenced_evidence_id,
                    )
                )
            )
            item = _candidate(
                rule_id="CR-REF-001",
                source=CorrelationCandidateSource.EXPLICIT_REFERENCE,
                evidence_ids=evidence_ids,
                reference_source_id=reference.source_evidence_id,
                reference_target_id=reference.referenced_evidence_id,
                reference_type=reference.reference_type.value,
            )
            selected[item.candidate_id] = item

    ordered = tuple(sorted(selected.values(), key=lambda item: item.candidate_id))
    return CandidateSelection(
        candidates=ordered[:MAX_CORRELATION_CANDIDATES],
        truncated=len(ordered) > MAX_CORRELATION_CANDIDATES,
    )
