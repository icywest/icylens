from __future__ import annotations

import asyncio
import json
import time
from collections import Counter
from collections.abc import Callable, Sequence
from typing import TypeAlias

from app.attack.catalog import (
    ATTACKCatalogSnapshot,
    ATTACKCatalogStore,
    ATTACKCatalogUnavailableError,
)
from app.behavior.attack_mapping_evidence import (
    find_rule_finding,
    relationship_references,
    rule_reference,
)
from app.behavior.attack_mapping_registry import (
    DEFAULT_ATTACK_MAPPING_POLICY_REGISTRY,
    AttackMappingPolicyRegistry,
)
from app.behavior.correlation import TemporalCorrelationEngine
from app.behavior.rule_engine import BehavioralRuleEngine
from app.schemas.attack import ATTACKObjectStatus, ATTACKTechnique
from app.schemas.attack_mapping import (
    MAPPING_EVALUATION_DEADLINE_SECONDS,
    MAPPING_MAX_CONCURRENCY,
    MAPPING_OPERATION_TIMEOUT_SECONDS,
    MAX_MAPPING_OUTPUT_BYTES,
    AttackMappingAssessment,
    AttackMappingPolicy,
    AttackMappingPolicyIdentifier,
    AttackMappingPolicyRegistryResponse,
    AttackMappingRequest,
    AttackMappingSummary,
    MappingCandidate,
    MappingEvaluation,
    MappingEvidenceReference,
    MappingEvidenceType,
    MappingExplanation,
    MappingState,
)
from app.schemas.behavior import (
    ConfigurationEvent,
    EventUnion,
    FileEvent,
    NetworkEvent,
    ProcessEvent,
)
from app.schemas.behavior_correlation import (
    CorrelationIssueSeverity,
    TemporalCorrelationRequest,
    TemporalCorrelationResult,
)
from app.schemas.behavior_rules import (
    RuleEvaluationRequest,
    RuleEvaluationResult,
    RuleFinding,
    RuleMatchStatus,
)

Clock: TypeAlias = Callable[[], float]


class AttackMappingLimitError(RuntimeError):
    pass


class AttackMappingCapacityError(RuntimeError):
    pass


class AttackMappingCapacity:
    def __init__(self, maximum: int = MAPPING_MAX_CONCURRENCY) -> None:
        if maximum < 1:
            raise ValueError("mapping capacity must be positive")
        self.maximum = maximum
        self._active = 0
        self._lock = asyncio.Lock()

    @property
    def active(self) -> int:
        return self._active

    async def try_acquire(self) -> bool:
        async with self._lock:
            if self._active >= self.maximum:
                return False
            self._active += 1
            return True

    async def release(self) -> None:
        async with self._lock:
            if self._active <= 0:
                raise RuntimeError("mapping capacity release is unbalanced")
            self._active -= 1


def _family_events(
    policy: AttackMappingPolicy, events: Sequence[EventUnion]
) -> tuple[EventUnion, ...]:
    expected: type[ProcessEvent | FileEvent | NetworkEvent | ConfigurationEvent]
    if policy.applicable_family.value == "process":
        expected = ProcessEvent
    elif policy.applicable_family.value == "file":
        expected = FileEvent
    elif policy.applicable_family.value == "network":
        expected = NetworkEvent
    else:
        expected = ConfigurationEvent
    return tuple(event for event in events if isinstance(event, expected))


def _candidate(
    technique: ATTACKTechnique, snapshot: ATTACKCatalogSnapshot
) -> MappingCandidate:
    official_urls = tuple(
        dict.fromkeys(
            reference.url
            for reference in technique.references
            if reference.source_name == "mitre-attack" and reference.url is not None
        )
    )[:8]
    return MappingCandidate(
        attack_id=technique.attack_id,
        stix_id=technique.stix_id,
        name=technique.name,
        parent_attack_id=technique.parent_attack_id,
        is_subtechnique=technique.is_subtechnique,
        tactic_ids=technique.tactic_ids,
        platforms=technique.platforms,
        status=technique.status,
        domain=technique.domain,
        catalog_version=snapshot.provenance.attack_version,
        official_references=official_urls,
    )


def _assessment_text(state: MappingState) -> str:
    statements = {
        MappingState.CANDIDATE: (
            "All minimum policy requirements are present; this is a limited educational candidate only."
        ),
        MappingState.INSUFFICIENT_EVIDENCE: (
            "Applicable evidence exists, but one or more minimum requirements are absent."
        ),
        MappingState.NOT_SUPPORTED: (
            "Available trusted evidence does not satisfy or contradicts this policy."
        ),
        MappingState.NOT_APPLICABLE: (
            "The submitted event families or platforms do not make this policy applicable."
        ),
        MappingState.CATALOG_UNAVAILABLE: (
            "The pinned ATT&CK catalog is unavailable, so technique knowledge cannot be resolved."
        ),
        MappingState.RETIRED_TECHNIQUE: (
            "The referenced ATT&CK object is retired and can never be emitted as a candidate."
        ),
    }
    return statements[state]


def _explanation(
    state: MappingState,
    policy: AttackMappingPolicy,
    technique: MappingCandidate | None,
    satisfied: tuple[str, ...],
    missing: tuple[str, ...],
    contradictions: tuple[str, ...],
) -> MappingExplanation:
    catalog_information = (
        ()
        if technique is None
        else (
            f"ATT&CK {technique.attack_id} resolves to {technique.name}.",
            f"Pinned Enterprise ATT&CK catalog version is {technique.catalog_version}.",
            f"Published tactic memberships: {', '.join(technique.tactic_ids) or 'none'}.",
        )
    )
    return MappingExplanation(
        assessment=_assessment_text(state),
        satisfied_conditions=satisfied,
        missing_conditions=missing,
        contradictory_conditions=contradictions,
        declared_information=(
            f"Policy {policy.policy_id} evaluated backend-generated rule and temporal evidence.",
            "Event provenance remains a producer declaration, including synthetic or declared nature.",
        ),
        catalog_information=catalog_information,
    )


class AttackMappingService:
    def __init__(
        self,
        store: ATTACKCatalogStore,
        registry: AttackMappingPolicyRegistry = DEFAULT_ATTACK_MAPPING_POLICY_REGISTRY,
        *,
        rule_engine: BehavioralRuleEngine | None = None,
        temporal_engine: TemporalCorrelationEngine | None = None,
        clock: Clock = time.monotonic,
    ) -> None:
        self._store = store
        self._registry = registry
        self._rule_engine = rule_engine or BehavioralRuleEngine()
        self._temporal_engine = temporal_engine or TemporalCorrelationEngine()
        self._clock = clock

    def policy_registry(self) -> AttackMappingPolicyRegistryResponse:
        try:
            snapshot = self._store.snapshot
            self._registry.validate_catalog(snapshot)
        except ATTACKCatalogUnavailableError:
            return AttackMappingPolicyRegistryResponse(
                policies=self._registry.policies,
                count=len(self._registry.policies),
                catalog_available=False,
                catalog_version=None,
            )
        return AttackMappingPolicyRegistryResponse(
            policies=self._registry.policies,
            count=len(self._registry.policies),
            catalog_available=True,
            catalog_version=snapshot.provenance.attack_version,
        )

    def evaluate(self, request: AttackMappingRequest) -> AttackMappingAssessment:
        started = self._clock()
        rule_ids = self.required_rule_ids(request.policy_ids)
        rule_result = self._rule_engine.evaluate(
            RuleEvaluationRequest(batch=request.batch, rule_ids=rule_ids)
        )
        temporal_result = self._temporal_engine.correlate(
            TemporalCorrelationRequest(
                batch=request.batch, policy=request.correlation_policy
            )
        )
        return self.evaluate_trusted(
            request,
            rule_result,
            temporal_result,
            started_at=started,
        )

    def required_rule_ids(
        self, policy_ids: tuple[AttackMappingPolicyIdentifier, ...] | None
    ) -> tuple[str, ...]:
        policies = self._registry.select(policy_ids)
        return tuple(sorted({policy.required_rule_id for policy in policies}))

    def evaluate_trusted(
        self,
        request: AttackMappingRequest,
        rule_result: RuleEvaluationResult,
        temporal_result: TemporalCorrelationResult,
        *,
        started_at: float | None = None,
    ) -> AttackMappingAssessment:
        """Evaluate only backend-produced evidence within the current request."""
        started = self._clock() if started_at is None else started_at
        policies = self._registry.select(request.policy_ids)
        try:
            loaded_snapshot = self._store.snapshot
            self._registry.validate_catalog(loaded_snapshot)
            snapshot: ATTACKCatalogSnapshot | None = loaded_snapshot
        except ATTACKCatalogUnavailableError:
            snapshot = None

        evaluations: list[MappingEvaluation] = []
        for policy in policies:
            if self._clock() - started > MAPPING_EVALUATION_DEADLINE_SECONDS:
                raise AttackMappingLimitError("ATT&CK mapping deadline exceeded")
            finding = find_rule_finding(rule_result, policy.required_rule_id)
            evaluations.append(
                self._evaluate_policy(
                    policy,
                    request.batch.events,
                    finding,
                    temporal_result,
                    snapshot,
                )
            )
        counts = Counter(item.state for item in evaluations)
        result = AttackMappingAssessment(
            catalog_provenance=snapshot.provenance if snapshot else None,
            rule_evaluation_summary=rule_result.summary,
            temporal_correlation_summary=temporal_result.summary,
            evaluations=tuple(evaluations),
            summary=AttackMappingSummary(
                evaluated_policies=len(evaluations),
                candidates=counts[MappingState.CANDIDATE],
                insufficient_evidence=counts[MappingState.INSUFFICIENT_EVIDENCE],
                not_supported=counts[MappingState.NOT_SUPPORTED],
                not_applicable=counts[MappingState.NOT_APPLICABLE],
                catalog_unavailable=counts[MappingState.CATALOG_UNAVAILABLE],
                retired_technique=counts[MappingState.RETIRED_TECHNIQUE],
                evidence_references=sum(
                    len(item.positive_evidence) for item in evaluations
                ),
                evaluations_truncated=False,
            ),
            limitations=(
                "Mappings are iCYLENS educational policy assessments, not official MITRE detections.",
                "Candidate never confirms adversary behavior, malicious activity, compromise, attribution, or malware.",
                "No CVE, CWE, KEV, EPSS, ML, name, path, command-line text, or port-only inference is performed.",
                "Only backend-recomputed rule findings and temporal relationships are trusted.",
            ),
        )
        encoded = json.dumps(
            result.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":")
        ).encode()
        if len(encoded) > MAX_MAPPING_OUTPUT_BYTES:
            raise AttackMappingLimitError("ATT&CK mapping output exceeds byte limit")
        return result

    def _evaluate_policy(
        self,
        policy: AttackMappingPolicy,
        events: Sequence[EventUnion],
        finding: RuleFinding | None,
        temporal_result: TemporalCorrelationResult,
        snapshot: ATTACKCatalogSnapshot | None,
    ) -> MappingEvaluation:
        applicable = _family_events(policy, events)
        platform_match = any(
            event.platform in policy.applicable_platforms for event in applicable
        )
        candidate = (
            _candidate(snapshot.techniques_by_id[policy.technique_id], snapshot)
            if snapshot is not None
            else None
        )
        positive: list[MappingEvidenceReference] = []
        satisfied: list[str] = []
        missing: list[str] = []
        contradictions: list[str] = []

        if snapshot is None:
            state = MappingState.CATALOG_UNAVAILABLE
        elif (
            candidate is not None and candidate.status is not ATTACKObjectStatus.ACTIVE
        ):
            state = MappingState.RETIRED_TECHNIQUE
        elif not applicable or not platform_match or finding is None:
            state = MappingState.NOT_APPLICABLE
        elif finding.result is RuleMatchStatus.NOT_APPLICABLE:
            state = MappingState.NOT_APPLICABLE
        elif finding.result is RuleMatchStatus.NOT_MATCHED:
            state = MappingState.NOT_SUPPORTED
            contradictions.append(
                f"Backend rule {policy.required_rule_id} did not match."
            )
        elif finding.result is RuleMatchStatus.INSUFFICIENT_EVIDENCE:
            state = MappingState.INSUFFICIENT_EVIDENCE
            missing.append(
                f"Backend rule {policy.required_rule_id} reported insufficient evidence."
            )
        else:
            reference = rule_reference(finding)
            if reference is not None:
                positive.append(reference)
                satisfied.append(
                    f"Backend rule {policy.required_rule_id} matched declared evidence."
                )
            relevant_ids = set(finding.event_ids)
            for requirement in policy.minimum_evidence:
                if requirement.evidence_type is MappingEvidenceType.RULE_FINDING:
                    continue
                if requirement.evidence_type is MappingEvidenceType.SCHEMA_CAPABILITY:
                    missing.append(requirement.description)
            for requirement in policy.optional_evidence:
                if (
                    requirement.evidence_type
                    is MappingEvidenceType.TEMPORAL_RELATIONSHIP
                ):
                    references = relationship_references(
                        temporal_result,
                        requirement.evidence_key,
                        relevant_ids,
                        events,
                    )
                    positive.extend(references)
                    if references:
                        satisfied.append(requirement.description)
            correlation_errors = [
                issue
                for issue in temporal_result.issues
                if issue.severity is CorrelationIssueSeverity.ERROR
                and relevant_ids.intersection(issue.event_ids)
            ]
            contradictions.extend(
                f"Temporal correlation reported {issue.code}."
                for issue in correlation_errors
            )
            if contradictions:
                state = MappingState.NOT_SUPPORTED
            elif missing:
                state = MappingState.INSUFFICIENT_EVIDENCE
            else:
                state = MappingState.CANDIDATE

        conditions = tuple(
            requirement.description
            for requirement in policy.minimum_evidence + policy.optional_evidence
        )
        return MappingEvaluation(
            policy_id=policy.policy_id,
            policy_version=policy.version,
            state=state,
            technique=candidate,
            conditions_evaluated=conditions,
            positive_evidence=tuple(positive[:16]),
            missing_evidence=tuple(missing),
            contradictory_evidence=tuple(contradictions),
            explanation=_explanation(
                state,
                policy,
                candidate,
                tuple(satisfied),
                tuple(missing),
                tuple(contradictions),
            ),
            limitations=policy.limitations,
        )


async def evaluate_attack_mapping(
    service: AttackMappingService,
    request: AttackMappingRequest,
    capacity: AttackMappingCapacity,
) -> AttackMappingAssessment:
    if not await capacity.try_acquire():
        raise AttackMappingCapacityError("ATT&CK mapping capacity is exhausted")
    worker = asyncio.create_task(asyncio.to_thread(service.evaluate, request))
    deferred_release = False

    async def release_after_worker() -> None:
        try:
            await worker
        except BaseException:
            pass
        finally:
            await capacity.release()

    try:
        try:
            return await asyncio.wait_for(
                asyncio.shield(worker),
                timeout=MAPPING_OPERATION_TIMEOUT_SECONDS,
            )
        except TimeoutError as error:
            deferred_release = True
            asyncio.create_task(release_after_worker())
            raise AttackMappingLimitError(
                "ATT&CK mapping operation timed out"
            ) from error
        except asyncio.CancelledError:
            deferred_release = True
            asyncio.create_task(release_after_worker())
            raise
    finally:
        if not deferred_release:
            await capacity.release()
