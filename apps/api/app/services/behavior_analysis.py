from __future__ import annotations

import json
import time
from collections import Counter
from collections.abc import Callable, Sequence
from typing import TypeAlias
from uuid import NAMESPACE_URL, UUID, uuid5

from app.attack.catalog import ATTACKCatalogStore
from app.behavior.correlation import TemporalCorrelationEngine
from app.behavior.generator import generate_scenario
from app.behavior.rule_engine import BehavioralRuleEngine
from app.behavior.validation import validate_event_batch
from app.schemas.attack_mapping import AttackMappingRequest
from app.schemas.behavior import (
    MAX_EVENTS_PER_BATCH,
    MAX_SYNTHETIC_EVENTS,
    EventBatch,
    EventNature,
    EventUnion,
    EventValidationResult,
    SyntheticScenarioKind,
    ValidationSeverity,
)
from app.schemas.behavior_analysis import (
    MAX_UNIFIED_ANALYSIS_OUTPUT_BYTES,
    UNIFIED_ANALYSIS_DEADLINE_SECONDS,
    UNIFIED_ANALYSIS_MAX_CONCURRENCY,
    UNIFIED_ANALYSIS_OPERATION_TIMEOUT_SECONDS,
    BehavioralAnalysisExplanation,
    BehavioralAnalysisIssue,
    BehavioralAnalysisOptions,
    BehavioralAnalysisProvenance,
    BehavioralAnalysisRequest,
    BehavioralAnalysisResult,
    BehavioralAnalysisSource,
    BehavioralAnalysisStage,
    BehavioralAnalysisStageName,
    BehavioralAnalysisStageStatus,
    BehavioralAnalysisStatus,
    BehavioralAnalysisSummary,
    BehavioralEventSummary,
    BehavioralRuleFindingSummary,
    SyntheticAnalysisRequest,
)
from app.schemas.behavior_correlation import TemporalCorrelationRequest
from app.schemas.behavior_rules import RuleEvaluationRequest, RuleFinding
from app.services.attack_mapping import AttackMappingService
from app.services.synchronous_workers import SynchronousWorkerManager

Clock: TypeAlias = Callable[[], float]
_ANALYSIS_NAMESPACE = uuid5(
    NAMESPACE_URL, "https://icylens.local/behavior/unified-analysis/v1"
)


class BehavioralAnalysisLimitError(RuntimeError):
    pass


class BehavioralAnalysisCapacityError(RuntimeError):
    pass


class BehavioralAnalysisCapacity(SynchronousWorkerManager):
    def __init__(self, maximum: int = UNIFIED_ANALYSIS_MAX_CONCURRENCY) -> None:
        super().__init__(maximum, thread_name_prefix="icylens-phase05")


def _analysis_id(
    source: BehavioralAnalysisSource,
    events: Sequence[EventUnion],
    options: BehavioralAnalysisOptions,
    scenario_key: str | None,
) -> UUID:
    event_payload = [
        event.model_dump(mode="json")
        for event in sorted(events, key=lambda item: (item.timestamp, item.event_id))
    ]
    payload = json.dumps(
        {
            "source": source.value,
            "scenario": scenario_key,
            "events": event_payload,
            "options": options.model_dump(mode="json"),
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return uuid5(_ANALYSIS_NAMESPACE, payload)


def _event_summary(events: Sequence[EventUnion]) -> BehavioralEventSummary:
    counts = Counter(event.event_type for event in events)
    nature_counts = Counter(event.provenance.nature for event in events)
    return BehavioralEventSummary(
        submitted_events=len(events),
        unique_event_ids=len({event.event_id for event in events}),
        declared_events=nature_counts[EventNature.DECLARED],
        synthetic_events=nature_counts[EventNature.SYNTHETIC],
        process_events=counts["process"],
        file_events=counts["file"],
        network_events=counts["network"],
        configuration_events=counts["configuration"],
    )


def _finding_summary(finding: RuleFinding) -> BehavioralRuleFindingSummary:
    return BehavioralRuleFindingSummary(
        rule_id=finding.rule_id,
        rule_version=finding.rule_version,
        rule_name=finding.rule_name,
        family=finding.family,
        result=finding.result,
        event_ids=tuple(sorted(finding.event_ids))[:8],
        satisfied_conditions=finding.satisfied_conditions,
        limitations=finding.limitations,
    )


def _validation_issues(
    validation: EventValidationResult,
) -> tuple[BehavioralAnalysisIssue, ...]:
    return tuple(
        BehavioralAnalysisIssue(
            stage=BehavioralAnalysisStageName.VALIDATION,
            code=issue.code,
            severity=issue.severity,
            message=issue.message,
            event_ids=issue.event_ids[:16],
        )
        for issue in validation.issues
    )


class BehavioralAnalysisService:
    def __init__(
        self,
        attack_store: ATTACKCatalogStore,
        *,
        rule_engine: BehavioralRuleEngine | None = None,
        temporal_engine: TemporalCorrelationEngine | None = None,
        mapping_service: AttackMappingService | None = None,
        clock: Clock = time.monotonic,
    ) -> None:
        self._rule_engine = rule_engine or BehavioralRuleEngine()
        self._temporal_engine = temporal_engine or TemporalCorrelationEngine()
        self._mapping_service = mapping_service or AttackMappingService(attack_store)
        self._clock = clock

    def analyze(self, request: BehavioralAnalysisRequest) -> BehavioralAnalysisResult:
        return self._analyze_batch(
            request.batch,
            request.options,
            BehavioralAnalysisSource.DECLARED_BATCH,
            scenario_id=None,
            scenario_kind=None,
            scenario_seed=None,
            scenario_key=None,
        )

    def analyze_synthetic(
        self, request: SyntheticAnalysisRequest
    ) -> BehavioralAnalysisResult:
        started = self._clock()
        scenario = generate_scenario(request.scenario)
        scenario_key = (
            f"{request.scenario.scenario_id}:{request.scenario.scenario_kind.value}:"
            f"{request.scenario.seed}:{request.scenario.platform.value}:"
            f"{request.scenario.start_time.isoformat()}:{request.scenario.event_count}"
        )
        return self._analyze_batch(
            EventBatch(events=scenario.events),
            request.options,
            BehavioralAnalysisSource.SYNTHETIC_SCENARIO,
            scenario_id=request.scenario.scenario_id,
            scenario_kind=request.scenario.scenario_kind,
            scenario_seed=request.scenario.seed,
            scenario_key=scenario_key,
            started_at=started,
            existing_validation=scenario.validation,
        )

    def _analyze_batch(
        self,
        batch: EventBatch,
        options: BehavioralAnalysisOptions,
        source: BehavioralAnalysisSource,
        *,
        scenario_id: str | None,
        scenario_kind: SyntheticScenarioKind | None,
        scenario_seed: int | None,
        scenario_key: str | None,
        started_at: float | None = None,
        existing_validation: EventValidationResult | None = None,
    ) -> BehavioralAnalysisResult:
        started = self._clock() if started_at is None else started_at

        def check_deadline() -> None:
            if self._clock() - started > UNIFIED_ANALYSIS_DEADLINE_SECONDS:
                raise BehavioralAnalysisLimitError(
                    "Unified behavioral analysis deadline exceeded"
                )

        # Synthetic generation already invokes the same validator. Reusing that
        # immutable result avoids a redundant pass while declared input is always
        # validated here, regardless of any client claims.
        validation = existing_validation or validate_event_batch(batch)
        check_deadline()
        if not validation.valid:
            return self._invalid_result(
                batch,
                options,
                source,
                validation,
                scenario_id=scenario_id,
                scenario_kind=scenario_kind,
                scenario_seed=scenario_seed,
                scenario_key=scenario_key,
            )

        mapping_rule_ids = self._mapping_service.required_rule_ids(
            options.mapping_policy_ids
        )
        if options.rule_ids is None:
            selected_rule_ids = None
        else:
            selected_rule_ids = tuple(
                sorted(set(options.rule_ids).union(mapping_rule_ids))
            )
        rule_result = self._rule_engine.evaluate(
            RuleEvaluationRequest(batch=batch, rule_ids=selected_rule_ids),
            batch_validation=validation,
        )
        check_deadline()
        temporal_result = self._temporal_engine.correlate(
            TemporalCorrelationRequest(batch=batch, policy=options.correlation_policy),
            batch_validation=validation,
        )
        check_deadline()
        mapping_request = AttackMappingRequest(
            batch=batch,
            policy_ids=options.mapping_policy_ids,
            correlation_policy=options.correlation_policy,
        )
        mapping_result = self._mapping_service.evaluate_trusted(
            mapping_request,
            rule_result,
            temporal_result,
            started_at=started,
        )
        check_deadline()

        catalog_unavailable = mapping_result.summary.catalog_unavailable > 0
        status = (
            BehavioralAnalysisStatus.PARTIAL
            if catalog_unavailable
            else BehavioralAnalysisStatus.COMPLETE
        )
        stages = (
            BehavioralAnalysisStage(
                stage=BehavioralAnalysisStageName.VALIDATION,
                status=BehavioralAnalysisStageStatus.COMPLETED,
                item_count=validation.event_count,
                detail="The canonical 05.02 batch validator completed.",
            ),
            BehavioralAnalysisStage(
                stage=BehavioralAnalysisStageName.RULES,
                status=BehavioralAnalysisStageStatus.COMPLETED,
                item_count=len(rule_result.findings),
                detail="The immutable 05.03 rule engine completed.",
            ),
            BehavioralAnalysisStage(
                stage=BehavioralAnalysisStageName.TEMPORAL_CORRELATION,
                status=BehavioralAnalysisStageStatus.COMPLETED,
                item_count=len(temporal_result.relationships),
                detail="The 05.04 temporal engine completed without causal inference.",
            ),
            BehavioralAnalysisStage(
                stage=BehavioralAnalysisStageName.ATTACK_MAPPING,
                status=(
                    BehavioralAnalysisStageStatus.UNAVAILABLE
                    if catalog_unavailable
                    else BehavioralAnalysisStageStatus.COMPLETED
                ),
                item_count=len(mapping_result.evaluations),
                detail=(
                    "The pinned catalog was unavailable; mapping states preserve that distinction."
                    if catalog_unavailable
                    else "The 05.05 mapping policies completed against the pinned catalog."
                ),
            ),
            BehavioralAnalysisStage(
                stage=BehavioralAnalysisStageName.EXPLAINABILITY,
                status=BehavioralAnalysisStageStatus.COMPLETED,
                item_count=1,
                detail="A controlled structured explanation was assembled.",
            ),
        )
        issues = list(_validation_issues(validation))
        issues.extend(
            BehavioralAnalysisIssue(
                stage=BehavioralAnalysisStageName.TEMPORAL_CORRELATION,
                code=issue.code,
                severity=(
                    ValidationSeverity.ERROR
                    if issue.severity.value == "error"
                    else ValidationSeverity.WARNING
                ),
                message=issue.message,
                event_ids=issue.event_ids,
            )
            for issue in temporal_result.issues
        )
        unknowns = tuple(
            dict.fromkeys(
                missing
                for evaluation in mapping_result.evaluations
                for missing in evaluation.missing_evidence
            )
        )[:16]
        result = BehavioralAnalysisResult(
            analysis_id=_analysis_id(source, batch.events, options, scenario_key),
            status=status,
            generated_at=temporal_result.generated_at,
            source=source,
            provenance=self._provenance(
                source,
                batch.events,
                scenario_id,
                scenario_kind,
                scenario_seed,
            ),
            event_summary=_event_summary(batch.events),
            validation=validation,
            rule_findings=tuple(
                _finding_summary(item) for item in rule_result.findings
            ),
            rule_summary=rule_result.summary,
            temporal_relationships=temporal_result.relationships,
            temporal_sequences=temporal_result.sequences,
            temporal_summary=temporal_result.summary,
            attack_mapping_evaluations=mapping_result.evaluations,
            attack_mapping_summary=mapping_result.summary,
            catalog_version=(
                mapping_result.catalog_provenance.attack_version
                if mapping_result.catalog_provenance
                else None
            ),
            stages=stages,
            issues=tuple(issues[:512]),
            summary=BehavioralAnalysisSummary(
                valid_events=validation.event_count,
                validation_errors=sum(
                    issue.severity is ValidationSeverity.ERROR
                    for issue in validation.issues
                ),
                validation_warnings=sum(
                    issue.severity is ValidationSeverity.WARNING
                    for issue in validation.issues
                ),
                evaluated_rules=rule_result.summary.evaluated_rules,
                matched_rules=rule_result.summary.matched,
                temporal_relationships=len(temporal_result.relationships),
                strong_relationships=temporal_result.summary.strong_relationships,
                weak_relationships=temporal_result.summary.weak_relationships,
                mapping_policies=mapping_result.summary.evaluated_policies,
                mapping_candidates=mapping_result.summary.candidates,
                insufficient_mappings=mapping_result.summary.insufficient_evidence,
                unknowns=len(unknowns),
            ),
            explanation=BehavioralAnalysisExplanation(
                input_statement=(
                    "A deterministic synthetic scenario was generated and analyzed."
                    if source is BehavioralAnalysisSource.SYNTHETIC_SCENARIO
                    else "A submitted canonical event batch was analyzed."
                ),
                validation_statement=(
                    f"Validation completed for {validation.event_count} events with no blocking errors."
                ),
                rule_statement=(
                    f"{rule_result.summary.evaluated_rules} rules were evaluated; "
                    f"{rule_result.summary.matched} matched declared conditions."
                ),
                temporal_statement=(
                    f"{len(temporal_result.relationships)} bounded relationships were produced; all remain non-causal."
                ),
                mapping_statement=(
                    f"{mapping_result.summary.evaluated_policies} mapping policies were evaluated; "
                    f"{mapping_result.summary.candidates} educational candidates resulted."
                ),
                unknowns=unknowns,
            ),
            limitations=(
                "The response summarizes submitted or generated declarations and returns no raw event payloads.",
                "Rule matches are not alerts; temporal relationships are not causality; ATT&CK candidates are not attack confirmation.",
                "No host telemetry collection, command execution, persistence, ML, SIEM ingestion, or vulnerability mapping occurred.",
            ),
        )
        return self._bounded(result)

    def _invalid_result(
        self,
        batch: EventBatch,
        options: BehavioralAnalysisOptions,
        source: BehavioralAnalysisSource,
        validation: EventValidationResult,
        *,
        scenario_id: str | None,
        scenario_kind: SyntheticScenarioKind | None,
        scenario_seed: int | None,
        scenario_key: str | None,
    ) -> BehavioralAnalysisResult:
        skipped = (
            BehavioralAnalysisStageName.RULES,
            BehavioralAnalysisStageName.TEMPORAL_CORRELATION,
            BehavioralAnalysisStageName.ATTACK_MAPPING,
        )
        stages = [
            BehavioralAnalysisStage(
                stage=BehavioralAnalysisStageName.VALIDATION,
                status=BehavioralAnalysisStageStatus.COMPLETED,
                item_count=validation.event_count,
                detail="Validation completed and found blocking batch errors.",
            )
        ]
        stages.extend(
            BehavioralAnalysisStage(
                stage=stage,
                status=BehavioralAnalysisStageStatus.SKIPPED,
                item_count=0,
                detail="Skipped because validation reported a blocking error.",
            )
            for stage in skipped
        )
        stages.append(
            BehavioralAnalysisStage(
                stage=BehavioralAnalysisStageName.EXPLAINABILITY,
                status=BehavioralAnalysisStageStatus.COMPLETED,
                item_count=1,
                detail="A controlled explanation of the partial result was assembled.",
            )
        )
        errors = sum(
            issue.severity is ValidationSeverity.ERROR for issue in validation.issues
        )
        warnings = sum(
            issue.severity is ValidationSeverity.WARNING for issue in validation.issues
        )
        result = BehavioralAnalysisResult(
            analysis_id=_analysis_id(source, batch.events, options, scenario_key),
            status=BehavioralAnalysisStatus.PARTIAL,
            generated_at=max(event.provenance.received_at for event in batch.events),
            source=source,
            provenance=self._provenance(
                source,
                batch.events,
                scenario_id,
                scenario_kind,
                scenario_seed,
            ),
            event_summary=_event_summary(batch.events),
            validation=validation,
            rule_findings=(),
            rule_summary=None,
            temporal_relationships=(),
            temporal_sequences=(),
            temporal_summary=None,
            attack_mapping_evaluations=(),
            attack_mapping_summary=None,
            catalog_version=None,
            stages=tuple(stages),
            issues=_validation_issues(validation),
            summary=BehavioralAnalysisSummary(
                valid_events=0,
                validation_errors=errors,
                validation_warnings=warnings,
                evaluated_rules=0,
                matched_rules=0,
                temporal_relationships=0,
                strong_relationships=0,
                weak_relationships=0,
                mapping_policies=0,
                mapping_candidates=0,
                insufficient_mappings=0,
                unknowns=errors + warnings,
            ),
            explanation=BehavioralAnalysisExplanation(
                input_statement=(
                    "A deterministic synthetic scenario was generated but failed batch validation."
                    if source is BehavioralAnalysisSource.SYNTHETIC_SCENARIO
                    else "A submitted event batch failed semantic validation."
                ),
                validation_statement=(
                    f"Validation found {errors} blocking errors and {warnings} warnings."
                ),
                rule_statement="Rule evaluation was skipped after blocking validation errors.",
                temporal_statement="Temporal correlation was skipped after blocking validation errors.",
                mapping_statement="ATT&CK mapping was skipped after blocking validation errors.",
                unknowns=(
                    "No downstream conclusion is available for a batch with blocking validation errors.",
                ),
            ),
            limitations=(
                "Structurally valid but semantically inconsistent input is returned as an explicit partial assessment.",
                "No downstream engine ran on the invalid batch.",
            ),
        )
        return self._bounded(result)

    @staticmethod
    def _provenance(
        source: BehavioralAnalysisSource,
        events: Sequence[EventUnion],
        scenario_id: str | None,
        scenario_kind: SyntheticScenarioKind | None,
        scenario_seed: int | None,
    ) -> BehavioralAnalysisProvenance:
        return BehavioralAnalysisProvenance(
            source=source,
            event_natures=tuple(
                sorted(
                    {event.provenance.nature for event in events},
                    key=lambda item: item.value,
                )
            ),
            scenario_id=scenario_id,
            scenario_kind=scenario_kind,
            scenario_seed=scenario_seed,
        )

    @staticmethod
    def _bounded(result: BehavioralAnalysisResult) -> BehavioralAnalysisResult:
        encoded = json.dumps(
            result.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":")
        ).encode()
        if len(encoded) > MAX_UNIFIED_ANALYSIS_OUTPUT_BYTES:
            raise BehavioralAnalysisLimitError(
                "Unified behavioral analysis output exceeds byte limit"
            )
        return result


async def execute_behavioral_analysis(
    operation: Callable[[], BehavioralAnalysisResult],
    capacity: SynchronousWorkerManager,
) -> BehavioralAnalysisResult:
    worker = capacity.try_submit(operation)
    if worker is None:
        raise BehavioralAnalysisCapacityError("Behavioral analysis capacity exhausted")
    try:
        return await capacity.wait(
            worker,
            timeout=UNIFIED_ANALYSIS_OPERATION_TIMEOUT_SECONDS,
        )
    except TimeoutError as error:
        raise BehavioralAnalysisLimitError(
            "Unified behavioral analysis operation timed out"
        ) from error


def analysis_limits() -> dict[str, int]:
    return {
        "maximum_declared_events": MAX_EVENTS_PER_BATCH,
        "maximum_synthetic_events": MAX_SYNTHETIC_EVENTS,
        "maximum_response_bytes": MAX_UNIFIED_ANALYSIS_OUTPUT_BYTES,
        "maximum_concurrency": UNIFIED_ANALYSIS_MAX_CONCURRENCY,
    }
