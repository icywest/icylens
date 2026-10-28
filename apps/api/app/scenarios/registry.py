from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType
from uuid import UUID

from app.schemas.correlation import CorrelationRelationshipType
from app.schemas.evidence import EvidenceDomain
from app.schemas.sufficiency import (
    EvidenceGapCategory,
    SufficiencyState,
    UncertaintyCategory,
)
from app.schemas.synthetic_scenarios import (
    MAX_SYNTHETIC_SCENARIOS,
    SyntheticAssertionSelection,
    SyntheticBehavioralSource,
    SyntheticEvidenceSource,
    SyntheticExpectedAssessment,
    SyntheticMLSource,
    SyntheticScenario,
    SyntheticScenarioDefinition,
    SyntheticScenarioExpectation,
    SyntheticScenarioIdentifier,
    SyntheticScenarioLearningObjective,
    SyntheticScenarioMetadata,
    SyntheticStaticSource,
    SyntheticVulnerabilitySource,
)

_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64
_DIGEST_C = "c" * 64
_ANALYSIS_A = UUID("10000000-0000-4000-8000-000000000001")
_ANALYSIS_B = UUID("10000000-0000-4000-8000-000000000002")
_ANALYSIS_SHARED = UUID("20000000-0000-4000-8000-000000000001")


def _metadata(
    scenario_id: str,
    title: str,
    objective_id: str,
    objective: str,
    domains: tuple[EvidenceDomain, ...],
    *boundaries: str,
) -> SyntheticScenarioMetadata:
    return SyntheticScenarioMetadata(
        identifier=SyntheticScenarioIdentifier(scenario_id=scenario_id),
        title=title,
        objective=SyntheticScenarioLearningObjective(
            objective_id=objective_id, statement=objective
        ),
        domains=domains,
        scientific_boundaries=boundaries,
    )


def _selection(assertion_id: str, *source_ids: str) -> SyntheticAssertionSelection:
    return SyntheticAssertionSelection(
        assertion_id=assertion_id, source_ids=tuple(sorted(source_ids))
    )


def _expectation(
    assertion_id: str,
    status: SufficiencyState,
    *,
    relationships: tuple[CorrelationRelationshipType, ...] = (),
    conflicts: int = 0,
    gaps: tuple[EvidenceGapCategory, ...] = (),
    uncertainties: tuple[UncertaintyCategory, ...] = (
        UncertaintyCategory.SYNTHETIC_ORIGIN,
    ),
    positive_absent: bool = False,
) -> SyntheticScenarioExpectation:
    return SyntheticScenarioExpectation(
        assessments=(
            SyntheticExpectedAssessment(assertion_id=assertion_id, status=status),
        ),
        relationship_types=relationships,
        relevant_conflicts=conflicts,
        missing_requirement_categories=gaps,
        uncertainty_categories=uncertainties,
        positive_relationships_absent=positive_absent,
    )


def _scenario(
    metadata: SyntheticScenarioMetadata,
    sources: tuple[SyntheticEvidenceSource, ...],
    selection: SyntheticAssertionSelection,
    expectation: SyntheticScenarioExpectation,
) -> SyntheticScenario:
    return SyntheticScenario(
        definition=SyntheticScenarioDefinition(
            metadata=metadata,
            sources=sources,
            assertions=(selection,),
            expectation=expectation,
        )
    )


BUILTIN_SYNTHETIC_SCENARIOS = (
    _scenario(
        _metadata(
            "scenario_conflicting_file_identity",
            "Conflicting synthetic file identity",
            "LO-002",
            "Observe conflict retention without selecting an authoritative digest.",
            (EvidenceDomain.STATIC,),
            "Conflicting digests do not identify a correct source.",
            "No execution, malware, device, or causality is established.",
        ),
        (
            SyntheticStaticSource(
                source_id="fixture_static_conflict_a",
                source_analysis_id=_ANALYSIS_A,
                sha256=_DIGEST_A,
            ),
            SyntheticStaticSource(
                source_id="fixture_static_conflict_b",
                source_analysis_id=_ANALYSIS_A,
                sha256=_DIGEST_B,
            ),
        ),
        _selection(
            "AS-CONTENT-001",
            "fixture_static_conflict_a",
            "fixture_static_conflict_b",
        ),
        _expectation(
            "AS-CONTENT-001",
            SufficiencyState.CONFLICTING_EVIDENCE,
            conflicts=1,
            uncertainties=(
                UncertaintyCategory.SYNTHETIC_ORIGIN,
                UncertaintyCategory.CONFLICTING_CLAIMS,
            ),
            positive_absent=True,
        ),
    ),
    _scenario(
        _metadata(
            "scenario_cross_namespace_analysis",
            "Cross-module analysis namespace separation",
            "LO-011",
            "Verify that an equal UUID in different modules is not shared identity.",
            (EvidenceDomain.SYNTHETIC_ML, EvidenceDomain.BEHAVIORAL),
            "A UUID is source scoped and not a global investigation identity.",
            "No host, process, tenant, or causal context is inferred.",
        ),
        (
            SyntheticMLSource(
                source_id="fixture_cross_ml",
                source_analysis_id=_ANALYSIS_A,
                analysis_context_id=_ANALYSIS_SHARED,
            ),
            SyntheticBehavioralSource(
                source_id="fixture_cross_behavior",
                source_analysis_id=_ANALYSIS_B,
                analysis_context_id=_ANALYSIS_SHARED,
            ),
        ),
        _selection("AS-ANALYSIS-001", "fixture_cross_behavior", "fixture_cross_ml"),
        _expectation(
            "AS-ANALYSIS-001",
            SufficiencyState.INSUFFICIENT_EVIDENCE,
            gaps=(
                EvidenceGapCategory.MISSING_IDENTITY,
                EvidenceGapCategory.MISSING_RELATIONSHIP,
            ),
            uncertainties=(
                UncertaintyCategory.SYNTHETIC_ORIGIN,
                UncertaintyCategory.MISSING_IDENTITY,
                UncertaintyCategory.UNSUPPORTED_CROSS_MODULE_RELATION,
            ),
            positive_absent=True,
        ),
    ),
    _scenario(
        _metadata(
            "scenario_empty_non_positive_correlation",
            "Valid non-positive correlation",
            "LO-010",
            "Treat a valid empty relationship graph as an analytical result.",
            (EvidenceDomain.STATIC, EvidenceDomain.VULNERABILITY),
            "Co-membership in a batch is not a relationship.",
            "Absence of an edge is not proof of unrelated real-world activity.",
        ),
        (
            SyntheticStaticSource(
                source_id="fixture_empty_static",
                source_analysis_id=_ANALYSIS_A,
                sha256=_DIGEST_C,
            ),
            SyntheticVulnerabilitySource(
                source_id="fixture_empty_vuln",
                source_analysis_id=_ANALYSIS_B,
                cve_id="CVE-2024-1001",
            ),
        ),
        _selection("AS-REF-001", "fixture_empty_static", "fixture_empty_vuln"),
        _expectation(
            "AS-REF-001",
            SufficiencyState.INSUFFICIENT_EVIDENCE,
            gaps=(EvidenceGapCategory.MISSING_RELATIONSHIP,),
            positive_absent=True,
        ),
    ),
    _scenario(
        _metadata(
            "scenario_explicit_evidence_reference",
            "Explicit synthetic evidence reference",
            "LO-006",
            "Trace a validated internal derivation reference without inferring causality.",
            (EvidenceDomain.STATIC, EvidenceDomain.VULNERABILITY),
            "The reference supports only the declared derivation link.",
            "The reference does not prove identity, execution, or maliciousness.",
        ),
        (
            SyntheticStaticSource(
                source_id="fixture_reference_target",
                source_analysis_id=_ANALYSIS_A,
                sha256=_DIGEST_A,
            ),
            SyntheticVulnerabilitySource(
                source_id="fixture_reference_source",
                source_analysis_id=_ANALYSIS_B,
                cve_id="CVE-2024-1002",
                explicit_derivation_of="fixture_reference_target",
            ),
        ),
        _selection(
            "AS-REF-001", "fixture_reference_source", "fixture_reference_target"
        ),
        _expectation(
            "AS-REF-001",
            SufficiencyState.SUFFICIENT,
            relationships=(CorrelationRelationshipType.EXPLICIT_EVIDENCE_REFERENCE,),
        ),
    ),
    _scenario(
        _metadata(
            "scenario_insufficient_cross_module",
            "Insufficient cross-module context",
            "LO-007",
            "Explain why independent ML and CVE context cannot be linked.",
            (EvidenceDomain.SYNTHETIC_ML, EvidenceDomain.VULNERABILITY),
            "No supported identity spans the selected modules.",
            "An educational prediction and a CVE do not imply a threat chain.",
        ),
        (
            SyntheticMLSource(
                source_id="fixture_insufficient_ml",
                source_analysis_id=_ANALYSIS_A,
                analysis_context_id=_ANALYSIS_SHARED,
                output_label="malicious",
            ),
            SyntheticVulnerabilitySource(
                source_id="fixture_insufficient_vuln",
                source_analysis_id=_ANALYSIS_B,
                cve_id="CVE-2024-1003",
            ),
        ),
        _selection(
            "AS-ANALYSIS-001",
            "fixture_insufficient_ml",
            "fixture_insufficient_vuln",
        ),
        _expectation(
            "AS-ANALYSIS-001",
            SufficiencyState.NOT_APPLICABLE,
            gaps=(EvidenceGapCategory.INAPPLICABLE_DOMAIN,),
            uncertainties=(
                UncertaintyCategory.SYNTHETIC_ORIGIN,
                UncertaintyCategory.MISSING_IDENTITY,
                UncertaintyCategory.UNSUPPORTED_CROSS_MODULE_RELATION,
            ),
            positive_absent=True,
        ),
    ),
    _scenario(
        _metadata(
            "scenario_shared_analysis_context",
            "Shared source-scoped analysis context",
            "LO-005",
            "Demonstrate exact analysis identity within one source namespace.",
            (EvidenceDomain.SYNTHETIC_ML,),
            "Shared analysis context is not shared device or sample identity.",
            "No model prediction is promoted to observed fact.",
        ),
        (
            SyntheticMLSource(
                source_id="fixture_analysis_a",
                source_analysis_id=_ANALYSIS_A,
                analysis_context_id=_ANALYSIS_SHARED,
            ),
            SyntheticMLSource(
                source_id="fixture_analysis_b",
                source_analysis_id=_ANALYSIS_B,
                analysis_context_id=_ANALYSIS_SHARED,
            ),
        ),
        _selection("AS-ANALYSIS-001", "fixture_analysis_a", "fixture_analysis_b"),
        _expectation(
            "AS-ANALYSIS-001",
            SufficiencyState.SUFFICIENT,
            relationships=(CorrelationRelationshipType.SHARED_ANALYSIS_CONTEXT,),
        ),
    ),
    _scenario(
        _metadata(
            "scenario_shared_file_content",
            "Shared synthetic file content",
            "LO-001",
            "Demonstrate exact comparable SHA-256 content identity.",
            (EvidenceDomain.STATIC,),
            "Digest equality does not demonstrate file execution or malware.",
            "Digest equality does not establish a shared device.",
        ),
        (
            SyntheticStaticSource(
                source_id="fixture_content_a",
                source_analysis_id=_ANALYSIS_A,
                sha256=_DIGEST_A,
            ),
            SyntheticStaticSource(
                source_id="fixture_content_b",
                source_analysis_id=_ANALYSIS_B,
                sha256=_DIGEST_A,
            ),
        ),
        _selection("AS-CONTENT-001", "fixture_content_a", "fixture_content_b"),
        _expectation(
            "AS-CONTENT-001",
            SufficiencyState.SUFFICIENT,
            relationships=(CorrelationRelationshipType.SHARED_CONTENT_IDENTITY,),
        ),
    ),
    _scenario(
        _metadata(
            "scenario_shared_vulnerability_identity",
            "Shared synthetic vulnerability identity",
            "LO-003",
            "Demonstrate equality of a canonical CVE subject.",
            (EvidenceDomain.VULNERABILITY,),
            "CVE equality does not confirm installed software or exposure.",
            "CVE equality does not confirm exploitation or compromise.",
        ),
        (
            SyntheticVulnerabilitySource(
                source_id="fixture_vuln_a",
                source_analysis_id=_ANALYSIS_A,
                cve_id="CVE-2024-1000",
            ),
            SyntheticVulnerabilitySource(
                source_id="fixture_vuln_b",
                source_analysis_id=_ANALYSIS_B,
                cve_id="CVE-2024-1000",
            ),
        ),
        _selection("AS-VULN-001", "fixture_vuln_a", "fixture_vuln_b"),
        _expectation(
            "AS-VULN-001",
            SufficiencyState.SUFFICIENT,
            relationships=(CorrelationRelationshipType.SHARED_VULNERABILITY_IDENTITY,),
        ),
    ),
    _scenario(
        _metadata(
            "scenario_synthetic_provenance",
            "Backend educational provenance",
            "LO-009",
            "Preserve backend-generated educational provenance end to end.",
            (EvidenceDomain.STATIC,),
            "Synthetic origin is not authenticated external telemetry.",
            "A structurally valid fixture is not an operational observation.",
        ),
        (
            SyntheticStaticSource(
                source_id="fixture_provenance_a",
                source_analysis_id=_ANALYSIS_A,
                sha256=_DIGEST_B,
            ),
            SyntheticStaticSource(
                source_id="fixture_provenance_b",
                source_analysis_id=_ANALYSIS_B,
                sha256=_DIGEST_B,
            ),
        ),
        _selection("AS-CONTENT-001", "fixture_provenance_a", "fixture_provenance_b"),
        _expectation(
            "AS-CONTENT-001",
            SufficiencyState.SUFFICIENT,
            relationships=(CorrelationRelationshipType.SHARED_CONTENT_IDENTITY,),
        ),
    ),
    _scenario(
        _metadata(
            "scenario_unrelated_vulnerabilities",
            "Distinct synthetic vulnerabilities",
            "LO-004",
            "Demonstrate that different CVE identities do not correlate.",
            (EvidenceDomain.VULNERABILITY,),
            "Different CVEs do not establish unrelated real-world systems.",
            "No installation, exposure, or exploitation is inferred.",
        ),
        (
            SyntheticVulnerabilitySource(
                source_id="fixture_unrelated_vuln_a",
                source_analysis_id=_ANALYSIS_A,
                cve_id="CVE-2024-1004",
            ),
            SyntheticVulnerabilitySource(
                source_id="fixture_unrelated_vuln_b",
                source_analysis_id=_ANALYSIS_B,
                cve_id="CVE-2024-1005",
            ),
        ),
        _selection(
            "AS-VULN-001",
            "fixture_unrelated_vuln_a",
            "fixture_unrelated_vuln_b",
        ),
        _expectation(
            "AS-VULN-001",
            SufficiencyState.INSUFFICIENT_EVIDENCE,
            gaps=(
                EvidenceGapCategory.MISSING_IDENTITY,
                EvidenceGapCategory.MISSING_RELATIONSHIP,
            ),
            uncertainties=(
                UncertaintyCategory.SYNTHETIC_ORIGIN,
                UncertaintyCategory.MISSING_IDENTITY,
            ),
            positive_absent=True,
        ),
    ),
    _scenario(
        _metadata(
            "scenario_unsupported_threat_assertion",
            "Unsupported synthetic threat assertion",
            "LO-008",
            "Show that threat claims outside the policy registry remain unsupported.",
            (EvidenceDomain.SYNTHETIC_ML,),
            "A suspicious-looking educational label is not a detection.",
            "No attack narrative, malware verdict, or causality is generated.",
        ),
        (
            SyntheticMLSource(
                source_id="fixture_unsupported_ml",
                source_analysis_id=_ANALYSIS_A,
                analysis_context_id=_ANALYSIS_SHARED,
                output_label="malicious",
            ),
        ),
        _selection("AS-THREAT-999", "fixture_unsupported_ml"),
        _expectation(
            "AS-THREAT-999",
            SufficiencyState.UNSUPPORTED_ASSERTION,
            positive_absent=True,
        ),
    ),
)


class SyntheticScenarioRegistryError(RuntimeError):
    pass


class SyntheticScenarioRegistry:
    def __init__(
        self, scenarios: Iterable[SyntheticScenario] = BUILTIN_SYNTHETIC_SCENARIOS
    ) -> None:
        ordered = tuple(
            sorted(
                scenarios,
                key=lambda item: item.definition.metadata.identifier.scenario_id,
            )
        )
        if not ordered or len(ordered) > MAX_SYNTHETIC_SCENARIOS:
            raise SyntheticScenarioRegistryError("invalid scenario registry size")
        by_id: dict[str, SyntheticScenario] = {}
        for scenario in ordered:
            identifier = scenario.definition.metadata.identifier.scenario_id
            if identifier in by_id:
                raise SyntheticScenarioRegistryError(
                    "duplicate synthetic scenario identifier"
                )
            by_id[identifier] = scenario
        self._scenarios = ordered
        self._by_id: Mapping[str, SyntheticScenario] = MappingProxyType(by_id)

    @property
    def scenarios(self) -> tuple[SyntheticScenario, ...]:
        return self._scenarios

    @property
    def by_id(self) -> Mapping[str, SyntheticScenario]:
        return self._by_id

    def get(self, scenario_id: str, version: str = "1.0.0") -> SyntheticScenario:
        scenario = self._by_id.get(scenario_id)
        if scenario is None:
            raise SyntheticScenarioRegistryError(
                "unknown synthetic scenario identifier"
            )
        if scenario.definition.metadata.identifier.version != version:
            raise SyntheticScenarioRegistryError(
                "unsupported synthetic scenario version"
            )
        return scenario


DEFAULT_SYNTHETIC_SCENARIO_REGISTRY = SyntheticScenarioRegistry()
