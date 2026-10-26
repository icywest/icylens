from __future__ import annotations

from app.schemas.attack_mapping import (
    AttackMappingPolicy,
    MappingEvidenceRequirement,
    MappingEvidenceType,
)
from app.schemas.behavior import EventPlatform
from app.schemas.behavior_rules import RuleEventFamily


def _requirement(
    requirement_id: str,
    evidence_type: MappingEvidenceType,
    evidence_key: str,
    description: str,
    *,
    required: bool = True,
) -> MappingEvidenceRequirement:
    return MappingEvidenceRequirement(
        requirement_id=requirement_id,
        evidence_type=evidence_type,
        evidence_key=evidence_key,
        description=description,
        required=required,
    )


BUILTIN_ATTACK_MAPPING_POLICIES: tuple[AttackMappingPolicy, ...] = (
    AttackMappingPolicy(
        policy_id="AMP-CONF-001",
        version="1.0.0",
        technique_id="T1053.005",
        purpose=(
            "Assess whether declared scheduled-task evidence could support limited "
            "educational context for Scheduled Task/Job: Scheduled Task."
        ),
        applicable_family=RuleEventFamily.CONFIGURATION,
        applicable_platforms=(EventPlatform.WINDOWS,),
        required_rule_id="BR-CONF-002",
        minimum_evidence=(
            _requirement(
                "scheduled_task_declaration",
                MappingEvidenceType.RULE_FINDING,
                "BR-CONF-002",
                "A backend rule finding establishes declared scheduled-task creation semantics.",
            ),
            _requirement(
                "independent_task_execution",
                MappingEvidenceType.SCHEMA_CAPABILITY,
                "independent_task_execution",
                "Independent telemetry establishes that the task executed the declared action.",
            ),
        ),
        optional_evidence=(
            _requirement(
                "strong_process_context",
                MappingEvidenceType.TEMPORAL_RELATIONSHIP,
                "same_process_instance",
                "A strong same-process relationship supplies bounded context.",
                required=False,
            ),
        ),
        contradictory_conditions=(
            "Host or process identity conflicts in referenced evidence.",
        ),
        limitations=(
            "A declared scheduled task does not confirm persistence or execution.",
            "Schema 1.0.0 has no independent task-execution telemetry.",
            "This policy is authored by iCYLENS and is not an official MITRE rule.",
        ),
    ),
    AttackMappingPolicy(
        policy_id="AMP-NET-001",
        version="1.0.0",
        technique_id="T1071.001",
        purpose=(
            "Assess whether network evidence could support limited educational "
            "context for Application Layer Protocol: Web Protocols."
        ),
        applicable_family=RuleEventFamily.NETWORK,
        applicable_platforms=(
            EventPlatform.WINDOWS,
            EventPlatform.LINUX,
            EventPlatform.MACOS,
        ),
        required_rule_id="BR-NET-003",
        minimum_evidence=(
            _requirement(
                "tcp_443_declaration",
                MappingEvidenceType.RULE_FINDING,
                "BR-NET-003",
                "A backend rule finding establishes only declared TCP destination port 443.",
            ),
            _requirement(
                "verified_application_protocol",
                MappingEvidenceType.SCHEMA_CAPABILITY,
                "verified_application_protocol",
                "Protocol-aware telemetry verifies use of an ATT&CK-described web protocol.",
            ),
        ),
        optional_evidence=(
            _requirement(
                "declared_connection_context",
                MappingEvidenceType.TEMPORAL_RELATIONSHIP,
                "same_declared_connection",
                "A weak declared-connection relationship supplies bounded context.",
                required=False,
            ),
        ),
        contradictory_conditions=("Connection or process identity conflicts.",),
        limitations=(
            "TCP/443 alone does not establish HTTP, HTTPS, Command and Control, or malicious use.",
            "Schema 1.0.0 has no application-layer protocol evidence.",
            "This policy is authored by iCYLENS and is not an official MITRE rule.",
        ),
    ),
    AttackMappingPolicy(
        policy_id="AMP-PROC-001",
        version="1.0.0",
        technique_id="T1059",
        purpose=(
            "Assess whether process evidence could support limited educational "
            "context for Command and Scripting Interpreter."
        ),
        applicable_family=RuleEventFamily.PROCESS,
        applicable_platforms=(
            EventPlatform.WINDOWS,
            EventPlatform.LINUX,
            EventPlatform.MACOS,
        ),
        required_rule_id="BR-PROC-003",
        minimum_evidence=(
            _requirement(
                "command_line_declaration",
                MappingEvidenceType.RULE_FINDING,
                "BR-PROC-003",
                "A backend rule finding establishes only that command-line context is present.",
            ),
            _requirement(
                "verified_interpreter_semantics",
                MappingEvidenceType.SCHEMA_CAPABILITY,
                "verified_interpreter_semantics",
                "Structured telemetry identifies interpreter type and execution semantics.",
            ),
        ),
        optional_evidence=(
            _requirement(
                "strong_process_context",
                MappingEvidenceType.TEMPORAL_RELATIONSHIP,
                "same_process_instance",
                "A strong same-process relationship supplies bounded context.",
                required=False,
            ),
        ),
        contradictory_conditions=("Host or process identity conflicts.",),
        limitations=(
            "Command-line presence does not identify an interpreter or malicious intent.",
            "No command-line text matching or executable-name inference is permitted.",
            "This policy is authored by iCYLENS and is not an official MITRE rule.",
        ),
    ),
)
