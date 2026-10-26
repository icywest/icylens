from __future__ import annotations

from app.schemas.behavior_rules import (
    BehavioralRule,
    RuleCondition,
    RuleConditionOperator,
    RuleEventFamily,
)

_FACT_LIMITATION = (
    "The rule reports a declared condition, not malicious intent or compromise.",
    "No MITRE ATT&CK technique mapping is performed.",
)


def _condition(
    field: str,
    operator: RuleConditionOperator,
    description: str,
    expected: str | int | bool | None = None,
) -> RuleCondition:
    return RuleCondition(
        field=field, operator=operator, expected=expected, description=description
    )


BUILTIN_RULES: tuple[BehavioralRule, ...] = (
    BehavioralRule(
        rule_id="BR-PROC-001",
        version="1.0.0",
        name="Process start without declared parent context",
        description="Reports a process start whose optional parent identity is absent.",
        family=RuleEventFamily.PROCESS,
        conditions=(
            _condition(
                "action",
                RuleConditionOperator.EQUALS,
                "Action is process start.",
                "start",
            ),
            _condition(
                "parent_process",
                RuleConditionOperator.ABSENT,
                "Parent process context is absent.",
            ),
        ),
        required_evidence_fields=(
            "action",
            "process.process_instance_id",
            "parent_process",
        ),
        limitations=_FACT_LIMITATION
        + (
            "Parent context may be unavailable at the source; absence is not suspiciousness.",
        ),
    ),
    BehavioralRule(
        rule_id="BR-PROC-002",
        version="1.0.0",
        name="Inconsistent declared parent reference",
        description="Reports a parent identity that does not predate the declared child identity.",
        family=RuleEventFamily.PROCESS,
        conditions=(
            _condition(
                "parent_process",
                RuleConditionOperator.PRESENT,
                "A parent identity is declared.",
            ),
            _condition(
                "parent_process.started_at",
                RuleConditionOperator.PRECEDES,
                "Parent start must precede child start.",
            ),
        ),
        required_evidence_fields=("process.started_at", "parent_process.started_at"),
        limitations=_FACT_LIMITATION
        + ("Clock and source identity errors can produce this condition.",),
    ),
    BehavioralRule(
        rule_id="BR-PROC-003",
        version="1.0.0",
        name="Declared command line present on process start",
        description="Reports the educational fact that a start record contains command-line context.",
        family=RuleEventFamily.PROCESS,
        conditions=(
            _condition(
                "action",
                RuleConditionOperator.EQUALS,
                "Action is process start.",
                "start",
            ),
            _condition(
                "command_line",
                RuleConditionOperator.PRESENT,
                "Command-line context is present.",
            ),
        ),
        required_evidence_fields=(
            "action",
            "command_line_present",
            "command_line_length",
        ),
        limitations=_FACT_LIMITATION
        + ("Command-line content is not returned as evidence.",),
    ),
    BehavioralRule(
        rule_id="BR-FILE-001",
        version="1.0.0",
        name="File modification after declared creation",
        description="Reports a same-host path modification preceded by creation in this batch.",
        family=RuleEventFamily.FILE,
        conditions=(
            _condition(
                "action",
                RuleConditionOperator.EQUALS,
                "A file modification is declared.",
                "modify",
            ),
            _condition(
                "file_path",
                RuleConditionOperator.PRECEDES,
                "Same-host path creation appears earlier.",
            ),
        ),
        required_evidence_fields=("action", "host_id", "file_path"),
        limitations=_FACT_LIMITATION
        + ("Only ordering inside the submitted batch is considered.",),
    ),
    BehavioralRule(
        rule_id="BR-FILE-002",
        version="1.0.0",
        name="Rename with limited attribution metadata",
        description="Reports a rename lacking a process identity or declared hash metadata.",
        family=RuleEventFamily.FILE,
        conditions=(
            _condition(
                "action",
                RuleConditionOperator.EQUALS,
                "Action is file rename.",
                "rename",
            ),
            _condition(
                "process_or_hashes",
                RuleConditionOperator.ABSENT,
                "Process identity or hash metadata is absent.",
            ),
        ),
        required_evidence_fields=(
            "action",
            "destination_path",
            "process_present",
            "hashes_present",
        ),
        limitations=_FACT_LIMITATION
        + ("Optional metadata absence can be normal for many telemetry sources.",),
    ),
    BehavioralRule(
        rule_id="BR-FILE-003",
        version="1.0.0",
        name="File operation without process identity",
        description="Reports a file record with no associated process instance.",
        family=RuleEventFamily.FILE,
        conditions=(
            _condition(
                "process", RuleConditionOperator.ABSENT, "Process identity is absent."
            ),
        ),
        required_evidence_fields=("action", "file_path", "process_present"),
        limitations=_FACT_LIMITATION
        + ("The source may not collect process attribution.",),
    ),
    BehavioralRule(
        rule_id="BR-NET-001",
        version="1.0.0",
        name="Connection attempt without later known state",
        description="Reports an attempted connection with no later established or closed state in this batch.",
        family=RuleEventFamily.NETWORK,
        conditions=(
            _condition(
                "action",
                RuleConditionOperator.EQUALS,
                "A connection attempt is declared.",
                "attempted",
            ),
            _condition(
                "connection_state",
                RuleConditionOperator.NO_LATER_STATE,
                "No later state exists for the same connection identity.",
            ),
        ),
        required_evidence_fields=(
            "action",
            "local_endpoint",
            "remote_endpoint",
            "protocol",
        ),
        limitations=_FACT_LIMITATION
        + ("The later state may exist outside the submitted batch.",),
    ),
    BehavioralRule(
        rule_id="BR-NET-002",
        version="1.0.0",
        name="Established connection without process identity",
        description="Reports an established-state record lacking process attribution.",
        family=RuleEventFamily.NETWORK,
        conditions=(
            _condition(
                "action",
                RuleConditionOperator.EQUALS,
                "Connection state is established.",
                "established",
            ),
            _condition(
                "process", RuleConditionOperator.ABSENT, "Process identity is absent."
            ),
        ),
        required_evidence_fields=("action", "remote_endpoint", "process_present"),
        limitations=_FACT_LIMITATION
        + ("Process attribution may be unavailable from network-only sources.",),
    ),
    BehavioralRule(
        rule_id="BR-NET-003",
        version="1.0.0",
        name="Declared TCP destination port 443",
        description="Reports the explicit educational condition TCP with remote port 443.",
        family=RuleEventFamily.NETWORK,
        conditions=(
            _condition(
                "protocol", RuleConditionOperator.EQUALS, "Protocol is TCP.", "tcp"
            ),
            _condition(
                "remote_port", RuleConditionOperator.EQUALS, "Remote port is 443.", 443
            ),
        ),
        required_evidence_fields=("protocol", "remote_port"),
        limitations=_FACT_LIMITATION
        + ("TCP/443 is common administrative and application traffic.",),
    ),
    BehavioralRule(
        rule_id="BR-CONF-001",
        version="1.0.0",
        name="Reported configuration change",
        description="Reports the fact that a structured configuration change was declared.",
        family=RuleEventFamily.CONFIGURATION,
        conditions=(
            _condition(
                "action",
                RuleConditionOperator.EQUALS,
                "A reported change is declared.",
                "reported_change",
            ),
        ),
        required_evidence_fields=("action", "configuration_kind", "target"),
        limitations=_FACT_LIMITATION
        + ("Administrative configuration changes can be routine.",),
    ),
    BehavioralRule(
        rule_id="BR-CONF-002",
        version="1.0.0",
        name="Declared scheduled task creation",
        description="Reports a scheduled-task record with no previous value and a current value.",
        family=RuleEventFamily.CONFIGURATION,
        conditions=(
            _condition(
                "configuration_kind",
                RuleConditionOperator.EQUALS,
                "Kind is scheduled task.",
                "scheduled_task",
            ),
            _condition(
                "previous_value",
                RuleConditionOperator.ABSENT,
                "Previous value is absent.",
            ),
            _condition(
                "current_value",
                RuleConditionOperator.PRESENT,
                "Current value is present.",
            ),
        ),
        required_evidence_fields=(
            "configuration_kind",
            "previous_value_present",
            "current_value_present",
        ),
        limitations=_FACT_LIMITATION
        + ("This describes declared creation semantics only.",),
    ),
    BehavioralRule(
        rule_id="BR-CONF-003",
        version="1.0.0",
        name="Declared service modification",
        description="Reports a service change with previous and current declared values.",
        family=RuleEventFamily.CONFIGURATION,
        conditions=(
            _condition(
                "configuration_kind",
                RuleConditionOperator.EQUALS,
                "Kind is service.",
                "service",
            ),
            _condition(
                "previous_value",
                RuleConditionOperator.PRESENT,
                "Previous value is present.",
            ),
            _condition(
                "current_value",
                RuleConditionOperator.PRESENT,
                "Current value is present.",
            ),
        ),
        required_evidence_fields=(
            "configuration_kind",
            "previous_value_present",
            "current_value_present",
        ),
        limitations=_FACT_LIMITATION
        + ("A service modification is not inherently malicious.",),
    ),
)
