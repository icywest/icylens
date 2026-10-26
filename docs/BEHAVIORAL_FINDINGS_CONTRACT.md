# Behavioral findings contract

`RuleEvaluationResult` contains the existing `EventValidationResult`, one
`RuleFinding` per evaluated rule, an aggregate summary, scientific limitations,
and explicit false flags for ATT&CK mapping, malware classification, and
persistence.

Each finding preserves:

- stable rule ID, version, name, and event family;
- `matched`, `not_matched`, `insufficient_evidence`, or `not_applicable`;
- bounded associated event UUIDs;
- satisfied condition descriptions only for a match;
- source identifiers and synthetic/declared nature;
- bounded evidence fields extracted from the exact events;
- rule limitations and the non-detection interpretation.

Evidence contains identifiers and fields needed to explain the condition. It
never invents an absent event. Process command-line evidence contains only a
presence boolean and length; command-line content is never copied. File paths
and configuration targets are marked sensitive and truncated at 256 characters.
At most eight unique event records support one finding; truncation is stated in
the finding limitations.

The summary counts every state separately. Unknown is never converted to false:
when required process-parent or command-line evidence is missing, applicable
rules return `insufficient_evidence`. A rule for an absent event family returns
`not_applicable`, while a complete applicable condition that fails returns
`not_matched`.

`POST /api/v1/behavior/rules/evaluate` accepts only an `EventBatch` plus an
optional tuple of registered rule IDs. Omission evaluates every enabled built-in
rule. Duplicate, malformed, or unknown IDs are rejected. No caller-controlled
condition, expression, severity, interpretation, or executable content exists
in the contract.

