# Behavioral Synthetic Demonstration

The 05.06 demonstration is an offline teaching flow built only on the 05.02
deterministic generator. It executes no described action, contacts no host,
uses no external provider, writes no telemetry, and fabricates no extra evidence
to obtain a positive ATT&CK result.

## Request

Send one scenario specification to
`POST /api/v1/behavior/scenarios/analyze`:

```json
{
  "scenario": {
    "scenario_id": "demo-process-lifecycle",
    "scenario_kind": "normal_process_lifecycle",
    "seed": 42,
    "platform": "linux",
    "start_time": "2026-10-26T16:00:00Z",
    "event_count": 2
  },
  "options": {
    "rule_ids": ["BR-PROC-003"],
    "mapping_policy_ids": ["AMP-PROC-001"],
    "correlation_policy": {}
  }
}
```

The scenario kind values are published by the existing 05.02 OpenAPI schema.
Supported educational demonstrations include benign process lifecycle, file
activity, network lifecycle, configuration change, incomplete evidence,
contradictory evidence, and out-of-order events. No scenario catalog extension
was required for 05.06.

## Suggested walkthrough

1. Generate the benign process lifecycle twice with the same specification.
   Compare the analysis ID, stage records, ordered relationships, rule states,
   and mapping evaluations; they are identical.
2. Run file activity and inspect weak declared-file relationships. Weak means
   shared declared context, not causality.
3. Run network lifecycle and inspect attempt/established/closed ordering where
   the selected generator supports it. Declared endpoints are not echoed in the
   unified result.
4. Run configuration change and distinguish a reported administrative fact
   from persistence or maliciousness.
5. Run incomplete evidence and inspect `insufficient_evidence` plus the
   explanation's unknowns.
6. Run contradictory evidence. Blocking validation issues produce `partial`;
   every downstream stage is visibly skipped.
7. Run out-of-order events. Canonical UTC ordering is deterministic, but the
   service does not invent missing events or causal links.

The current mapping policies can legitimately return zero candidates in every
demo. This is the intended evidence lesson: a matching declared condition or a
nearby event is not enough to claim an ATT&CK technique, malware, or an attack.

## Reading the response

Start with `status` and `stages`, then review `validation`, `rule_findings`,
`temporal_relationships`, `attack_mapping_evaluations`, and `explanation` in
that order. The event summary establishes scope; UUIDs tie minimized evidence
back to the caller's own input. `limitations` and all false verdict flags are
part of the interpretation, not boilerplate to hide in a UI.

For declared data, replace `scenario` with a canonical `batch` and submit it to
`POST /api/v1/behavior/analyze`. The same result contract and scientific
boundaries apply.
