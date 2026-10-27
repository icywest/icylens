# Uncertainty and Contradictions

Checkpoint 06.04 keeps sufficiency, consistency and uncertainty distinct.
Uncertainty is categorical context about limitations; it is not a numerical
confidence estimate. A reason may remain visible without invalidating the
narrow assertion being evaluated.

## Uncertainty taxonomy

| Reason | Typical meaning | Necessarily blocks sufficiency? |
| --- | --- | --- |
| `missing_identity` | Exact required identity is unavailable | Yes for identity-based assertions |
| `unverified_provenance` | Origin is declared/reported rather than authenticated | No; preserved as a limitation |
| `synthetic_origin` | Educational synthetic evidence | No for equality inside that scenario |
| `declared_context` | Client-declared context remains unverified | No; never promoted |
| `missing_model_version` | No independent model version exists | Only for a policy requiring model identity, which 06.04 does not provide |
| `missing_temporal_context` | A semantic timestamp is absent | No; absence is not non-occurrence |
| `weak_contextual_association` | Only compatible context exists | Yes when exact identity/relationship is required |
| `unsupported_cross_module_relation` | 06.03 has no approved relation | Yes for the requested relationship |
| `conflicting_claims` | Relevant retained claims disagree | Yes |
| `incomplete_source_metadata` | Source completeness is partial | Not automatically |

Every reason includes an assertion ID, bounded evidence IDs, a safe explanation
and `affects_sufficiency`. `numeric_confidence` is contractually always null.

## Contradiction scope

Conflicts are relevant only when they intersect the selected evidence and
affect the identity type or explicit reference required by the active policy.
The result records affected evidence IDs, identity namespace when available,
assertion, requirement, category and originating 06.02/06.03 conflict ID.

A conflicting file-content claim can block `AS-CONTENT-001`. It does not block
an independent `AS-VULN-001` evaluation over different evidence. Duplicate
explicit references block `AS-REF-001` for their selected records. Missing or
unsupported namespaces remain gaps rather than being mislabeled as positive
contradictions.

No conflict is resolved by choosing a preferred source. No conflict is applied
globally merely because it exists in the same batch.

## Temporal limits

Event, observation, receipt, generation, analysis, intelligence publication,
modification and retrieval timestamps keep their original meanings. 06.04
does not compare incompatible clocks, infer order from proximity or interpret
missing time as proof of inactivity.

## Negative assertion matrix

There is no registered positive policy for malware detection, attack
confirmation, host compromise, CVE exploitation, ATT&CK execution, file
execution, persistence, command and control, operational ML validation or same
physical device without a verified identifier. Requests for these properties
return `unsupported_assertion`, not `insufficient_evidence`, `false` or a
fabricated positive association.

Process/host identity, product installation, execution, independent model
version, individual ATT&CK technique references and exploitation events are not
reconstructed from text or fetched from earlier engines. P05-CONC-008 remains
an inherited educational-local lifecycle condition and is unchanged.
