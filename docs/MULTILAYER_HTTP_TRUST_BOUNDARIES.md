# Multilayer HTTP Trust Boundaries

## Structural validity is not accreditation

Pydantic validation proves only that a request has the expected structure. A
canonical hash proves only consistency with canonical content. Neither proves
who produced a statement, whether it is factually true or whether an external
activity occurred.

For that reason, 06.06 never accepts an internal `EvidenceBatch` or any
precomputed Phase 06 result from HTTP. Extra fields such as `trusted`,
`origin_verified`, `confirmed`, `is_malware`, `risk_score`, `execute`, graphs,
assessments, traces and dynamic rules are rejected.

## Admission policy

The admitted values are deliberately narrow identifiers and numeric
declarations. The server creates the evidence contracts and assigns:

- origin: `client_declared`;
- trust: `client_declared`;
- origin verification: false;
- integrity verification: `origin_unverified`;
- synthetic: false;
- no operational detection or threat verdict.

A declared SHA-256 is not described as a backend-computed digest. A canonical
CVE does not imply provider confirmation. A declared ML prediction is not
described as server inference. The currently enabled modes cannot submit
behavioral telemetry, synthetic scenarios or explicit evidence-reference
graphs. Unsupported registered assertions therefore remain insufficient or
not applicable where required evidence is unavailable.

## Cross-stage consistency

The service creates all prerequisite results in one worker from one normalized
batch. Exact batch IDs bind identity, correlation, sufficiency and traces.
The response additionally verifies that:

- every relationship and assessment references published evidence;
- every trace evidence reference is published;
- every identity/correlation object used by a trace was produced internally;
- every published assessment has exactly one trace;
- policy/rule versions remain the fixed Phase 06 versions;
- summaries and the canonical analysis ID match the underlying results.

No intermediate object is accepted from the consumer or cached between
requests.

## Concurrency and cancellation

The Phase 06 chain is synchronous CPU work and runs outside the event loop in
the existing lifecycle-owned `SynchronousWorkerManager`. Admission is
immediate and queue-free. The manager retains ownership and occupancy until
the real `Future` completes, including after HTTP cancellation or timeout.
Python threads are not claimed to be forcibly stoppable.

Repeated shutdown calls share one shielded close task. Shutdown fences new
admission, waits for late completion, observes worker exceptions and closes the
executor only after all active work drains. This preserves P05-CONC-003 and
does not change residual risk P05-CONC-008.

## Privacy and error boundary

Source IDs use a restricted non-path alphabet. Requests cannot include free
text, paths, commands, users, hosts, IP addresses, telemetry or raw model
inputs. Responses contain minimized IDs, categorical states and static
limitations only.

The router uses a local validation route that converts FastAPI validation
details into a constant 422 message, preventing forbidden extra values from
being reflected. Runtime logs contain exception types or fixed events, never
exception text. 429, 500, 503 and 504 responses are also constant.

Deterministic IDs remain correlatable and are not anonymous.

## Resource and scientific limits

- request body: 256 KiB, enforced while receiving and via `Content-Length`;
- sources: 16;
- assertions/traces: 32;
- internal evidence/identity/correlation/sufficiency limits remain active;
- response: 1 MiB;
- active workers: four shared queue-free slots;
- operation timeout: four seconds, without premature capacity release.

The API confirms no malware, exploitation, host compromise, ATT&CK execution,
file execution, attribution, causal sequence or operational threat score. A
`sufficient` state is meaningful only for its exact registered assertion.
There is no persistence, filesystem write, external lookup, subprocess,
background job, queue, alert or automated response.
