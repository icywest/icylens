# ML Feature Contract

## Scope and version

Feature schema `1.0.0` is the first reproducible input contract for the future
supervised classifier. It adapts an already validated `StaticAnalysisResponse`;
it does not read an upload, parse bytes, infer a label, train a model, or make a
prediction. The adapter version is `static-analysis-adapter/1.0.0`.

The dataset record deliberately contains separate `identity`, `features`,
`label`, `provenance`, `extraction`, and `split` objects. Only the fields in the
following table are returned by `MLFeatureVector.ordered_predictive_values()`.

| Order | Feature | Type | Unit/domain | Meaning |
|---:|---|---|---|---|
| 1 | `file_size_bytes` | integer > 0 | bytes | Actual accepted byte-stream size |
| 2 | `shannon_entropy` | finite float 0..8 | bits/byte | Whole-stream Shannon entropy |
| 3 | `printable_string_count` | integer >= 0 | count | All qualifying ASCII runs observed |
| 4 | `retained_string_count` | integer >= 0 | count | Qualifying runs retained within bounds |
| 5 | `indicator_count` | integer >= 0 | count | Bounded indicators present in the report |
| 6 | `detected_format` | category | `pdf`, `png`, `jpeg`, `gif`, `zip`, `pe`, `elf`, `unknown` | Leading-signature result |
| 7 | `format_consistency` | category | `match`, `mismatch`, `unknown` | Extension/signature comparison |
| 8 | `has_url_candidate` | boolean | true/false | `network.url_candidate` observed |
| 9 | `has_ipv4_candidate` | boolean | true/false | `network.ipv4_candidate` observed |
| 10 | `has_powershell_reference` | boolean | true/false | `command.powershell_reference` observed |
| 11 | `has_encoded_command_token` | boolean | true/false | `command.encoded_command_token` observed |
| 12 | `has_script_reference` | boolean | true/false | `file.script_reference` observed |
| 13 | `strings_truncated` | boolean | true/false | A string preview or retention bound applied |
| 14 | `indicators_truncated` | boolean | true/false | The indicator result bound applied |

`feature_schema_version` is required metadata, not a predictive value. An
unmapped indicator still contributes to `indicator_count` but cannot silently
create a new boolean feature. Adding or redefining a predictive field requires
a new schema version and compatibility/migration decision.

## Missing values and bounded observations

Every schema `1.0.0` feature is mandatory because the current static report
always supplies it. A missing field is rejected; it is never changed to zero,
false, `unknown`, or another plausible value. `unknown` is a valid result only
when the upstream format contract explicitly reports it. Non-finite values,
coerced integer booleans, out-of-range entropy, non-positive sizes, unsupported
categories, unknown fields, and unsupported schema versions are rejected.

Counts remain the observed bounded-pipeline values. The two truncation fields
must be considered with them: `retained_string_count` is not the same as the
number observed, and a truncated indicator list is not evidence that no other
indicators exist. No downstream builder may silently impute bounded-away data.

## Non-feature fields

- SHA-256 and `record_id` are identity and deduplication fields.
- Label, label source, confidence, verification date, and the synthetic flag
  are ground-truth metadata.
- Dataset/source/license metadata is provenance.
- Extraction limits and adapter/schema versions are reproducibility metadata.
- Filename, analysis UUID, timestamps, dataset identifier, source, split, and
  label never enter the predictive vector.

This separation prevents obvious identity, lifecycle, label, and source
leakage. It does not prove the absence of semantic leakage; dataset review must
also examine how every feature and label was produced.

## Extraction contract

`app.ml.features.extract_ml_features(report, settings)` is deterministic and
has no FastAPI dependency. It consumes the existing typed report in memory, so
there is no second upload read or duplicate parsing. The caller must preserve
the extraction settings used for the report. The adapter verifies all string
limits exposed by the report and rejects disagreement. The current report does
not expose its indicator limit, so the orchestrating dataset builder must pass
and persist that setting; it must never guess it from the observed count.

Serialization uses Pydantic's strict, extra-forbidden contracts. Field order in
JSON is not the model-input contract; `PREDICTIVE_FEATURE_ORDER` is.

## Future model consumption

A later checkpoint may encode the two categorical fields, retain the explicit
ordered feature list, fit preprocessing only on the training split, and pass
the resulting matrix to Random Forest. The test split must stay untouched
during preprocessing choices, feature selection, model selection, and
hyperparameter tuning. Schema `1.0.0` does not claim that these observations
are sufficient, causal, unbiased, or predictive.

## Dataset artifact compatibility

The Phase 03.02 builder preserves this schema unchanged. It rejects unsupported
versions before splitting and serializes the version into both split
configuration and manifest. Canonical records retain the nested feature object;
the later trainer must verify artifact integrity and call the established
ordered-vector contract rather than relying on incidental JSON key order.

## Training transformation contract

Phase 03.03 converts the ordered 14 inputs into 23 float columns. The first five
numeric features remain individual columns; the two categorical features become
11 explicit one-hot columns across all supported contract categories; and the
seven booleans become stable 0/1 columns. This width is checked after fitting.

Logistic Regression standardizes only numeric columns. Random Forest and
HistGradientBoosting preserve numeric scale. Encoding, scaling, and estimator
are one fitted Pipeline so future inference cannot accidentally use different
preprocessing. Identity, labels, provenance, splits, timestamps, and dataset
metadata remain excluded.
