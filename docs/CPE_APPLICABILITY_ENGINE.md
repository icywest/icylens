# CPE Applicability Engine

The engine evaluates preserved NVD CPE configuration trees against an explicit,
caller-supplied inventory. It performs no discovery, scanning, package lookup,
exploit execution, or persistence.

## Inventory contract

`AssetInventory` 1.0.0 contains an identifier, provenance, completeness, and up
to 256 `AssetProduct` entries. Each product supplies a bounded CPE 2.3 formatted
name, optional exact version, version scheme (`numeric`, `semver`, or `unknown`),
and evidence type (`declared` or `observed_by_tool`). Observed evidence is still
not proof of vulnerability. Extra fields such as `confirmed_vulnerable` are
rejected.

`complete` means the caller asserts that absence is evidence for this evaluation
scope. With `incomplete`, an absent product yields `UNKNOWN`, not `FALSE`.

## Matching and versions

Part, vendor, product, version, update, edition, language, software edition,
target software, target hardware, and other are compared structurally and
case-insensitively. No substring matching or vendor aliases are used. A literal
mismatch is `FALSE`; missing identity is `UNKNOWN`; unsupported syntax is
`UNKNOWN` with an unsupported marker.

Exact literal versions require equality. Range bounds support:

- dotted non-negative numeric versions, including zero-padding equivalence;
- SemVer only when the inventory declares `semver`, including prerelease order;
- safe numeric inference only when the asset version and every bound are dotted
  numeric strings.

Vendor/date/custom schemes are not ordered. All four NVD bounds are enforced at
their exact inclusive or exclusive edge. Missing or non-comparable versions
never produce `TRUE`.

## Three-valued evaluation

The engine implements explicit Kleene-style truth operations. `AND` returns
false when any child is false, otherwise unknown when any child is unknown.
`OR` returns true when any child is true, otherwise unknown when any child is
unknown. `NOT UNKNOWN` remains unknown. Python truthiness is not used.

Nodes retain AND, OR, negation, matches, and children. Multiple NVD
configurations are alternative applicability statements and are represented by
an explicit `configuration_set` OR node. An operatorless configuration with one
child passes that child through; zero or multiple children are unsupported
rather than assigned an invented operator.

`vulnerable=false` identifies a required platform condition. The condition is
still evaluated, but evidence labels it `required_platform` and never reports it
as the vulnerable product.

## Outcomes and trace

- `potentially_applicable`: the declared evidence satisfies the expression.
- `not_applicable`: sufficient evidence makes the complete expression false.
- `insufficient_evidence`: required identity, version, platform, or completeness
  is missing.
- `unsupported_criteria`: required syntax/semantics or a resource limit cannot
  be evaluated safely.

Unsupported conditions take precedence over a positive status even when
another OR branch is true. The response retains matched, excluded, unknown, and
unsupported conditions; original CPE, match ID, bounds, vulnerable role,
logical path, minimally necessary product IDs, and the recursive evaluation
tree. It never returns `confirmed_vulnerable`, `safe`, `clean`, `exploited`, or
`compromised`.

## Resource and security controls

- raw applicability request body: 262,144 bytes by default, enforced while
  streaming and before JSON decoding;
- products: 256; CPE text: 4,096 characters; bounded identifiers/versions;
- logical depth: 16; nodes: 512; conditions: 2,048;
- synchronous evaluation deadline: 250 ms, checked during traversal;
- frozen strict Pydantic contracts and sanitized public errors;
- no dynamic expression evaluation, shell execution, or inventory logging.

The public POST endpoint is currently unauthenticated like the rest of the
development API. Deployment must add authentication, authorization, request
rate controls, and trusted inventory provenance at the platform boundary.

## Example

```json
{
  "schema_version": "1.0.0",
  "inventory_id": "declared-2026-10-25",
  "products": [{
    "product_id": "web-1",
    "cpe23_name": "cpe:2.3:a:example:server:1.5:*:*:*:*:*:*:*",
    "version": "1.5",
    "version_scheme": "numeric",
    "evidence_type": "declared"
  }],
  "provenance": {"source": "operator", "collected_at": null},
  "completeness": "incomplete"
}
```
