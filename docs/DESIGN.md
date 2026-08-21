# Design Notes

## Goal

`permscope` focuses on one reusable job: parse and audit HTTP security response
headers without pulling in an HTTP server, browser runtime, or framework
adapter. `Permissions-Policy` remains the deepest parser, while CSP and other
headers provide a broader response-level security score.

## Data Model

- `Policy` stores parsed directives and non-fatal warnings.
- `Directive` stores the normalized feature name, allowlist tokens, original
  segment, and segment index.
- `AllowToken` represents `self`, `*`, and explicit origins.
- `Baseline` describes project-specific security expectations.
- `AuditReport` stores findings that can be rendered in CI logs.
- `PolicyIntent` lets users generate strict headers from declarative feature
  rules.
- `PolicyDiff` records feature-level changes between two parsed policies.
- `FeatureSpec` stores the built-in browser capability catalog.
- `PolicySummary` keeps count-style output for dashboards and release notes.
- `BaselineProfile` represents built-in policy presets for common deployments.
- `HeaderSet` and `HeaderAudit` let callers audit copied HTTP response header
  blocks without adding a network client.
- `AccessMatrix` records feature/origin decisions for documentation and review
  workflows.
- `CspPolicy`, `CspDirective`, `CspSummary`, and `SourceExpression` represent a
  practical CSP subset.
- `HeaderCheck`, `SecurityScore`, and `SecurityAudit` aggregate CSP,
  Permissions-Policy, HSTS, referrer, clickjacking, MIME sniffing, and
  cross-origin isolation checks.
- `SecurityHeaderBundle` stores reusable deployment presets for strict,
  static-site, API-service, media-app, and device-lab scenarios.
- `ResponseSample` and `BatchAudit` support multi-route or multi-environment
  security reviews.

## Parsing Strategy

The modern parser splits a header by comma, expects `feature=(allowlist)` pairs,
normalizes feature names to lowercase, and keeps malformed segments as warnings
instead of failing the whole parse. The legacy parser accepts semicolon-separated
`Feature-Policy` syntax so users can migrate older headers.

## Audit Strategy

The default baseline treats camera, microphone, geolocation, payment, USB,
serial, HID, and Bluetooth as features that should be explicitly denied unless a
project opts into a different baseline. Wildcard access to sensitive features is
reported as high severity. Plain HTTP origins are reported as warnings except
for localhost development origins.

## Build and Diff Strategy

The builder deliberately exposes a small intent vocabulary: deny, self-only,
all-origins, and self-plus-origins. This keeps generated headers stable and easy
to review. The diff function compares normalized directive text and classifies
changes as added, removed, changed, loosened, or tightened based on allowlist
power.

## Header-Block Strategy

The header-block parser accepts line-oriented response header text, ignores HTTP
status lines, classifies modern and legacy policy headers, and preserves
non-fatal parse issues as warnings. Modern `Permissions-Policy` takes precedence
when both modern and legacy headers are present; legacy `Feature-Policy` is used
only as a migration fallback.

## CSP Strategy

The CSP parser focuses on source directives commonly needed in CI checks:
`default-src`, `script-src`, `style-src`, `img-src`, `connect-src`,
`object-src`, `base-uri`, `frame-ancestors`, and `form-action`. It recognizes
wildcards, `unsafe-inline`, `unsafe-eval`, HTTP sources, nonce/hash sources, and
fallback to `default-src`. The goal is not to implement a browser, but to catch
high-value production risks.

## Security-Header Strategy

The response-level auditor turns each header family into a `HeaderCheck` with
points, maximum points, findings, observed value, and recommended value. The
final `SecurityScore` is deterministic and easy to place in CI logs: it records
points, percentage, grade, and severity counts.

## Bundle and Batch Strategy

Bundles generate concrete response header blocks for common deployment profiles.
Batch audits let callers check multiple routes or environments, compare sample
scores, collect recommendations, and enforce a CI gate across all samples.

## Profile Strategy

Profiles are generated from the same feature catalog as the recommended header.
`strict` disables every known feature, `balanced` follows the catalog defaults,
`media-app` keeps same-origin media capabilities available, and `device-lab`
allows selected hardware features only for self and caller-provided trusted
origins.

## Matrix Strategy

The access matrix runs the same `allows` decision across selected features and
origins. It is intentionally textual so a caller can paste the result into CI
logs, release notes, or review comments without needing a UI dependency.

## Catalog Strategy

The built-in feature catalog is intentionally small but useful. It covers
commonly delegated browser capabilities and marks high-risk device, media,
sensor, identity, and payment features. The catalog powers recommended headers,
catalog-derived baselines, and summary reports.

## Non-Goals

- No network scanning.
- No web server middleware in the initial version.
- No third-party code or generated fixture corpus.
