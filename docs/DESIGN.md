# Design Notes

## Goal

`permscope` focuses on one reusable job: parse and audit
`Permissions-Policy` response headers without pulling in an HTTP server,
browser runtime, or framework adapter.

## Data Model

- `Policy` stores parsed directives and non-fatal warnings.
- `Directive` stores the normalized feature name, allowlist tokens, original
  segment, and segment index.
- `AllowToken` represents `self`, `*`, and explicit origins.
- `Baseline` describes project-specific security expectations.
- `AuditReport` stores findings that can be rendered in CI logs.

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

## Non-Goals

- No network scanning.
- No web server middleware in the initial version.
- No bundled browser feature database.
- No third-party code or generated fixture corpus.
