# Test Record

Date: 2026-08-19

Local checks:

```bash
moon fmt --check
moon check --deny-warn
moon build
moon test --deny-warn
moon info
moon run cmd/main
```

Coverage focus:

- Modern `Permissions-Policy` parsing.
- Legacy `Feature-Policy` migration.
- Duplicate and malformed directive warnings.
- `self`, `*`, empty list, and explicit origin allowlist behavior.
- Default sensitive-feature audit baseline.
- High-severity wildcard risk detection.
- Declarative policy builder output.
- Built-in feature catalog lookup.
- Recommended header audit behavior.
- Built-in deployment profile generation.
- Raw HTTP response header-block parsing and precedence.
- Legacy header fallback migration from header blocks.
- Feature/origin access matrix rendering.
- Content-Security-Policy parsing, fallback, nonce/hash handling, and risk
  detection.
- HSTS, Referrer-Policy, X-Frame-Options, X-Content-Type-Options, COOP, COEP,
  and CORP scoring.
- Security header bundles for strict, static-site, API-service, media-app, and
  device-lab scenarios.
- Security score, finding summary, recommendations, Markdown/JSON-style output,
  and CI gate rendering.
- Batch audit of multiple response samples, batch recommendations, and batch
  gate rendering.
- Policy summary counts.
- Feature-level policy diff rendering.
- Internal feature and origin normalization helpers.
