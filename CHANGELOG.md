# Changelog

## 0.1.2 (unreleased)

- Align source formatting with the September MoonBit toolchain and keep strict
  CI checks while isolating the derived-method migration warning.
- Count an explicitly enabled undeclared wildcard capability once in strict
  contract findings, without also reporting it as a missing directive.
- Audit only the final HTTP response block in redirect and interim-response
  chains, preventing earlier hops from supplying a missing final security
  policy. Add regression coverage and a redirect-aware route example.
- Reject undeclared low-risk capability exposure in strict contracts and
  missing explicit restrictions for declared features, plus malformed policies.
- Add observed-response capability audit with missing-header, malformed-policy,
  and origin-mismatch checks.
- Add a named route inventory audit that rejects missing, undeclared, duplicate,
  or failing response samples.
- Add a runnable route contract example and regression tests.
- Add September community-maintenance application and release/provenance notes.

## 0.1.1

- Add route-level capability contracts for `Permissions-Policy` boundary checks.
- Add minimal policy generation from declared browser capability needs.
- Add contract audit findings for missing, overbroad, optional, and undeclared
  origin delegation cases.
- Clarify project differentiation from generic security-header scanners,
  mooncakes publishing checkers, README provenance tools, robots.txt tools, and
  contest review proof tools.

## 0.1.0

- Start the `permscope` MoonBit project.
- Define the package metadata for `LMK-ai-nb/permscope`.
- Add modern `Permissions-Policy` parsing and rendering.
- Add legacy `Feature-Policy` migration.
- Add allowlist evaluation and baseline audit reports.
- Add declarative policy builder and feature-level diff reports.
- Add browser capability catalog, recommended header generation, and summaries.
- Add deployment profiles for strict, balanced, media-app, and device-lab use.
- Add raw HTTP response header-block parsing and end-to-end header auditing.
- Add feature/origin access matrix rendering for reviews and CI logs.
- Add route-level capability contracts and minimal policy generation for
  `Permissions-Policy` boundary checks.
- Add CSP parsing, source-expression analysis, and CSP audit reports.
- Add HSTS, Referrer-Policy, X-Frame-Options, X-Content-Type-Options, COOP,
  COEP, and CORP checks.
- Add response-level security scoring, finding summaries, recommendations,
  Markdown/JSON-style reports, and CI gates.
- Add reusable security header bundles and batch audits across multiple response
  samples.
- Add tests, runnable demo, CI, README, design notes, and project application.
