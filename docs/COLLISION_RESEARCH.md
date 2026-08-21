# Collision Research

Date: 2026-08-21

## Checked Keywords

- `permscope`
- `Permissions-Policy MoonBit`
- `permissions-policy MoonBit`
- `Feature-Policy MoonBit`
- `Content-Security-Policy MoonBit`
- `CSP MoonBit security headers`
- `HTTP security headers MoonBit`
- `Strict-Transport-Security MoonBit`
- `Referrer-Policy MoonBit`
- `COOP COEP CORP MoonBit`
- `site:mooncakes.io Permissions-Policy MoonBit`
- `site:mooncakes.io security headers MoonBit`
- `site:github.com Permissions-Policy MoonBit`

## Result

No public MoonBit package with the same name `permscope` was found in the
checked public search results.

One related MoonBit package named `moonsec-headers` was found with a broader
HTTP security response-header audit scope, including CSP and common security
header scoring. This is adjacent to the supporting context checks in
`permscope`, so the project materials and implementation were updated to make
the independent scope explicit.

Related but different directions:

- Mooncakes publish/preflight checkers.
- README example provenance or source-proof checkers.
- Robots.txt or crawler-policy packages.
- Generic contest review proof or correction evidence tools.
- Broad HTTP security-header scoring packages.

## Differentiation

`permscope` is scoped around browser capability exposure through the HTTP
`Permissions-Policy` header. Its current unique value is combining:

- deep `Permissions-Policy` parsing and rendering;
- legacy `Feature-Policy` migration;
- `self`, wildcard, empty deny-list, and explicit-origin decisions;
- a browser capability catalog with risk tiers and profile generation;
- feature/origin access matrices for review;
- policy diffs that classify loosened and tightened capability changes;
- route-level capability contracts that detect missing, overbroad, or
  undeclared origin delegations;
- stable MoonBit CI output and runnable examples.

The CSP, HSTS, referrer, clickjacking, MIME sniffing, and cross-origin isolation
checks are supporting response-header context. They do not change the project
boundary into a general-purpose web security scanner.
