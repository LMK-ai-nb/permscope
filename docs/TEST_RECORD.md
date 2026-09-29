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
- Capability contract generation and auditing for missing, wildcard, optional,
  and undeclared origin delegation cases.
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

## September Local Review (2026-09-30)

Source reviewed: GitHub `main` at `f553b93342d12b4e3123532b97828c16bde8edda`,
plus the local `0.1.2` candidate. The old local Git directory had been removed;
this review used a public source archive, so these results are **local only**.

Executed against the candidate:

```text
moon version --all             passed (moonc v0.10.10)
moon fmt --check                passed
moon check --deny-warn          passed
moon build                      passed
moon test --deny-warn           66 passed, 0 failed
moon info                       passed
moon run cmd/main               passed
moon run examples/route_contract passed; printed contract: pass
moon package --list             passed; inspected 0.1.2 package file list
moon publish --frozen --dry-run package check passed, upload preflight failed:
                               HTTP 403 User mismatch (wrong CLI account)
```

New regression cases cover a strict contract's undeclared low-risk capability,
a declared capability with no directive, a valid observed response, a missing
modern header, a mismatched document origin, a malformed policy, valid and
incomplete route inventories, duplicate names, and an empty inventory. No
GitHub Actions run or Mooncakes publication for `0.1.2` has been verified yet.
The failed dry-run did not publish the package.

## Redirect-Chain Regression (2026-09-30)

After selecting the final response block for `curl -I -L` input, these local
commands passed on the same uncommitted `0.1.2` candidate:

```text
moon fmt --check                 passed
moon check --deny-warn           passed
moon build                       passed
moon test --deny-warn            72 passed, 0 failed
moon test --target wasm --deny-warn 72 passed, 0 failed
moon test --target js --deny-warn 72 passed, 0 failed
moon info                        passed
moon run cmd/main                passed
moon run examples/route_contract passed; printed contract: pass and inventory: pass
moon package --list              passed; inspected the package file list
```

The added regressions cover CRLF redirects, a `100 Continue` response, an
earlier malformed block, a headerless final response, folded text resembling a
status line, missing final policy in a route contract, and a final-only security
header score. These are synthetic fixtures, not claims of a live site audit.
GitHub Actions and publication for `0.1.2` remain unverified.
`moon test --target native --deny-warn` was attempted but could not build a
test plan because this Windows machine has no C compiler (`cl`, `cc`, `gcc`, or
`clang`); it is not recorded as a passing backend. The CI workflow now includes
the verified JavaScript backend test, but that CI step has not run remotely yet.
