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
- Policy summary counts.
- Feature-level policy diff rendering.
- Internal feature and origin normalization helpers.
