# Collision Research

Date: 2026-08-19

## Checked Keywords

- `permscope`
- `Permissions-Policy MoonBit`
- `permissions-policy MoonBit`
- `Feature-Policy MoonBit`
- `site:mooncakes.io Permissions-Policy MoonBit`
- `site:github.com Permissions-Policy MoonBit`

## Result

No public MoonBit package with the same name or the same standalone
`Permissions-Policy` parser/auditor scope was found in the checked public search
results.

Related but different findings:

- Some public results mention application runtime permissions, PDF permissions,
  or manifest permissions, but they are unrelated to browser
  `Permissions-Policy` response headers.

## Differentiation

`permscope` is narrowly scoped around browser capability exposure through the
HTTP `Permissions-Policy` header. Its current unique value is combining parsing,
legacy migration, allowlist evaluation, baseline-driven audit findings, and
stable MoonBit CI output in one dependency-light package.
