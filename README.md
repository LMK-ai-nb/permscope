# permscope

MoonBit library for parsing and auditing the `Permissions-Policy` HTTP response
header.

`permscope` helps small web tools, gateways, static-site checks, and CI scripts
answer three questions:

- Which browser capabilities does this header allow?
- Are sensitive features such as camera, microphone, geolocation, payment, USB,
  serial, HID, or Bluetooth too permissive?
- Can an old `Feature-Policy` header be migrated to modern
  `Permissions-Policy` syntax?

## Status

Initial August Hackathon version by 李明坤.

## Features

- Parse modern `Permissions-Policy` directives.
- Parse legacy `Feature-Policy` headers for migration.
- Normalize allowlists containing `self`, `*`, empty deny lists, and explicit
  origins.
- Evaluate whether a browser feature is allowed for a document origin and target
  origin.
- Audit high-risk capabilities such as camera, microphone, geolocation, payment,
  USB, serial, HID, and Bluetooth.
- Build strict headers from declarative policy intents.
- Use a built-in browser capability catalog to create recommended policies.
- Compare two policies and classify loosened or tightened changes.
- Summarize how many features are disabled, self-only, wildcard, or delegated to
  explicit origins.
- Render stable text reports for CI logs or command-line tools.

## Quick Start

```bash
moon check
moon test
moon run cmd/main
```

## Example

```moonbit
let header =
  "camera=(), microphone=(), geolocation=(), fullscreen=(self \"https://video.example\")"
let policy = @permscope.parse(header)

let can_use_camera = @permscope.allows(
  policy,
  "camera",
  "https://app.example",
  "https://app.example",
)

let report = @permscope.audit(
  policy,
  @permscope.default_baseline("https://app.example"),
)
println(can_use_camera.to_string())
println(@permscope.render_report(report))
```

Run the bundled demo:

```bash
moon run cmd/main
```

Expected highlights:

```text
permscope demo
camera cross-site=false
permscope: pass
```

## API Overview

- `parse(header)` parses a modern `Permissions-Policy` header.
- `parse_feature_policy(header)` parses old `Feature-Policy` syntax.
- `migrate_feature_policy(header)` renders old syntax as modern syntax.
- `directive(policy, feature)` returns the first directive for a feature.
- `allows(policy, feature, document_origin, target_origin)` checks allowlist
  behavior.
- `default_baseline(document_origin)` creates a practical web-app security
  baseline.
- `audit(policy, baseline)` reports risky wildcards, missing denies, parse
  warnings, and insecure origins.
- `deny`, `self_only`, `all_origins`, `self_and_origins`, and `build` create
  normalized headers from code.
- `known_features`, `known_feature`, `recommended_header`, and
  `catalog_baseline` provide a practical browser capability catalog.
- `summarize` and `render_summary` produce compact dashboard-friendly counts.
- `diff` and `render_diffs` show feature-level policy changes.
- `render(policy)` and `render_report(report)` produce stable text output.

## Development

```bash
moon fmt --check
moon check --deny-warn
moon build
moon test --deny-warn
moon info
moon run cmd/main
```

The GitHub Actions workflow runs the same checks on every push and pull request.
Generated `pkg.generated.mbti` files document the public MoonBit API.

## Project Boundary

`permscope` is intentionally a small policy library. It does not make HTTP
requests, start a web server, or depend on a browser runtime. Host applications
can use it inside a gateway, static analysis tool, CI check, documentation
generator, or web framework adapter.

## License

Apache-2.0. This repository does not vendor third-party source code, fixtures,
or media assets.
