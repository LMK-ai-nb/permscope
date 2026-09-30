# permscope

MoonBit library for browser capability boundary auditing, with a deep
`Permissions-Policy` parser and route-level capability contracts at its core.
Supporting checks for CSP, HSTS, referrer, clickjacking, MIME sniffing, and
cross-origin isolation provide response-header context around that core.

`permscope` helps small web tools, gateways, static-site checks, and CI scripts
answer questions such as:

- Which browser capabilities does this header allow?
- Are sensitive features such as camera, microphone, geolocation, payment, USB,
  serial, HID, or Bluetooth too permissive?
- Can an old `Feature-Policy` header be migrated to modern
  `Permissions-Policy` syntax?
- Does a route or component expose only the browser capabilities it declared in
  its capability contract?
- Do the response headers satisfy practical web security baselines for CSP,
  HSTS, referrer leakage, clickjacking, MIME sniffing, and cross-origin
  isolation?

## Status

Initial August Hackathon version by 李明坤.
The September work extends this existing project as a community maintenance
entry. Published versions are listed on
[Mooncakes](https://mooncakes.io/docs/LMK-ai-nb/permscope).

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
- Generate built-in profile headers for strict, balanced, media-app, and
  device-lab deployments.
- Compare two policies and classify loosened or tightened changes.
- Summarize how many features are disabled, self-only, wildcard, or delegated to
  explicit origins.
- Parse raw HTTP response headers copied from `curl -I -L` output, auditing
  only the final response rather than mixing redirect-hop policies.
- Audit the effective policy from modern and legacy response headers.
- Render feature/origin access matrices for documentation and reviews.
- Define route-level capability contracts and audit missing, overbroad, or
  undeclared `Permissions-Policy` delegations.
- Audit an observed route response against its declared capability contract,
  rejecting absent or malformed modern policy headers and origin mismatches.
- Compare named route contracts with observed response samples as a CI
  inventory, reporting missing, undeclared, or duplicate route names.
- Generate the strictest `Permissions-Policy` header that satisfies a declared
  capability contract.
- Parse and audit core `Content-Security-Policy` directives.
- Audit `Strict-Transport-Security`, `Referrer-Policy`,
  `X-Frame-Options`, `X-Content-Type-Options`, COOP, COEP, and CORP.
- Generate strict, static-site, API-service, media-app, and device-lab security
  header bundles.
- Score security headers with grades, finding summaries, recommendations, CI
  gates, and batch reports across multiple routes.
- Render stable text reports for CI logs or command-line tools.

## Install

Install the latest published release:

```bash
moon add LMK-ai-nb/permscope
```

Add `"LMK-ai-nb/permscope"` to the `import` block of your `moon.pkg`, then
call its functions through `@permscope`. Pin a version in `moon add` when a
reproducible dependency version is needed.

## Quick Start

```bash
moon check
moon test
moon run cmd/main
moon run examples/route_contract
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
let contract = @permscope.capability_contract(
  "video-room",
  "https://app.example",
  [
    @permscope.capability_need("camera", ["self"], "local preview"),
    @permscope.capability_need(
      "fullscreen",
      ["self", "https://video.example"],
      "embedded player",
    ),
  ],
  true,
)
let contract_policy = @permscope.parse(
  @permscope.minimal_policy_for_contract(contract),
)
let contract_report = @permscope.audit_capability_contract(
  contract_policy,
  contract,
)
println(can_use_camera.to_string())
println(@permscope.render_report(report))
println(@permscope.render_capability_contract_report(contract_report))
```

Run the bundled demo:

```bash
moon run cmd/main
```

For observed responses, run `moon run examples/route_contract`. This example
declares capability needs for `/video` and `/checkout`, builds scoped policies,
checks synthetic response blocks and document origins, then checks both routes
as an inventory. The `/video` sample includes a redirect whose broad policy
must not override the final response. It prints a `route=/video` audit with
`sample=video-room`, `contract: pass`, and `inventory: pass`.

Expected highlights:

```text
permscope demo
camera cross-site=false
effective=permissions-policy
permscope access matrix document=https://app.example
permscope capability contract
contract=video-room
score 80/80 percent=100 grade=A
permscope batch security audit
permscope: pass
```

## API Overview

- `parse(header)` parses a modern `Permissions-Policy` header.
- `parse_feature_policy(header)` parses old `Feature-Policy` syntax.
- `migrate_feature_policy(header)` renders old syntax as modern syntax.
- `directive(policy, feature)` returns the first directive for a feature.
- `allows(policy, feature, document_origin, target_origin)` checks whether the
  supplied header restricts a feature for an origin; it does not model every
  browser default, iframe policy, or user permission.
- `default_baseline(document_origin)` creates a practical web-app security
  baseline.
- `audit(policy, baseline)` reports risky wildcards, missing denies, parse
  warnings, and insecure origins.
- `deny`, `self_only`, `all_origins`, `self_and_origins`, and `build` create
  normalized headers from code.
- `known_features`, `known_feature`, `recommended_header`, and
  `catalog_baseline` provide a practical browser capability catalog.
- `built_in_profiles`, `profile_header`, `profile_policy`, `profile_baseline`,
  and `render_profile` provide deployment-oriented policy presets.
- `capability_contract`, `capability_need`, `optional_capability_need`,
  `minimal_policy_for_contract`, `audit_capability_contract`, and
  `render_capability_contract_report` provide scenario-level capability
  boundary checks.
- `audit_capability_response(sample, contract)` and
  `render_capability_response_audit` check an observed route response. This
  strict path requires a modern `Permissions-Policy` header; use
  `audit_header_block` to inspect legacy `Feature-Policy` for migration.
- `audit_capability_inventory(samples, contracts)` and
  `render_capability_inventory` join routes by trimmed name and fail on missing
  samples, samples without contracts, duplicate names, or failing route audits.
- `summarize` and `render_summary` produce compact dashboard-friendly counts.
- `parse_header_block`, `permissions_policy_header`, `feature_policy_header`,
  `policy_from_headers`, `audit_header_block`, and `render_header_audit` work
  with raw HTTP response header blocks. For multi-response `curl -I -L` text,
  only the final HTTP status block contributes headers and parse warnings.
- `access_matrix`, `matrix_cell`, and `render_access_matrix` explain whether
  selected features are allowed for selected origins.
- `parse_csp`, `audit_csp`, `strict_csp_header`, and `app_csp_header` cover the
  CSP subset used by common web applications.
- `audit_security_header_block`, `render_security_audit`,
  `render_security_markdown`, `render_security_json`,
  `security_recommendations`, and `security_gate` provide full response-header
  scoring and CI output.
- `strict_security_bundle`, `static_site_security_bundle`,
  `api_service_security_bundle`, `media_security_bundle`, and
  `device_lab_security_bundle` generate reusable deployment presets.
- `audit_response_samples`, `render_batch_audit`, `render_batch_markdown`,
  `render_batch_json`, and `batch_security_gate` support multi-route checks.
- `diff` and `render_diffs` show feature-level policy changes.
- `render(policy)` and `render_report(report)` produce stable text output.

## Development

The current CI uses MoonBit `moonc v0.10.14`. The root package disables only
the `implicit_impl_as_method` migration warning emitted for existing derived
`Eq` and `Debug` implementations; all other enabled warnings remain fatal in
the strict checks below.

```bash
moon fmt --check
moon check --deny-warn
moon build
moon test --deny-warn
moon test --target js --deny-warn
moon info
moon run cmd/main
moon run examples/route_contract
```

The GitHub Actions workflow runs the same checks on every push and pull request.
Generated `pkg.generated.mbti` files document the public MoonBit API.

## Publishing

The package name, repository, license, README, and version are defined in
`moon.mod`. After validating the release candidate and syncing its source to
the public default branch, inspect the package contents and publish with:

```bash
moon package --list
moon whoami
moon publish --frozen
```

Publishing needs the Mooncakes account authorized for the `LMK-ai-nb` namespace.
The [Mooncakes package page](https://mooncakes.io/docs/LMK-ai-nb/permscope)
lists published versions. See the [release checklist](docs/RELEASE_CHECKLIST.md)
for verification evidence.

## Project Boundary

`permscope` is intentionally a browser capability policy library. It can parse
response header text that a caller already has, but it does not make HTTP
requests, start a web server, or depend on a browser runtime. Host applications
can use it inside a gateway, static analysis tool, CI check, documentation
generator, or web framework adapter.

The project does not audit mooncakes.io publishing status, does not verify
README example provenance, does not implement robots.txt policy, and is not a
general contest review proof tool. Its core boundary is `Permissions-Policy`
capability exposure: parsing, legacy migration, origin decisions, feature
catalogs, access matrices, policy diffs, and capability contracts. Broader
security-header scoring is supporting context for that capability workflow.
The parser is a focused audit aid, not a browser implementation or a substitute
for deployment testing. It does not fetch live URLs. Callers supply observed
response headers and should verify browser-specific enforcement separately.
For redirected URLs, pass the complete `curl -I -L` header output and the
**final** document origin; `permscope` cannot infer that origin from headers.

## License

Apache-2.0. This repository does not vendor third-party source code, fixtures,
or media assets. See [source and AI use](docs/PROVENANCE_AND_AI.md),
[design notes](docs/DESIGN.md), [test record](docs/TEST_RECORD.md), and the
[September application](docs/SEPTEMBER_APPLICATION.md).
