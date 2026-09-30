///|
/// One Permissions-Policy allowlist token.
pub enum AllowToken {
  TokenSelf
  TokenAll
  TokenOrigin(String)
} derive(Eq, @debug.Debug)

///|
/// A parsed Permissions-Policy directive such as `camera=()`.
pub struct Directive {
  feature : String
  tokens : Array[AllowToken]
  raw : String
  index : Int
} derive(Eq, @debug.Debug)

///|
/// A non-fatal parser warning. Warnings keep the policy usable in CI reports.
pub struct ParseWarning {
  index : Int
  message : String
  text : String
} derive(Eq, @debug.Debug)

///|
/// Parsed modern Permissions-Policy header.
pub struct Policy {
  directives : Array[Directive]
  warnings : Array[ParseWarning]
} derive(Eq, @debug.Debug)

///|
/// Audit severity used by reports and CI output.
pub enum Severity {
  SeverityInfo
  SeverityWarning
  SeverityHigh
} derive(Eq, @debug.Debug)

///|
/// One policy audit finding.
pub struct Finding {
  severity : Severity
  code : String
  feature : String?
  message : String
} derive(Eq, @debug.Debug)

///|
/// Project-specific security expectations.
pub struct Baseline {
  document_origin : String
  sensitive_features : Array[String]
  deny_by_default : Array[String]
} derive(Eq, @debug.Debug)

///|
/// Result of auditing a parsed policy against a baseline.
pub struct AuditReport {
  ok : Bool
  findings : Array[Finding]
} derive(Eq, @debug.Debug)

///|
/// One mutable builder operation is represented as a value so callers can keep
/// configuration declarative.
pub enum PolicyIntent {
  IntentDeny(String)
  IntentSelf(String)
  IntentAll(String)
  IntentOrigins(String, Array[String])
  IntentOriginsOnly(String, Array[String])
} derive(Eq, @debug.Debug)

///|
/// Difference severity between two policies.
pub enum DiffKind {
  DiffAdded
  DiffRemoved
  DiffChanged
  DiffLoosened
  DiffTightened
} derive(Eq, @debug.Debug)

///|
/// One feature-level policy difference.
pub struct PolicyDiff {
  kind : DiffKind
  feature : String
  before : String?
  after : String?
} derive(Eq, @debug.Debug)

///|
/// Browser capability category used by the built-in feature catalog.
pub enum FeatureCategory {
  CategorySensors
  CategoryMedia
  CategoryDevice
  CategoryIdentity
  CategoryPayment
  CategoryDisplay
  CategoryStorage
  CategoryExperimental
  CategoryOther
} derive(Eq, @debug.Debug)

///|
/// Approximate risk tier for a browser capability.
pub enum RiskLevel {
  RiskLow
  RiskMedium
  RiskHigh
} derive(Eq, @debug.Debug)

///|
/// Metadata for a known Permissions-Policy feature.
pub struct FeatureSpec {
  feature : String
  category : FeatureCategory
  risk : RiskLevel
  recommended : PolicyIntent
  rationale : String
} derive(Eq, @debug.Debug)

///|
/// Compact policy summary for dashboards and release notes.
pub struct PolicySummary {
  disabled : Int
  self_only : Int
  wildcard : Int
  explicit_origins : Int
  missing_sensitive : Array[String]
} derive(Eq, @debug.Debug)

///|
/// Built-in policy profiles for common web application shapes.
pub enum BaselineProfile {
  ProfileStrict
  ProfileBalanced
  ProfileMediaApp
  ProfileDeviceLab
} derive(Eq, @debug.Debug)

///|
/// Kind of HTTP response header recognized by the header-block parser.
pub enum HeaderKind {
  HeaderPermissionsPolicy
  HeaderFeaturePolicy
  HeaderOther
} derive(Eq, @debug.Debug)

///|
/// One parsed HTTP response header line.
pub struct HeaderLine {
  name : String
  value : String
  index : Int
  kind : HeaderKind
} derive(Eq, @debug.Debug)

///|
/// Parsed final HTTP response header block, suitable for `curl -I -L` output.
pub struct HeaderSet {
  lines : Array[HeaderLine]
  warnings : Array[ParseWarning]
} derive(Eq, @debug.Debug)

///|
/// End-to-end audit result for a raw HTTP response header block.
pub struct HeaderAudit {
  headers : HeaderSet
  modern : Policy?
  legacy : Policy?
  effective : Policy
  report : AuditReport
  used_legacy : Bool
  migration : String
} derive(Eq, @debug.Debug)

///|
/// One feature/origin access decision in a matrix report.
pub struct AccessCell {
  feature : String
  target_origin : String
  allowed : Bool
} derive(Eq, @debug.Debug)

///|
/// Matrix view of many features across many target origins.
pub struct AccessMatrix {
  document_origin : String
  features : Array[String]
  target_origins : Array[String]
  cells : Array[AccessCell]
} derive(Eq, @debug.Debug)

///|
/// Create an intent that disables a feature.
pub fn deny(feature : String) -> PolicyIntent {
  IntentDeny(feature)
}

///|
/// Create an intent that allows a feature only for the document origin.
pub fn self_only(feature : String) -> PolicyIntent {
  IntentSelf(feature)
}

///|
/// Create an intent that allows a feature for every origin.
pub fn all_origins(feature : String) -> PolicyIntent {
  IntentAll(feature)
}

///|
/// Create an intent that allows a feature for self plus explicit origins.
pub fn self_and_origins(
  feature : String,
  origins : Array[String],
) -> PolicyIntent {
  IntentOrigins(feature, origins)
}

///|
/// Create an intent that allows a feature only for explicit origins.
pub fn origins_only(feature : String, origins : Array[String]) -> PolicyIntent {
  IntentOriginsOnly(feature, origins)
}

///|
/// Return the built-in browser capability catalog.
pub fn known_features() -> Array[FeatureSpec] {
  [
    feature_spec(
      "accelerometer",
      CategorySensors,
      RiskMedium,
      deny("accelerometer"),
      "motion sensors can reveal device movement",
    ),
    feature_spec(
      "ambient-light-sensor",
      CategorySensors,
      RiskMedium,
      deny("ambient-light-sensor"),
      "ambient sensors may expose user environment signals",
    ),
    feature_spec(
      "autoplay",
      CategoryMedia,
      RiskLow,
      self_only("autoplay"),
      "same-origin autoplay is usually easier to control",
    ),
    feature_spec(
      "bluetooth",
      CategoryDevice,
      RiskHigh,
      deny("bluetooth"),
      "device access should require explicit application review",
    ),
    feature_spec(
      "browsing-topics",
      CategoryExperimental,
      RiskMedium,
      deny("browsing-topics"),
      "interest topics should be disabled unless advertising logic needs them",
    ),
    feature_spec(
      "camera",
      CategoryMedia,
      RiskHigh,
      deny("camera"),
      "camera access is a high-risk user privacy capability",
    ),
    feature_spec(
      "clipboard-read",
      CategoryDevice,
      RiskHigh,
      deny("clipboard-read"),
      "clipboard read access may expose sensitive user data",
    ),
    feature_spec(
      "clipboard-write",
      CategoryDevice,
      RiskMedium,
      self_only("clipboard-write"),
      "same-origin clipboard writes are safer than broad delegation",
    ),
    feature_spec(
      "display-capture",
      CategoryMedia,
      RiskHigh,
      deny("display-capture"),
      "screen capture should be explicitly reviewed",
    ),
    feature_spec(
      "encrypted-media",
      CategoryMedia,
      RiskMedium,
      self_only("encrypted-media"),
      "DRM media access should be scoped to trusted origins",
    ),
    feature_spec(
      "fullscreen",
      CategoryDisplay,
      RiskLow,
      self_only("fullscreen"),
      "fullscreen is normally acceptable for the document origin",
    ),
    feature_spec(
      "gamepad",
      CategoryDevice,
      RiskMedium,
      deny("gamepad"),
      "gamepad access can reveal connected hardware state",
    ),
    feature_spec(
      "geolocation",
      CategorySensors,
      RiskHigh,
      deny("geolocation"),
      "location access is high-risk and should be denied by default",
    ),
    feature_spec(
      "gyroscope",
      CategorySensors,
      RiskMedium,
      deny("gyroscope"),
      "motion sensors should be opt-in",
    ),
    feature_spec(
      "hid",
      CategoryDevice,
      RiskHigh,
      deny("hid"),
      "human-interface device access reaches local hardware",
    ),
    feature_spec(
      "idle-detection",
      CategoryIdentity,
      RiskMedium,
      deny("idle-detection"),
      "idle signals can reveal user presence",
    ),
    feature_spec(
      "local-fonts",
      CategoryStorage,
      RiskMedium,
      deny("local-fonts"),
      "local font enumeration may contribute to fingerprinting",
    ),
    feature_spec(
      "magnetometer",
      CategorySensors,
      RiskMedium,
      deny("magnetometer"),
      "motion and compass sensors should be opt-in",
    ),
    feature_spec(
      "microphone",
      CategoryMedia,
      RiskHigh,
      deny("microphone"),
      "microphone access is a high-risk user privacy capability",
    ),
    feature_spec(
      "midi",
      CategoryDevice,
      RiskMedium,
      deny("midi"),
      "MIDI device access should not be delegated broadly",
    ),
    feature_spec(
      "payment",
      CategoryPayment,
      RiskHigh,
      deny("payment"),
      "payment access should only be enabled after product review",
    ),
    feature_spec(
      "publickey-credentials-get",
      CategoryIdentity,
      RiskHigh,
      self_only("publickey-credentials-get"),
      "passkey requests should stay on trusted document origins",
    ),
    feature_spec(
      "serial",
      CategoryDevice,
      RiskHigh,
      deny("serial"),
      "serial ports expose local hardware resources",
    ),
    feature_spec(
      "speaker-selection",
      CategoryMedia,
      RiskMedium,
      self_only("speaker-selection"),
      "output device selection should be scoped",
    ),
    feature_spec(
      "storage-access",
      CategoryStorage,
      RiskMedium,
      deny("storage-access"),
      "cross-site storage access should be deliberate",
    ),
    feature_spec(
      "usb",
      CategoryDevice,
      RiskHigh,
      deny("usb"),
      "USB access reaches local hardware and should be denied by default",
    ),
    feature_spec(
      "web-share",
      CategoryOther,
      RiskLow,
      self_only("web-share"),
      "same-origin sharing keeps delegation predictable",
    ),
    feature_spec(
      "window-management",
      CategoryDisplay,
      RiskMedium,
      deny("window-management"),
      "window placement should be opt-in for trusted apps",
    ),
    feature_spec(
      "xr-spatial-tracking",
      CategorySensors,
      RiskHigh,
      deny("xr-spatial-tracking"),
      "XR tracking can reveal physical-space information",
    ),
  ]
}

///|
/// Find metadata for one known feature.
pub fn known_feature(feature : String) -> FeatureSpec? {
  let wanted = normalize_feature(feature)
  for spec in known_features() {
    if spec.feature == wanted {
      return Some(spec)
    }
  }
  None
}

///|
/// Return a normalized list of known feature names.
pub fn known_feature_names() -> Array[String] {
  let names : Array[String] = []
  for spec in known_features() {
    names.push(spec.feature)
  }
  names
}

///|
/// Render the built-in recommended header.
pub fn recommended_header() -> String {
  build(recommended_intents())
}

///|
/// Build a baseline from the feature catalog instead of a hard-coded list.
pub fn catalog_baseline(document_origin : String) -> Baseline {
  let sensitive_features : Array[String] = []
  let deny_by_default : Array[String] = []
  for spec in known_features() {
    if spec.risk == RiskHigh {
      sensitive_features.push(spec.feature)
    }
    if intent_disables(spec.recommended) {
      deny_by_default.push(spec.feature)
    }
  }
  { document_origin, sensitive_features, deny_by_default, }
}

///|
/// Summarize a policy against a baseline.
pub fn summarize(policy : Policy, baseline : Baseline) -> PolicySummary {
  let mut disabled = 0
  let mut self_only = 0
  let mut wildcard = 0
  let mut explicit_origins = 0
  let missing_sensitive : Array[String] = []
  for item in policy.directives {
    match directive_shape(item) {
      "disabled" => disabled = disabled + 1
      "self" => self_only = self_only + 1
      "wildcard" => wildcard = wildcard + 1
      "explicit" => explicit_origins = explicit_origins + 1
      _ => ()
    }
  }
  for feature in baseline.deny_by_default {
    if directive(policy, feature) is None {
      missing_sensitive.push(feature)
    }
  }
  { disabled, self_only, wildcard, explicit_origins, missing_sensitive, }
}

///|
/// Render a compact summary for CLI output.
pub fn render_summary(summary : PolicySummary) -> String {
  "summary disabled=" +
  summary.disabled.to_string() +
  " self=" +
  summary.self_only.to_string() +
  " wildcard=" +
  summary.wildcard.to_string() +
  " explicit=" +
  summary.explicit_origins.to_string() +
  " missing_sensitive=" +
  summary.missing_sensitive.join("|")
}

///|
/// Return all built-in policy profiles.
pub fn built_in_profiles() -> Array[BaselineProfile] {
  [ProfileStrict, ProfileBalanced, ProfileMediaApp, ProfileDeviceLab]
}

///|
/// Profile that disables every known browser capability.
pub fn strict_profile() -> BaselineProfile {
  ProfileStrict
}

///|
/// Profile that follows the package's default recommendation catalog.
pub fn balanced_profile() -> BaselineProfile {
  ProfileBalanced
}

///|
/// Profile for media-heavy sites that need same-origin playback features.
pub fn media_app_profile() -> BaselineProfile {
  ProfileMediaApp
}

///|
/// Profile for hardware labs that delegate device features to trusted origins.
pub fn device_lab_profile() -> BaselineProfile {
  ProfileDeviceLab
}

///|
/// Return a stable name for a built-in profile.
pub fn profile_name(profile : BaselineProfile) -> String {
  match profile {
    ProfileStrict => "strict"
    ProfileBalanced => "balanced"
    ProfileMediaApp => "media-app"
    ProfileDeviceLab => "device-lab"
  }
}

///|
/// Build declarative intents for a built-in profile.
pub fn profile_intents(
  profile : BaselineProfile,
  trusted_origins : Array[String],
) -> Array[PolicyIntent] {
  let intents : Array[PolicyIntent] = []
  for spec in known_features() {
    intents.push(profile_intent(profile, spec.feature, trusted_origins))
  }
  intents
}

///|
/// Render a complete header for a built-in profile.
pub fn profile_header(
  profile : BaselineProfile,
  trusted_origins : Array[String],
) -> String {
  build(profile_intents(profile, trusted_origins))
}

///|
/// Build a parsed policy for a built-in profile.
pub fn profile_policy(
  profile : BaselineProfile,
  trusted_origins : Array[String],
) -> Policy {
  build_policy(profile_intents(profile, trusted_origins))
}

///|
/// Build an audit baseline that matches a built-in profile.
pub fn profile_baseline(
  profile : BaselineProfile,
  document_origin : String,
) -> Baseline {
  let sensitive_features : Array[String] = []
  let deny_by_default : Array[String] = []
  for spec in known_features() {
    if profile_marks_sensitive(profile, spec) {
      sensitive_features.push(spec.feature)
    }
    if profile_requires_cross_site_guard(profile, spec.feature) {
      deny_by_default.push(spec.feature)
    }
  }
  {
    document_origin: normalize_origin(document_origin),
    sensitive_features,
    deny_by_default,
  }
}

///|
/// Render profile metadata and generated header for documentation or logs.
pub fn render_profile(
  profile : BaselineProfile,
  trusted_origins : Array[String],
) -> String {
  let lines : Array[String] = []
  lines.push("profile=" + profile_name(profile))
  lines.push("trusted_origins=" + trusted_origins.join("|"))
  lines.push("header=" + profile_header(profile, trusted_origins))
  lines.join("\n")
}

///|
/// Parse the final HTTP response header block, including `curl -I -L` output.
pub fn parse_header_block(block : String) -> HeaderSet {
  let mut lines : Array[HeaderLine] = []
  let mut warnings : Array[ParseWarning] = []
  let mut index = 0
  for line_view in block.split("\n") {
    index = index + 1
    let raw = line_view.to_owned()
    let clean = trim(raw)
    if clean == "" {
      continue
    }
    if raw.has_prefix(" ") || raw.has_prefix("\t") {
      warnings.push({
        index,
        message: "folded header continuation is ignored",
        text: clean,
      })
      continue
    }
    if clean.to_lower().has_prefix("http/") {
      // Each status line begins a separate response; earlier redirects and
      // informational responses must not contribute policy to the final one.
      lines = []
      warnings = []
      continue
    }
    match clean.find(":") {
      None =>
        warnings.push({
          index,
          message: "header line is missing ':'",
          text: clean,
        })
      Some(colon) => {
        let name = normalize_header_name(clean[:colon].to_owned())
        let value = trim(clean[colon + 1:].to_owned())
        if name == "" {
          warnings.push({ index, message: "empty header name", text: clean, })
        } else {
          lines.push({ name, value, index, kind: classify_header_name(name), })
        }
      }
    }
  }
  { lines, warnings, }
}

///|
/// Return combined modern `Permissions-Policy` header value, if present.
pub fn permissions_policy_header(headers : HeaderSet) -> String? {
  joined_header_value(headers, HeaderPermissionsPolicy, ", ")
}

///|
/// Return combined legacy `Feature-Policy` header value, if present.
pub fn feature_policy_header(headers : HeaderSet) -> String? {
  joined_header_value(headers, HeaderFeaturePolicy, "; ")
}

///|
/// Choose the effective policy from parsed headers.
///
/// Modern `Permissions-Policy` takes precedence. Legacy `Feature-Policy` is
/// used only when no modern header is present.
pub fn policy_from_headers(headers : HeaderSet) -> Policy {
  match permissions_policy_header(headers) {
    Some(value) => prepend_warnings(parse(value), headers.warnings)
    None =>
      match feature_policy_header(headers) {
        Some(value) =>
          prepend_warnings(parse_feature_policy(value), headers.warnings)
        None => prepend_warnings(parse(""), headers.warnings)
      }
  }
}

///|
/// Audit a raw HTTP response header block.
pub fn audit_header_block(block : String, baseline : Baseline) -> HeaderAudit {
  let headers = parse_header_block(block)
  let modern_value = permissions_policy_header(headers)
  let legacy_value = feature_policy_header(headers)
  let modern = match modern_value {
    Some(value) => Some(parse(value))
    None => None
  }
  let legacy = match legacy_value {
    Some(value) => Some(parse_feature_policy(value))
    None => None
  }
  let effective = policy_from_headers(headers)
  let report = audit(effective, baseline)
  let migration = match legacy_value {
    Some(value) => migrate_feature_policy(value)
    None => ""
  }
  {
    headers,
    modern,
    legacy,
    effective,
    report,
    used_legacy: modern_value is None && legacy_value is Some(_),
    migration,
  }
}

///|
/// Render an end-to-end header audit result.
pub fn render_header_audit(audit : HeaderAudit) -> String {
  let lines : Array[String] = []
  lines.push("permscope header audit")
  lines.push("headers=" + audit.headers.lines.length().to_string())
  match audit.modern {
    Some(_) => lines.push("effective=permissions-policy")
    None =>
      if audit.used_legacy {
        lines.push("effective=feature-policy-migration")
      } else {
        lines.push("effective=missing")
      }
  }
  if audit.migration != "" {
    lines.push("migration=" + audit.migration)
  }
  lines.push(render_report(audit.report))
  lines.join("\n")
}

///|
/// Build a many-feature, many-origin access matrix.
pub fn access_matrix(
  policy : Policy,
  features : Array[String],
  document_origin : String,
  target_origins : Array[String],
) -> AccessMatrix {
  let normalized_document = normalize_origin(document_origin)
  let normalized_features : Array[String] = []
  let normalized_targets : Array[String] = []
  let cells : Array[AccessCell] = []
  for feature in features {
    let normalized = normalize_feature(feature)
    if normalized != "" {
      normalized_features.push(normalized)
    }
  }
  for target in target_origins {
    let normalized = normalize_origin(target)
    if normalized != "" {
      normalized_targets.push(normalized)
    }
  }
  for feature in normalized_features {
    for target in normalized_targets {
      cells.push({
        feature,
        target_origin: target,
        allowed: allows(policy, feature, normalized_document, target),
      })
    }
  }
  {
    document_origin: normalized_document,
    features: normalized_features,
    target_origins: normalized_targets,
    cells,
  }
}

///|
/// Find one cell in an access matrix.
pub fn matrix_cell(
  matrix : AccessMatrix,
  feature : String,
  target_origin : String,
) -> AccessCell? {
  let wanted_feature = normalize_feature(feature)
  let wanted_origin = normalize_origin(target_origin)
  for cell in matrix.cells {
    if cell.feature == wanted_feature && cell.target_origin == wanted_origin {
      return Some(cell)
    }
  }
  None
}

///|
/// Render an access matrix as compact line-oriented text.
pub fn render_access_matrix(matrix : AccessMatrix) -> String {
  let lines : Array[String] = []
  lines.push("permscope access matrix document=" + matrix.document_origin)
  let header : Array[String] = ["feature"]
  for target in matrix.target_origins {
    header.push(target)
  }
  lines.push(header.join(" "))
  for feature in matrix.features {
    let row : Array[String] = [feature]
    for target in matrix.target_origins {
      match matrix_cell(matrix, feature, target) {
        None => row.push("n/a")
        Some(cell) => {
          let mut label = "deny"
          if cell.allowed {
            label = "allow"
          }
          row.push(label)
        }
      }
    }
    lines.push(row.join(" "))
  }
  lines.join("\n")
}

///|
/// Parse a modern `Permissions-Policy` header.
pub fn parse(header : String) -> Policy {
  let directives : Array[Directive] = []
  let warnings : Array[ParseWarning] = []
  let clean = trim(header)
  if clean == "" {
    warnings.push({ index: 0, message: "empty header", text: header, })
    return { directives, warnings, }
  }
  let mut index = 0
  for part_view in clean.split(",") {
    index = index + 1
    let part = trim(part_view.to_owned())
    if part == "" {
      warnings.push({
        index,
        message: "empty directive segment",
        text: part_view.to_owned(),
      })
      continue
    }
    match parse_modern_directive(part, index, warnings) {
      None => ()
      Some(directive) => {
        if has_feature(directives, directive.feature) {
          warnings.push({
            index,
            message: "duplicate directive for feature: " + directive.feature,
            text: part,
          })
        }
        directives.push(directive)
      }
    }
  }
  { directives, warnings, }
}

///|
/// Parse a legacy `Feature-Policy` header and normalize it to this package's
/// modern directive representation.
pub fn parse_feature_policy(header : String) -> Policy {
  let directives : Array[Directive] = []
  let warnings : Array[ParseWarning] = []
  let clean = trim(header)
  if clean == "" {
    warnings.push({ index: 0, message: "empty legacy header", text: header, })
    return { directives, warnings, }
  }
  let mut index = 0
  for part_view in clean.split(";") {
    index = index + 1
    let part = trim(part_view.to_owned())
    if part == "" {
      continue
    }
    match parse_legacy_directive(part, index, warnings) {
      None => ()
      Some(directive) => {
        if has_feature(directives, directive.feature) {
          warnings.push({
            index,
            message: "duplicate legacy directive for feature: " +
            directive.feature,
            text: part,
          })
        }
        directives.push(directive)
      }
    }
  }
  { directives, warnings, }
}

///|
/// Return the first directive for `feature`, if one is present.
pub fn directive(policy : Policy, feature : String) -> Directive? {
  let wanted = normalize_feature(feature)
  for d in policy.directives {
    if d.feature == wanted {
      return Some(d)
    }
  }
  None
}

///|
/// Decide whether a feature is allowed for a target origin.
///
/// Missing directives return true because this header adds no restriction for
/// that feature. This does not assert that a browser will grant access: feature
/// defaults, user permissions, and iframe policies are outside this check.
/// Use `audit` to flag missing explicit restrictions.
pub fn allows(
  policy : Policy,
  feature : String,
  document_origin : String,
  target_origin : String,
) -> Bool {
  match directive(policy, feature) {
    None => true
    Some(directive) =>
      tokens_allow(
        directive.tokens,
        normalize_origin(document_origin),
        normalize_origin(target_origin),
      )
  }
}

///|
/// Render a policy back to normalized modern header syntax.
pub fn render(policy : Policy) -> String {
  let parts : Array[String] = []
  for d in policy.directives {
    parts.push(render_directive(d))
  }
  parts.join(", ")
}

///|
/// Recommended baseline for public web applications.
pub fn default_baseline(document_origin : String) -> Baseline {
  {
    document_origin,
    sensitive_features: [
      "accelerometer", "ambient-light-sensor", "autoplay", "bluetooth", "browsing-topics",
      "camera", "clipboard-read", "clipboard-write", "display-capture", "encrypted-media",
      "fullscreen", "gamepad", "geolocation", "gyroscope", "hid", "idle-detection",
      "local-fonts", "magnetometer", "microphone", "midi", "payment", "publickey-credentials-get",
      "serial", "usb", "xr-spatial-tracking",
    ],
    deny_by_default: [
      "bluetooth", "camera", "geolocation", "hid", "microphone", "payment", "serial",
      "usb",
    ],
  }
}

///|
/// Audit a parsed policy for risky defaults and overly broad allowlists.
pub fn audit(policy : Policy, baseline : Baseline) -> AuditReport {
  let findings : Array[Finding] = []
  if policy.directives.length() == 0 {
    findings.push({
      severity: SeverityHigh,
      code: "missing-header",
      feature: None,
      message: "no Permissions-Policy directive is present",
    })
  }
  for warning in policy.warnings {
    findings.push({
      severity: SeverityWarning,
      code: "parse-warning",
      feature: None,
      message: "segment " + warning.index.to_string() + ": " + warning.message,
    })
  }
  for directive in policy.directives {
    audit_directive(directive, baseline, findings)
  }
  for feature in baseline.deny_by_default {
    if allows(
        policy,
        feature,
        baseline.document_origin,
        "https://cross-site.invalid",
      ) {
      findings.push({
        severity: SeverityHigh,
        code: "not-denied-by-default",
        feature: Some(feature),
        message: "sensitive feature is not explicitly blocked for cross-site contexts",
      })
    }
  }
  if findings.length() == 0 {
    findings.push({
      severity: SeverityInfo,
      code: "baseline-satisfied",
      feature: None,
      message: "policy satisfies the selected baseline",
    })
  }
  { ok: !has_high(findings), findings, }
}

///|
/// Build a modern header from declarative feature intents.
pub fn build(intents : Array[PolicyIntent]) -> String {
  let policy = build_policy(intents)
  render(policy)
}

///|
/// Build a policy from declarative feature intents.
pub fn build_policy(intents : Array[PolicyIntent]) -> Policy {
  let directives : Array[Directive] = []
  let warnings : Array[ParseWarning] = []
  let mut index = 0
  for intent in intents {
    index = index + 1
    let directive = directive_from_intent(intent, index)
    if has_feature(directives, directive.feature) {
      warnings.push({
        index,
        message: "duplicate builder intent for feature: " + directive.feature,
        text: render_directive(directive),
      })
    }
    directives.push(directive)
  }
  { directives, warnings, }
}

///|
/// Compare two policies feature by feature.
pub fn diff(before : Policy, after : Policy) -> Array[PolicyDiff] {
  let diffs : Array[PolicyDiff] = []
  for before_directive in before.directives {
    match directive(after, before_directive.feature) {
      None =>
        diffs.push({
          kind: DiffRemoved,
          feature: before_directive.feature,
          before: Some(render_directive(before_directive)),
          after: None,
        })
      Some(after_directive) =>
        if render_directive(before_directive) !=
          render_directive(after_directive) {
          diffs.push({
            kind: classify_diff(before_directive, after_directive),
            feature: before_directive.feature,
            before: Some(render_directive(before_directive)),
            after: Some(render_directive(after_directive)),
          })
        }
    }
  }
  for after_directive in after.directives {
    if directive(before, after_directive.feature) is None {
      diffs.push({
        kind: DiffAdded,
        feature: after_directive.feature,
        before: None,
        after: Some(render_directive(after_directive)),
      })
    }
  }
  diffs
}

///|
/// Render policy diffs as stable line-oriented text.
pub fn render_diffs(diffs : Array[PolicyDiff]) -> String {
  if diffs.length() == 0 {
    return "permscope diff: no changes"
  }
  let lines : Array[String] = ["permscope diff:"]
  for item in diffs {
    lines.push(
      diff_label(item.kind) +
      " " +
      item.feature +
      " before=" +
      item.before.unwrap_or("-") +
      " after=" +
      item.after.unwrap_or("-"),
    )
  }
  lines.join("\n")
}

///|
/// Convert legacy `Feature-Policy` syntax into modern `Permissions-Policy`.
pub fn migrate_feature_policy(header : String) -> String {
  render(parse_feature_policy(header))
}

///|
/// Render an audit report as line-oriented text for examples and CI logs.
pub fn render_report(report : AuditReport) -> String {
  let lines : Array[String] = []
  if report.ok {
    lines.push("permscope: pass")
  } else {
    lines.push("permscope: fail")
  }
  for finding in report.findings {
    let feature = match finding.feature {
      None => "-"
      Some(value) => value
    }
    lines.push(
      severity_label(finding.severity) +
      " " +
      finding.code +
      " " +
      feature +
      " - " +
      finding.message,
    )
  }
  lines.join("\n")
}

///|
fn parse_modern_directive(
  part : String,
  index : Int,
  warnings : Array[ParseWarning],
) -> Directive? {
  match part.find("=") {
    None => {
      warnings.push({ index, message: "directive is missing '='", text: part, })
      None
    }
    Some(eq) => {
      let feature = normalize_feature(part[:eq].to_owned())
      let value = trim(part[eq + 1:].to_owned())
      if feature == "" {
        warnings.push({ index, message: "empty feature name", text: part, })
        return None
      }
      if !feature_name_ok(feature) {
        warnings.push({
          index,
          message: "feature name contains unusual characters",
          text: part,
        })
      }
      if !value.has_prefix("(") || !value.has_suffix(")") {
        warnings.push({
          index,
          message: "allowlist should be wrapped in parentheses",
          text: part,
        })
        return Some({
          feature,
          tokens: parse_token_list(value, index, warnings),
          raw: part,
          index,
        })
      }
      let body = value[1:value.length() - 1].to_owned()
      Some({
        feature,
        tokens: parse_token_list(body, index, warnings),
        raw: part,
        index,
      })
    }
  }
}

///|
fn parse_legacy_directive(
  part : String,
  index : Int,
  warnings : Array[ParseWarning],
) -> Directive? {
  match part.find(" ") {
    None => {
      let feature = normalize_feature(part)
      if feature == "" {
        warnings.push({
          index,
          message: "empty legacy feature name",
          text: part,
        })
        None
      } else {
        warnings.push({
          index,
          message: "legacy directive has no allowlist; treating as disabled",
          text: part,
        })
        Some({ feature, tokens: [], raw: part, index, })
      }
    }
    Some(space) => {
      let feature = normalize_feature(part[:space].to_owned())
      let value = trim(part[space + 1:].to_owned())
      if feature == "" {
        warnings.push({
          index,
          message: "empty legacy feature name",
          text: part,
        })
        None
      } else {
        warnings.push({
          index,
          message: "legacy Feature-Policy syntax parsed for migration",
          text: part,
        })
        Some({
          feature,
          tokens: parse_token_list(value, index, warnings),
          raw: part,
          index,
        })
      }
    }
  }
}

///|
fn parse_token_list(
  body : String,
  index : Int,
  warnings : Array[ParseWarning],
) -> Array[AllowToken] {
  let tokens : Array[AllowToken] = []
  let mut saw_none = false
  for token_view in body.split(" ") {
    let token = strip_quotes(trim(token_view.to_owned())).to_lower()
    if token == "" {
      continue
    }
    match token {
      "*" => tokens.push(TokenAll)
      "self" => tokens.push(TokenSelf)
      "'self'" => tokens.push(TokenSelf)
      "none" | "'none'" => saw_none = true
      _ => {
        if !origin_like(token) {
          warnings.push({
            index,
            message: "allowlist token is not self, none, wildcard, or an origin",
            text: token,
          })
        }
        tokens.push(TokenOrigin(token))
      }
    }
  }
  if saw_none && tokens.length() > 0 {
    warnings.push({
      index,
      message: "none is mixed with other allowlist tokens; none wins",
      text: body,
    })
    []
  } else {
    tokens
  }
}

///|
fn tokens_allow(
  tokens : Array[AllowToken],
  document_origin : String,
  target_origin : String,
) -> Bool {
  for token in tokens {
    match token {
      TokenAll => return true
      TokenSelf => if document_origin == target_origin { return true }
      TokenOrigin(origin) =>
        if normalize_origin(origin) == target_origin {
          return true
        }
    }
  }
  false
}

///|
fn render_directive(directive : Directive) -> String {
  if directive.tokens.length() == 0 {
    directive.feature + "=()"
  } else {
    let tokens : Array[String] = []
    for token in directive.tokens {
      tokens.push(render_token(token))
    }
    directive.feature + "=(" + tokens.join(" ") + ")"
  }
}

///|
fn render_token(token : AllowToken) -> String {
  match token {
    TokenAll => "*"
    TokenSelf => "self"
    TokenOrigin(origin) => "\"" + normalize_origin(origin) + "\""
  }
}

///|
fn directive_from_intent(intent : PolicyIntent, index : Int) -> Directive {
  match intent {
    IntentDeny(feature) =>
      { feature: normalize_feature(feature), tokens: [], raw: "", index, }
    IntentSelf(feature) =>
      {
        feature: normalize_feature(feature),
        tokens: [TokenSelf],
        raw: "",
        index,
      }
    IntentAll(feature) =>
      {
        feature: normalize_feature(feature),
        tokens: [TokenAll],
        raw: "",
        index,
      }
    IntentOrigins(feature, origins) => {
      let tokens : Array[AllowToken] = []
      tokens.push(TokenSelf)
      for origin in origins {
        tokens.push(TokenOrigin(normalize_origin(origin)))
      }
      { feature: normalize_feature(feature), tokens, raw: "", index, }
    }
    IntentOriginsOnly(feature, origins) => {
      let tokens : Array[AllowToken] = []
      for origin in origins {
        tokens.push(TokenOrigin(normalize_origin(origin)))
      }
      { feature: normalize_feature(feature), tokens, raw: "", index, }
    }
  }
}

///|
fn feature_spec(
  feature : String,
  category : FeatureCategory,
  risk : RiskLevel,
  recommended : PolicyIntent,
  rationale : String,
) -> FeatureSpec {
  {
    feature: normalize_feature(feature),
    category,
    risk,
    recommended,
    rationale,
  }
}

///|
fn recommended_intents() -> Array[PolicyIntent] {
  let intents : Array[PolicyIntent] = []
  for spec in known_features() {
    intents.push(spec.recommended)
  }
  intents
}

///|
fn profile_intent(
  profile : BaselineProfile,
  feature : String,
  trusted_origins : Array[String],
) -> PolicyIntent {
  match profile {
    ProfileStrict => deny(feature)
    ProfileBalanced =>
      match known_feature(feature) {
        Some(spec) => spec.recommended
        None => deny(feature)
      }
    ProfileMediaApp => media_profile_intent(feature)
    ProfileDeviceLab => device_lab_profile_intent(feature, trusted_origins)
  }
}

///|
fn media_profile_intent(feature : String) -> PolicyIntent {
  match normalize_feature(feature) {
    "autoplay"
    | "encrypted-media"
    | "fullscreen"
    | "speaker-selection"
    | "web-share" => self_only(feature)
    _ => deny(feature)
  }
}

///|
fn device_lab_profile_intent(
  feature : String,
  trusted_origins : Array[String],
) -> PolicyIntent {
  match normalize_feature(feature) {
    "bluetooth" | "hid" | "serial" | "usb" =>
      self_and_origins(feature, trusted_origins)
    "clipboard-write" | "fullscreen" | "web-share" => self_only(feature)
    _ => deny(feature)
  }
}

///|
fn profile_marks_sensitive(
  profile : BaselineProfile,
  spec : FeatureSpec,
) -> Bool {
  match profile {
    ProfileStrict => true
    ProfileBalanced => spec.risk != RiskLow
    ProfileMediaApp => spec.risk != RiskLow
    ProfileDeviceLab => spec.risk != RiskLow
  }
}

///|
fn profile_requires_cross_site_guard(
  profile : BaselineProfile,
  feature : String,
) -> Bool {
  match profile {
    ProfileStrict => true
    ProfileBalanced =>
      match known_feature(feature) {
        Some(spec) => spec.risk != RiskLow || intent_disables(spec.recommended)
        None => true
      }
    ProfileMediaApp =>
      match normalize_feature(feature) {
        "autoplay"
        | "encrypted-media"
        | "fullscreen"
        | "speaker-selection"
        | "web-share" => false
        _ => true
      }
    ProfileDeviceLab =>
      match normalize_feature(feature) {
        "bluetooth"
        | "hid"
        | "serial"
        | "usb"
        | "clipboard-write"
        | "fullscreen"
        | "web-share" => false
        _ => true
      }
  }
}

///|
fn intent_disables(intent : PolicyIntent) -> Bool {
  match intent {
    IntentDeny(_) => true
    _ => false
  }
}

///|
fn directive_shape(directive : Directive) -> String {
  if directive.tokens.length() == 0 {
    return "disabled"
  }
  if has_wildcard(directive.tokens) {
    return "wildcard"
  }
  if directive.tokens.length() == 1 && directive.tokens[0] == TokenSelf {
    return "self"
  }
  "explicit"
}

///|
fn classify_diff(before : Directive, after : Directive) -> DiffKind {
  let before_power = allow_power(before.tokens)
  let after_power = allow_power(after.tokens)
  if after_power > before_power {
    DiffLoosened
  } else if after_power < before_power {
    DiffTightened
  } else {
    DiffChanged
  }
}

///|
fn allow_power(tokens : Array[AllowToken]) -> Int {
  let mut score = tokens.length()
  for token in tokens {
    match token {
      TokenAll => return 10000
      TokenSelf => score = score + 10
      TokenOrigin(_) => score = score + 20
    }
  }
  score
}

///|
fn diff_label(kind : DiffKind) -> String {
  match kind {
    DiffAdded => "added"
    DiffRemoved => "removed"
    DiffChanged => "changed"
    DiffLoosened => "loosened"
    DiffTightened => "tightened"
  }
}

///|
fn audit_directive(
  directive : Directive,
  baseline : Baseline,
  findings : Array[Finding],
) -> Unit {
  if directive.tokens.length() == 0 {
    findings.push({
      severity: SeverityInfo,
      code: "feature-disabled",
      feature: Some(directive.feature),
      message: "feature is explicitly disabled",
    })
    return
  }
  if feature_in(baseline.sensitive_features, directive.feature) &&
    has_wildcard(directive.tokens) {
    findings.push({
      severity: SeverityHigh,
      code: "sensitive-wildcard",
      feature: Some(directive.feature),
      message: "sensitive browser capability is allowed for every origin",
    })
  }
  for token in directive.tokens {
    match token {
      TokenOrigin(origin) =>
        if insecure_external_origin(origin) {
          findings.push({
            severity: SeverityWarning,
            code: "insecure-origin",
            feature: Some(directive.feature),
            message: "allowlist origin should use HTTPS unless it is localhost",
          })
        }
      _ => ()
    }
  }
}

///|
fn has_wildcard(tokens : Array[AllowToken]) -> Bool {
  for token in tokens {
    if token == TokenAll {
      return true
    }
  }
  false
}

///|
fn has_high(findings : Array[Finding]) -> Bool {
  for finding in findings {
    if finding.severity == SeverityHigh {
      return true
    }
  }
  false
}

///|
fn feature_in(features : Array[String], feature : String) -> Bool {
  for candidate in features {
    if normalize_feature(candidate) == feature {
      return true
    }
  }
  false
}

///|
fn insecure_external_origin(origin : String) -> Bool {
  let clean = normalize_origin(origin)
  clean.has_prefix("http://") &&
  !clean.has_prefix("http://localhost") &&
  !clean.has_prefix("http://127.0.0.1")
}

///|
fn severity_label(severity : Severity) -> String {
  match severity {
    SeverityInfo => "info"
    SeverityWarning => "warning"
    SeverityHigh => "high"
  }
}

///|
fn joined_header_value(
  headers : HeaderSet,
  kind : HeaderKind,
  separator : String,
) -> String? {
  let values : Array[String] = []
  for line in headers.lines {
    if line.kind == kind {
      values.push(line.value)
    }
  }
  if values.length() == 0 {
    None
  } else {
    Some(values.join(separator))
  }
}

///|
fn prepend_warnings(policy : Policy, warnings : Array[ParseWarning]) -> Policy {
  if warnings.length() == 0 {
    return policy
  }
  let merged : Array[ParseWarning] = []
  for warning in warnings {
    merged.push(warning)
  }
  for warning in policy.warnings {
    merged.push(warning)
  }
  { directives: policy.directives, warnings: merged, }
}

///|
fn normalize_header_name(value : String) -> String {
  trim(value).to_lower()
}

///|
fn classify_header_name(name : String) -> HeaderKind {
  match normalize_header_name(name) {
    "permissions-policy" => HeaderPermissionsPolicy
    "feature-policy" => HeaderFeaturePolicy
    _ => HeaderOther
  }
}

///|
fn has_feature(directives : Array[Directive], feature : String) -> Bool {
  for directive in directives {
    if directive.feature == feature {
      return true
    }
  }
  false
}

///|
fn normalize_feature(value : String) -> String {
  trim(value).to_lower()
}

///|
fn normalize_origin(value : String) -> String {
  let clean = strip_quotes(trim(value)).to_lower()
  if clean.has_suffix("/") {
    clean[:clean.length() - 1].to_owned()
  } else {
    clean
  }
}

///|
fn strip_quotes(value : String) -> String {
  let clean = trim(value)
  if clean.length() >= 2 &&
    (
      (clean.has_prefix("\"") && clean.has_suffix("\"")) ||
      (clean.has_prefix("'") && clean.has_suffix("'"))
    ) {
    clean[1:clean.length() - 1].to_owned()
  } else {
    clean
  }
}

///|
fn origin_like(value : String) -> Bool {
  value.has_prefix("https://") ||
  value.has_prefix("http://localhost") ||
  value.has_prefix("http://127.0.0.1")
}

///|
fn feature_name_ok(feature : String) -> Bool {
  if feature == "" {
    return false
  }
  for ch in feature {
    if ch == '-' || ch.is_ascii_digit() {
      continue
    }
    let piece = ch.to_string()
    if piece < "a" || piece > "z" {
      return false
    }
  }
  true
}

///|
fn trim(value : String) -> String {
  value.trim(chars=" \t\r\n").to_owned()
}
