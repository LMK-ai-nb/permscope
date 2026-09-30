///|
/// One parsed Content-Security-Policy directive.
pub struct CspDirective {
  name : String
  values : Array[String]
  raw : String
  index : Int
} derive(Eq, @debug.Debug)

///|
/// Parsed Content-Security-Policy header.
pub struct CspPolicy {
  directives : Array[CspDirective]
  warnings : Array[ParseWarning]
} derive(Eq, @debug.Debug)

///|
/// Compact Content-Security-Policy summary.
pub struct CspSummary {
  directive_count : Int
  source_directives : Int
  wildcard_sources : Int
  unsafe_inline : Int
  unsafe_eval : Int
  nonce_sources : Int
  hash_sources : Int
  insecure_sources : Int
  missing_core : Array[String]
} derive(Eq, @debug.Debug)

///|
/// One interpreted CSP source expression.
pub struct SourceExpression {
  value : String
  kind : String
  secure : Bool
  wildcard : Bool
} derive(Eq, @debug.Debug)

///|
/// Result of auditing one security header family.
pub struct HeaderCheck {
  header : String
  present : Bool
  score : Int
  max_score : Int
  findings : Array[Finding]
  observed : String
  recommended : String
} derive(Eq, @debug.Debug)

///|
/// Aggregated security score for a response.
pub struct SecurityScore {
  points : Int
  max_points : Int
  percent : Int
  grade : String
  high : Int
  warning : Int
  info : Int
} derive(Eq, @debug.Debug)

///|
/// Full response security-header audit.
pub struct SecurityAudit {
  headers : HeaderSet
  csp : CspPolicy?
  permissions : HeaderAudit
  checks : Array[HeaderCheck]
  score : SecurityScore
} derive(Eq, @debug.Debug)

///|
/// Summary of findings grouped by severity.
pub struct SecurityFindingSummary {
  total : Int
  high : Int
  warning : Int
  info : Int
  high_codes : Array[String]
  warning_codes : Array[String]
  info_codes : Array[String]
} derive(Eq, @debug.Debug)

///|
/// Human-facing recommendation for a security header.
pub struct HeaderRecommendation {
  header : String
  value : String
  reason : String
  priority : String
} derive(Eq, @debug.Debug)

///|
/// Return the core response security headers that `permscope` can audit.
pub fn security_header_names() -> Array[String] {
  [
    "content-security-policy", "strict-transport-security", "permissions-policy",
    "referrer-policy", "x-frame-options", "x-content-type-options", "cross-origin-opener-policy",
    "cross-origin-embedder-policy", "cross-origin-resource-policy",
  ]
}

///|
/// Return the CSP source directives handled by the simplified CSP auditor.
pub fn csp_source_directive_names() -> Array[String] {
  [
    "default-src", "script-src", "style-src", "img-src", "connect-src", "font-src",
    "object-src", "base-uri", "frame-ancestors", "form-action", "worker-src", "media-src",
    "manifest-src", "child-src", "frame-src",
  ]
}

///|
/// Return the core CSP directives expected for public web applications.
pub fn csp_core_directives() -> Array[String] {
  [
    "default-src", "script-src", "object-src", "base-uri", "frame-ancestors", "form-action",
  ]
}

///|
/// Parse a Content-Security-Policy header.
pub fn parse_csp(header : String) -> CspPolicy {
  let directives : Array[CspDirective] = []
  let warnings : Array[ParseWarning] = []
  let clean = trim(header)
  if clean == "" {
    warnings.push({ index: 0, message: "empty csp header", text: header, })
    return { directives, warnings, }
  }
  let mut index = 0
  for part_view in clean.split(";") {
    index = index + 1
    let part = trim(part_view.to_owned())
    if part == "" {
      continue
    }
    match parse_csp_directive(part, index, warnings) {
      None => ()
      Some(directive) => {
        if csp_has_directive(directives, directive.name) {
          warnings.push({
            index,
            message: "duplicate csp directive: " + directive.name,
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
/// Return a CSP directive by name.
pub fn csp_directive(policy : CspPolicy, name : String) -> CspDirective? {
  let wanted = normalize_csp_name(name)
  for directive in policy.directives {
    if directive.name == wanted {
      return Some(directive)
    }
  }
  None
}

///|
/// Return values for a CSP directive, falling back where CSP semantics expect it.
pub fn csp_effective_values(policy : CspPolicy, name : String) -> Array[String] {
  let wanted = normalize_csp_name(name)
  match csp_directive(policy, wanted) {
    Some(directive) => directive.values
    None =>
      match csp_fallback_directive(wanted) {
        Some(fallback) =>
          match csp_directive(policy, fallback) {
            Some(directive) => directive.values
            None => []
          }
        None => []
      }
  }
}

///|
/// Check whether a CSP directive contains a source expression.
pub fn csp_has_source(
  policy : CspPolicy,
  directive : String,
  source : String,
) -> Bool {
  let wanted = normalize_csp_source(source)
  for value in csp_effective_values(policy, directive) {
    if normalize_csp_source(value) == wanted {
      return true
    }
  }
  false
}

///|
/// Check whether inline scripts are allowed.
pub fn csp_allows_inline_script(policy : CspPolicy) -> Bool {
  csp_has_source(policy, "script-src", "'unsafe-inline'")
}

///|
/// Check whether dynamic code evaluation is allowed.
pub fn csp_allows_eval(policy : CspPolicy) -> Bool {
  csp_has_source(policy, "script-src", "'unsafe-eval'")
}

///|
/// Check whether a directive has a nonce or hash source.
pub fn csp_has_nonce_or_hash(policy : CspPolicy, directive : String) -> Bool {
  for value in csp_effective_values(policy, directive) {
    let normalized = normalize_csp_source(value)
    if csp_source_is_nonce(normalized) || csp_source_is_hash(normalized) {
      return true
    }
  }
  false
}

///|
/// Return fallback chain used by this package for a source directive.
pub fn csp_fallback_chain(name : String) -> Array[String] {
  let result : Array[String] = []
  let normalized = normalize_csp_name(name)
  result.push(normalized)
  match csp_fallback_directive(normalized) {
    Some(fallback) => result.push(fallback)
    None => ()
  }
  result
}

///|
/// Interpret one CSP source expression.
pub fn csp_source_expression(value : String) -> SourceExpression {
  let normalized = normalize_csp_source(value)
  {
    value: normalized,
    kind: csp_source_kind(normalized),
    secure: csp_source_secure(normalized),
    wildcard: csp_source_wildcard(normalized),
  }
}

///|
/// Interpret every source expression in a directive.
pub fn csp_sources(
  policy : CspPolicy,
  directive : String,
) -> Array[SourceExpression] {
  let sources : Array[SourceExpression] = []
  for value in csp_effective_values(policy, directive) {
    sources.push(csp_source_expression(value))
  }
  sources
}

///|
/// Render CSP back to normalized syntax.
pub fn render_csp(policy : CspPolicy) -> String {
  let parts : Array[String] = []
  for directive in policy.directives {
    if directive.values.length() == 0 {
      parts.push(directive.name)
    } else {
      parts.push(directive.name + " " + directive.values.join(" "))
    }
  }
  parts.join("; ")
}

///|
/// Summarize a CSP policy for dashboards and release notes.
pub fn summarize_csp(policy : CspPolicy) -> CspSummary {
  let missing_core : Array[String] = []
  let mut source_directives = 0
  let mut wildcard_sources = 0
  let mut unsafe_inline = 0
  let mut unsafe_eval = 0
  let mut nonce_sources = 0
  let mut hash_sources = 0
  let mut insecure_sources = 0
  for directive in policy.directives {
    if csp_is_source_directive(directive.name) {
      source_directives = source_directives + 1
    }
    for value in directive.values {
      let source = csp_source_expression(value)
      if source.wildcard {
        wildcard_sources = wildcard_sources + 1
      }
      if source.value == "'unsafe-inline'" {
        unsafe_inline = unsafe_inline + 1
      }
      if source.value == "'unsafe-eval'" {
        unsafe_eval = unsafe_eval + 1
      }
      if csp_source_is_nonce(source.value) {
        nonce_sources = nonce_sources + 1
      }
      if csp_source_is_hash(source.value) {
        hash_sources = hash_sources + 1
      }
      if !source.secure {
        insecure_sources = insecure_sources + 1
      }
    }
  }
  for required in csp_core_directives() {
    if csp_directive(policy, required) is None {
      missing_core.push(required)
    }
  }
  {
    directive_count: policy.directives.length(),
    source_directives,
    wildcard_sources,
    unsafe_inline,
    unsafe_eval,
    nonce_sources,
    hash_sources,
    insecure_sources,
    missing_core,
  }
}

///|
/// Render a compact CSP summary.
pub fn render_csp_summary(summary : CspSummary) -> String {
  "csp directives=" +
  summary.directive_count.to_string() +
  " source=" +
  summary.source_directives.to_string() +
  " wildcard=" +
  summary.wildcard_sources.to_string() +
  " unsafe_inline=" +
  summary.unsafe_inline.to_string() +
  " unsafe_eval=" +
  summary.unsafe_eval.to_string() +
  " nonce=" +
  summary.nonce_sources.to_string() +
  " hash=" +
  summary.hash_sources.to_string() +
  " insecure=" +
  summary.insecure_sources.to_string() +
  " missing=" +
  summary.missing_core.join("|")
}

///|
/// Audit a Content-Security-Policy header.
pub fn audit_csp(policy : CspPolicy) -> AuditReport {
  let findings : Array[Finding] = []
  if policy.directives.length() == 0 {
    findings.push({
      severity: SeverityHigh,
      code: "missing-csp",
      feature: Some("content-security-policy"),
      message: "Content-Security-Policy header is missing or empty",
    })
  }
  for warning in policy.warnings {
    findings.push({
      severity: SeverityWarning,
      code: "csp-parse-warning",
      feature: None,
      message: "segment " + warning.index.to_string() + ": " + warning.message,
    })
  }
  audit_csp_required(policy, findings)
  audit_csp_script(policy, findings)
  audit_csp_style(policy, findings)
  audit_csp_objects(policy, findings)
  audit_csp_frames(policy, findings)
  audit_csp_network(policy, findings)
  audit_csp_insecure_sources(policy, findings)
  if findings.length() == 0 {
    findings.push({
      severity: SeverityInfo,
      code: "csp-baseline-satisfied",
      feature: Some("content-security-policy"),
      message: "CSP satisfies the built-in baseline",
    })
  }
  { ok: !has_high(findings), findings, }
}

///|
/// Render a CSP audit report with a CSP-specific heading.
pub fn render_csp_audit(report : AuditReport) -> String {
  "permscope csp audit\n" + render_report(report)
}

///|
/// Build a strict starter Content-Security-Policy for static applications.
pub fn strict_csp_header() -> String {
  [
    "default-src 'self'", "script-src 'self'", "style-src 'self'", "img-src 'self' data:",
    "font-src 'self'", "connect-src 'self'", "object-src 'none'", "base-uri 'self'",
    "frame-ancestors 'none'", "form-action 'self'", "upgrade-insecure-requests",
  ].join("; ")
}

///|
/// Build a CSP for an app that needs selected trusted API and media origins.
pub fn app_csp_header(
  api_origins : Array[String],
  media_origins : Array[String],
) -> String {
  let connect_values : Array[String] = ["'self'"]
  for origin in api_origins {
    connect_values.push(normalize_csp_source(origin))
  }
  let media_values : Array[String] = ["'self'"]
  for origin in media_origins {
    media_values.push(normalize_csp_source(origin))
  }
  [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data: " + media_values.join(" "),
    "font-src 'self'",
    "connect-src " + connect_values.join(" "),
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join("; ")
}

///|
/// Audit a raw HTTP response header block for multiple security headers.
pub fn audit_security_header_block(
  block : String,
  document_origin : String,
) -> SecurityAudit {
  let headers = parse_header_block(block)
  audit_security_headers(headers, document_origin)
}

///|
/// Audit parsed HTTP response headers for multiple security headers.
pub fn audit_security_headers(
  headers : HeaderSet,
  document_origin : String,
) -> SecurityAudit {
  let csp_value = header_value(headers, "content-security-policy")
  let csp_policy = match csp_value {
    Some(value) => Some(parse_csp(value))
    None => None
  }
  let permissions = audit_header_set_permissions(
    headers,
    catalog_baseline(document_origin),
  )
  let checks : Array[HeaderCheck] = []
  checks.push(check_content_security_policy(csp_policy))
  checks.push(check_strict_transport_security(headers))
  checks.push(check_permissions_policy(permissions))
  checks.push(check_referrer_policy(headers))
  checks.push(check_x_frame_options(headers))
  checks.push(check_x_content_type_options(headers))
  checks.push(check_cross_origin_opener_policy(headers))
  checks.push(check_cross_origin_embedder_policy(headers))
  checks.push(check_cross_origin_resource_policy(headers))
  let score = score_security_checks(checks)
  { headers, csp: csp_policy, permissions, checks, score, }
}

///|
/// Return a check by header name.
pub fn security_check(audit : SecurityAudit, header : String) -> HeaderCheck? {
  let wanted = normalize_header_lookup(header)
  for check in audit.checks {
    if normalize_header_lookup(check.header) == wanted {
      return Some(check)
    }
  }
  None
}

///|
/// Render one header check.
pub fn render_header_check(check : HeaderCheck) -> String {
  let lines : Array[String] = []
  let present = if check.present { "present" } else { "missing" }
  lines.push(
    check.header +
    " " +
    present +
    " score=" +
    check.score.to_string() +
    "/" +
    check.max_score.to_string(),
  )
  if check.observed != "" {
    lines.push("observed=" + check.observed)
  }
  if check.recommended != "" {
    lines.push("recommended=" + check.recommended)
  }
  for finding in check.findings {
    lines.push(render_finding_line(finding))
  }
  lines.join("\n")
}

///|
/// Render a full security-header audit as plain text.
pub fn render_security_audit(audit : SecurityAudit) -> String {
  let lines : Array[String] = []
  lines.push("permscope security audit")
  lines.push(render_security_score(audit.score))
  for check in audit.checks {
    lines.push(render_header_check(check))
  }
  lines.join("\n")
}

///|
/// Render an audit score.
pub fn render_security_score(score : SecurityScore) -> String {
  "score " +
  score.points.to_string() +
  "/" +
  score.max_points.to_string() +
  " percent=" +
  score.percent.to_string() +
  " grade=" +
  score.grade +
  " high=" +
  score.high.to_string() +
  " warning=" +
  score.warning.to_string() +
  " info=" +
  score.info.to_string()
}

///|
/// Render a Markdown report for issue comments or release notes.
pub fn render_security_markdown(audit : SecurityAudit) -> String {
  let lines : Array[String] = []
  lines.push("# permscope security audit")
  lines.push("")
  lines.push(
    "- Score: " +
    audit.score.points.to_string() +
    "/" +
    audit.score.max_points.to_string(),
  )
  lines.push("- Percent: " + audit.score.percent.to_string())
  lines.push("- Grade: " + audit.score.grade)
  lines.push("- High findings: " + audit.score.high.to_string())
  lines.push("- Warning findings: " + audit.score.warning.to_string())
  lines.push("")
  lines.push("| Header | Present | Score | Findings |")
  lines.push("| --- | --- | ---: | ---: |")
  for check in audit.checks {
    lines.push(
      "| " +
      check.header +
      " | " +
      bool_word(check.present) +
      " | " +
      check.score.to_string() +
      "/" +
      check.max_score.to_string() +
      " | " +
      check.findings.length().to_string() +
      " |",
    )
  }
  lines.push("")
  for check in audit.checks {
    lines.push("## " + check.header)
    lines.push("")
    lines.push("- Observed: `" + markdown_inline(check.observed) + "`")
    lines.push("- Recommended: `" + markdown_inline(check.recommended) + "`")
    for finding in check.findings {
      lines.push(
        "- " +
        severity_label(finding.severity) +
        ": " +
        finding.code +
        " - " +
        finding.message,
      )
    }
    lines.push("")
  }
  lines.join("\n")
}

///|
/// Render a deterministic JSON-like text report without external dependencies.
pub fn render_security_json(audit : SecurityAudit) -> String {
  let lines : Array[String] = []
  lines.push("{")
  lines.push("  \"score\": {")
  lines.push("    \"points\": " + audit.score.points.to_string() + ",")
  lines.push("    \"max_points\": " + audit.score.max_points.to_string() + ",")
  lines.push("    \"percent\": " + audit.score.percent.to_string() + ",")
  lines.push("    \"grade\": \"" + audit.score.grade + "\",")
  lines.push("    \"high\": " + audit.score.high.to_string() + ",")
  lines.push("    \"warning\": " + audit.score.warning.to_string() + ",")
  lines.push("    \"info\": " + audit.score.info.to_string())
  lines.push("  },")
  lines.push("  \"checks\": [")
  let mut index = 0
  for check in audit.checks {
    index = index + 1
    lines.push("    {")
    lines.push("      \"header\": \"" + json_escape(check.header) + "\",")
    lines.push("      \"present\": " + check.present.to_string() + ",")
    lines.push("      \"score\": " + check.score.to_string() + ",")
    lines.push("      \"max_score\": " + check.max_score.to_string() + ",")
    lines.push("      \"observed\": \"" + json_escape(check.observed) + "\",")
    lines.push(
      "      \"recommended\": \"" + json_escape(check.recommended) + "\",",
    )
    lines.push("      \"findings\": " + check.findings.length().to_string())
    if index == audit.checks.length() {
      lines.push("    }")
    } else {
      lines.push("    },")
    }
  }
  lines.push("  ]")
  lines.push("}")
  lines.join("\n")
}

///|
/// Summarize findings across every header check.
pub fn summarize_security_findings(
  audit : SecurityAudit,
) -> SecurityFindingSummary {
  let high_codes : Array[String] = []
  let warning_codes : Array[String] = []
  let info_codes : Array[String] = []
  let mut total = 0
  let mut high = 0
  let mut warning = 0
  let mut info = 0
  for check in audit.checks {
    for finding in check.findings {
      total = total + 1
      match finding.severity {
        SeverityHigh => {
          high = high + 1
          push_unique(high_codes, finding.code)
        }
        SeverityWarning => {
          warning = warning + 1
          push_unique(warning_codes, finding.code)
        }
        SeverityInfo => {
          info = info + 1
          push_unique(info_codes, finding.code)
        }
      }
    }
  }
  { total, high, warning, info, high_codes, warning_codes, info_codes, }
}

///|
/// Return findings that match a severity label.
pub fn security_findings_by_severity(
  audit : SecurityAudit,
  severity : String,
) -> Array[Finding] {
  let findings : Array[Finding] = []
  let wanted = severity.to_lower()
  for check in audit.checks {
    for finding in check.findings {
      if severity_label(finding.severity) == wanted {
        findings.push(finding)
      }
    }
  }
  findings
}

///|
/// Return unique finding codes across the audit.
pub fn security_finding_codes(audit : SecurityAudit) -> Array[String] {
  let codes : Array[String] = []
  for check in audit.checks {
    for finding in check.findings {
      push_unique(codes, finding.code)
    }
  }
  codes
}

///|
/// Render finding summary as stable line-oriented text.
pub fn render_security_finding_summary(
  summary : SecurityFindingSummary,
) -> String {
  "findings total=" +
  summary.total.to_string() +
  " high=" +
  summary.high.to_string() +
  " warning=" +
  summary.warning.to_string() +
  " info=" +
  summary.info.to_string() +
  " high_codes=" +
  summary.high_codes.join("|") +
  " warning_codes=" +
  summary.warning_codes.join("|") +
  " info_codes=" +
  summary.info_codes.join("|")
}

///|
/// Render a compact table-like check list for CI logs.
pub fn render_security_check_table(audit : SecurityAudit) -> String {
  let lines : Array[String] = []
  lines.push("header present score severity")
  for check in audit.checks {
    lines.push(
      check.header +
      " " +
      bool_word(check.present) +
      " " +
      check.score.to_string() +
      "/" +
      check.max_score.to_string() +
      " " +
      header_check_severity(check),
    )
  }
  lines.join("\n")
}

///|
/// Return fix recommendations for missing or weak headers.
pub fn security_recommendations(
  audit : SecurityAudit,
) -> Array[HeaderRecommendation] {
  let recommendations : Array[HeaderRecommendation] = []
  for check in audit.checks {
    if check.score < check.max_score {
      recommendations.push({
        header: check.header,
        value: check.recommended,
        reason: recommendation_reason(check),
        priority: recommendation_priority(check),
      })
    }
  }
  recommendations
}

///|
/// Render fix recommendations as line-oriented text.
pub fn render_security_recommendations(
  recommendations : Array[HeaderRecommendation],
) -> String {
  if recommendations.length() == 0 {
    return "permscope recommendations: no changes"
  }
  let lines : Array[String] = ["permscope recommendations:"]
  for item in recommendations {
    lines.push(
      item.priority +
      " " +
      item.header +
      " -> " +
      item.value +
      " - " +
      item.reason,
    )
  }
  lines.join("\n")
}

///|
/// Return the highest severity in a check.
pub fn header_check_severity(check : HeaderCheck) -> String {
  let mut high = false
  let mut warning = false
  for finding in check.findings {
    match finding.severity {
      SeverityHigh => high = true
      SeverityWarning => warning = true
      SeverityInfo => ()
    }
  }
  if high {
    "high"
  } else if warning {
    "warning"
  } else {
    "info"
  }
}

///|
/// Return whether an audit meets a minimum grade.
pub fn security_grade_at_least(audit : SecurityAudit, grade : String) -> Bool {
  grade_rank(audit.score.grade) <= grade_rank(grade)
}

///|
/// Return whether an audit has no high-severity findings.
pub fn security_has_no_high(audit : SecurityAudit) -> Bool {
  audit.score.high == 0
}

///|
/// Return a stable list of default secure header recommendations.
pub fn default_security_recommendations() -> Array[HeaderRecommendation] {
  [
    {
      header: "Content-Security-Policy",
      value: strict_csp_header(),
      reason: "limits script, object, frame, form, and network capabilities",
      priority: "high",
    },
    {
      header: "Strict-Transport-Security",
      value: "max-age=31536000; includeSubDomains; preload",
      reason: "keeps browsers on HTTPS and enables preload readiness",
      priority: "high",
    },
    {
      header: "Permissions-Policy",
      value: recommended_header(),
      reason: "disables sensitive browser capabilities by default",
      priority: "high",
    },
    {
      header: "Referrer-Policy",
      value: "strict-origin-when-cross-origin",
      reason: "reduces cross-site URL leakage while preserving useful origins",
      priority: "warning",
    },
    {
      header: "X-Frame-Options",
      value: "DENY",
      reason: "blocks legacy clickjacking vectors",
      priority: "warning",
    },
    {
      header: "X-Content-Type-Options",
      value: "nosniff",
      reason: "prevents MIME type sniffing",
      priority: "warning",
    },
    {
      header: "Cross-Origin-Opener-Policy",
      value: "same-origin",
      reason: "isolates the browsing context group",
      priority: "warning",
    },
    {
      header: "Cross-Origin-Embedder-Policy",
      value: "require-corp",
      reason: "requires explicit opt-in for cross-origin embeds",
      priority: "warning",
    },
    {
      header: "Cross-Origin-Resource-Policy",
      value: "same-origin",
      reason: "limits who can load the response as a subresource",
      priority: "warning",
    },
  ]
}

///|
fn parse_csp_directive(
  part : String,
  index : Int,
  warnings : Array[ParseWarning],
) -> CspDirective? {
  let tokens = split_words(part)
  if tokens.length() == 0 {
    warnings.push({ index, message: "empty csp directive", text: part, })
    return None
  }
  let name = normalize_csp_name(tokens[0])
  if !csp_name_ok(name) {
    warnings.push({
      index,
      message: "csp directive name contains unusual characters",
      text: part,
    })
  }
  let values : Array[String] = []
  let mut i = 1
  while i < tokens.length() {
    values.push(normalize_csp_source(tokens[i]))
    i = i + 1
  }
  Some({ name, values, raw: part, index, })
}

///|
fn audit_csp_required(policy : CspPolicy, findings : Array[Finding]) -> Unit {
  for required in csp_core_directives() {
    if csp_directive(policy, required) is None {
      findings.push({
        severity: csp_required_severity(required),
        code: "csp-missing-directive",
        feature: Some(required),
        message: "recommended CSP directive is missing",
      })
    }
  }
}

///|
fn audit_csp_script(policy : CspPolicy, findings : Array[Finding]) -> Unit {
  if csp_allows_inline_script(policy) &&
    !csp_has_nonce_or_hash(policy, "script-src") {
    findings.push({
      severity: SeverityHigh,
      code: "csp-unsafe-inline-script",
      feature: Some("script-src"),
      message: "script-src allows unsafe-inline without a nonce or hash",
    })
  }
  if csp_allows_eval(policy) {
    findings.push({
      severity: SeverityHigh,
      code: "csp-unsafe-eval",
      feature: Some("script-src"),
      message: "script-src allows unsafe-eval",
    })
  }
  if csp_has_source(policy, "script-src", "*") {
    findings.push({
      severity: SeverityHigh,
      code: "csp-script-wildcard",
      feature: Some("script-src"),
      message: "script-src allows every origin",
    })
  }
  if csp_has_source(policy, "script-src", "http:") {
    findings.push({
      severity: SeverityHigh,
      code: "csp-script-http",
      feature: Some("script-src"),
      message: "script-src allows insecure HTTP scheme",
    })
  }
}

///|
fn audit_csp_style(policy : CspPolicy, findings : Array[Finding]) -> Unit {
  if csp_has_source(policy, "style-src", "'unsafe-inline'") &&
    !csp_has_nonce_or_hash(policy, "style-src") {
    findings.push({
      severity: SeverityWarning,
      code: "csp-unsafe-inline-style",
      feature: Some("style-src"),
      message: "style-src allows unsafe-inline without a nonce or hash",
    })
  }
  if csp_has_source(policy, "style-src", "*") {
    findings.push({
      severity: SeverityWarning,
      code: "csp-style-wildcard",
      feature: Some("style-src"),
      message: "style-src allows every origin",
    })
  }
}

///|
fn audit_csp_objects(policy : CspPolicy, findings : Array[Finding]) -> Unit {
  if !csp_has_source(policy, "object-src", "'none'") {
    findings.push({
      severity: SeverityHigh,
      code: "csp-object-src-not-none",
      feature: Some("object-src"),
      message: "object-src should be 'none'",
    })
  }
  if csp_has_source(policy, "base-uri", "*") ||
    csp_directive(policy, "base-uri") is None {
    findings.push({
      severity: SeverityWarning,
      code: "csp-base-uri-weak",
      feature: Some("base-uri"),
      message: "base-uri should usually be 'self' or 'none'",
    })
  }
}

///|
fn audit_csp_frames(policy : CspPolicy, findings : Array[Finding]) -> Unit {
  if csp_directive(policy, "frame-ancestors") is None {
    findings.push({
      severity: SeverityHigh,
      code: "csp-frame-ancestors-missing",
      feature: Some("frame-ancestors"),
      message: "frame-ancestors is missing, leaving clickjacking protection to legacy headers",
    })
  } else if csp_has_source(policy, "frame-ancestors", "*") {
    findings.push({
      severity: SeverityHigh,
      code: "csp-frame-ancestors-wildcard",
      feature: Some("frame-ancestors"),
      message: "frame-ancestors allows every origin",
    })
  }
  if csp_directive(policy, "form-action") is None {
    findings.push({
      severity: SeverityWarning,
      code: "csp-form-action-missing",
      feature: Some("form-action"),
      message: "form-action is missing",
    })
  }
}

///|
fn audit_csp_network(policy : CspPolicy, findings : Array[Finding]) -> Unit {
  if csp_has_source(policy, "connect-src", "*") {
    findings.push({
      severity: SeverityWarning,
      code: "csp-connect-wildcard",
      feature: Some("connect-src"),
      message: "connect-src allows every origin",
    })
  }
  if csp_has_source(policy, "img-src", "*") {
    findings.push({
      severity: SeverityWarning,
      code: "csp-img-wildcard",
      feature: Some("img-src"),
      message: "img-src allows every origin",
    })
  }
}

///|
fn audit_csp_insecure_sources(
  policy : CspPolicy,
  findings : Array[Finding],
) -> Unit {
  for directive in policy.directives {
    for value in directive.values {
      let source = csp_source_expression(value)
      if !source.secure {
        findings.push({
          severity: SeverityWarning,
          code: "csp-insecure-source",
          feature: Some(directive.name),
          message: "source expression is not HTTPS, self, nonce, hash, data, or none: " +
          source.value,
        })
      }
    }
  }
}

///|
fn check_content_security_policy(csp : CspPolicy?) -> HeaderCheck {
  let recommended = strict_csp_header()
  match csp {
    None => {
      let findings : Array[Finding] = [
        {
          severity: SeverityHigh,
          code: "missing-content-security-policy",
          feature: Some("content-security-policy"),
          message: "Content-Security-Policy is missing",
        },
      ]
      {
        header: "Content-Security-Policy",
        present: false,
        score: 0,
        max_score: 20,
        findings,
        observed: "",
        recommended,
      }
    }
    Some(policy) => {
      let report = audit_csp(policy)
      {
        header: "Content-Security-Policy",
        present: true,
        score: score_from_report(report, 20),
        max_score: 20,
        findings: report.findings,
        observed: render_csp(policy),
        recommended,
      }
    }
  }
}

///|
fn check_strict_transport_security(headers : HeaderSet) -> HeaderCheck {
  let value = header_value(headers, "strict-transport-security").unwrap_or("")
  let findings : Array[Finding] = []
  let recommended = "max-age=31536000; includeSubDomains; preload"
  let mut score = 0
  if value == "" {
    findings.push({
      severity: SeverityHigh,
      code: "missing-hsts",
      feature: Some("strict-transport-security"),
      message: "Strict-Transport-Security is missing",
    })
  } else {
    let normalized = value.to_lower()
    let max_age = header_parameter(normalized, "max-age")
    match max_age {
      None =>
        findings.push({
          severity: SeverityHigh,
          code: "hsts-missing-max-age",
          feature: Some("strict-transport-security"),
          message: "HSTS does not declare max-age",
        })
      Some(age) => {
        let seconds = parse_decimal(age)
        if seconds >= 31536000 {
          score = score + 7
        } else if seconds >= 10886400 {
          score = score + 4
          findings.push({
            severity: SeverityWarning,
            code: "hsts-short-max-age",
            feature: Some("strict-transport-security"),
            message: "HSTS max-age is shorter than one year",
          })
        } else {
          findings.push({
            severity: SeverityHigh,
            code: "hsts-too-short",
            feature: Some("strict-transport-security"),
            message: "HSTS max-age is too short for production",
          })
        }
      }
    }
    if normalized.contains("includesubdomains") {
      score = score + 2
    } else {
      findings.push({
        severity: SeverityWarning,
        code: "hsts-no-subdomains",
        feature: Some("strict-transport-security"),
        message: "HSTS does not include subdomains",
      })
    }
    if normalized.contains("preload") {
      score = score + 1
    }
  }
  {
    header: "Strict-Transport-Security",
    present: value != "",
    score,
    max_score: 10,
    findings,
    observed: value,
    recommended,
  }
}

///|
fn check_permissions_policy(audit : HeaderAudit) -> HeaderCheck {
  let value = render(audit.effective)
  {
    header: "Permissions-Policy",
    present: audit.effective.directives.length() > 0,
    score: score_from_report(audit.report, 15),
    max_score: 15,
    findings: audit.report.findings,
    observed: value,
    recommended: recommended_header(),
  }
}

///|
fn check_referrer_policy(headers : HeaderSet) -> HeaderCheck {
  let value = header_value(headers, "referrer-policy").unwrap_or("")
  let normalized = value.to_lower()
  let findings : Array[Finding] = []
  let mut score = 0
  if value == "" {
    findings.push({
      severity: SeverityWarning,
      code: "missing-referrer-policy",
      feature: Some("referrer-policy"),
      message: "Referrer-Policy is missing",
    })
  } else if referrer_policy_strong(normalized) {
    score = 8
  } else if referrer_policy_acceptable(normalized) {
    score = 5
    findings.push({
      severity: SeverityInfo,
      code: "referrer-policy-acceptable",
      feature: Some("referrer-policy"),
      message: "Referrer-Policy is usable but not the strictest choice",
    })
  } else {
    findings.push({
      severity: SeverityWarning,
      code: "referrer-policy-weak",
      feature: Some("referrer-policy"),
      message: "Referrer-Policy may leak more URL data than necessary",
    })
  }
  {
    header: "Referrer-Policy",
    present: value != "",
    score,
    max_score: 8,
    findings,
    observed: value,
    recommended: "strict-origin-when-cross-origin",
  }
}

///|
fn check_x_frame_options(headers : HeaderSet) -> HeaderCheck {
  let value = header_value(headers, "x-frame-options").unwrap_or("")
  let normalized = value.to_lower()
  let findings : Array[Finding] = []
  let mut score = 0
  if value == "" {
    findings.push({
      severity: SeverityWarning,
      code: "missing-x-frame-options",
      feature: Some("x-frame-options"),
      message: "X-Frame-Options is missing for legacy browser protection",
    })
  } else if normalized == "deny" || normalized == "sameorigin" {
    score = 6
  } else {
    findings.push({
      severity: SeverityWarning,
      code: "x-frame-options-weak",
      feature: Some("x-frame-options"),
      message: "X-Frame-Options should be DENY or SAMEORIGIN",
    })
  }
  {
    header: "X-Frame-Options",
    present: value != "",
    score,
    max_score: 6,
    findings,
    observed: value,
    recommended: "DENY",
  }
}

///|
fn check_x_content_type_options(headers : HeaderSet) -> HeaderCheck {
  let value = header_value(headers, "x-content-type-options").unwrap_or("")
  let findings : Array[Finding] = []
  let mut score = 0
  if value.to_lower() == "nosniff" {
    score = 6
  } else if value == "" {
    findings.push({
      severity: SeverityWarning,
      code: "missing-x-content-type-options",
      feature: Some("x-content-type-options"),
      message: "X-Content-Type-Options is missing",
    })
  } else {
    findings.push({
      severity: SeverityWarning,
      code: "x-content-type-options-invalid",
      feature: Some("x-content-type-options"),
      message: "X-Content-Type-Options should be nosniff",
    })
  }
  {
    header: "X-Content-Type-Options",
    present: value != "",
    score,
    max_score: 6,
    findings,
    observed: value,
    recommended: "nosniff",
  }
}

///|
fn check_cross_origin_opener_policy(headers : HeaderSet) -> HeaderCheck {
  check_token_header(
    headers,
    "Cross-Origin-Opener-Policy",
    "same-origin",
    ["same-origin"],
    5,
    "missing-coop",
    "COOP is missing",
  )
}

///|
fn check_cross_origin_embedder_policy(headers : HeaderSet) -> HeaderCheck {
  check_token_header(
    headers,
    "Cross-Origin-Embedder-Policy",
    "require-corp",
    ["require-corp", "credentialless"],
    5,
    "missing-coep",
    "COEP is missing",
  )
}

///|
fn check_cross_origin_resource_policy(headers : HeaderSet) -> HeaderCheck {
  check_token_header(
    headers,
    "Cross-Origin-Resource-Policy",
    "same-origin",
    ["same-origin", "same-site"],
    5,
    "missing-corp",
    "CORP is missing",
  )
}

///|
fn check_token_header(
  headers : HeaderSet,
  display_name : String,
  recommended : String,
  accepted : Array[String],
  max_score : Int,
  missing_code : String,
  missing_message : String,
) -> HeaderCheck {
  let value = header_value(headers, display_name).unwrap_or("")
  let normalized = value.to_lower()
  let findings : Array[Finding] = []
  let mut score = 0
  if value == "" {
    findings.push({
      severity: SeverityWarning,
      code: missing_code,
      feature: Some(display_name.to_lower()),
      message: missing_message,
    })
  } else if string_in(accepted, normalized) {
    score = max_score
  } else {
    findings.push({
      severity: SeverityWarning,
      code: "weak-" + display_name.to_lower(),
      feature: Some(display_name.to_lower()),
      message: display_name + " has a weak or unknown value",
    })
  }
  {
    header: display_name,
    present: value != "",
    score,
    max_score,
    findings,
    observed: value,
    recommended,
  }
}

///|
fn audit_header_set_permissions(
  headers : HeaderSet,
  baseline : Baseline,
) -> HeaderAudit {
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
fn score_security_checks(checks : Array[HeaderCheck]) -> SecurityScore {
  let mut points = 0
  let mut max_points = 0
  let mut high = 0
  let mut warning = 0
  let mut info = 0
  for check in checks {
    points = points + check.score
    max_points = max_points + check.max_score
    for finding in check.findings {
      match finding.severity {
        SeverityHigh => high = high + 1
        SeverityWarning => warning = warning + 1
        SeverityInfo => info = info + 1
      }
    }
  }
  let percent = if max_points == 0 { 0 } else { points * 100 / max_points }
  {
    points,
    max_points,
    percent,
    grade: grade_for(percent, high),
    high,
    warning,
    info,
  }
}

///|
fn score_from_report(report : AuditReport, max_score : Int) -> Int {
  let mut score = max_score
  for finding in report.findings {
    match finding.severity {
      SeverityHigh => score = score - 6
      SeverityWarning => score = score - 2
      SeverityInfo => ()
    }
  }
  if score < 0 {
    0
  } else {
    score
  }
}

///|
fn grade_for(percent : Int, high : Int) -> String {
  if high > 0 && percent < 80 {
    return "D"
  }
  if percent >= 90 {
    "A"
  } else if percent >= 80 {
    "B"
  } else if percent >= 70 {
    "C"
  } else if percent >= 55 {
    "D"
  } else {
    "F"
  }
}

///|
fn grade_rank(grade : String) -> Int {
  match grade.to_upper() {
    "A" => 1
    "B" => 2
    "C" => 3
    "D" => 4
    _ => 5
  }
}

///|
fn header_value(headers : HeaderSet, name : String) -> String? {
  let wanted = normalize_header_lookup(name)
  for line in headers.lines {
    if normalize_header_lookup(line.name) == wanted {
      return Some(line.value)
    }
  }
  None
}

///|
pub fn header_values(headers : HeaderSet, name : String) -> Array[String] {
  let values : Array[String] = []
  let wanted = normalize_header_lookup(name)
  for line in headers.lines {
    if normalize_header_lookup(line.name) == wanted {
      values.push(line.value)
    }
  }
  values
}

///|
fn header_parameter(value : String, name : String) -> String? {
  let wanted = name.to_lower()
  for part_view in value.split(";") {
    let part = trim(part_view.to_owned()).to_lower()
    match part.find("=") {
      None => ()
      Some(eq) => {
        let key = trim(part[:eq].to_owned())
        if key == wanted {
          return Some(trim(part[eq + 1:].to_owned()))
        }
      }
    }
  }
  None
}

///|
fn parse_decimal(value : String) -> Int {
  let mut result = 0
  for ch in trim(value) {
    let digit = decimal_digit(ch)
    if digit < 0 {
      return result
    }
    result = result * 10 + digit
  }
  result
}

///|
fn decimal_digit(ch : Char) -> Int {
  match ch {
    '0' => 0
    '1' => 1
    '2' => 2
    '3' => 3
    '4' => 4
    '5' => 5
    '6' => 6
    '7' => 7
    '8' => 8
    '9' => 9
    _ => -1
  }
}

///|
fn split_words(value : String) -> Array[String] {
  let result : Array[String] = []
  for part_view in value.split(" ") {
    let part = trim(part_view.to_owned())
    if part != "" {
      result.push(part)
    }
  }
  result
}

///|
fn csp_has_directive(directives : Array[CspDirective], name : String) -> Bool {
  for directive in directives {
    if directive.name == name {
      return true
    }
  }
  false
}

///|
fn csp_fallback_directive(name : String) -> String? {
  match normalize_csp_name(name) {
    "script-src"
    | "style-src"
    | "img-src"
    | "connect-src"
    | "font-src"
    | "object-src"
    | "media-src"
    | "manifest-src"
    | "worker-src"
    | "frame-src"
    | "child-src" => Some("default-src")
    _ => None
  }
}

///|
fn csp_is_source_directive(name : String) -> Bool {
  string_in(csp_source_directive_names(), normalize_csp_name(name))
}

///|
fn csp_required_severity(name : String) -> Severity {
  match normalize_csp_name(name) {
    "default-src" | "script-src" | "object-src" | "frame-ancestors" =>
      SeverityHigh
    _ => SeverityWarning
  }
}

///|
fn csp_source_kind(value : String) -> String {
  let normalized = normalize_csp_source(value)
  if normalized == "*" {
    "wildcard"
  } else if normalized == "'self'" ||
    normalized == "'none'" ||
    normalized == "'unsafe-inline'" ||
    normalized == "'unsafe-eval'" {
    "keyword"
  } else if csp_source_is_nonce(normalized) {
    "nonce"
  } else if csp_source_is_hash(normalized) {
    "hash"
  } else if normalized.has_suffix(":") {
    "scheme"
  } else if normalized.has_prefix("https://") ||
    normalized.has_prefix("http://") {
    "origin"
  } else if normalized == "data:" ||
    normalized == "blob:" ||
    normalized == "filesystem:" {
    "scheme"
  } else {
    "host"
  }
}

///|
fn csp_source_secure(value : String) -> Bool {
  let normalized = normalize_csp_source(value)
  normalized == "'self'" ||
  normalized == "'none'" ||
  csp_source_is_nonce(normalized) ||
  csp_source_is_hash(normalized) ||
  normalized.has_prefix("https://") ||
  normalized == "https:" ||
  normalized == "data:" ||
  normalized == "blob:" ||
  normalized == "'strict-dynamic'"
}

///|
fn csp_source_wildcard(value : String) -> Bool {
  let normalized = normalize_csp_source(value)
  normalized == "*" ||
  normalized.has_prefix("*.") ||
  normalized.contains("://*.") ||
  normalized == "http:" ||
  normalized == "https:"
}

///|
fn csp_name_ok(name : String) -> Bool {
  if name == "" {
    return false
  }
  for ch in name {
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
fn normalize_csp_name(value : String) -> String {
  strip_quotes(trim(value)).to_lower()
}

///|
fn normalize_csp_source(value : String) -> String {
  let clean = strip_quotes(trim(value)).to_lower()
  if clean == "self" {
    "'self'"
  } else if clean == "none" {
    "'none'"
  } else if clean == "unsafe-inline" {
    "'unsafe-inline'"
  } else if clean == "unsafe-eval" {
    "'unsafe-eval'"
  } else if clean.has_suffix("/") && clean.length() > 1 {
    clean[:clean.length() - 1].to_owned()
  } else {
    clean
  }
}

///|
fn csp_source_is_nonce(value : String) -> Bool {
  let normalized = normalize_csp_source(value)
  normalized.has_prefix("nonce-") || normalized.has_prefix("'nonce-")
}

///|
fn csp_source_is_hash(value : String) -> Bool {
  let normalized = normalize_csp_source(value)
  normalized.has_prefix("sha256-") ||
  normalized.has_prefix("sha384-") ||
  normalized.has_prefix("sha512-") ||
  normalized.has_prefix("'sha256-") ||
  normalized.has_prefix("'sha384-") ||
  normalized.has_prefix("'sha512-")
}

///|
fn referrer_policy_strong(value : String) -> Bool {
  value == "no-referrer" ||
  value == "strict-origin" ||
  value == "strict-origin-when-cross-origin"
}

///|
fn referrer_policy_acceptable(value : String) -> Bool {
  value == "same-origin" ||
  value == "origin" ||
  value == "origin-when-cross-origin"
}

///|
fn render_finding_line(finding : Finding) -> String {
  let feature = match finding.feature {
    None => "-"
    Some(value) => value
  }
  severity_label(finding.severity) +
  " " +
  finding.code +
  " " +
  feature +
  " - " +
  finding.message
}

///|
fn recommendation_reason(check : HeaderCheck) -> String {
  if check.findings.length() == 0 {
    "score can be improved"
  } else {
    check.findings[0].message
  }
}

///|
fn recommendation_priority(check : HeaderCheck) -> String {
  match header_check_severity(check) {
    "high" => "high"
    "warning" => "warning"
    _ => "info"
  }
}

///|
fn normalize_header_lookup(name : String) -> String {
  trim(name).to_lower()
}

///|
fn string_in(values : Array[String], wanted : String) -> Bool {
  for value in values {
    if value == wanted {
      return true
    }
  }
  false
}

///|
fn push_unique(values : Array[String], value : String) -> Unit {
  if !string_in(values, value) {
    values.push(value)
  }
}

///|
fn bool_word(value : Bool) -> String {
  if value {
    "yes"
  } else {
    "no"
  }
}

///|
fn markdown_inline(value : String) -> String {
  if value == "" {
    "-"
  } else {
    value
  }
}

///|
fn json_escape(value : String) -> String {
  let parts : Array[String] = []
  for ch in value {
    match ch {
      '"' => parts.push("\\\"")
      '\\' => parts.push("\\\\")
      '\n' => parts.push("\\n")
      '\r' => parts.push("\\r")
      '\t' => parts.push("\\t")
      _ => parts.push(ch.to_string())
    }
  }
  parts.join("")
}
