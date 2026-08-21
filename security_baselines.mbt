///|
/// One generated HTTP security header.
pub struct SecurityHeaderEntry {
  name : String
  value : String
} derive(Eq, @debug.Debug)

///|
/// A reusable security-header bundle for a deployment scenario.
pub struct SecurityHeaderBundle {
  name : String
  description : String
  document_origin : String
  headers : Array[SecurityHeaderEntry]
  notes : Array[String]
} derive(Eq, @debug.Debug)

///|
/// Coverage summary for the headers audited by `permscope`.
pub struct SecurityCoverage {
  required : Int
  present : Int
  strong : Int
  missing : Array[String]
  weak : Array[String]
} derive(Eq, @debug.Debug)

///|
/// One score change between two security audits.
pub struct SecurityRegression {
  header : String
  before_score : Int
  after_score : Int
  delta : Int
  severity : String
  message : String
} derive(Eq, @debug.Debug)

///|
/// CI-style gate result for a security audit.
pub struct SecurityGate {
  ok : Bool
  required_grade : String
  actual_grade : String
  allow_warnings : Bool
  messages : Array[String]
} derive(Eq, @debug.Debug)

///|
/// Create a header entry.
pub fn security_header_entry(
  name : String,
  value : String,
) -> SecurityHeaderEntry {
  { name, value }
}

///|
/// Strict browser-facing bundle for high-sensitivity apps.
pub fn strict_security_bundle(document_origin : String) -> SecurityHeaderBundle {
  {
    name: "strict",
    description: "Strict browser-facing defaults for public production apps",
    document_origin,
    headers: [
      security_header_entry("Content-Security-Policy", strict_csp_header()),
      security_header_entry(
        "Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload",
      ),
      security_header_entry("Permissions-Policy", recommended_header()),
      security_header_entry(
        "Referrer-Policy", "strict-origin-when-cross-origin",
      ),
      security_header_entry("X-Frame-Options", "DENY"),
      security_header_entry("X-Content-Type-Options", "nosniff"),
      security_header_entry("Cross-Origin-Opener-Policy", "same-origin"),
      security_header_entry("Cross-Origin-Embedder-Policy", "require-corp"),
      security_header_entry("Cross-Origin-Resource-Policy", "same-origin"),
    ],
    notes: [
      "Use for applications that control all scripts and subresources.", "COEP may require third-party resources to send CORP or CORS headers.",
      "Frame embedding is disabled by CSP and X-Frame-Options.",
    ],
  }
}

///|
/// Practical static-site bundle.
pub fn static_site_security_bundle(
  document_origin : String,
) -> SecurityHeaderBundle {
  {
    name: "static-site",
    description: "Balanced defaults for documentation and static sites",
    document_origin,
    headers: [
      security_header_entry("Content-Security-Policy", strict_csp_header()),
      security_header_entry(
        "Strict-Transport-Security", "max-age=31536000; includeSubDomains",
      ),
      security_header_entry("Permissions-Policy", recommended_header()),
      security_header_entry(
        "Referrer-Policy", "strict-origin-when-cross-origin",
      ),
      security_header_entry("X-Frame-Options", "DENY"),
      security_header_entry("X-Content-Type-Options", "nosniff"),
      security_header_entry("Cross-Origin-Opener-Policy", "same-origin"),
      security_header_entry("Cross-Origin-Resource-Policy", "same-origin"),
    ],
    notes: [
      "Preload is omitted so site owners can opt in deliberately.", "COEP is omitted because many static sites embed third-party assets.",
    ],
  }
}

///|
/// API service bundle for JSON endpoints and machine clients.
pub fn api_service_security_bundle(
  document_origin : String,
) -> SecurityHeaderBundle {
  {
    name: "api-service",
    description: "Security headers for JSON APIs and service endpoints",
    document_origin,
    headers: [
      security_header_entry(
        "Content-Security-Policy", "default-src 'none'; script-src 'none'; style-src 'none'; img-src 'none'; connect-src 'none'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
      ),
      security_header_entry(
        "Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload",
      ),
      security_header_entry("Permissions-Policy", recommended_header()),
      security_header_entry("Referrer-Policy", "no-referrer"),
      security_header_entry("X-Frame-Options", "DENY"),
      security_header_entry("X-Content-Type-Options", "nosniff"),
      security_header_entry("Cross-Origin-Opener-Policy", "same-origin"),
      security_header_entry("Cross-Origin-Resource-Policy", "same-origin"),
    ],
    notes: [
      "CSP is intentionally restrictive because API responses should not execute.",
      "Referrer data is disabled for machine-readable endpoints.",
    ],
  }
}

///|
/// Media app bundle with trusted API and media origins.
pub fn media_security_bundle(
  document_origin : String,
  api_origins : Array[String],
  media_origins : Array[String],
) -> SecurityHeaderBundle {
  {
    name: "media-app",
    description: "Headers for media-heavy applications with trusted origins",
    document_origin,
    headers: [
      security_header_entry(
        "Content-Security-Policy",
        app_csp_header(api_origins, media_origins),
      ),
      security_header_entry(
        "Strict-Transport-Security", "max-age=31536000; includeSubDomains",
      ),
      security_header_entry(
        "Permissions-Policy",
        profile_header(media_app_profile(), media_origins),
      ),
      security_header_entry(
        "Referrer-Policy", "strict-origin-when-cross-origin",
      ),
      security_header_entry("X-Frame-Options", "SAMEORIGIN"),
      security_header_entry("X-Content-Type-Options", "nosniff"),
      security_header_entry("Cross-Origin-Opener-Policy", "same-origin"),
      security_header_entry("Cross-Origin-Resource-Policy", "same-site"),
    ],
    notes: [
      "Media origins are allowed in CSP img-src and in the media profile.", "X-Frame-Options is SAMEORIGIN to allow same-site media shells.",
    ],
  }
}

///|
/// Hardware lab bundle for WebUSB, WebHID, Bluetooth, and serial demos.
pub fn device_lab_security_bundle(
  document_origin : String,
  trusted_device_origins : Array[String],
) -> SecurityHeaderBundle {
  {
    name: "device-lab",
    description: "Headers for trusted hardware demo labs",
    document_origin,
    headers: [
      security_header_entry("Content-Security-Policy", strict_csp_header()),
      security_header_entry(
        "Strict-Transport-Security", "max-age=31536000; includeSubDomains",
      ),
      security_header_entry(
        "Permissions-Policy",
        profile_header(device_lab_profile(), trusted_device_origins),
      ),
      security_header_entry(
        "Referrer-Policy", "strict-origin-when-cross-origin",
      ),
      security_header_entry("X-Frame-Options", "DENY"),
      security_header_entry("X-Content-Type-Options", "nosniff"),
      security_header_entry("Cross-Origin-Opener-Policy", "same-origin"),
      security_header_entry("Cross-Origin-Embedder-Policy", "require-corp"),
      security_header_entry("Cross-Origin-Resource-Policy", "same-origin"),
    ],
    notes: [
      "Device capabilities are delegated only to explicitly trusted origins.", "COOP and COEP help isolate device demo pages from unrelated contexts.",
    ],
  }
}

///|
/// Return all built-in bundle names.
pub fn security_bundle_names() -> Array[String] {
  ["strict", "static-site", "api-service", "media-app", "device-lab"]
}

///|
/// Return the first value for a header in a bundle.
pub fn bundle_header_value(
  bundle : SecurityHeaderBundle,
  name : String,
) -> String? {
  let wanted = name.to_lower()
  for header in bundle.headers {
    if header.name.to_lower() == wanted {
      return Some(header.value)
    }
  }
  None
}

///|
/// Render a header bundle as an HTTP response header block.
pub fn render_security_bundle(bundle : SecurityHeaderBundle) -> String {
  let lines : Array[String] = []
  lines.push("HTTP/2 200")
  for header in bundle.headers {
    lines.push(header.name + ": " + header.value)
  }
  lines.join("\n")
}

///|
/// Render bundle notes for documentation.
pub fn render_security_bundle_notes(bundle : SecurityHeaderBundle) -> String {
  let lines : Array[String] = []
  lines.push("bundle=" + bundle.name)
  lines.push("description=" + bundle.description)
  for note in bundle.notes {
    lines.push("note=" + note)
  }
  lines.join("\n")
}

///|
/// Audit a generated bundle.
pub fn audit_security_bundle(bundle : SecurityHeaderBundle) -> SecurityAudit {
  audit_security_header_block(
    render_security_bundle(bundle),
    bundle.document_origin,
  )
}

///|
/// Summarize required header coverage.
pub fn security_coverage(audit : SecurityAudit) -> SecurityCoverage {
  let missing : Array[String] = []
  let weak : Array[String] = []
  let mut present = 0
  let mut strong = 0
  for check in audit.checks {
    if check.present {
      present = present + 1
    } else {
      missing.push(check.header)
    }
    if check.score == check.max_score {
      strong = strong + 1
    } else if check.present {
      weak.push(check.header)
    }
  }
  { required: audit.checks.length(), present, strong, missing, weak }
}

///|
/// Render header coverage as stable text.
pub fn render_security_coverage(coverage : SecurityCoverage) -> String {
  "coverage required=" +
  coverage.required.to_string() +
  " present=" +
  coverage.present.to_string() +
  " strong=" +
  coverage.strong.to_string() +
  " missing=" +
  coverage.missing.join("|") +
  " weak=" +
  coverage.weak.join("|")
}

///|
/// Compare two audits and return score regressions or improvements.
pub fn compare_security_audits(
  before : SecurityAudit,
  after : SecurityAudit,
) -> Array[SecurityRegression] {
  let changes : Array[SecurityRegression] = []
  for before_check in before.checks {
    match security_check(after, before_check.header) {
      None =>
        changes.push({
          header: before_check.header,
          before_score: before_check.score,
          after_score: 0,
          delta: 0 - before_check.score,
          severity: "high",
          message: "header disappeared from the later audit",
        })
      Some(after_check) =>
        if before_check.score != after_check.score {
          let delta = after_check.score - before_check.score
          changes.push({
            header: before_check.header,
            before_score: before_check.score,
            after_score: after_check.score,
            delta,
            severity: regression_severity(delta, after_check),
            message: regression_message(delta, after_check),
          })
        }
    }
  }
  for after_check in after.checks {
    if security_check(before, after_check.header) is None {
      changes.push({
        header: after_check.header,
        before_score: 0,
        after_score: after_check.score,
        delta: after_check.score,
        severity: "info",
        message: "new header appears in the later audit",
      })
    }
  }
  changes
}

///|
/// Render audit changes as line-oriented text.
pub fn render_security_regressions(
  changes : Array[SecurityRegression],
) -> String {
  if changes.length() == 0 {
    return "permscope security changes: no score changes"
  }
  let lines : Array[String] = ["permscope security changes:"]
  for item in changes {
    lines.push(
      item.severity +
      " " +
      item.header +
      " " +
      item.before_score.to_string() +
      "->" +
      item.after_score.to_string() +
      " delta=" +
      item.delta.to_string() +
      " - " +
      item.message,
    )
  }
  lines.join("\n")
}

///|
/// Build a CI-style gate for a security audit.
pub fn security_gate(
  audit : SecurityAudit,
  required_grade : String,
  allow_warnings : Bool,
) -> SecurityGate {
  let messages : Array[String] = []
  if !security_grade_at_least(audit, required_grade) {
    messages.push(
      "grade " +
      audit.score.grade +
      " is below required " +
      required_grade.to_upper(),
    )
  }
  if audit.score.high > 0 {
    messages.push("high severity findings are present")
  }
  if !allow_warnings && audit.score.warning > 0 {
    messages.push("warning findings are present")
  }
  {
    ok: messages.length() == 0,
    required_grade: required_grade.to_upper(),
    actual_grade: audit.score.grade,
    allow_warnings,
    messages,
  }
}

///|
/// Render a CI gate result.
pub fn render_security_gate(gate : SecurityGate) -> String {
  let lines : Array[String] = []
  if gate.ok {
    lines.push("permscope gate: pass")
  } else {
    lines.push("permscope gate: fail")
  }
  lines.push("required_grade=" + gate.required_grade)
  lines.push("actual_grade=" + gate.actual_grade)
  lines.push("allow_warnings=" + gate.allow_warnings.to_string())
  for message in gate.messages {
    lines.push("message=" + message)
  }
  lines.join("\n")
}

///|
/// Return the strongest bundle among built-in presets for a simple name.
pub fn named_security_bundle(
  name : String,
  document_origin : String,
) -> SecurityHeaderBundle {
  match name.to_lower() {
    "static-site" => static_site_security_bundle(document_origin)
    "api-service" => api_service_security_bundle(document_origin)
    "media-app" => media_security_bundle(document_origin, [], [])
    "device-lab" => device_lab_security_bundle(document_origin, [])
    _ => strict_security_bundle(document_origin)
  }
}

///|
/// Render a concise one-line audit badge.
pub fn render_security_badge(audit : SecurityAudit) -> String {
  "permscope grade " +
  audit.score.grade +
  " (" +
  audit.score.points.to_string() +
  "/" +
  audit.score.max_points.to_string() +
  ", high=" +
  audit.score.high.to_string() +
  ", warning=" +
  audit.score.warning.to_string() +
  ")"
}

///|
fn regression_severity(delta : Int, after : HeaderCheck) -> String {
  if delta < 0 && header_check_severity(after) == "high" {
    "high"
  } else if delta < 0 {
    "warning"
  } else {
    "info"
  }
}

///|
fn regression_message(delta : Int, after : HeaderCheck) -> String {
  if delta < 0 {
    "score decreased; current severity is " + header_check_severity(after)
  } else {
    "score improved"
  }
}
