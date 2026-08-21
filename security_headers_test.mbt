///|
test "csp parser normalizes directives and source expressions" {
  let policy = @permscope.parse_csp(
    "Default-Src 'SELF'; script-src 'self' 'nonce-abc' https://cdn.example/; object-src 'none'",
  )
  @test.assert_eq(policy.directives.length(), 3)
  match @permscope.csp_directive(policy, "SCRIPT-SRC") {
    None => @test.assert_eq(true, false)
    Some(directive) => {
      @test.assert_eq(directive.name, "script-src")
      @test.assert_eq(directive.values.length(), 3)
    }
  }
  @test.assert_eq(
    @permscope.csp_has_source(policy, "script-src", "https://cdn.example"),
    true,
  )
  @test.assert_eq(@permscope.csp_has_nonce_or_hash(policy, "script-src"), true)
}

///|
test "csp summary counts unsafe and wildcard sources" {
  let policy = @permscope.parse_csp(
    "default-src *; script-src 'unsafe-inline' 'unsafe-eval' http:; img-src * data:",
  )
  let summary = @permscope.summarize_csp(policy)
  @test.assert_eq(summary.directive_count, 3)
  @test.assert_eq(summary.wildcard_sources >= 2, true)
  @test.assert_eq(summary.unsafe_inline, 1)
  @test.assert_eq(summary.unsafe_eval, 1)
  @test.assert_eq(summary.insecure_sources >= 2, true)
  @test.assert_eq(
    @permscope.render_csp_summary(summary).contains("unsafe_eval=1"),
    true,
  )
}

///|
test "csp audit rejects unsafe eval and weak object policy" {
  let report = @permscope.audit_csp(
    @permscope.parse_csp(
      "default-src 'self'; script-src 'self' 'unsafe-eval'; frame-ancestors *",
    ),
  )
  @test.assert_eq(report.ok, false)
  @test.assert_eq(
    @permscope.render_csp_audit(report).contains("csp-unsafe-eval"),
    true,
  )
  @test.assert_eq(
    @permscope.render_csp_audit(report).contains("csp-object-src-not-none"),
    true,
  )
}

///|
test "strict csp header passes the built in csp audit" {
  let policy = @permscope.parse_csp(@permscope.strict_csp_header())
  let report = @permscope.audit_csp(policy)
  @test.assert_eq(report.ok, true)
  @test.assert_eq(@permscope.csp_allows_inline_script(policy), false)
  @test.assert_eq(@permscope.csp_allows_eval(policy), false)
  @test.assert_eq(
    @permscope.render_csp(policy).contains("frame-ancestors 'none'"),
    true,
  )
}

///|
test "app csp header includes trusted api and media origins" {
  let header = @permscope.app_csp_header(["https://api.example/"], [
    "https://media.example/",
  ])
  @test.assert_eq(header.contains("https://api.example"), true)
  @test.assert_eq(header.contains("https://media.example"), true)
  let policy = @permscope.parse_csp(header)
  @test.assert_eq(
    @permscope.csp_has_source(policy, "connect-src", "https://api.example"),
    true,
  )
}

///|
test "security audit grades a strict bundle as strong" {
  let bundle = @permscope.strict_security_bundle("https://app.example")
  let audit = @permscope.audit_security_bundle(bundle)
  @test.assert_eq(audit.score.grade, "A")
  @test.assert_eq(audit.score.high, 0)
  @test.assert_eq(@permscope.security_has_no_high(audit), true)
  @test.assert_eq(@permscope.security_grade_at_least(audit, "B"), true)
  @test.assert_eq(
    @permscope.render_security_badge(audit).contains("grade A"),
    true,
  )
}

///|
test "security coverage reports missing and weak headers" {
  let audit = @permscope.audit_security_header_block(
    "HTTP/2 200\nX-Content-Type-Options: nosniff", "https://app.example",
  )
  let coverage = @permscope.security_coverage(audit)
  @test.assert_eq(coverage.present, 1)
  @test.assert_eq(coverage.missing.length() >= 5, true)
  @test.assert_eq(
    @permscope.render_security_coverage(coverage).contains(
      "X-Content-Type-Options",
    ),
    false,
  )
  @test.assert_eq(audit.score.high > 0, true)
}

///|
test "security recommendations explain weak audit results" {
  let audit = @permscope.audit_security_header_block(
    "HTTP/2 200\nReferrer-Policy: unsafe-url\nX-Frame-Options: ALLOW-FROM https://old.example",
    "https://app.example",
  )
  let recommendations = @permscope.security_recommendations(audit)
  @test.assert_eq(recommendations.length() > 0, true)
  @test.assert_eq(
    @permscope.render_security_recommendations(recommendations).contains(
      "Content-Security-Policy",
    ),
    true,
  )
}

///|
test "header values helper returns repeated response headers" {
  let headers = @permscope.parse_header_block(
    "Set-Cookie: a=1\nSet-Cookie: b=2\nContent-Security-Policy: default-src 'self'",
  )
  @test.assert_eq(@permscope.header_values(headers, "set-cookie").length(), 2)
  @test.assert_eq(
    @permscope.header_values(headers, "content-security-policy")[0],
    "default-src 'self'",
  )
}

///|
test "bundle rendering creates auditable response header blocks" {
  let bundle = @permscope.static_site_security_bundle("https://docs.example")
  let block = @permscope.render_security_bundle(bundle)
  @test.assert_eq(block.contains("HTTP/2 200"), true)
  @test.assert_eq(block.contains("Content-Security-Policy:"), true)
  @test.assert_eq(
    @permscope.render_security_bundle_notes(bundle).contains(
      "bundle=static-site",
    ),
    true,
  )
  match @permscope.bundle_header_value(bundle, "referrer-policy") {
    None => @test.assert_eq(true, false)
    Some(value) => @test.assert_eq(value, "strict-origin-when-cross-origin")
  }
}

///|
test "named bundle returns expected deployment presets" {
  @test.assert_eq(@permscope.security_bundle_names().length(), 5)
  let api = @permscope.named_security_bundle(
    "api-service", "https://api.example",
  )
  @test.assert_eq(api.name, "api-service")
  match @permscope.bundle_header_value(api, "Content-Security-Policy") {
    None => @test.assert_eq(true, false)
    Some(value) => @test.assert_eq(value.contains("default-src 'none'"), true)
  }
}

///|
test "media and device bundles keep policy scope explicit" {
  let media = @permscope.media_security_bundle(
    "https://media.example",
    ["https://api.example"],
    ["https://cdn.example"],
  )
  let device = @permscope.device_lab_security_bundle("https://lab.example", [
    "https://kit.example",
  ])
  @test.assert_eq(
    @permscope.render_security_bundle(media).contains("https://cdn.example"),
    true,
  )
  @test.assert_eq(
    @permscope.render_security_bundle(device).contains(
      "usb=(self \"https://kit.example\")",
    ),
    true,
  )
}

///|
test "security gate fails below grade or high findings" {
  let audit = @permscope.audit_security_header_block(
    "HTTP/2 200\nContent-Security-Policy: default-src *; script-src 'unsafe-eval'",
    "https://app.example",
  )
  let gate = @permscope.security_gate(audit, "B", false)
  @test.assert_eq(gate.ok, false)
  @test.assert_eq(gate.messages.length() > 0, true)
  @test.assert_eq(
    @permscope.render_security_gate(gate).contains("permscope gate: fail"),
    true,
  )
}

///|
test "security gate passes strict bundle with required grade" {
  let audit = @permscope.audit_security_bundle(
    @permscope.strict_security_bundle("https://app.example"),
  )
  let gate = @permscope.security_gate(audit, "A", false)
  @test.assert_eq(gate.ok, true)
  @test.assert_eq(
    @permscope.render_security_gate(gate).contains("permscope gate: pass"),
    true,
  )
}

///|
test "security audit renders text markdown and json reports" {
  let audit = @permscope.audit_security_bundle(
    @permscope.strict_security_bundle("https://app.example"),
  )
  @test.assert_eq(
    @permscope.render_security_audit(audit).contains("permscope security audit"),
    true,
  )
  @test.assert_eq(
    @permscope.render_security_markdown(audit).contains(
      "# permscope security audit",
    ),
    true,
  )
  @test.assert_eq(
    @permscope.render_security_json(audit).contains("\"grade\": \"A\""),
    true,
  )
}

///|
test "security regression comparison detects weaker later policy" {
  let before = @permscope.audit_security_bundle(
    @permscope.strict_security_bundle("https://app.example"),
  )
  let after = @permscope.audit_security_header_block(
    "HTTP/2 200\nContent-Security-Policy: default-src *; script-src 'unsafe-eval'\nX-Content-Type-Options: nosniff",
    "https://app.example",
  )
  let changes = @permscope.compare_security_audits(before, after)
  @test.assert_eq(changes.length() > 0, true)
  @test.assert_eq(
    @permscope.render_security_regressions(changes).contains("delta=-"),
    true,
  )
}

///|
test "security regression comparison reports no changes for same audit" {
  let audit = @permscope.audit_security_bundle(
    @permscope.strict_security_bundle("https://app.example"),
  )
  let changes = @permscope.compare_security_audits(audit, audit)
  @test.assert_eq(changes.length(), 0)
  @test.assert_eq(
    @permscope.render_security_regressions(changes),
    "permscope security changes: no score changes",
  )
}

///|
test "security finding summary groups findings by severity" {
  let audit = @permscope.audit_security_header_block(
    "HTTP/2 200\nContent-Security-Policy: default-src *; script-src 'unsafe-eval'\nReferrer-Policy: unsafe-url",
    "https://app.example",
  )
  let summary = @permscope.summarize_security_findings(audit)
  @test.assert_eq(summary.total > 0, true)
  @test.assert_eq(summary.high > 0, true)
  @test.assert_eq(
    @permscope.render_security_finding_summary(summary).contains("high_codes="),
    true,
  )
  @test.assert_eq(
    @permscope.security_findings_by_severity(audit, "high").length() > 0,
    true,
  )
}

///|
test "security check table and finding codes are stable" {
  let audit = @permscope.audit_security_header_block(
    "HTTP/2 200\nX-Content-Type-Options: nosniff", "https://app.example",
  )
  @test.assert_eq(
    @permscope.render_security_check_table(audit).contains(
      "header present score severity",
    ),
    true,
  )
  @test.assert_eq(@permscope.security_finding_codes(audit).length() > 0, true)
}

///|
test "batch audit scores multiple response samples" {
  let strong = @permscope.response_sample_from_bundle(
    "home",
    "/",
    @permscope.strict_security_bundle("https://app.example"),
  )
  let weak = @permscope.response_sample(
    "legacy", "/legacy", "https://app.example", "HTTP/2 200\nX-Content-Type-Options: nosniff",
  )
  let batch = @permscope.audit_response_samples([strong, weak])
  @test.assert_eq(batch.samples.length(), 2)
  @test.assert_eq(batch.scores.length(), 2)
  @test.assert_eq(batch.high_total > 0, true)
  @test.assert_eq(
    @permscope.render_batch_audit(batch).contains("samples=2"),
    true,
  )
}

///|
test "batch audit finds best weakest and recommendations" {
  let strong = @permscope.response_sample_from_bundle(
    "api",
    "/api",
    @permscope.api_service_security_bundle("https://api.example"),
  )
  let weak = @permscope.response_sample(
    "empty", "/empty", "https://api.example", "HTTP/2 200",
  )
  let batch = @permscope.audit_response_samples([strong, weak])
  match @permscope.best_sample_score(batch) {
    None => @test.assert_eq(true, false)
    Some(score) => @test.assert_eq(score.name, "api")
  }
  match @permscope.weakest_sample_score(batch) {
    None => @test.assert_eq(true, false)
    Some(score) => @test.assert_eq(score.name, "empty")
  }
  @test.assert_eq(
    @permscope.render_batch_recommendations(
      @permscope.batch_recommendations(batch),
    ).contains("Content-Security-Policy"),
    true,
  )
}

///|
test "batch gate and reports render stable output" {
  let batch = @permscope.audit_response_samples([
    @permscope.response_sample_from_bundle(
      "home",
      "/",
      @permscope.strict_security_bundle("https://app.example"),
    ),
  ])
  let gate = @permscope.batch_security_gate(batch, "A", 0, 100)
  @test.assert_eq(gate.ok, true)
  @test.assert_eq(
    @permscope.render_batch_gate(gate).contains("permscope batch gate: pass"),
    true,
  )
  @test.assert_eq(
    @permscope.render_batch_markdown(batch).contains(
      "# permscope batch security audit",
    ),
    true,
  )
  @test.assert_eq(
    @permscope.render_batch_json(batch).contains("\"worst_grade\": \"A\""),
    true,
  )
}
