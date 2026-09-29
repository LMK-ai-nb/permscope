///|
test "response audit passes a matching route with a scoped header" {
  let contract = @permscope.capability_contract(
    "video-room",
    "https://app.example",
    [@permscope.capability_need("camera", ["self"], "local preview")],
    true,
  )
  let sample = @permscope.response_sample(
    "video-room",
    "/video",
    "https://app.example",
    "HTTP/2 200\nPermissions-Policy: " +
    @permscope.minimal_policy_for_contract(contract),
  )
  let audit = @permscope.audit_capability_response(sample, contract)
  @test.assert_eq(audit.report.ok, true)
  @test.assert_eq(audit.report.allowed, 1)
  @test.assert_eq(
    @permscope.render_capability_response_audit(audit).contains(
      "route=/video sample=video-room",
    ),
    true,
  )
}

///|
test "response audit rejects a missing policy on the final redirect target" {
  let contract = @permscope.capability_contract(
    "camera",
    "https://app.example",
    [@permscope.capability_need("camera", ["self"], "preview")],
    true,
  )
  let sample = @permscope.response_sample(
    "camera",
    "/camera",
    "https://app.example",
    "HTTP/1.1 302 Found\nPermissions-Policy: " +
    @permscope.minimal_policy_for_contract(contract) +
    "\nLocation: /camera\n\nHTTP/2 200\nX-Trace: final",
  )
  let audit = @permscope.audit_capability_response(sample, contract)
  @test.assert_eq(audit.report.ok, false)
  @test.assert_eq(
    @permscope.render_capability_response_audit(audit).contains(
      "permissions-policy-header-missing",
    ),
    true,
  )
}

///|
test "response audit rejects missing modern policy even with legacy fallback" {
  let contract = @permscope.capability_contract(
    "camera",
    "https://app.example",
    [@permscope.capability_need("camera", ["self"], "preview")],
    false,
  )
  let sample = @permscope.response_sample(
    "camera", "/camera", "https://app.example", "HTTP/2 200\nFeature-Policy: camera 'self'",
  )
  let audit = @permscope.audit_capability_response(sample, contract)
  @test.assert_eq(audit.report.ok, false)
  @test.assert_eq(
    @permscope.render_capability_response_audit(audit).contains(
      "permissions-policy-header-missing",
    ),
    true,
  )
}

///|
test "response audit rejects an origin mismatch" {
  let contract = @permscope.capability_contract(
    "reader",
    "https://app.example",
    [],
    false,
  )
  let sample = @permscope.response_sample(
    "reader", "/", "https://other.example", "Permissions-Policy: camera=()",
  )
  let audit = @permscope.audit_capability_response(sample, contract)
  @test.assert_eq(audit.report.ok, false)
  @test.assert_eq(
    @permscope.render_capability_response_audit(audit).contains(
      "document-origin-mismatch",
    ),
    true,
  )
}

///|
test "response audit rejects malformed policy input" {
  let contract = @permscope.capability_contract(
    "reader",
    "https://app.example",
    [],
    false,
  )
  let sample = @permscope.response_sample(
    "reader", "/", "https://app.example", "Permissions-Policy: camera=(self",
  )
  let audit = @permscope.audit_capability_response(sample, contract)
  @test.assert_eq(audit.report.ok, false)
  @test.assert_eq(
    @permscope.render_capability_response_audit(audit).contains(
      "response-policy-invalid",
    ),
    true,
  )
}
