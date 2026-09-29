///|
test "inventory audits two declared routes" {
  let video = @permscope.capability_contract(
    "video",
    "https://app.example",
    [@permscope.capability_need("camera", ["self"], "preview")],
    true,
  )
  let checkout = @permscope.capability_contract(
    "checkout",
    "https://shop.example",
    [@permscope.capability_need("payment", ["self"], "checkout")],
    true,
  )
  let samples = [
    @permscope.response_sample(
      "video",
      "/video",
      "https://app.example",
      "Permissions-Policy: " + @permscope.minimal_policy_for_contract(video),
    ),
    @permscope.response_sample(
      "checkout",
      "/checkout",
      "https://shop.example",
      "Permissions-Policy: " + @permscope.minimal_policy_for_contract(checkout),
    ),
  ]
  let audit = @permscope.audit_capability_inventory(samples, [video, checkout])
  @test.assert_eq(audit.ok, true)
  @test.assert_eq(audit.audits.length(), 2)
  @test.assert_eq(audit.findings.length(), 0)
}

///|
test "inventory rejects missing and undeclared route samples" {
  let video = @permscope.capability_contract(
    "video",
    "https://app.example",
    [],
    false,
  )
  let sample = @permscope.response_sample(
    "search", "/search", "https://app.example", "Permissions-Policy: camera=()",
  )
  let audit = @permscope.audit_capability_inventory([sample], [video])
  @test.assert_eq(audit.ok, false)
  @test.assert_eq(audit.findings.length(), 2)
  let rendered = @permscope.render_capability_inventory(audit)
  @test.assert_eq(rendered.contains("contract-without-sample video"), true)
  @test.assert_eq(rendered.contains("sample-without-contract search"), true)
}

///|
test "inventory rejects duplicate response names" {
  let video = @permscope.capability_contract(
    "video",
    "https://app.example",
    [],
    false,
  )
  let first = @permscope.response_sample(
    "video", "/video", "https://app.example", "Permissions-Policy: camera=()",
  )
  let second = @permscope.response_sample(
    "video", "/video-copy", "https://app.example", "Permissions-Policy: camera=()",
  )
  let audit = @permscope.audit_capability_inventory([first, second], [video])
  @test.assert_eq(audit.ok, false)
  @test.assert_eq(audit.audits.length(), 1)
  @test.assert_eq(
    @permscope.render_capability_inventory(audit).contains(
      "duplicate-sample-name video",
    ),
    true,
  )
}

///|
test "inventory fails closed when no evidence is supplied" {
  let audit = @permscope.audit_capability_inventory([], [])
  @test.assert_eq(audit.ok, false)
  @test.assert_eq(audit.findings.length(), 1)
  @test.assert_eq(
    @permscope.render_capability_inventory(audit).contains("inventory-empty"),
    true,
  )
}

///|
test "inventory propagates a route response failure" {
  let video = @permscope.capability_contract(
    "video",
    "https://app.example",
    [],
    false,
  )
  let sample = @permscope.response_sample(
    "video", "/video", "https://app.example", "Feature-Policy: camera 'none'",
  )
  let audit = @permscope.audit_capability_inventory([sample], [video])
  @test.assert_eq(audit.ok, false)
  @test.assert_eq(audit.findings.length(), 0)
  @test.assert_eq(audit.audits[0].report.ok, false)
}

///|
test "inventory rejects duplicate contract names" {
  let video = @permscope.capability_contract(
    "video",
    "https://app.example",
    [],
    false,
  )
  let sample = @permscope.response_sample(
    "video", "/video", "https://app.example", "Permissions-Policy: camera=()",
  )
  let audit = @permscope.audit_capability_inventory([sample], [video, video])
  @test.assert_eq(audit.ok, false)
  @test.assert_eq(
    @permscope.render_capability_inventory(audit).contains(
      "duplicate-contract-name video",
    ),
    true,
  )
}

///|
test "inventory rejects empty route names" {
  let unnamed = @permscope.capability_contract(
    "",
    "https://app.example",
    [],
    false,
  )
  let sample = @permscope.response_sample(
    "", "/video", "https://app.example", "Permissions-Policy: camera=()",
  )
  let audit = @permscope.audit_capability_inventory([sample], [unnamed])
  @test.assert_eq(audit.ok, false)
  @test.assert_eq(audit.findings.length(), 2)
}

///|
test "inventory joins route names after trimming" {
  let video = @permscope.capability_contract(
    "video",
    "https://app.example",
    [],
    false,
  )
  let sample = @permscope.response_sample(
    " video ", "/video", "https://app.example", "Permissions-Policy: camera=()",
  )
  let audit = @permscope.audit_capability_inventory([sample], [video])
  @test.assert_eq(audit.ok, true)
  @test.assert_eq(audit.findings.length(), 0)
}
