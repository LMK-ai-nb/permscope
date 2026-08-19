///|
fn strict_policy() -> @permscope.Policy {
  @permscope.parse(
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), hid=(), bluetooth=(), fullscreen=(self \"https://video.example\")",
  )
}

///|
test "parse modern permissions policy directives" {
  let policy = strict_policy()
  @test.assert_eq(policy.directives.length(), 9)
  @test.assert_eq(policy.warnings.length(), 0)
  match @permscope.directive(policy, "CAMERA") {
    None => @test.assert_eq(true, false)
    Some(camera) => {
      @test.assert_eq(camera.feature, "camera")
      @test.assert_eq(camera.tokens.length(), 0)
    }
  }
}

///|
test "allowlist honors self wildcard and explicit origins" {
  let policy = strict_policy()
  @test.assert_eq(
    @permscope.allows(
      policy, "fullscreen", "https://app.example", "https://app.example/",
    ),
    true,
  )
  @test.assert_eq(
    @permscope.allows(
      policy, "fullscreen", "https://app.example", "https://video.example",
    ),
    true,
  )
  @test.assert_eq(
    @permscope.allows(
      policy, "fullscreen", "https://app.example", "https://evil.example",
    ),
    false,
  )
}

///|
test "empty allowlist disables a feature for every origin" {
  let policy = strict_policy()
  @test.assert_eq(
    @permscope.allows(
      policy, "camera", "https://app.example", "https://app.example",
    ),
    false,
  )
  @test.assert_eq(
    @permscope.allows(
      policy, "camera", "https://app.example", "https://video.example",
    ),
    false,
  )
}

///|
test "missing directives remain allowed but audit can flag them" {
  let policy = @permscope.parse("fullscreen=(self)")
  @test.assert_eq(
    @permscope.allows(
      policy, "camera", "https://app.example", "https://evil.example",
    ),
    true,
  )
  let report = @permscope.audit(
    policy,
    @permscope.default_baseline("https://app.example"),
  )
  @test.assert_eq(report.ok, false)
}

///|
test "audit passes when default sensitive features are denied" {
  let report = @permscope.audit(
    strict_policy(),
    @permscope.default_baseline("https://app.example"),
  )
  @test.assert_eq(report.ok, true)
}

///|
test "audit rejects wildcard sensitive capabilities" {
  let policy = @permscope.parse(
    "camera=(*), microphone=(), geolocation=(), payment=(), usb=(), serial=(), hid=(), bluetooth=()",
  )
  let report = @permscope.audit(
    policy,
    @permscope.default_baseline("https://app.example"),
  )
  @test.assert_eq(report.ok, false)
}

///|
test "parser records duplicate and malformed directive warnings" {
  let policy = @permscope.parse("camera=(), camera=(*), geolocation=self")
  @test.assert_eq(policy.directives.length(), 3)
  @test.assert_eq(policy.warnings.length(), 2)
}

///|
test "legacy feature policy can be migrated" {
  let header = "camera 'none'; fullscreen 'self' https://video.example"
  @test.assert_eq(
    @permscope.migrate_feature_policy(header),
    "camera=(), fullscreen=(self \"https://video.example\")",
  )
}

///|
test "render creates stable normalized header" {
  let policy = @permscope.parse(
    "Fullscreen=( SELF \"HTTPS://VIDEO.EXAMPLE/\" )",
  )
  @test.assert_eq(
    @permscope.render(policy),
    "fullscreen=(self \"https://video.example\")",
  )
}

///|
test "build creates policy from declarative intents" {
  let header = @permscope.build([
    @permscope.deny("camera"),
    @permscope.self_only("fullscreen"),
    @permscope.self_and_origins("payment", ["HTTPS://PAY.EXAMPLE/"]),
  ])
  @test.assert_eq(
    header, "camera=(), fullscreen=(self), payment=(self \"https://pay.example\")",
  )
}

///|
test "build policy records duplicate feature intent warnings" {
  let policy = @permscope.build_policy([
    @permscope.deny("camera"),
    @permscope.all_origins("camera"),
  ])
  @test.assert_eq(policy.directives.length(), 2)
  @test.assert_eq(policy.warnings.length(), 1)
}

///|
test "diff classifies looser and tighter policy changes" {
  let before = @permscope.parse("camera=(), fullscreen=(*)")
  let after = @permscope.parse("camera=(self), fullscreen=(self)")
  let diffs = @permscope.diff(before, after)
  @test.assert_eq(diffs.length(), 2)
  @test.assert_eq(
    @permscope.render_diffs(diffs),
    "permscope diff:\nloosened camera before=camera=() after=camera=(self)\ntightened fullscreen before=fullscreen=(*) after=fullscreen=(self)",
  )
}

///|
test "render diffs emits stable no change message" {
  let policy = @permscope.parse("camera=()")
  @test.assert_eq(
    @permscope.render_diffs(@permscope.diff(policy, policy)),
    "permscope diff: no changes",
  )
}

///|
test "known feature catalog exposes high risk capabilities" {
  @test.assert_eq(@permscope.known_features().length() >= 20, true)
  match @permscope.known_feature("CAMERA") {
    None => @test.assert_eq(true, false)
    Some(spec) => {
      @test.assert_eq(spec.feature, "camera")
      @test.assert_eq(spec.recommended, @permscope.deny("camera"))
    }
  }
}

///|
test "recommended header is parseable and audit safe" {
  let policy = @permscope.parse(@permscope.recommended_header())
  let report = @permscope.audit(
    policy,
    @permscope.catalog_baseline("https://app.example"),
  )
  @test.assert_eq(policy.warnings.length(), 0)
  @test.assert_eq(report.ok, true)
}

///|
test "summary counts common allowlist shapes" {
  let policy = @permscope.parse(
    "camera=(), fullscreen=(self), payment=(self \"https://pay.example\"), autoplay=(*)",
  )
  let summary = @permscope.summarize(
    policy,
    @permscope.catalog_baseline("https://app.example"),
  )
  @test.assert_eq(summary.disabled, 1)
  @test.assert_eq(summary.self_only, 1)
  @test.assert_eq(summary.explicit_origins, 1)
  @test.assert_eq(summary.wildcard, 1)
  @test.assert_eq(
    @permscope.render_summary(summary).contains("missing_sensitive="),
    true,
  )
}

///|
test "built in profiles generate auditable headers" {
  @test.assert_eq(@permscope.built_in_profiles().length(), 4)
  let profile = @permscope.media_app_profile()
  let header = @permscope.profile_header(profile, [])
  @test.assert_eq(header.contains("camera=()"), true)
  @test.assert_eq(header.contains("fullscreen=(self)"), true)
  let policy = @permscope.parse(header)
  let report = @permscope.audit(
    policy,
    @permscope.profile_baseline(profile, "https://app.example"),
  )
  @test.assert_eq(report.ok, true)
}

///|
test "device lab profile scopes hardware to trusted origins" {
  let profile = @permscope.device_lab_profile()
  let header = @permscope.profile_header(profile, ["https://kit.example/"])
  @test.assert_eq(header.contains("usb=(self \"https://kit.example\")"), true)
  @test.assert_eq(
    @permscope.render_profile(profile, ["https://kit.example"]).contains(
      "profile=device-lab",
    ),
    true,
  )
}

///|
test "header block parser extracts modern permissions policy" {
  let block = "HTTP/2 200\nPermissions-Policy: camera=(), fullscreen=(self)\nFeature-Policy: camera *\nX-Trace: ok"
  let headers = @permscope.parse_header_block(block)
  @test.assert_eq(headers.lines.length(), 3)
  match @permscope.permissions_policy_header(headers) {
    None => @test.assert_eq(true, false)
    Some(value) => @test.assert_eq(value, "camera=(), fullscreen=(self)")
  }
  let audit = @permscope.audit_header_block(
    block,
    @permscope.default_baseline("https://app.example"),
  )
  @test.assert_eq(audit.used_legacy, false)
  @test.assert_eq(
    @permscope.render_header_audit(audit).contains(
      "effective=permissions-policy",
    ),
    true,
  )
}

///|
test "header audit falls back to legacy feature policy migration" {
  let block = "Feature-Policy: camera 'none'; fullscreen 'self' https://video.example"
  let audit = @permscope.audit_header_block(
    block,
    @permscope.default_baseline("https://app.example"),
  )
  @test.assert_eq(audit.used_legacy, true)
  @test.assert_eq(
    audit.migration,
    "camera=(), fullscreen=(self \"https://video.example\")",
  )
}

///|
test "access matrix explains feature behavior across origins" {
  let policy = @permscope.parse(
    "camera=(), fullscreen=(self \"https://video.example\")",
  )
  let matrix = @permscope.access_matrix(
    policy,
    ["camera", "fullscreen"],
    "https://app.example",
    ["https://app.example/", "https://video.example"],
  )
  @test.assert_eq(matrix.cells.length(), 4)
  match @permscope.matrix_cell(matrix, "FULLSCREEN", "https://video.example/") {
    None => @test.assert_eq(true, false)
    Some(cell) => @test.assert_eq(cell.allowed, true)
  }
  @test.assert_eq(
    @permscope.render_access_matrix(matrix).contains("camera deny deny"),
    true,
  )
}
