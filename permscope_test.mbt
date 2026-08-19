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
