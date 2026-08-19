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
