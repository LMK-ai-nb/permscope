///|
fn main {
  let header = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), hid=(), bluetooth=(), fullscreen=(self \"https://video.example\")"
  let policy = @permscope.parse(header)
  let report = @permscope.audit(
    policy,
    @permscope.default_baseline("https://app.example"),
  )
  println("permscope demo")
  println("normalized=" + @permscope.render(policy))
  println(
    "fullscreen self=" +
    @permscope.allows(
      policy, "fullscreen", "https://app.example", "https://app.example",
    ).to_string(),
  )
  println(
    "fullscreen partner=" +
    @permscope.allows(
      policy, "fullscreen", "https://app.example", "https://video.example",
    ).to_string(),
  )
  println(
    "camera cross-site=" +
    @permscope.allows(
      policy, "camera", "https://app.example", "https://evil.example",
    ).to_string(),
  )
  println(@permscope.render_report(report))
  println(
    "legacy-migration=" +
    @permscope.migrate_feature_policy(
      "camera 'none'; fullscreen 'self' https://video.example",
    ),
  )
}
