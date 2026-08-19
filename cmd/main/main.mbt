///|
fn main {
  let header = @permscope.recommended_header()
  let policy = @permscope.parse(header)
  let report = @permscope.audit(
    policy,
    @permscope.catalog_baseline("https://app.example"),
  )
  let summary = @permscope.summarize(
    policy,
    @permscope.catalog_baseline("https://app.example"),
  )
  let relaxed = @permscope.parse(
    @permscope.build([
      @permscope.all_origins("camera"),
      @permscope.self_only("fullscreen"),
    ]),
  )
  println("permscope demo")
  println("normalized=" + @permscope.render(policy))
  println(@permscope.render_summary(summary))
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
  println(@permscope.render_diffs(@permscope.diff(policy, relaxed)))
}
