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
  let header_block = "HTTP/2 200\nPermissions-Policy: " +
    header +
    "\nX-Content-Type-Options: nosniff"
  let header_audit = @permscope.audit_header_block(
    header_block,
    @permscope.catalog_baseline("https://app.example"),
  )
  let matrix = @permscope.access_matrix(
    policy,
    ["camera", "fullscreen", "usb"],
    "https://app.example",
    ["https://app.example", "https://video.example"],
  )
  println("permscope demo")
  println("normalized=" + @permscope.render(policy))
  println(@permscope.render_summary(summary))
  println(@permscope.render_profile(@permscope.media_app_profile(), []))
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
  println(@permscope.render_header_audit(header_audit))
  println(@permscope.render_access_matrix(matrix))
  println(@permscope.render_diffs(@permscope.diff(policy, relaxed)))
}
