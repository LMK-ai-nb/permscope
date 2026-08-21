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
    "\nContent-Security-Policy: " +
    @permscope.strict_csp_header() +
    "\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload" +
    "\nReferrer-Policy: strict-origin-when-cross-origin" +
    "\nX-Frame-Options: DENY" +
    "\nX-Content-Type-Options: nosniff" +
    "\nCross-Origin-Opener-Policy: same-origin" +
    "\nCross-Origin-Embedder-Policy: require-corp" +
    "\nCross-Origin-Resource-Policy: same-origin"
  let header_audit = @permscope.audit_header_block(
    header_block,
    @permscope.catalog_baseline("https://app.example"),
  )
  let security_audit = @permscope.audit_security_header_block(
    header_block, "https://app.example",
  )
  let batch = @permscope.audit_response_samples([
    @permscope.response_sample("home", "/", "https://app.example", header_block),
    @permscope.response_sample_from_bundle(
      "api",
      "/api",
      @permscope.api_service_security_bundle("https://api.example"),
    ),
  ])
  let matrix = @permscope.access_matrix(
    policy,
    ["camera", "fullscreen", "usb"],
    "https://app.example",
    ["https://app.example", "https://video.example"],
  )
  let contract = @permscope.capability_contract(
    "video-room",
    "https://app.example",
    [
      @permscope.capability_need("camera", ["self"], "local preview"),
      @permscope.capability_need(
        "fullscreen",
        ["self", "https://video.example"],
        "embedded player",
      ),
    ],
    true,
  )
  let contract_policy = @permscope.parse(
    @permscope.minimal_policy_for_contract(contract),
  )
  let contract_report = @permscope.audit_capability_contract(
    contract_policy, contract,
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
  println(@permscope.render_capability_contract_report(contract_report))
  println(@permscope.render_security_score(security_audit.score))
  println(
    @permscope.render_security_finding_summary(
      @permscope.summarize_security_findings(security_audit),
    ),
  )
  println(@permscope.render_batch_audit(batch))
  println(@permscope.render_diffs(@permscope.diff(policy, relaxed)))
}
