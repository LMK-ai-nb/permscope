///|
fn main {
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
  let sample = @permscope.response_sample(
    "video-room",
    "/video",
    "https://app.example",
    "HTTP/1.1 302 Found\nLocation: /video\nPermissions-Policy: camera=*\n\nHTTP/2 200\nPermissions-Policy: " +
    @permscope.minimal_policy_for_contract(contract),
  )
  let audit = @permscope.audit_capability_response(sample, contract)
  println(@permscope.render_capability_response_audit(audit))
  let checkout = @permscope.capability_contract(
    "checkout",
    "https://shop.example",
    [@permscope.capability_need("payment", ["self"], "checkout flow")],
    true,
  )
  let checkout_sample = @permscope.response_sample(
    "checkout",
    "/checkout",
    "https://shop.example",
    "Permissions-Policy: " + @permscope.minimal_policy_for_contract(checkout),
  )
  let inventory = @permscope.audit_capability_inventory(
    [sample, checkout_sample],
    [contract, checkout],
  )
  println(@permscope.render_capability_inventory(inventory))
}
