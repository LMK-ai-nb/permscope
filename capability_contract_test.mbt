///|
test "capability contract generates a minimal satisfying policy" {
  let contract = @permscope.capability_contract(
    "video-room",
    "https://app.example",
    [
      @permscope.capability_need("camera", ["self"], "local preview"),
      @permscope.capability_need(
        "fullscreen",
        ["self", "https://video.example/"],
        "embedded player",
      ),
    ],
    true,
  )
  let header = @permscope.minimal_policy_for_contract(contract)
  @test.assert_eq(header.contains("camera=(self)"), true)
  @test.assert_eq(
    header.contains("fullscreen=(self \"https://video.example\")"),
    true,
  )
  let report = @permscope.audit_capability_contract(
    @permscope.parse(header),
    contract,
  )
  @test.assert_eq(report.ok, true)
  @test.assert_eq(report.allowed, 3)
  @test.assert_eq(
    @permscope.render_capability_contract_report(report).contains(
      "contract: pass",
    ),
    true,
  )
}

///|
test "capability contract detects missing required features" {
  let contract = @permscope.capability_contract(
    "paywall-checkout",
    "https://shop.example",
    [@permscope.capability_need("payment", ["self"], "checkout flow")],
    true,
  )
  let report = @permscope.audit_capability_contract(
    @permscope.parse("payment=()"),
    contract,
  )
  @test.assert_eq(report.ok, false)
  @test.assert_eq(report.missing, 1)
  @test.assert_eq(
    @permscope.render_capability_contract_report(report).contains(
      "required-capability-blocked",
    ),
    true,
  )
}

///|
test "capability contract flags wildcard delegation" {
  let contract = @permscope.capability_contract(
    "device-lab",
    "https://lab.example",
    [
      @permscope.capability_need(
        "usb",
        ["self", "https://kit.example"],
        "hardware diagnostics",
      ),
    ],
    true,
  )
  let report = @permscope.audit_capability_contract(
    @permscope.parse("usb=(*)"),
    contract,
  )
  @test.assert_eq(report.ok, false)
  @test.assert_eq(report.overbroad, 1)
  @test.assert_eq(
    @permscope.render_capability_contract_report(report).contains(
      "capability-wildcard",
    ),
    true,
  )
}

///|
test "capability contract catches undeclared delegated origins" {
  let contract = @permscope.capability_contract(
    "device-lab",
    "https://lab.example",
    [
      @permscope.capability_need(
        "serial",
        ["https://kit.example"],
        "test station bridge",
      ),
    ],
    true,
  )
  let report = @permscope.audit_capability_contract(
    @permscope.parse(
      "serial=(\"https://kit.example\" \"https://extra.example\")",
    ),
    contract,
  )
  @test.assert_eq(report.ok, false)
  @test.assert_eq(report.unexpected > 0, true)
  @test.assert_eq(
    @permscope.render_capability_contract_report(report).contains(
      "unexpected-origin-delegation",
    ),
    true,
  )
}

///|
test "optional capability can be blocked without failing the contract" {
  let contract = @permscope.capability_contract(
    "reader",
    "https://docs.example",
    [
      @permscope.optional_capability_need(
        "web-share",
        ["self"],
        "native share button",
      ),
    ],
    false,
  )
  let report = @permscope.audit_capability_contract(
    @permscope.parse("web-share=()"),
    contract,
  )
  @test.assert_eq(report.ok, true)
  @test.assert_eq(
    @permscope.render_capability_contract_report(report).contains(
      "optional-capability-blocked",
    ),
    true,
  )
}

///|
test "strict contract rejects an undeclared low risk capability" {
  let contract = @permscope.capability_contract(
    "reader",
    "https://docs.example",
    [],
    true,
  )
  let intents : Array[@permscope.PolicyIntent] = []
  for spec in @permscope.known_features() {
    if spec.feature == "web-share" {
      intents.push(@permscope.self_only(spec.feature))
    } else {
      intents.push(@permscope.deny(spec.feature))
    }
  }
  let report = @permscope.audit_capability_contract(
    @permscope.parse(@permscope.build(intents)),
    contract,
  )
  @test.assert_eq(report.ok, false)
  @test.assert_eq(report.unexpected, 1)
  @test.assert_eq(
    @permscope.render_capability_contract_report(report).contains(
      "warning undeclared-feature-enabled web-share",
    ),
    true,
  )
}

///|
test "contract rejects a missing directive for a declared capability" {
  let contract = @permscope.capability_contract(
    "checkout",
    "https://shop.example",
    [@permscope.capability_need("payment", ["self"], "checkout")],
    false,
  )
  let report = @permscope.audit_capability_contract(
    @permscope.parse("camera=()"),
    contract,
  )
  @test.assert_eq(report.ok, false)
  @test.assert_eq(report.overbroad, 1)
  @test.assert_eq(
    @permscope.render_capability_contract_report(report).contains(
      "capability-directive-missing",
    ),
    true,
  )
}

///|
test "contract rejects a malformed policy with parse warnings" {
  let contract = @permscope.capability_contract(
    "reader",
    "https://docs.example",
    [],
    false,
  )
  let report = @permscope.audit_capability_contract(
    @permscope.parse("not-a-directive"),
    contract,
  )
  @test.assert_eq(report.ok, false)
  @test.assert_eq(
    @permscope.render_capability_contract_report(report).contains(
      "policy-parse-warning",
    ),
    true,
  )
}
