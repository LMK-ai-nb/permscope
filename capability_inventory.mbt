///|
/// An inventory-level mismatch between declared routes and observed responses.
pub struct CapabilityInventoryFinding {
  code : String
  name : String
  message : String
} derive(Eq, @debug.Debug)

///|
/// Audit of all observed route responses against named capability contracts.
pub struct CapabilityInventoryAudit {
  audits : Array[CapabilityResponseAudit]
  findings : Array[CapabilityInventoryFinding]
  ok : Bool
} derive(Eq, @debug.Debug)

///|
/// Check that every named contract has one observed response and every response
/// has one contract. Names are compared after trimming surrounding whitespace.
pub fn audit_capability_inventory(
  samples : Array[ResponseSample],
  contracts : Array[CapabilityContract],
) -> CapabilityInventoryAudit {
  let audits : Array[CapabilityResponseAudit] = []
  let findings : Array[CapabilityInventoryFinding] = []
  let contract_names : Array[String] = []
  let sample_names : Array[String] = []
  if samples.length() == 0 && contracts.length() == 0 {
    findings.push({
      code: "inventory-empty",
      name: "-",
      message: "no response samples or contracts were supplied",
    })
  }
  for contract in contracts {
    let name = trim(contract.name)
    if name == "" {
      findings.push({
        code: "empty-contract-name",
        name: "-",
        message: "a capability contract has no route name",
      })
      continue
    }
    if string_in(contract_names, name) {
      findings.push({
        code: "duplicate-contract-name",
        name,
        message: "more than one capability contract uses this route name",
      })
      continue
    }
    contract_names.push(name)
    let mut observed : ResponseSample? = None
    for sample in samples {
      if trim(sample.name) == name {
        observed = Some(sample)
        break
      }
    }
    match observed {
      Some(sample) => audits.push(audit_capability_response(sample, contract))
      None =>
        findings.push({
          code: "contract-without-sample",
          name,
          message: "declared route has no observed response sample",
        })
    }
  }
  for sample in samples {
    let name = trim(sample.name)
    if name == "" {
      findings.push({
        code: "empty-sample-name",
        name: "-",
        message: "an observed response sample has no route name",
      })
      continue
    }
    if string_in(sample_names, name) {
      findings.push({
        code: "duplicate-sample-name",
        name,
        message: "more than one response sample uses this route name",
      })
      continue
    }
    sample_names.push(name)
    if !string_in(contract_names, name) {
      findings.push({
        code: "sample-without-contract",
        name,
        message: "observed response has no capability contract",
      })
    }
  }
  let mut ok = findings.length() == 0
  for audit in audits {
    if !audit.report.ok {
      ok = false
    }
  }
  { audits, findings, ok, }
}

///|
/// Render the inventory and every route result for CI logs.
pub fn render_capability_inventory(audit : CapabilityInventoryAudit) -> String {
  let lines : Array[String] = [
    "permscope capability inventory",
    "audited=" +
    audit.audits.length().to_string() +
    " inventory_findings=" +
    audit.findings.length().to_string(),
  ]
  if audit.ok {
    lines.push("inventory: pass")
  } else {
    lines.push("inventory: fail")
  }
  for finding in audit.findings {
    lines.push(finding.code + " " + finding.name + " - " + finding.message)
  }
  for route_audit in audit.audits {
    lines.push(render_capability_response_audit(route_audit))
  }
  lines.join("\n")
}
