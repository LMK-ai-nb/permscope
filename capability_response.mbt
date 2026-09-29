///|
/// A route's observed response and the result of checking its capability contract.
pub struct CapabilityResponseAudit {
  sample : ResponseSample
  report : CapabilityContractReport
} derive(Eq, @debug.Debug)

///|
/// Audit the actual response headers for one declared route.
///
/// This check requires a modern Permissions-Policy header. Legacy Feature-Policy
/// can still be inspected with audit_header_block for migration work.
pub fn audit_capability_response(
  sample : ResponseSample,
  contract : CapabilityContract,
) -> CapabilityResponseAudit {
  let headers = parse_header_block(sample.header_block)
  let policy = policy_from_headers(headers)
  let base = audit_capability_contract(policy, contract)
  let findings : Array[CapabilityFinding] = []
  let mut invalid_response = false
  if permissions_policy_header(headers) is None {
    invalid_response = true
    findings.push({
      severity: SeverityHigh,
      code: "permissions-policy-header-missing",
      feature: "-",
      target_origin: "-",
      message: "response does not contain a modern Permissions-Policy header",
    })
  }
  if policy.warnings.length() > 0 {
    invalid_response = true
    findings.push({
      severity: SeverityHigh,
      code: "response-policy-invalid",
      feature: "-",
      target_origin: "-",
      message: "response header block or capability policy has parse warnings",
    })
  }
  if normalize_origin(sample.document_origin) != base.contract.document_origin {
    invalid_response = true
    findings.push({
      severity: SeverityHigh,
      code: "document-origin-mismatch",
      feature: "-",
      target_origin: normalize_origin(sample.document_origin),
      message: "response origin differs from the declared contract origin",
    })
  }
  for finding in base.findings {
    if finding.code != "capability-contract-satisfied" || !invalid_response {
      findings.push(finding)
    }
  }
  { sample, report: { ..base, ok: base.ok && !invalid_response, findings } }
}

///|
/// Render a route-level response audit for CI logs.
pub fn render_capability_response_audit(
  audit : CapabilityResponseAudit,
) -> String {
  "route=" +
  audit.sample.path +
  " sample=" +
  audit.sample.name +
  "\n" +
  render_capability_contract_report(audit.report)
}
