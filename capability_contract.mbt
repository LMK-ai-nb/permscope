///|
/// One capability needed by a route, component, or user journey.
pub struct CapabilityNeed {
  feature : String
  target_origins : Array[String]
  reason : String
  required : Bool
} derive(Eq, @debug.Debug)

///|
/// A scenario-specific contract for browser capabilities.
pub struct CapabilityContract {
  name : String
  document_origin : String
  needs : Array[CapabilityNeed]
  forbid_unspecified : Bool
} derive(Eq, @debug.Debug)

///|
/// One finding produced while checking a capability contract.
pub struct CapabilityFinding {
  severity : Severity
  code : String
  feature : String
  target_origin : String
  message : String
} derive(Eq, @debug.Debug)

///|
/// Result of auditing a Permissions-Policy against a capability contract.
pub struct CapabilityContractReport {
  contract : CapabilityContract
  ok : Bool
  findings : Array[CapabilityFinding]
  allowed : Int
  missing : Int
  overbroad : Int
  unexpected : Int
} derive(Eq, @debug.Debug)

///|
/// Declare a required browser capability for one or more target origins.
pub fn capability_need(
  feature : String,
  target_origins : Array[String],
  reason : String,
) -> CapabilityNeed {
  { feature, target_origins, reason, required: true }
}

///|
/// Declare an optional browser capability for one or more target origins.
pub fn optional_capability_need(
  feature : String,
  target_origins : Array[String],
  reason : String,
) -> CapabilityNeed {
  { feature, target_origins, reason, required: false }
}

///|
/// Create a named capability contract.
pub fn capability_contract(
  name : String,
  document_origin : String,
  needs : Array[CapabilityNeed],
  forbid_unspecified : Bool,
) -> CapabilityContract {
  normalize_capability_contract({
    name,
    document_origin,
    needs,
    forbid_unspecified,
  })
}

///|
/// Return the declared feature names in stable first-seen order.
pub fn capability_contract_features(
  contract : CapabilityContract,
) -> Array[String] {
  let normalized = normalize_capability_contract(contract)
  let features : Array[String] = []
  for need in normalized.needs {
    push_unique(features, need.feature)
  }
  features
}

///|
/// Build the strictest Permissions-Policy header that satisfies a contract.
pub fn minimal_policy_for_contract(contract : CapabilityContract) -> String {
  build(minimal_policy_intents(contract))
}

///|
/// Build policy intents from a capability contract and the known feature catalog.
pub fn minimal_policy_intents(
  contract : CapabilityContract,
) -> Array[PolicyIntent] {
  let normalized = normalize_capability_contract(contract)
  let intents : Array[PolicyIntent] = []
  let covered : Array[String] = []
  for spec in known_features() {
    push_unique(covered, spec.feature)
    intents.push(contract_intent_for_feature(normalized, spec.feature))
  }
  for feature in capability_contract_features(normalized) {
    if !string_in(covered, feature) {
      intents.push(contract_intent_for_feature(normalized, feature))
    }
  }
  intents
}

///|
/// Audit whether a policy exactly supports a route-level capability contract.
pub fn audit_capability_contract(
  policy : Policy,
  contract : CapabilityContract,
) -> CapabilityContractReport {
  let normalized = normalize_capability_contract(contract)
  let findings : Array[CapabilityFinding] = []
  let checked : Array[String] = []
  let mut allowed = 0
  let mut missing = 0
  let mut overbroad = 0
  let mut unexpected = 0
  for warning in policy.warnings {
    findings.push({
      severity: SeverityWarning,
      code: "policy-parse-warning",
      feature: "-",
      target_origin: "-",
      message: "segment " + warning.index.to_string() + ": " + warning.message,
    })
  }
  for need in normalized.needs {
    if string_in(checked, need.feature) {
      continue
    }
    push_unique(checked, need.feature)
    match combined_need_for_feature(normalized, need.feature) {
      None => ()
      Some(combined) => {
        let counters = audit_declared_capability(
          policy, normalized, combined, findings,
        )
        allowed = allowed + counters.allowed
        missing = missing + counters.missing
        overbroad = overbroad + counters.overbroad
        unexpected = unexpected + counters.unexpected
      }
    }
  }
  if normalized.forbid_unspecified {
    let counters = audit_unspecified_capabilities(policy, normalized, findings)
    unexpected = unexpected + counters.unexpected
  }
  if findings.length() == 0 {
    findings.push({
      severity: SeverityInfo,
      code: "capability-contract-satisfied",
      feature: "-",
      target_origin: "-",
      message: "policy satisfies declared browser capability needs",
    })
  }
  {
    contract: normalized,
    ok: policy.warnings.length() == 0 &&
    !capability_has_high(findings) &&
    (!normalized.forbid_unspecified || unexpected == 0),
    findings,
    allowed,
    missing,
    overbroad,
    unexpected,
  }
}

///|
/// Render a contract audit in stable line-oriented text for CI logs.
pub fn render_capability_contract_report(
  report : CapabilityContractReport,
) -> String {
  let lines : Array[String] = []
  lines.push("permscope capability contract")
  lines.push("contract=" + report.contract.name)
  lines.push("document_origin=" + report.contract.document_origin)
  lines.push(
    "allowed=" +
    report.allowed.to_string() +
    " missing=" +
    report.missing.to_string() +
    " overbroad=" +
    report.overbroad.to_string() +
    " unexpected=" +
    report.unexpected.to_string(),
  )
  if report.ok {
    lines.push("contract: pass")
  } else {
    lines.push("contract: fail")
  }
  for finding in report.findings {
    lines.push(
      severity_label(finding.severity) +
      " " +
      finding.code +
      " " +
      finding.feature +
      " " +
      finding.target_origin +
      " - " +
      finding.message,
    )
  }
  lines.join("\n")
}

///|
struct ContractCounters {
  allowed : Int
  missing : Int
  overbroad : Int
  unexpected : Int
} derive(Eq, @debug.Debug)

///|
fn empty_contract_counters() -> ContractCounters {
  { allowed: 0, missing: 0, overbroad: 0, unexpected: 0 }
}

///|
fn audit_declared_capability(
  policy : Policy,
  contract : CapabilityContract,
  need : CapabilityNeed,
  findings : Array[CapabilityFinding],
) -> ContractCounters {
  let mut counters = empty_contract_counters()
  for target in need_targets(need, contract.document_origin) {
    if allows(policy, need.feature, contract.document_origin, target) {
      counters = { ..counters, allowed: counters.allowed + 1 }
    } else if need.required {
      counters = { ..counters, missing: counters.missing + 1 }
      findings.push({
        severity: SeverityHigh,
        code: "required-capability-blocked",
        feature: need.feature,
        target_origin: target,
        message: "declared required capability is blocked by the policy: " +
        need.reason,
      })
    } else {
      findings.push({
        severity: SeverityInfo,
        code: "optional-capability-blocked",
        feature: need.feature,
        target_origin: target,
        message: "optional capability is blocked by the policy: " + need.reason,
      })
    }
  }
  match directive(policy, need.feature) {
    None => {
      counters = { ..counters, overbroad: counters.overbroad + 1 }
      findings.push({
        severity: SeverityHigh,
        code: "capability-directive-missing",
        feature: need.feature,
        target_origin: "*",
        message: "missing directive provides no explicit header restriction for this capability",
      })
    }
    Some(item) => {
      if has_wildcard(item.tokens) {
        counters = { ..counters, overbroad: counters.overbroad + 1 }
        findings.push({
          severity: SeverityHigh,
          code: "capability-wildcard",
          feature: need.feature,
          target_origin: "*",
          message: "declared capability is delegated to every origin",
        })
      }
      if contract.forbid_unspecified {
        let extra = audit_extra_tokens(contract, need, item, findings)
        counters = {
          ..counters,
          unexpected: counters.unexpected + extra.unexpected,
        }
      }
    }
  }
  counters
}

///|
fn audit_extra_tokens(
  contract : CapabilityContract,
  need : CapabilityNeed,
  item : Directive,
  findings : Array[CapabilityFinding],
) -> ContractCounters {
  let mut counters = empty_contract_counters()
  for token in item.tokens {
    match token {
      TokenAll => ()
      TokenSelf =>
        if !need_allows_target(need, contract.document_origin) {
          counters = { ..counters, unexpected: counters.unexpected + 1 }
          findings.push({
            severity: SeverityWarning,
            code: "unexpected-self-delegation",
            feature: need.feature,
            target_origin: contract.document_origin,
            message: "policy allows self but the contract did not declare it",
          })
        }
      TokenOrigin(origin) => {
        let target = normalize_origin(origin)
        if !need_allows_target(need, target) {
          counters = { ..counters, unexpected: counters.unexpected + 1 }
          findings.push({
            severity: feature_risk_severity(need.feature),
            code: "unexpected-origin-delegation",
            feature: need.feature,
            target_origin: target,
            message: "policy delegates this capability to an undeclared origin",
          })
        }
      }
    }
  }
  counters
}

///|
fn audit_unspecified_capabilities(
  policy : Policy,
  contract : CapabilityContract,
  findings : Array[CapabilityFinding],
) -> ContractCounters {
  let mut counters = empty_contract_counters()
  for item in policy.directives {
    if !contract_declares_feature(contract, item.feature) &&
      item.tokens.length() > 0 {
      counters = { ..counters, unexpected: counters.unexpected + 1 }
      findings.push({
        severity: feature_risk_severity(item.feature),
        code: "undeclared-feature-enabled",
        feature: item.feature,
        target_origin: token_scope_label(item.tokens),
        message: "policy enables a feature not declared by the capability contract",
      })
    }
  }
  for spec in known_features() {
    if !contract_declares_feature(contract, spec.feature) &&
      allows(
        policy,
        spec.feature,
        contract.document_origin,
        "https://cross-site.invalid",
      ) {
      counters = { ..counters, unexpected: counters.unexpected + 1 }
      findings.push({
        severity: feature_risk_severity(spec.feature),
        code: "undeclared-feature-not-restricted",
        feature: spec.feature,
        target_origin: "https://cross-site.invalid",
        message: "header does not explicitly restrict this undeclared feature",
      })
    }
  }
  counters
}

///|
fn contract_intent_for_feature(
  contract : CapabilityContract,
  feature : String,
) -> PolicyIntent {
  match combined_need_for_feature(contract, feature) {
    None => deny(feature)
    Some(need) => {
      let targets = need_targets(need, contract.document_origin)
      let external : Array[String] = []
      let mut include_self = false
      for target in targets {
        if target == contract.document_origin {
          include_self = true
        } else {
          push_unique(external, target)
        }
      }
      if include_self && external.length() == 0 {
        self_only(feature)
      } else if include_self {
        self_and_origins(feature, external)
      } else if external.length() > 0 {
        origins_only(feature, external)
      } else {
        deny(feature)
      }
    }
  }
}

///|
fn combined_need_for_feature(
  contract : CapabilityContract,
  feature : String,
) -> CapabilityNeed? {
  let wanted = normalize_feature(feature)
  let targets : Array[String] = []
  let reasons : Array[String] = []
  let mut required = false
  let mut found = false
  for need in contract.needs {
    if need.feature == wanted {
      found = true
      if need.required {
        required = true
      }
      for target in need_targets(need, contract.document_origin) {
        push_unique(targets, target)
      }
      if need.reason != "" {
        reasons.push(need.reason)
      }
    }
  }
  if found {
    Some({
      feature: wanted,
      target_origins: targets,
      reason: reasons.join("; "),
      required,
    })
  } else {
    None
  }
}

///|
fn normalize_capability_contract(
  contract : CapabilityContract,
) -> CapabilityContract {
  let document_origin = normalize_origin(contract.document_origin)
  let needs : Array[CapabilityNeed] = []
  for need in contract.needs {
    needs.push(normalize_capability_need(need, document_origin))
  }
  {
    name: trim(contract.name),
    document_origin,
    needs,
    forbid_unspecified: contract.forbid_unspecified,
  }
}

///|
fn normalize_capability_need(
  need : CapabilityNeed,
  document_origin : String,
) -> CapabilityNeed {
  let targets : Array[String] = []
  for target in need.target_origins {
    let normalized = normalize_contract_target(target, document_origin)
    if normalized != "" {
      push_unique(targets, normalized)
    }
  }
  {
    feature: normalize_feature(need.feature),
    target_origins: targets,
    reason: trim(need.reason),
    required: need.required,
  }
}

///|
fn normalize_contract_target(
  target : String,
  document_origin : String,
) -> String {
  let clean = strip_quotes(trim(target)).to_lower()
  if clean == "" || clean == "self" {
    document_origin
  } else {
    normalize_origin(clean)
  }
}

///|
fn need_targets(
  need : CapabilityNeed,
  document_origin : String,
) -> Array[String] {
  if need.target_origins.length() == 0 {
    [document_origin]
  } else {
    need.target_origins
  }
}

///|
fn need_allows_target(need : CapabilityNeed, target_origin : String) -> Bool {
  let target = normalize_origin(target_origin)
  for declared in need.target_origins {
    if normalize_origin(declared) == target {
      return true
    }
  }
  false
}

///|
fn contract_declares_feature(
  contract : CapabilityContract,
  feature : String,
) -> Bool {
  let wanted = normalize_feature(feature)
  for need in contract.needs {
    if need.feature == wanted {
      return true
    }
  }
  false
}

///|
fn feature_risk_severity(feature : String) -> Severity {
  match known_feature(feature) {
    Some(spec) =>
      if spec.risk == RiskHigh {
        SeverityHigh
      } else {
        SeverityWarning
      }
    None => SeverityWarning
  }
}

///|
fn token_scope_label(tokens : Array[AllowToken]) -> String {
  if has_wildcard(tokens) {
    "*"
  } else if tokens.length() == 1 && tokens[0] == TokenSelf {
    "self"
  } else {
    "explicit"
  }
}

///|
fn capability_has_high(findings : Array[CapabilityFinding]) -> Bool {
  for finding in findings {
    if finding.severity == SeverityHigh {
      return true
    }
  }
  false
}
