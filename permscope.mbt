///|
/// One Permissions-Policy allowlist token.
pub enum AllowToken {
  TokenSelf
  TokenAll
  TokenOrigin(String)
} derive(Eq, @debug.Debug)

///|
/// A parsed Permissions-Policy directive such as `camera=()`.
pub struct Directive {
  feature : String
  tokens : Array[AllowToken]
  raw : String
  index : Int
} derive(Eq, @debug.Debug)

///|
/// A non-fatal parser warning. Warnings keep the policy usable in CI reports.
pub struct ParseWarning {
  index : Int
  message : String
  text : String
} derive(Eq, @debug.Debug)

///|
/// Parsed modern Permissions-Policy header.
pub struct Policy {
  directives : Array[Directive]
  warnings : Array[ParseWarning]
} derive(Eq, @debug.Debug)

///|
/// Parse a modern `Permissions-Policy` header.
pub fn parse(header : String) -> Policy {
  let directives : Array[Directive] = []
  let warnings : Array[ParseWarning] = []
  let clean = trim(header)
  if clean == "" {
    warnings.push({ index: 0, message: "empty header", text: header })
    return { directives, warnings }
  }
  let mut index = 0
  for part_view in clean.split(",") {
    index = index + 1
    let part = trim(part_view.to_owned())
    if part == "" {
      warnings.push({
        index,
        message: "empty directive segment",
        text: part_view.to_owned(),
      })
      continue
    }
    match parse_modern_directive(part, index, warnings) {
      None => ()
      Some(directive) => {
        if has_feature(directives, directive.feature) {
          warnings.push({
            index,
            message: "duplicate directive for feature: " + directive.feature,
            text: part,
          })
        }
        directives.push(directive)
      }
    }
  }
  { directives, warnings }
}

///|
/// Parse a legacy `Feature-Policy` header and normalize it to this package's
/// modern directive representation.
pub fn parse_feature_policy(header : String) -> Policy {
  let directives : Array[Directive] = []
  let warnings : Array[ParseWarning] = []
  let clean = trim(header)
  if clean == "" {
    warnings.push({ index: 0, message: "empty legacy header", text: header })
    return { directives, warnings }
  }
  let mut index = 0
  for part_view in clean.split(";") {
    index = index + 1
    let part = trim(part_view.to_owned())
    if part == "" {
      continue
    }
    match parse_legacy_directive(part, index, warnings) {
      None => ()
      Some(directive) => {
        if has_feature(directives, directive.feature) {
          warnings.push({
            index,
            message: "duplicate legacy directive for feature: " +
            directive.feature,
            text: part,
          })
        }
        directives.push(directive)
      }
    }
  }
  { directives, warnings }
}

///|
/// Return the first directive for `feature`, if one is present.
pub fn directive(policy : Policy, feature : String) -> Directive? {
  let wanted = normalize_feature(feature)
  for d in policy.directives {
    if d.feature == wanted {
      return Some(d)
    }
  }
  None
}

///|
/// Decide whether a feature is allowed for a target origin.
///
/// Missing directives are treated as allowed because the header does not impose
/// a restriction for that feature. Use `audit` to flag missing restrictions for
/// high-risk browser capabilities.
pub fn allows(
  policy : Policy,
  feature : String,
  document_origin : String,
  target_origin : String,
) -> Bool {
  match directive(policy, feature) {
    None => true
    Some(directive) =>
      tokens_allow(
        directive.tokens,
        normalize_origin(document_origin),
        normalize_origin(target_origin),
      )
  }
}

///|
/// Render a policy back to normalized modern header syntax.
pub fn render(policy : Policy) -> String {
  let parts : Array[String] = []
  for d in policy.directives {
    parts.push(render_directive(d))
  }
  parts.join(", ")
}

///|
fn parse_modern_directive(
  part : String,
  index : Int,
  warnings : Array[ParseWarning],
) -> Directive? {
  match part.find("=") {
    None => {
      warnings.push({ index, message: "directive is missing '='", text: part })
      None
    }
    Some(eq) => {
      let feature = normalize_feature(part[:eq].to_owned())
      let value = trim(part[eq + 1:].to_owned())
      if feature == "" {
        warnings.push({ index, message: "empty feature name", text: part })
        return None
      }
      if !feature_name_ok(feature) {
        warnings.push({
          index,
          message: "feature name contains unusual characters",
          text: part,
        })
      }
      if !value.has_prefix("(") || !value.has_suffix(")") {
        warnings.push({
          index,
          message: "allowlist should be wrapped in parentheses",
          text: part,
        })
        return Some({
          feature,
          tokens: parse_token_list(value, index, warnings),
          raw: part,
          index,
        })
      }
      let body = value[1:value.length() - 1].to_owned()
      Some({
        feature,
        tokens: parse_token_list(body, index, warnings),
        raw: part,
        index,
      })
    }
  }
}

///|
fn parse_legacy_directive(
  part : String,
  index : Int,
  warnings : Array[ParseWarning],
) -> Directive? {
  match part.find(" ") {
    None => {
      let feature = normalize_feature(part)
      if feature == "" {
        warnings.push({
          index,
          message: "empty legacy feature name",
          text: part,
        })
        None
      } else {
        warnings.push({
          index,
          message: "legacy directive has no allowlist; treating as disabled",
          text: part,
        })
        Some({ feature, tokens: [], raw: part, index })
      }
    }
    Some(space) => {
      let feature = normalize_feature(part[:space].to_owned())
      let value = trim(part[space + 1:].to_owned())
      if feature == "" {
        warnings.push({
          index,
          message: "empty legacy feature name",
          text: part,
        })
        None
      } else {
        warnings.push({
          index,
          message: "legacy Feature-Policy syntax parsed for migration",
          text: part,
        })
        Some({
          feature,
          tokens: parse_token_list(value, index, warnings),
          raw: part,
          index,
        })
      }
    }
  }
}

///|
fn parse_token_list(
  body : String,
  index : Int,
  warnings : Array[ParseWarning],
) -> Array[AllowToken] {
  let tokens : Array[AllowToken] = []
  let mut saw_none = false
  for token_view in body.split(" ") {
    let token = strip_quotes(trim(token_view.to_owned()))
    if token == "" {
      continue
    }
    match token {
      "*" => tokens.push(TokenAll)
      "self" => tokens.push(TokenSelf)
      "'self'" => tokens.push(TokenSelf)
      "none" | "'none'" => saw_none = true
      _ => {
        if !origin_like(token) {
          warnings.push({
            index,
            message: "allowlist token is not self, none, wildcard, or an origin",
            text: token,
          })
        }
        tokens.push(TokenOrigin(token))
      }
    }
  }
  if saw_none && tokens.length() > 0 {
    warnings.push({
      index,
      message: "none is mixed with other allowlist tokens; none wins",
      text: body,
    })
    []
  } else {
    tokens
  }
}

///|
fn tokens_allow(
  tokens : Array[AllowToken],
  document_origin : String,
  target_origin : String,
) -> Bool {
  for token in tokens {
    match token {
      TokenAll => return true
      TokenSelf => if document_origin == target_origin { return true }
      TokenOrigin(origin) =>
        if normalize_origin(origin) == target_origin {
          return true
        }
    }
  }
  false
}

///|
fn render_directive(directive : Directive) -> String {
  if directive.tokens.length() == 0 {
    directive.feature + "=()"
  } else {
    let tokens : Array[String] = []
    for token in directive.tokens {
      tokens.push(render_token(token))
    }
    directive.feature + "=(" + tokens.join(" ") + ")"
  }
}

///|
fn render_token(token : AllowToken) -> String {
  match token {
    TokenAll => "*"
    TokenSelf => "self"
    TokenOrigin(origin) => "\"" + normalize_origin(origin) + "\""
  }
}

///|
fn has_feature(directives : Array[Directive], feature : String) -> Bool {
  for directive in directives {
    if directive.feature == feature {
      return true
    }
  }
  false
}

///|
fn normalize_feature(value : String) -> String {
  trim(value).to_lower()
}

///|
fn normalize_origin(value : String) -> String {
  let clean = strip_quotes(trim(value)).to_lower()
  if clean.has_suffix("/") {
    clean[:clean.length() - 1].to_owned()
  } else {
    clean
  }
}

///|
fn strip_quotes(value : String) -> String {
  let clean = trim(value)
  if clean.length() >= 2 &&
    (
      (clean.has_prefix("\"") && clean.has_suffix("\"")) ||
      (clean.has_prefix("'") && clean.has_suffix("'"))
    ) {
    clean[1:clean.length() - 1].to_owned()
  } else {
    clean
  }
}

///|
fn origin_like(value : String) -> Bool {
  value.has_prefix("https://") ||
  value.has_prefix("http://localhost") ||
  value.has_prefix("http://127.0.0.1")
}

///|
fn feature_name_ok(feature : String) -> Bool {
  if feature == "" {
    return false
  }
  for ch in feature {
    if ch == '-' || ch.is_ascii_digit() {
      continue
    }
    let piece = ch.to_string()
    if piece < "a" || piece > "z" {
      return false
    }
  }
  true
}

///|
fn trim(value : String) -> String {
  value.trim(chars=" \t\r\n").to_owned()
}
