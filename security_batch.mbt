///|
/// One response sample collected from a route, endpoint, or deployment.
pub struct ResponseSample {
  name : String
  path : String
  document_origin : String
  header_block : String
} derive(Eq, @debug.Debug)

///|
/// Score for one audited response sample.
pub struct SampleScore {
  name : String
  path : String
  grade : String
  points : Int
  max_points : Int
  percent : Int
  high : Int
  warning : Int
} derive(Eq, @debug.Debug)

///|
/// Batch audit across many response samples.
pub struct BatchAudit {
  samples : Array[ResponseSample]
  audits : Array[SecurityAudit]
  scores : Array[SampleScore]
  average_percent : Int
  worst_grade : String
  high_total : Int
  warning_total : Int
} derive(Eq, @debug.Debug)

///|
/// Batch-level CI gate result.
pub struct BatchGate {
  ok : Bool
  required_grade : String
  max_high : Int
  max_warning : Int
  messages : Array[String]
} derive(Eq, @debug.Debug)

///|
/// One batch recommendation tied to a response sample.
pub struct BatchRecommendation {
  sample : String
  path : String
  header : String
  value : String
  priority : String
  reason : String
} derive(Eq, @debug.Debug)

///|
/// Create a response sample.
pub fn response_sample(
  name : String,
  path : String,
  document_origin : String,
  header_block : String,
) -> ResponseSample {
  { name, path, document_origin, header_block, }
}

///|
/// Create a response sample from a security header bundle.
pub fn response_sample_from_bundle(
  name : String,
  path : String,
  bundle : SecurityHeaderBundle,
) -> ResponseSample {
  {
    name,
    path,
    document_origin: bundle.document_origin,
    header_block: render_security_bundle(bundle),
  }
}

///|
/// Audit one response sample.
pub fn audit_response_sample(sample : ResponseSample) -> SecurityAudit {
  audit_security_header_block(sample.header_block, sample.document_origin)
}

///|
/// Audit many response samples.
pub fn audit_response_samples(samples : Array[ResponseSample]) -> BatchAudit {
  let audits : Array[SecurityAudit] = []
  let scores : Array[SampleScore] = []
  let mut total_percent = 0
  let mut high_total = 0
  let mut warning_total = 0
  let mut worst_grade = "A"
  for sample in samples {
    let audit = audit_response_sample(sample)
    audits.push(audit)
    let score = sample_score(sample, audit)
    scores.push(score)
    total_percent = total_percent + score.percent
    high_total = high_total + score.high
    warning_total = warning_total + score.warning
    if grade_rank(score.grade) > grade_rank(worst_grade) {
      worst_grade = score.grade
    }
  }
  let average_percent = if scores.length() == 0 {
    0
  } else {
    total_percent / scores.length()
  }
  {
    samples,
    audits,
    scores,
    average_percent,
    worst_grade,
    high_total,
    warning_total,
  }
}

///|
/// Return scores at or below a grade threshold.
pub fn batch_scores_at_or_below(
  batch : BatchAudit,
  grade : String,
) -> Array[SampleScore] {
  let result : Array[SampleScore] = []
  let threshold = grade_rank(grade)
  for score in batch.scores {
    if grade_rank(score.grade) >= threshold {
      result.push(score)
    }
  }
  result
}

///|
/// Return samples with high-severity findings.
pub fn batch_samples_with_high(batch : BatchAudit) -> Array[SampleScore] {
  let result : Array[SampleScore] = []
  for score in batch.scores {
    if score.high > 0 {
      result.push(score)
    }
  }
  result
}

///|
/// Return the best sample score in a batch.
pub fn best_sample_score(batch : BatchAudit) -> SampleScore? {
  let mut best : SampleScore? = None
  for score in batch.scores {
    match best {
      None => best = Some(score)
      Some(current) => if score.percent > current.percent { best = Some(score) }
    }
  }
  best
}

///|
/// Return the weakest sample score in a batch.
pub fn weakest_sample_score(batch : BatchAudit) -> SampleScore? {
  let mut weakest : SampleScore? = None
  for score in batch.scores {
    match weakest {
      None => weakest = Some(score)
      Some(current) =>
        if score.percent < current.percent {
          weakest = Some(score)
        }
    }
  }
  weakest
}

///|
/// Collect recommendations across every response sample.
pub fn batch_recommendations(batch : BatchAudit) -> Array[BatchRecommendation] {
  let recommendations : Array[BatchRecommendation] = []
  let mut index = 0
  for audit in batch.audits {
    let sample = batch.samples[index]
    for item in security_recommendations(audit) {
      recommendations.push({
        sample: sample.name,
        path: sample.path,
        header: item.header,
        value: item.value,
        priority: item.priority,
        reason: item.reason,
      })
    }
    index = index + 1
  }
  recommendations
}

///|
/// Build a batch gate for CI.
pub fn batch_security_gate(
  batch : BatchAudit,
  required_grade : String,
  max_high : Int,
  max_warning : Int,
) -> BatchGate {
  let messages : Array[String] = []
  if grade_rank(batch.worst_grade) > grade_rank(required_grade) {
    messages.push(
      "worst grade " +
      batch.worst_grade +
      " is below required " +
      required_grade.to_upper(),
    )
  }
  if batch.high_total > max_high {
    messages.push(
      "high findings " +
      batch.high_total.to_string() +
      " exceed limit " +
      max_high.to_string(),
    )
  }
  if batch.warning_total > max_warning {
    messages.push(
      "warning findings " +
      batch.warning_total.to_string() +
      " exceed limit " +
      max_warning.to_string(),
    )
  }
  {
    ok: messages.length() == 0,
    required_grade: required_grade.to_upper(),
    max_high,
    max_warning,
    messages,
  }
}

///|
/// Render a batch audit summary.
pub fn render_batch_audit(batch : BatchAudit) -> String {
  let lines : Array[String] = []
  lines.push("permscope batch security audit")
  lines.push("samples=" + batch.samples.length().to_string())
  lines.push("average_percent=" + batch.average_percent.to_string())
  lines.push("worst_grade=" + batch.worst_grade)
  lines.push("high_total=" + batch.high_total.to_string())
  lines.push("warning_total=" + batch.warning_total.to_string())
  for score in batch.scores {
    lines.push(render_sample_score(score))
  }
  lines.join("\n")
}

///|
/// Render one sample score.
pub fn render_sample_score(score : SampleScore) -> String {
  score.name +
  " " +
  score.path +
  " grade=" +
  score.grade +
  " score=" +
  score.points.to_string() +
  "/" +
  score.max_points.to_string() +
  " percent=" +
  score.percent.to_string() +
  " high=" +
  score.high.to_string() +
  " warning=" +
  score.warning.to_string()
}

///|
/// Render batch recommendations.
pub fn render_batch_recommendations(
  recommendations : Array[BatchRecommendation],
) -> String {
  if recommendations.length() == 0 {
    return "permscope batch recommendations: no changes"
  }
  let lines : Array[String] = ["permscope batch recommendations:"]
  for item in recommendations {
    lines.push(
      item.priority +
      " " +
      item.sample +
      " " +
      item.path +
      " " +
      item.header +
      " -> " +
      item.value +
      " - " +
      item.reason,
    )
  }
  lines.join("\n")
}

///|
/// Render a batch gate result.
pub fn render_batch_gate(gate : BatchGate) -> String {
  let lines : Array[String] = []
  if gate.ok {
    lines.push("permscope batch gate: pass")
  } else {
    lines.push("permscope batch gate: fail")
  }
  lines.push("required_grade=" + gate.required_grade)
  lines.push("max_high=" + gate.max_high.to_string())
  lines.push("max_warning=" + gate.max_warning.to_string())
  for message in gate.messages {
    lines.push("message=" + message)
  }
  lines.join("\n")
}

///|
/// Render a Markdown batch report.
pub fn render_batch_markdown(batch : BatchAudit) -> String {
  let lines : Array[String] = []
  lines.push("# permscope batch security audit")
  lines.push("")
  lines.push("- Samples: " + batch.samples.length().to_string())
  lines.push("- Average percent: " + batch.average_percent.to_string())
  lines.push("- Worst grade: " + batch.worst_grade)
  lines.push("- High findings: " + batch.high_total.to_string())
  lines.push("- Warning findings: " + batch.warning_total.to_string())
  lines.push("")
  lines.push("| Sample | Path | Grade | Percent | High | Warning |")
  lines.push("| --- | --- | --- | ---: | ---: | ---: |")
  for score in batch.scores {
    lines.push(
      "| " +
      score.name +
      " | " +
      score.path +
      " | " +
      score.grade +
      " | " +
      score.percent.to_string() +
      " | " +
      score.high.to_string() +
      " | " +
      score.warning.to_string() +
      " |",
    )
  }
  lines.join("\n")
}

///|
/// Render a JSON-like batch report.
pub fn render_batch_json(batch : BatchAudit) -> String {
  let lines : Array[String] = []
  lines.push("{")
  lines.push("  \"samples\": " + batch.samples.length().to_string() + ",")
  lines.push(
    "  \"average_percent\": " + batch.average_percent.to_string() + ",",
  )
  lines.push("  \"worst_grade\": \"" + batch.worst_grade + "\",")
  lines.push("  \"scores\": [")
  let mut index = 0
  for score in batch.scores {
    index = index + 1
    lines.push("    {")
    lines.push("      \"name\": \"" + batch_json_escape(score.name) + "\",")
    lines.push("      \"path\": \"" + batch_json_escape(score.path) + "\",")
    lines.push("      \"grade\": \"" + score.grade + "\",")
    lines.push("      \"percent\": " + score.percent.to_string())
    if index == batch.scores.length() {
      lines.push("    }")
    } else {
      lines.push("    },")
    }
  }
  lines.push("  ]")
  lines.push("}")
  lines.join("\n")
}

///|
fn sample_score(sample : ResponseSample, audit : SecurityAudit) -> SampleScore {
  {
    name: sample.name,
    path: sample.path,
    grade: audit.score.grade,
    points: audit.score.points,
    max_points: audit.score.max_points,
    percent: audit.score.percent,
    high: audit.score.high,
    warning: audit.score.warning,
  }
}

///|
fn batch_json_escape(value : String) -> String {
  let parts : Array[String] = []
  for ch in value {
    match ch {
      '"' => parts.push("\\\"")
      '\\' => parts.push("\\\\")
      '\n' => parts.push("\\n")
      '\r' => parts.push("\\r")
      '\t' => parts.push("\\t")
      _ => parts.push(ch.to_string())
    }
  }
  parts.join("")
}
