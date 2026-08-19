///|
test "origin normalization lowercases and removes trailing slash" {
  @test.assert_eq(
    normalize_origin("\"HTTPS://APP.EXAMPLE/\""),
    "https://app.example",
  )
}

///|
test "feature names reject unexpected punctuation" {
  @test.assert_eq(feature_name_ok("camera"), true)
  @test.assert_eq(feature_name_ok("publickey-credentials-get"), true)
  @test.assert_eq(feature_name_ok("camera!"), false)
}

///|
test "none overrides mixed legacy allowlists" {
  let warnings : Array[ParseWarning] = []
  let tokens = parse_token_list("'none' https://video.example", 1, warnings)
  @test.assert_eq(tokens.length(), 0)
  @test.assert_eq(warnings.length(), 1)
}
