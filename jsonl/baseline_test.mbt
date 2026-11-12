///|
test "design baseline versions machine output independently" {
  inspect(@jsonl.schema_version, content="1")
  inspect(
    @jsonl.baseline_identity(),
    content="moonipfix/0.1.0-dev;jsonl=1;iana=2026-07-22",
  )
}
