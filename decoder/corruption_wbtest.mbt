///|
fn expect_code(outcome : DecodeOutcome, code : DiagnosticCode) -> Unit raise {
  match outcome {
    Rejected(diagnostics) => assert_eq(diagnostics[0].code, code)
    _ => fail("corruption vector must be rejected with a classified Diagnostic")
  }
}

///|
test "corruption matrix classifies framing and Template boundaries" {
  let session = SessionKey::new("tcp:corruption")
  expect_code(
    decode_message(
      b"\x00\x0a\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", session,
    ),
    DiagnosticCode::InvalidMessageLength,
  )
  expect_code(
    decode_message(
      b"\x00\x0a\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x03",
      session,
    ),
    DiagnosticCode::InvalidSetLength,
  )
  expect_code(
    decode_message(
      b"\x00\x0a\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x08",
      session,
    ),
    DiagnosticCode::SetExceedsMessage,
  )
  let decoder = Decoder::new()
  expect_code(
    decoder.decode_message(
      b"\x00\x0a\x00\x1c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2a\x00\x02\x00\x0c\x00\xff\x00\x01\x00\x08\x00\x04",
      session,
    ),
    DiagnosticCode::InvalidTemplateId,
  )
  expect_code(
    decoder.decode_message(
      b"\x00\x0a\x00\x1c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2a\x00\x02\x00\x0c\x01\x00\x00\x02\x00\x08\x00\x04",
      session,
    ),
    DiagnosticCode::TruncatedTemplateRecord,
  )
}

///|
test "complete and streaming decoders agree on limit failure classification" {
  let limits = { ..DecoderLimits::default(), max_fields_per_template: 1 }
  let session = SessionKey::new("tcp:stream-limit-equivalence")
  let complete = Decoder::with_limits(limits).unwrap()
  let expected = complete.decode_message(options_template_message(), session)
  expect_code(expected, DiagnosticCode::FieldCountLimitExceeded)
  let stream = StreamDecoder::with_limits_and_config(
    session,
    @registry.Registry::standard(),
    limits,
    StreamDecoderConfig::default(),
  ).unwrap()
  let batch = stream.push(options_template_message())
  assert_eq(batch.outcomes.length(), 1)
  expect_code(batch.outcomes[0], DiagnosticCode::FieldCountLimitExceeded)
  assert_eq(stream.finish(), StreamEnd::Complete)
}

///|
test "stream framing rejects invalid length once and never scans for recovery" {
  let stream = StreamDecoder::new(SessionKey::new("tcp:no-scan"))
  let invalid_then_valid = join_bytes(
    b"\x00\x0a\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    replacement_template_message(),
  )
  let batch = stream.push(invalid_then_valid)
  assert_eq(batch.outcomes.length(), 1)
  expect_code(batch.outcomes[0], DiagnosticCode::InvalidMessageLength)
  assert_eq(stream.finish(), StreamEnd::BoundaryLost)
  let after_loss = stream.push(replacement_template_message())
  expect_code(after_loss.outcomes[0], DiagnosticCode::StreamBoundaryLost)
}
