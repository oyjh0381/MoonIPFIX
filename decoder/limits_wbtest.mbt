///|
fn compact_limits() -> DecoderLimits {
  {
    max_sessions: 2,
    max_templates_per_session: 2,
    max_fields_per_template: 3,
    max_field_length: 4,
    max_records_per_message: 2,
    max_diagnostics_per_message: 2,
  }
}

///|
test "configured limits validate positivity and immutable hard ceilings" {
  let too_many_fields = {
    ..DecoderLimits::default(),
    max_fields_per_template: 4097,
  }
  match Decoder::with_limits(too_many_fields) {
    Err(AboveHardCeiling(name, configured, ceiling)) => {
      assert_eq(name, "max_fields_per_template")
      assert_eq(configured, 4097)
      assert_eq(ceiling, 4096)
    }
    _ => fail("hard ceiling must not be configurable away")
  }
  let zero_sessions = { ..DecoderLimits::default(), max_sessions: 0 }
  match Decoder::with_limits(zero_sessions) {
    Err(NonPositive(name, value)) => {
      assert_eq(name, "max_sessions")
      assert_eq(value, 0)
    }
    _ => fail("zero limits must be rejected before decoder construction")
  }
}

///|
test "Session and Template limits are classified and rejected state is atomic" {
  let limits = {
    ..compact_limits(),
    max_sessions: 1,
    max_templates_per_session: 1,
  }
  let decoder = Decoder::with_limits(limits).unwrap()
  let session_a = SessionKey::new("tcp:limited-a")
  let session_b = SessionKey::new("tcp:limited-b")
  ignore(decoder.decode_message(one_field_template_message(), session_a))
  let second_template = b"\x00\x0a\x00\x1c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2a\x00\x02\x00\x0c\x01\x01\x00\x01\x00\x08\x00\x04"
  match decoder.decode_message(second_template, session_a) {
    Rejected(diagnostics) =>
      assert_eq(diagnostics[0].code, DiagnosticCode::TemplateLimitExceeded)
    _ => fail("second scoped Template must exceed the per-Session limit")
  }
  match decoder.decode_message(second_template, session_b) {
    Rejected(diagnostics) =>
      assert_eq(diagnostics[0].code, DiagnosticCode::SessionLimitExceeded)
    _ => fail("second Session must exceed the configured Session limit")
  }
  let data_for_257 = b"\x00\x0a\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2a\x01\x01\x00\x08\x00\x00\x00\x01"
  match decoder.decode_message(data_for_257, session_a) {
    Decoded(message) =>
      assert_eq(message.diagnostics[0].code, DiagnosticCode::MissingTemplate)
    _ => fail("rejected Template install must leave no partial state")
  }
}

///|
test "field count and fixed field length limits reject before installation" {
  let decoder = Decoder::with_limits(compact_limits()).unwrap()
  let session = SessionKey::new("tcp:field-limits")
  match decoder.decode_message(fixed_template_message(), session) {
    Rejected(diagnostics) =>
      assert_eq(diagnostics[0].code, DiagnosticCode::FieldCountLimitExceeded)
    _ => fail("nine fields must exceed the configured field-count limit")
  }
  let long_field = b"\x00\x0a\x00\x1c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2a\x00\x02\x00\x0c\x01\x00\x00\x01\x00\x08\x00\x05"
  match decoder.decode_message(long_field, session) {
    Rejected(diagnostics) =>
      assert_eq(diagnostics[0].code, DiagnosticCode::FieldLengthLimitExceeded)
    _ => fail("fixed field length must obey the configured bound")
  }
}

///|
test "variable value and record limits remain bounded" {
  let decoder = Decoder::with_limits(compact_limits()).unwrap()
  let session = SessionKey::new("tcp:value-limits")
  ignore(decoder.decode_message(variable_string_template_message(), session))
  let long_value = b"\x00\x0a\x00\x1a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2a\x01\x00\x00\x0a\x05hello"
  match decoder.decode_message(long_value, session) {
    Rejected(diagnostics) =>
      assert_eq(diagnostics[0].code, DiagnosticCode::FieldLengthLimitExceeded)
    _ => fail("variable values must obey actual encoded-length limits")
  }
  let fixed_session = SessionKey::new("tcp:record-limits")
  ignore(decoder.decode_message(replacement_template_message(), fixed_session))
  let three_records = b"\x00\x0a\x00\x1a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2a\x01\x00\x00\x0a\x00\x01\x00\x02\x00\x03"
  match decoder.decode_message(three_records, fixed_session) {
    Rejected(diagnostics) =>
      assert_eq(diagnostics[0].code, DiagnosticCode::RecordLimitExceeded)
    _ => fail("third Data Record must exceed the per-Message limit")
  }
}

///|
test "Diagnostic limits classify warning expansion and preserve prior state" {
  let limits = { ..compact_limits(), max_diagnostics_per_message: 1 }
  let decoder = Decoder::with_limits(limits).unwrap()
  let session = SessionKey::new("tcp:diagnostic-limit")
  ignore(decoder.decode_message(replacement_template_message(), session))
  let redefine_then_invalid_data = b"\x00\x0a\x00\x26\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2a\x00\x02\x00\x10\x01\x00\x00\x02\x01\x14\x00\x01\x01\x14\x00\x01\x01\x00\x00\x06\x03\x04"
  match decoder.decode_message(redefine_then_invalid_data, session) {
    Rejected(diagnostics) =>
      assert_eq(diagnostics[0].code, DiagnosticCode::DiagnosticLimitExceeded)
    _ => fail("second warning must become a classified retained-limit failure")
  }
  match decoder.decode_message(replacement_data_message(), session) {
    Decoded(message) =>
      assert_eq(message.records[0].fields[0].value, FieldValue::Unsigned(443UL))
    _ =>
      fail("rejected Message must not partially replace prior Template state")
  }
}
