///|
fn one_field_template_message() -> Bytes {
  b"\x00\x0a\x00\x1c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x2a\x00\x02\x00\x0c\x01\x00\x00\x01\x00\x08\x00\x04"
}

///|
fn replacement_template_message() -> Bytes {
  b"\x00\x0a\x00\x1c\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x2a\x00\x02\x00\x0c\x01\x00\x00\x01\x00\x07\x00\x02"
}

///|
fn replacement_data_message() -> Bytes {
  b"\x00\x0a\x00\x16\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x2a\x01\x00\x00\x06\x01\xbb"
}

///|
fn options_template_message() -> Bytes {
  b"\x00\x0a\x00\x26\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x2a\x00\x03\x00\x16\x01\x2c\x00\x03\x00\x01\x00\x8d\x00\x04\x00\x29\x00\x02\x00\x2a\x00\x02"
}

///|
fn options_data_message() -> Bytes {
  b"\x00\x0a\x00\x1c\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x2a\x01\x2c\x00\x0c\x00\x00\x00\x07\x00\x0a\x00\x0b"
}

///|
test "Options Templates preserve ordered Scope and option fields" {
  let decoder = Decoder::new()
  match
    decoder.decode_message(
      options_template_message(),
      SessionKey::new("tcp:options"),
    ) {
    Decoded(message) => {
      assert_eq(message.templates.length(), 1)
      let template = message.templates[0]
      assert_eq(template.kind, TemplateKind::Options)
      assert_eq(template.scope_fields.length(), 1)
      assert_eq(template.scope_fields[0].identity.element_id, 141U)
      assert_eq(template.option_fields.length(), 2)
      assert_eq(template.option_fields[0].identity.element_id, 41U)
      assert_eq(template.option_fields[1].identity.element_id, 42U)
      assert_eq(template.record_length, 8)
    }
    _ => fail("valid Options Template must install")
  }
  match
    decoder.decode_message(
      options_data_message(),
      SessionKey::new("tcp:options"),
    ) {
    Decoded(message) => {
      assert_eq(message.records.length(), 1)
      assert_eq(message.records[0].fields.length(), 3)
      assert_eq(message.records[0].fields[0].value, FieldValue::Unsigned(7UL))
    }
    _ => fail("Options Data Record must use the installed Options Template")
  }
}

///|
test "invalid Options Scope Field counts are rejected" {
  let zero_scope = options_template_message().to_array()
  zero_scope[24] = b'\x00'
  zero_scope[25] = b'\x00'
  let decoder = Decoder::new()
  match
    decoder.decode_message(
      Bytes::from_array(zero_scope),
      SessionKey::new("tcp:bad-options"),
    ) {
    Rejected(diagnostics) => {
      assert_eq(diagnostics[0].code, DiagnosticCode::InvalidScopeFieldCount)
      assert_eq(diagnostics[0].offset, 24)
    }
    _ => fail("Options Scope Field Count must not be zero")
  }
  let too_many_scopes = options_template_message().to_array()
  too_many_scopes[24] = b'\x00'
  too_many_scopes[25] = b'\x04'
  match
    decoder.decode_message(
      Bytes::from_array(too_many_scopes),
      SessionKey::new("tcp:bad-options"),
    ) {
    Rejected(diagnostics) =>
      assert_eq(diagnostics[0].code, DiagnosticCode::InvalidScopeFieldCount)
    _ => fail("Scope Field Count cannot exceed Field Count")
  }
}

///|
test "replacement affects only the matching Session and Domain" {
  let decoder = Decoder::new()
  ignore(
    decoder.decode_message(
      one_field_template_message(),
      SessionKey::new("tcp:a"),
    ),
  )
  ignore(
    decoder.decode_message(
      one_field_template_message(),
      SessionKey::new("tcp:b"),
    ),
  )
  match
    decoder.decode_message(
      replacement_template_message(),
      SessionKey::new("tcp:a"),
    ) {
    Decoded(message) => {
      assert_eq(message.lifecycle.length(), 1)
      assert_eq(message.lifecycle[0].action, TemplateLifecycleAction::Replaced)
      assert_eq(message.diagnostics[0].code, DiagnosticCode::TemplateRedefined)
    }
    _ => fail("replacement must be observable")
  }
  match
    decoder.decode_message(replacement_data_message(), SessionKey::new("tcp:a")) {
    Decoded(message) => {
      assert_eq(message.records[0].fields.length(), 1)
      assert_eq(message.records[0].fields[0].value, FieldValue::Unsigned(443UL))
    }
    _ => fail("replacement schema must become current")
  }
  match
    decoder.decode_message(replacement_data_message(), SessionKey::new("tcp:b")) {
    Rejected(diagnostics) =>
      assert_eq(diagnostics[0].code, DiagnosticCode::IncompleteDataRecord)
    _ => fail("Session B must retain its four-octet record definition")
  }
}

///|
test "specific withdrawal takes effect before a later Set in the same Message" {
  let decoder = Decoder::new()
  ignore(
    decoder.decode_message(
      replacement_template_message(),
      SessionKey::new("tcp:withdraw"),
    ),
  )
  let withdrawal_then_data = b"\x00\x0a\x00\x1e\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x2a\x00\x02\x00\x08\x01\x00\x00\x00\x01\x00\x00\x06\x01\xbb"
  match
    decoder.decode_message(
      withdrawal_then_data,
      SessionKey::new("tcp:withdraw"),
    ) {
    Decoded(message) => {
      assert_eq(message.records.length(), 0)
      assert_eq(message.lifecycle[0].action, TemplateLifecycleAction::Withdrawn)
      assert_eq(message.diagnostics[0].code, DiagnosticCode::MissingTemplate)
    }
    _ => fail("withdrawal must precede the later Data Set")
  }
}

///|
test "all-Template withdrawal preserves Options Templates in the same scope" {
  let decoder = Decoder::new()
  ignore(
    decoder.decode_message(
      one_field_template_message(),
      SessionKey::new("tcp:all"),
    ),
  )
  ignore(
    decoder.decode_message(
      options_template_message(),
      SessionKey::new("tcp:all"),
    ),
  )
  let withdraw_all_regular = b"\x00\x0a\x00\x18\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x2a\x00\x02\x00\x08\x00\x02\x00\x00"
  match
    decoder.decode_message(withdraw_all_regular, SessionKey::new("tcp:all")) {
    Decoded(message) => {
      assert_eq(
        message.lifecycle[0].action,
        TemplateLifecycleAction::WithdrawnAll,
      )
      assert_eq(message.lifecycle[0].affected, 1)
    }
    _ => fail("all regular Templates withdrawal must decode")
  }
  match
    decoder.decode_message(options_data_message(), SessionKey::new("tcp:all")) {
    Decoded(message) => assert_eq(message.records.length(), 1)
    _ => fail("all regular withdrawal must not remove Options Templates")
  }
}

///|
test "Options Template withdrawal removes only the matching Options Template" {
  let decoder = Decoder::new()
  ignore(
    decoder.decode_message(
      options_template_message(),
      SessionKey::new("tcp:options-withdraw"),
    ),
  )
  let withdraw_options = b"\x00\x0a\x00\x18\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x2a\x00\x03\x00\x08\x01\x2c\x00\x00"
  match
    decoder.decode_message(
      withdraw_options,
      SessionKey::new("tcp:options-withdraw"),
    ) {
    Decoded(message) =>
      assert_eq(message.lifecycle[0].action, TemplateLifecycleAction::Withdrawn)
    _ => fail("Options withdrawal must decode")
  }
  match
    decoder.decode_message(
      options_data_message(),
      SessionKey::new("tcp:options-withdraw"),
    ) {
    Decoded(message) =>
      assert_eq(message.diagnostics[0].code, DiagnosticCode::MissingTemplate)
    _ => fail("withdrawn Options Template must no longer decode records")
  }
  match
    decoder.decode_message(
      withdraw_options,
      SessionKey::new("tcp:options-withdraw"),
    ) {
    Decoded(message) => {
      assert_eq(
        message.lifecycle[0].action,
        TemplateLifecycleAction::WithdrawalMissing,
      )
      assert_eq(
        message.diagnostics[0].code,
        DiagnosticCode::TemplateWithdrawalMissing,
      )
    }
    _ => fail("unknown withdrawal is ignored and reported")
  }
}

///|
test "UDP Template Withdrawals are ignored as required by RFC 7011" {
  let decoder = Decoder::new()
  let session = SessionKey::new("udp:rfc7011")
  decoder.set_session_transport(session, TransportProtocol::Udp)
  ignore(decoder.decode_message(replacement_template_message(), session))
  let withdraw = b"\x00\x0a\x00\x18\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x2a\x00\x02\x00\x08\x01\x00\x00\x00"
  match decoder.decode_message(withdraw, session) {
    Decoded(message) => {
      assert_eq(
        message.lifecycle[0].action,
        TemplateLifecycleAction::WithdrawalIgnored,
      )
      assert_eq(
        message.diagnostics[0].code,
        DiagnosticCode::TemplateWithdrawalIgnoredForUdp,
      )
    }
    _ => fail("UDP withdrawal is a reportable ignored action")
  }
  match decoder.decode_message(replacement_data_message(), session) {
    Decoded(message) => assert_eq(message.records.length(), 1)
    _ => fail("UDP withdrawal must not remove Template state")
  }
}

///|
test "reset_session removes only the selected Session" {
  let decoder = Decoder::new()
  ignore(
    decoder.decode_message(
      replacement_template_message(),
      SessionKey::new("tcp:reset-a"),
    ),
  )
  ignore(
    decoder.decode_message(
      replacement_template_message(),
      SessionKey::new("tcp:reset-b"),
    ),
  )
  let reset = decoder.reset_session(SessionKey::new("tcp:reset-a"))
  assert_eq(reset.action, TemplateLifecycleAction::SessionReset)
  assert_eq(reset.affected, 1)
  match
    decoder.decode_message(
      replacement_data_message(),
      SessionKey::new("tcp:reset-a"),
    ) {
    Decoded(message) =>
      assert_eq(message.diagnostics[0].code, DiagnosticCode::MissingTemplate)
    _ => fail("reset Session must have no Template state")
  }
  match
    decoder.decode_message(
      replacement_data_message(),
      SessionKey::new("tcp:reset-b"),
    ) {
    Decoded(message) => assert_eq(message.records.length(), 1)
    _ => fail("reset must not remove another Session")
  }
}
