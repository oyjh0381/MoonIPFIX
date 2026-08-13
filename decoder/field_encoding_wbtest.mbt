///|
fn variable_string_template_message() -> Bytes {
  b"\x00\x0a\x00\x1c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x2a\x00\x02\x00\x0c\x01\x00\x00\x01\x00\x52\xff\xff"
}

///|
test "one-octet variable lengths preserve multiple record boundaries" {
  let decoder = Decoder::new()
  let session = SessionKey::new("tcp:variable-short")
  ignore(decoder.decode_message(variable_string_template_message(), session))
  let data = b"\x00\x0a\x00\x1b\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x2a\x01\x00\x00\x0b\x03api\x02ok"
  match decoder.decode_message(data, session) {
    Decoded(message) => {
      assert_eq(message.records.length(), 2)
      assert_eq(message.records[0].fields[0].offset, 21)
      assert_eq(message.records[0].fields[0].encoded_length, 3)
      assert_eq(message.records[0].fields[0].value, FieldValue::String("api"))
      assert_eq(message.records[1].offset, 24)
      assert_eq(message.records[1].fields[0].value, FieldValue::String("ok"))
    }
    _ => fail("two variable-length records must decode independently")
  }
}

///|
test "three-octet variable length prefixes decode bounded values" {
  let decoder = Decoder::new()
  let session = SessionKey::new("tcp:variable-long")
  ignore(decoder.decode_message(variable_string_template_message(), session))
  let packet = b"\x00\x0a\x01\x16\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x2a\x01\x00\x01\x06\xff\x00\xff".to_array()
  for _ in 0..<255 {
    packet.push(b'a')
  }
  match decoder.decode_message(Bytes::from_array(packet), session) {
    Decoded(message) => {
      assert_eq(message.records.length(), 1)
      assert_eq(message.records[0].fields[0].offset, 23)
      assert_eq(message.records[0].fields[0].encoded_length, 255)
      match message.records[0].fields[0].value {
        String(value) => assert_eq(value.length(), 255)
        _ => fail("valid long UTF-8 must remain typed")
      }
    }
    _ => fail("valid three-octet length prefix must decode")
  }
}

///|
test "noncanonical and truncated variable lengths are rejected" {
  let decoder = Decoder::new()
  let session = SessionKey::new("tcp:variable-invalid")
  ignore(decoder.decode_message(variable_string_template_message(), session))
  let noncanonical = b"\x00\x0a\x00\x18\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x2a\x01\x00\x00\x08\xff\x00\x01x"
  match decoder.decode_message(noncanonical, session) {
    Rejected(diagnostics) =>
      assert_eq(
        diagnostics[0].code,
        DiagnosticCode::InvalidVariableLengthPrefix,
      )
    _ => fail("long form must not encode a length below 255")
  }
  let truncated = b"\x00\x0a\x00\x15\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x2a\x01\x00\x00\x05\xff"
  match decoder.decode_message(truncated, session) {
    Rejected(diagnostics) =>
      assert_eq(diagnostics[0].code, DiagnosticCode::IncompleteDataRecord)
    _ => fail("truncated three-octet prefix must be rejected")
  }
}

///|
fn enterprise_template_message() -> Bytes {
  b"\x00\x0a\x00\x20\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x2a\x00\x02\x00\x10\x01\x01\x00\x01\x81\x90\x00\x02\x00\x00\x7e\xd9"
}

///|
fn enterprise_data_message() -> Bytes {
  b"\x00\x0a\x00\x16\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x2a\x01\x01\x00\x06\x12\x34"
}

///|
test "Enterprise metadata drives typed decoding and unknown identities stay raw" {
  let identity = @registry.InformationElementIdentity::enterprise(32473U, 400U)
  let metadata : @registry.ElementMetadata = {
    identity,
    name: "vendorCounter",
    abstract_data_type: @registry.AbstractDataType::Unsigned16,
    semantics: Some("quantity"),
    units: Some("octets"),
    status: @registry.RegistryStatus::Current,
    canonical_length: Some(2),
  }
  let registry = @registry.Registry::with_enterprise([metadata]).unwrap()
  let typed = Decoder::with_registry(registry)
  let typed_session = SessionKey::new("tcp:enterprise-typed")
  match typed.decode_message(enterprise_template_message(), typed_session) {
    Decoded(message) => {
      assert_eq(message.templates[0].fields[0].identity, identity)
      assert_eq(message.templates[0].fields[0].length, 2)
    }
    _ => fail("Enterprise Field Specifier must retain PEN and element ID")
  }
  match typed.decode_message(enterprise_data_message(), typed_session) {
    Decoded(message) =>
      assert_eq(
        message.records[0].fields[0].value,
        FieldValue::Unsigned(4660UL),
      )
    _ => fail("caller Enterprise metadata must drive typed decoding")
  }
  let unknown = Decoder::new()
  let unknown_session = SessionKey::new("tcp:enterprise-unknown")
  ignore(unknown.decode_message(enterprise_template_message(), unknown_session))
  match unknown.decode_message(enterprise_data_message(), unknown_session) {
    Decoded(message) => {
      let field = message.records[0].fields[0]
      assert_eq(field.specifier.identity, identity)
      assert_eq(field.specifier.length, 2)
      assert_eq(field.encoded_length, 2)
      assert_eq(field.value, FieldValue::Octets(b"\x12\x34"))
    }
    _ => fail("unknown Enterprise values must be lossless raw octets")
  }
}

///|
test "Reduced-Size integers are typed but illegal scalar encodings stay raw" {
  let reduced_template = b"\x00\x0a\x00\x1c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x2a\x00\x02\x00\x0c\x01\x03\x00\x01\x00\x0a\x00\x02"
  let reduced_data = b"\x00\x0a\x00\x16\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x2a\x01\x03\x00\x06\x12\x34"
  let decoder = Decoder::new()
  let session = SessionKey::new("tcp:reduced")
  ignore(decoder.decode_message(reduced_template, session))
  match decoder.decode_message(reduced_data, session) {
    Decoded(message) =>
      assert_eq(
        message.records[0].fields[0].value,
        FieldValue::Unsigned(4660UL),
      )
    _ => fail("eligible unsigned32 Reduced-Size Encoding must decode")
  }

  let invalid_template = b"\x00\x0a\x00\x24\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x2a\x00\x02\x00\x14\x01\x02\x00\x03\x00\x04\x00\x02\x01\x14\x00\x01\x00\x52\x00\x01"
  let invalid_data = b"\x00\x0a\x00\x18\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x2a\x01\x02\x00\x08\x01\x02\x03\xff"
  let invalid_session = SessionKey::new("tcp:raw-fallback")
  ignore(decoder.decode_message(invalid_template, invalid_session))
  match decoder.decode_message(invalid_data, invalid_session) {
    Decoded(message) => {
      let fields = message.records[0].fields
      assert_eq(fields[0].value, FieldValue::Octets(b"\x01\x02"))
      assert_eq(fields[1].value, FieldValue::Octets(b"\x03"))
      assert_eq(fields[2].value, FieldValue::Octets(b"\xff"))
      assert_eq(message.diagnostics.length(), 3)
      for diagnostic in message.diagnostics {
        assert_eq(diagnostic.code, DiagnosticCode::InvalidFieldEncoding)
      }
    }
    _ => fail("invalid scalar encodings must fall back without data loss")
  }
}
