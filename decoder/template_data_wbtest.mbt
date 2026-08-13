///|
fn fixed_template_message() -> Bytes {
  b"\x00\x0a\x00\x3c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x2a\x00\x02\x00\x2c\x01\x00\x00\x09\x00\x08\x00\x04\x00\x07\x00\x02\x01\xb2\x00\x04\x01\x14\x00\x01\x00\x52\x00\x03\x00\x38\x00\x06\x00\x1b\x00\x10\x00\x98\x00\x08\x00\x46\x00\x03"
}

///|
fn fixed_data_message() -> Bytes {
  b"\x00\x0a\x00\x44\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x2a\x01\x00\x00\x34\xc0\xa8\x01\x0a\x01\xbb\xff\xff\xff\xfe\x01api\x00\x11\x22\x33\x44\x55\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x01\x8b\xcf\xe5\x68\x00\xde\xad\xbe\x00"
}

///|
test "Template state decodes a later fixed-length typed Data Record" {
  let decoder = Decoder::new()
  match
    decoder.decode_message(
      fixed_template_message(),
      SessionKey::new("udp:exporter-a"),
    ) {
    Decoded(message) => {
      assert_eq(message.templates.length(), 1)
      assert_eq(message.templates[0].identity.observation_domain_id, 42U)
      assert_eq(message.templates[0].identity.template_id, 256U)
      assert_eq(message.templates[0].fields.length(), 9)
      assert_eq(message.templates[0].record_length, 47)
      assert_eq(message.records.length(), 0)
    }
    _ => fail("valid Template Message must decode")
  }
  match
    decoder.decode_message(
      fixed_data_message(),
      SessionKey::new("udp:exporter-a"),
    ) {
    Decoded(message) => {
      assert_eq(message.records.length(), 1)
      let fields = message.records[0].fields
      assert_eq(fields.length(), 9)
      assert_eq(fields[0].value, FieldValue::Ipv4Address(b"\xc0\xa8\x01\x0a"))
      assert_eq(fields[1].value, FieldValue::Unsigned(443UL))
      assert_eq(fields[2].value, FieldValue::Signed(-2L))
      assert_eq(fields[3].value, FieldValue::Boolean(true))
      assert_eq(fields[4].value, FieldValue::String("api"))
      assert_eq(
        fields[5].value,
        FieldValue::MacAddress(b"\x00\x11\x22\x33\x44\x55"),
      )
      assert_eq(
        fields[6].value,
        FieldValue::Ipv6Address(
          b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
        ),
      )
      assert_eq(
        fields[7].value,
        FieldValue::DateTimeMilliseconds(1_700_000_000_000UL),
      )
      assert_eq(fields[8].value, FieldValue::Octets(b"\xde\xad\xbe"))
      assert_eq(message.diagnostics.length(), 0)
    }
    _ => fail("Data Message must resolve the prior Session/Domain Template")
  }
}

///|
test "one Template Set may install multiple Template Records" {
  let packet = b"\x00\x0a\x00\x24\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07\x00\x02\x00\x14\x01\x00\x00\x01\x00\x08\x00\x04\x01\x01\x00\x01\x00\x0c\x00\x04"
  let decoder = Decoder::new()
  match decoder.decode_message(packet, SessionKey::new("udp:multi-template")) {
    Decoded(message) => {
      assert_eq(message.templates.length(), 2)
      assert_eq(message.templates[0].identity.template_id, 256U)
      assert_eq(message.templates[1].identity.template_id, 257U)
    }
    _ => fail("both complete Template Records must be installed")
  }
}

///|
test "every complete fixed-length Data Record is emitted" {
  let decoder = Decoder::new()
  ignore(
    decoder.decode_message(
      fixed_template_message(),
      SessionKey::new("udp:two-records"),
    ),
  )
  let source = fixed_data_message()
  let packet : Array[Byte] = []
  for index in 0..<67 {
    packet.push(source[index])
  }
  for index in 20..<67 {
    packet.push(source[index])
  }
  packet[2] = b'\x00'
  packet[3] = b'\x72'
  packet[18] = b'\x00'
  packet[19] = b'\x62'
  match
    decoder.decode_message(
      Bytes::from_array(packet),
      SessionKey::new("udp:two-records"),
    ) {
    Decoded(message) => {
      assert_eq(message.records.length(), 2)
      assert_eq(message.records[0].offset, 20)
      assert_eq(message.records[1].offset, 67)
    }
    _ => fail("both complete records must decode in wire order")
  }
}

///|
test "invalid Template identity and shape are rejected before installation" {
  let invalid_id = b"\x00\x0a\x00\x1c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x00\x0c\x00\xff\x00\x01\x00\x08\x00\x04"
  let decoder = Decoder::new()
  match decoder.decode_message(invalid_id, SessionKey::new("udp:invalid")) {
    Rejected(diagnostics) => {
      assert_eq(diagnostics[0].code, DiagnosticCode::InvalidTemplateId)
      assert_eq(diagnostics[0].offset, 20)
    }
    _ => fail("Template IDs below 256 are invalid")
  }
  let zero_length_field = b"\x00\x0a\x00\x1c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x00\x0c\x01\x00\x00\x01\x00\x08\x00\x00"
  match
    decoder.decode_message(zero_length_field, SessionKey::new("udp:invalid")) {
    Rejected(diagnostics) => {
      assert_eq(diagnostics[0].code, DiagnosticCode::InvalidFieldLength)
      assert_eq(diagnostics[0].offset, 26)
    }
    _ => fail("zero-length fixed fields cannot produce a decodable record")
  }
}

///|
test "template namespaces include Session and Observation Domain" {
  let decoder = Decoder::new()
  ignore(
    decoder.decode_message(
      fixed_template_message(),
      SessionKey::new("udp:exporter-a"),
    ),
  )
  match
    decoder.decode_message(
      fixed_data_message(),
      SessionKey::new("udp:exporter-b"),
    ) {
    Decoded(message) => {
      assert_eq(message.records.length(), 0)
      assert_eq(message.diagnostics.length(), 2)
      assert_eq(message.diagnostics[0].code, DiagnosticCode::MissingTemplate)
      assert_eq(
        message.diagnostics[1].code,
        DiagnosticCode::SequenceUnverifiable,
      )
      assert_eq(message.diagnostics[0].context.set_id, Some(256U))
    }
    _ => fail("missing schema is a reportable state, not guessed decoding")
  }
  let other_domain = fixed_data_message().to_array()
  other_domain[15] = b'\x2b'
  match
    decoder.decode_message(
      Bytes::from_array(other_domain),
      SessionKey::new("udp:exporter-a"),
    ) {
    Decoded(message) => {
      assert_eq(message.records.length(), 0)
      assert_eq(message.diagnostics[0].code, DiagnosticCode::MissingTemplate)
      assert_eq(message.diagnostics[0].context.observation_domain_id, Some(43U))
    }
    _ => fail("Observation Domains must have independent Template namespaces")
  }
}

///|
test "zero padding is accepted but a partial nonzero record is rejected" {
  let decoder = Decoder::new()
  ignore(
    decoder.decode_message(
      fixed_template_message(),
      SessionKey::new("udp:padding"),
    ),
  )
  match
    decoder.decode_message(fixed_data_message(), SessionKey::new("udp:padding")) {
    Decoded(message) => assert_eq(message.records.length(), 1)
    _ => fail("one trailing zero octet is valid Set padding")
  }
  let malformed = fixed_data_message().to_array()
  malformed[malformed.length() - 1] = b'\x01'
  match
    decoder.decode_message(
      Bytes::from_array(malformed),
      SessionKey::new("udp:padding"),
    ) {
    Rejected(diagnostics) => {
      assert_eq(diagnostics[0].code, DiagnosticCode::IncompleteDataRecord)
      assert_eq(diagnostics[0].offset, 67)
    }
    _ => fail("nonzero partial record bytes must not be called padding")
  }
}
