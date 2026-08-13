///|
fn framing_packet() -> Bytes {
  b"\x00\x0a\x00\x18\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x02\x00\x08\x00\x00\x01\x00"
}

///|
test "decode a bounded IPFIX message and its Set framing" {
  let outcome = decode_message(framing_packet(), SessionKey::new("udp:test"))
  match outcome {
    Decoded(message) => {
      assert_eq(message.session.to_string(), "udp:test")
      assert_eq(message.header.version, 10U)
      assert_eq(message.header.length, 24)
      assert_eq(message.header.export_time, 1U)
      assert_eq(message.header.sequence_number, 2U)
      assert_eq(message.header.observation_domain_id, 3U)
      assert_eq(message.sets.length(), 1)
      assert_eq(message.sets[0].set_id, 2U)
      assert_eq(message.sets[0].offset, 16)
      assert_eq(message.sets[0].length, 8)
      assert_eq(message.sets[0].payload_offset, 20)
      assert_eq(message.sets[0].payload_length, 4)
      assert_eq(message.sets[0].kind, SetKind::Template)
      assert_eq(message.diagnostics.length(), 0)
    }
    _ => fail("expected a decoded message")
  }
}

///|
test "every strict prefix reports the exact required message extent" {
  let packet = framing_packet()
  for prefix_length in 0..<packet.length() {
    let prefix = Bytes::from_array(packet[0:prefix_length].to_array())
    match decode_message(prefix, SessionKey::new("udp:prefix")) {
      NeedMoreData(need) => {
        let expected = if prefix_length < 16 { 16 } else { 24 }
        assert_eq(need.available, prefix_length)
        assert_eq(need.required, expected)
      }
      _ => fail("a strict prefix must not be accepted or rejected as complete")
    }
  }
}

///|
test "invalid complete framing is rejected with stable codes and offsets" {
  let invalid_message_length = b"\x00\x0a\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  match
    decode_message(invalid_message_length, SessionKey::new("udp:bad-length")) {
    Rejected(diagnostics) => {
      assert_eq(diagnostics.length(), 1)
      assert_eq(diagnostics[0].code, DiagnosticCode::InvalidMessageLength)
      assert_eq(diagnostics[0].severity, DiagnosticSeverity::Error)
      assert_eq(diagnostics[0].offset, 2)
      assert_eq(diagnostics[0].context.session.to_string(), "udp:bad-length")
      assert_eq(diagnostics[0].context.observation_domain_id, None)
      assert_eq(diagnostics[0].context.set_id, None)
    }
    _ => fail("a declared message length below the header is invalid")
  }

  let trailing = framing_packet().to_array()
  trailing.push(b'\x00')
  match
    decode_message(Bytes::from_array(trailing), SessionKey::new("udp:trailing")) {
    Rejected(diagnostics) => {
      assert_eq(diagnostics[0].code, DiagnosticCode::TrailingBytes)
      assert_eq(diagnostics[0].offset, 24)
    }
    _ => fail("trailing bytes must not be silently ignored")
  }
}

///|
test "Set bounds are validated before payload interpretation" {
  let short_set = b"\x00\x0a\x00\x14\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x02\x00\x03"
  match decode_message(short_set, SessionKey::new("udp:short-set")) {
    Rejected(diagnostics) => {
      assert_eq(diagnostics[0].code, DiagnosticCode::InvalidSetLength)
      assert_eq(diagnostics[0].offset, 18)
      assert_eq(diagnostics[0].context.observation_domain_id, Some(3U))
      assert_eq(diagnostics[0].context.set_id, Some(2U))
    }
    _ => fail("a Set length below four is invalid")
  }

  let overrun_set = b"\x00\x0a\x00\x14\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x01\x00\x00\x08"
  match decode_message(overrun_set, SessionKey::new("udp:overrun")) {
    Rejected(diagnostics) => {
      assert_eq(diagnostics[0].code, DiagnosticCode::SetExceedsMessage)
      assert_eq(diagnostics[0].offset, 18)
    }
    _ => fail("a Set extent beyond the message is invalid")
  }

  let truncated_set_header = b"\x00\x0a\x00\x12\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x02"
  match
    decode_message(
      truncated_set_header,
      SessionKey::new("udp:truncated-set-header"),
    ) {
    Rejected(diagnostics) => {
      assert_eq(diagnostics[0].code, DiagnosticCode::TruncatedSetHeader)
      assert_eq(diagnostics[0].offset, 16)
    }
    _ => fail("a partial Set Header inside a complete Message is invalid")
  }
}

///|
test "a complete non-IPFIX message is rejected without boundary guessing" {
  let packet = b"\x00\x09\x00\x10\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03"
  match decode_message(packet, SessionKey::new("udp:version-9")) {
    Rejected(diagnostics) => {
      assert_eq(diagnostics[0].code, DiagnosticCode::UnsupportedVersion)
      assert_eq(diagnostics[0].offset, 0)
      assert_eq(diagnostics[0].context.observation_domain_id, Some(3U))
    }
    _ => fail("the complete-message API accepts only IPFIX version 10")
  }
}

///|
test "multiple Sets are summarized and reserved IDs remain opaque" {
  let packet = b"\x00\x0a\x00\x1c\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x01\x00\x00\x04\x00\x04\x00\x08\xde\xad\xbe\xef"
  match decode_message(packet, SessionKey::new("udp:multi")) {
    Decoded(message) => {
      assert_eq(message.sets.length(), 2)
      assert_eq(message.sets[0].kind, SetKind::Data)
      assert_eq(message.sets[1].kind, SetKind::Unknown)
      assert_eq(message.diagnostics.length(), 1)
      assert_eq(message.diagnostics[0].code, DiagnosticCode::UnknownSetId)
      assert_eq(message.diagnostics[0].severity, DiagnosticSeverity::Warning)
      assert_eq(message.diagnostics[0].offset, 20)
      assert_eq(message.diagnostics[0].context.set_id, Some(4U))
    }
    _ => fail("valid Set framing must decode")
  }
}
