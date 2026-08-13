///|
fn with_sequence(
  source : Bytes,
  b0 : Byte,
  b1 : Byte,
  b2 : Byte,
  b3 : Byte,
) -> Bytes {
  let owned = source.to_array()
  owned[8] = b0
  owned[9] = b1
  owned[10] = b2
  owned[11] = b3
  Bytes::from_array(owned)
}

///|
test "Sequence Number advances by Data Records and reports forward gaps" {
  let decoder = Decoder::new()
  let session = SessionKey::new("tcp:sequence-gap")
  match decoder.decode_message(replacement_template_message(), session) {
    Decoded(message) => {
      assert_eq(
        message.sequence.unwrap().continuity,
        SequenceContinuity::Baseline,
      )
      assert_eq(message.sequence.unwrap().next_expected, Some(0U))
      assert_eq(message.statistics.template_count, 1)
      assert_eq(message.statistics.record_count, 0)
    }
    _ => fail("Template baseline must decode")
  }
  match decoder.decode_message(replacement_data_message(), session) {
    Decoded(message) => {
      let audit = message.sequence.unwrap()
      assert_eq(audit.continuity, SequenceContinuity::Continuous)
      assert_eq(audit.observed, 0U)
      assert_eq(audit.expected, Some(0U))
      assert_eq(audit.decoded_record_count, 1)
      assert_eq(audit.next_expected, Some(1U))
      assert_eq(message.statistics.record_count, 1)
      assert_eq(message.statistics.field_count, 1)
    }
    _ => fail("one Data Record must advance expected Sequence Number")
  }
  let gap = with_sequence(
    replacement_data_message(),
    b'\x00',
    b'\x00',
    b'\x00',
    b'\x03',
  )
  match decoder.decode_message(gap, session) {
    Decoded(message) => {
      let audit = message.sequence.unwrap()
      assert_eq(audit.continuity, SequenceContinuity::Gap)
      assert_eq(audit.expected, Some(1U))
      assert_eq(audit.observed, 3U)
      assert_eq(audit.missing, Some(2U))
      assert_eq(audit.next_expected, Some(4U))
      assert_eq(message.diagnostics[0].code, DiagnosticCode::SequenceGap)
      assert_eq(message.statistics.diagnostic_count, 1)
    }
    _ => fail("forward discontinuity must remain observable")
  }
}

///|
test "Template-only Messages do not advance and uint32 wraparound is continuous" {
  let decoder = Decoder::new()
  let session = SessionKey::new("tcp:sequence-wrap")
  let template_at_wrap = with_sequence(
    replacement_template_message(),
    b'\xff',
    b'\xff',
    b'\xff',
    b'\xfe',
  )
  ignore(decoder.decode_message(template_at_wrap, session))
  let two_records = b"\x00\x0a\x00\x18\x00\x00\x00\x03\xff\xff\xff\xfe\x00\x00\x00\x2a\x01\x00\x00\x08\x01\xbb\x01\xbb"
  match decoder.decode_message(two_records, session) {
    Decoded(message) => {
      let audit = message.sequence.unwrap()
      assert_eq(audit.continuity, SequenceContinuity::Continuous)
      assert_eq(audit.decoded_record_count, 2)
      assert_eq(audit.next_expected, Some(0U))
    }
    _ => fail("two records at fffffffe must wrap expected to zero")
  }
  match decoder.decode_message(replacement_template_message(), session) {
    Decoded(message) => {
      let audit = message.sequence.unwrap()
      assert_eq(audit.continuity, SequenceContinuity::Continuous)
      assert_eq(audit.expected, Some(0U))
      assert_eq(audit.next_expected, Some(0U))
    }
    _ => fail("Template-only Message at wrapped zero must not create a gap")
  }
}

///|
test "Session reset clears only that Session sequence baseline" {
  let decoder = Decoder::new()
  let session_a = SessionKey::new("tcp:sequence-a")
  let session_b = SessionKey::new("tcp:sequence-b")
  ignore(decoder.decode_message(replacement_template_message(), session_a))
  let b_at_ten = with_sequence(
    replacement_template_message(),
    b'\x00',
    b'\x00',
    b'\x00',
    b'\x0a',
  )
  ignore(decoder.decode_message(b_at_ten, session_b))
  ignore(decoder.reset_session(session_a))
  let a_at_ninety_nine = with_sequence(
    replacement_template_message(),
    b'\x00',
    b'\x00',
    b'\x00',
    b'\x63',
  )
  match decoder.decode_message(a_at_ninety_nine, session_a) {
    Decoded(message) =>
      assert_eq(
        message.sequence.unwrap().continuity,
        SequenceContinuity::Baseline,
      )
    _ => fail("reset Session must establish a fresh baseline")
  }
  match decoder.decode_message(b_at_ten, session_b) {
    Decoded(message) =>
      assert_eq(
        message.sequence.unwrap().continuity,
        SequenceContinuity::Continuous,
      )
    _ => fail("another Session continuity must survive reset")
  }
}

///|
test "Observation Domains retain independent interleaved continuity" {
  let decoder = Decoder::new()
  let session = SessionKey::new("tcp:sequence-domains")
  let domain_42 = replacement_template_message()
  let domain_43_bytes = with_sequence(
    replacement_template_message(),
    b'\x00',
    b'\x00',
    b'\x00',
    b'\x0a',
  ).to_array()
  domain_43_bytes[15] = b'\x2b'
  let domain_43 = Bytes::from_array(domain_43_bytes)
  ignore(decoder.decode_message(domain_42, session))
  ignore(decoder.decode_message(domain_43, session))
  match decoder.decode_message(domain_42, session) {
    Decoded(message) => {
      let audit = message.sequence.unwrap()
      assert_eq(audit.observation_domain_id, 42U)
      assert_eq(audit.continuity, SequenceContinuity::Continuous)
    }
    _ => fail("Domain 42 must keep its own expectation")
  }
  match decoder.decode_message(domain_43, session) {
    Decoded(message) => {
      let audit = message.sequence.unwrap()
      assert_eq(audit.observation_domain_id, 43U)
      assert_eq(audit.continuity, SequenceContinuity::Continuous)
    }
    _ => fail("Domain 43 must keep its own expectation")
  }
}

///|
test "unknown Templates make record counts and next expectation unverifiable" {
  let decoder = Decoder::new()
  let session = SessionKey::new("tcp:sequence-unknown")
  let unknown = with_sequence(
    replacement_data_message(),
    b'\x00',
    b'\x00',
    b'\x00',
    b'\x05',
  )
  match decoder.decode_message(unknown, session) {
    Decoded(message) => {
      let audit = message.sequence.unwrap()
      assert_eq(audit.continuity, SequenceContinuity::Unverifiable)
      assert_eq(audit.record_count_complete, false)
      assert_eq(audit.next_expected, None)
      assert_eq(
        message.lifecycle[0].action,
        TemplateLifecycleAction::DataSetUnresolved,
      )
      assert_eq(message.statistics.lifecycle_count, 1)
      assert_eq(message.statistics.diagnostic_count, 2)
    }
    _ => fail("unknown Template remains a decoded audit event")
  }
}
