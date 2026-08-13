///|
fn byte_range(source : Bytes, start : Int, end : Int) -> Bytes {
  let owned : Array[Byte] = []
  for index in start..<end {
    owned.push(source[index])
  }
  Bytes::from_array(owned)
}

///|
fn join_bytes(left : Bytes, right : Bytes) -> Bytes {
  let joined : Array[Byte] = []
  for byte in left {
    joined.push(byte)
  }
  for byte in right {
    joined.push(byte)
  }
  Bytes::from_array(joined)
}

///|
test "every split point matches complete-message decoding" {
  let source = fixed_template_message()
  let session = SessionKey::new("tcp:every-split")
  let expected = Decoder::new().decode_message(source, session)
  for split in 0..<=source.length() {
    let stream = StreamDecoder::new(session)
    let first = stream.push(byte_range(source, 0, split))
    let second = stream.push(byte_range(source, split, source.length()))
    let completed : Array[DecodeOutcome] = []
    for outcome in first.outcomes {
      completed.push(outcome)
    }
    for outcome in second.outcomes {
      completed.push(outcome)
    }
    assert_eq(completed.length(), 1)
    assert_eq(completed[0], expected)
    assert_eq(stream.finish(), StreamEnd::Complete)
  }
}

///|
test "a multi-Message chunk preserves order under a small retained limit" {
  let template = replacement_template_message()
  let data = replacement_data_message()
  let session = SessionKey::new("tcp:multi-message")
  let complete = Decoder::new()
  let expected_template = complete.decode_message(template, session)
  let expected_data = complete.decode_message(data, session)
  let stream = StreamDecoder::with_config(session, { max_buffered_bytes: 32 }).unwrap()
  let batch = stream.push(join_bytes(template, data))
  assert_eq(batch.outcomes.length(), 2)
  assert_eq(batch.outcomes[0], expected_template)
  assert_eq(batch.outcomes[1], expected_data)
  assert_eq(batch.buffered, 0)
  assert_eq(stream.buffered_len(), 0)
  assert_eq(stream.finish(), StreamEnd::Complete)
}

///|
test "deterministic random-like chunk partitions and empty pushes are equivalent" {
  let template = replacement_template_message()
  let data = replacement_data_message()
  let source = join_bytes(template, data)
  let session = SessionKey::new("tcp:partition-matrix")
  let complete = Decoder::new()
  let expected = [
    complete.decode_message(template, session),
    complete.decode_message(data, session),
  ]
  for seed in 1..<=20 {
    let stream = StreamDecoder::new(session)
    let observed : Array[DecodeOutcome] = []
    let mut cursor = 0
    let mut state = seed
    while cursor < source.length() {
      assert_eq(stream.push(b"").outcomes.length(), 0)
      state = (state * 17 + 11) % 23
      let proposed = state % 9 + 1
      let end = minimum(source.length(), cursor + proposed)
      let batch = stream.push(byte_range(source, cursor, end))
      for outcome in batch.outcomes {
        observed.push(outcome)
      }
      cursor = end
    }
    assert_eq(observed, expected)
    assert_eq(stream.push(b"").outcomes.length(), 0)
    assert_eq(stream.finish(), StreamEnd::Complete)
  }
}

///|
test "partial Messages do not apply Template state before completion" {
  let template = replacement_template_message()
  let data = replacement_data_message()
  let session = SessionKey::new("tcp:state-once")
  let stream = StreamDecoder::new(session)
  let partial = stream.push(byte_range(template, 0, template.length() - 1))
  assert_eq(partial.outcomes.length(), 0)
  assert_eq(
    partial.need_more,
    Some({ available: template.length() - 1, required: template.length() }),
  )
  assert_eq(
    stream.finish(),
    StreamEnd::Truncated({
      available: template.length() - 1,
      required: template.length(),
    }),
  )
  let completion = stream.push(
    join_bytes(
      byte_range(template, template.length() - 1, template.length()),
      data,
    ),
  )
  assert_eq(completion.outcomes.length(), 2)
  match completion.outcomes[0] {
    Decoded(message) =>
      assert_eq(message.lifecycle[0].action, TemplateLifecycleAction::Installed)
    _ => fail("Template Message must complete once")
  }
  match completion.outcomes[1] {
    Decoded(message) => assert_eq(message.records.length(), 1)
    _ => fail("the following Data Message must observe installed state")
  }
  assert_eq(stream.push(b"").outcomes.length(), 0)
  assert_eq(stream.push(b"").outcomes.length(), 0)
}

///|
test "end-of-input distinguishes empty and truncated streams" {
  let fresh = StreamDecoder::new(SessionKey::new("tcp:empty"))
  assert_eq(fresh.finish(), StreamEnd::Complete)
  let partial = StreamDecoder::new(SessionKey::new("tcp:truncated"))
  let batch = partial.push(b"\x00\x0a\x00")
  assert_eq(batch.outcomes.length(), 0)
  assert_eq(batch.need_more, Some({ available: 3, required: 16 }))
  assert_eq(
    partial.finish(),
    StreamEnd::Truncated({ available: 3, required: 16 }),
  )
}

///|
test "retained limits reject oversized declared Messages without growth" {
  let stream = StreamDecoder::with_config(SessionKey::new("tcp:bounded"), {
    max_buffered_bytes: 32,
  }).unwrap()
  let batch = stream.push(byte_range(fixed_template_message(), 0, 16))
  assert_eq(batch.outcomes.length(), 1)
  match batch.outcomes[0] {
    Rejected(diagnostics) =>
      assert_eq(diagnostics[0].code, DiagnosticCode::StreamBufferLimitExceeded)
    _ => fail("declared lengths above the configured limit must be rejected")
  }
  assert_eq(stream.buffered_len(), 0)
  assert_eq(stream.finish(), StreamEnd::BoundaryLost)
}
