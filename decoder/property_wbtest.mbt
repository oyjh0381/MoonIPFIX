///|
fn seeded_chunks(source : Bytes, seed : Int) -> Array[Bytes] {
  let chunks : Array[Bytes] = []
  let mut cursor = 0
  let mut state = seed
  while cursor < source.length() {
    state = (state * 1103515245 + 12345) & 0x7fffffff
    let width = state % 13 + 1
    let end = minimum(source.length(), cursor + width)
    chunks.push(byte_range(source, cursor, end))
    cursor = end
  }
  chunks
}

///|
test "bounded generated streams match complete decoding for 64 replayable seeds" {
  for seed in 1..<=64 {
    let session = SessionKey::new("property:\{seed}")
    let template = replacement_template_message()
    let count = seed % 20 + 1
    let data : Array[Byte] = [
      b'\x00', b'\x0a', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
      b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x2a', b'\x01', b'\x00',
      b'\x00', b'\x00',
    ]
    for index in 0..<count {
      data.push(((seed + index) % 256).to_byte())
      data.push(((seed * 3 + index) % 256).to_byte())
    }
    let length = data.length()
    data[2] = (length / 256).to_byte()
    data[3] = (length % 256).to_byte()
    let set_length = length - 16
    data[18] = (set_length / 256).to_byte()
    data[19] = (set_length % 256).to_byte()
    let data_message = Bytes::from_array(data)
    let complete = Decoder::new()
    let expected = [
      complete.decode_message(template, session),
      complete.decode_message(data_message, session),
    ]
    let stream = StreamDecoder::new(session)
    let observed : Array[DecodeOutcome] = []
    for chunk in seeded_chunks(join_bytes(template, data_message), seed) {
      for outcome in stream.push(chunk).outcomes {
        observed.push(outcome)
      }
    }
    assert_eq(observed, expected, msg="replay seed=\{seed}")
    assert_eq(stream.finish(), StreamEnd::Complete, msg="replay seed=\{seed}")
  }
}

///|
test "deterministic mutators classify lengths IDs encodings padding and truncation" {
  for seed in 1..<=40 {
    let session = SessionKey::new("mutation:\{seed}")
    let decoder = Decoder::new()
    let source = replacement_template_message().to_array()
    match seed % 5 {
      0 => {
        source[2] = b'\x00'
        source[3] = b'\x0f'
      }
      1 => {
        source[18] = b'\x00'
        source[19] = b'\x03'
      }
      2 => {
        source[20] = b'\x00'
        source[21] = b'\xff'
      }
      3 => {
        source[22] = b'\x00'
        source[23] = b'\x02'
      }
      _ => source[source.length() - 1] = b'\x00'
    }
    let outcome = if seed % 5 == 3 {
      decoder.decode_message(Bytes::from_array(source), session)
    } else if seed % 5 == 4 {
      decoder.decode_message(
        byte_range(Bytes::from_array(source), 0, source.length() - 1),
        session,
      )
    } else {
      decoder.decode_message(Bytes::from_array(source), session)
    }
    match outcome {
      Rejected(_) | NeedMoreData(_) => ()
      Decoded(_) => fail("mutation unexpectedly accepted; replay seed=\{seed}")
    }
  }
}
