///|
test "all Output Records are independent valid JSON lines" {
  let decoder = @decoder.Decoder::new()
  let session = @decoder.SessionKey::new("tcp:\"json\ncontract")
  let template = b"\x00\x0a\x00\x1c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x2a\x00\x02\x00\x0c\x01\x00\x00\x01\x00\x08\x00\x04"
  match decoder.decode_message(template, session) {
    Decoded(message) => {
      let lines = encode_message(message)
      assert_eq(lines.length(), 6)
      for line in lines {
        ignore(@json.parse(line))
        assert_false(line.contains("\n"))
      }
      assert_eq(
        lines[2],
        "{\"schema_version\":1,\"record_kind\":\"template\",\"session\":\"tcp:\\\"json\\ncontract\",\"observation_domain_id\":42,\"template_id\":256,\"template_kind\":\"regular\",\"fields\":[{\"enterprise_number\":0,\"element_id\":8,\"declared_length\":4,\"scope\":false}]}",
      )
    }
    _ => fail("valid Template Message must encode")
  }
}

///|
test "integer and opaque value representations are explicitly lossless" {
  assert_eq(
    encode_value(@decoder.FieldValue::Unsigned(0xffffffffffffffffUL)),
    "{\"type\":\"unsigned\",\"decimal\":\"18446744073709551615\"}",
  )
  assert_eq(
    encode_value(@decoder.FieldValue::Signed(-9223372036854775807L - 1L)),
    "{\"type\":\"signed\",\"decimal\":\"-9223372036854775808\"}",
  )
  assert_eq(
    encode_value(@decoder.FieldValue::Octets(b"\x00\xff\x10")),
    "{\"type\":\"octets\",\"encoding\":\"hex\",\"value\":\"00ff10\"}",
  )
  assert_eq(
    encode_value(@decoder.FieldValue::Ipv4Address(b"\xc0\xa8\x01\x01")),
    "{\"type\":\"ipv4_address\",\"encoding\":\"hex\",\"value\":\"c0a80101\"}",
  )
  assert_eq(
    encode_value(@decoder.FieldValue::DateTimeMilliseconds(1700000000000UL)),
    "{\"type\":\"date_time_milliseconds\",\"decimal\":\"1700000000000\"}",
  )
}

///|
test "every typed value variant serializes deterministically" {
  let values = [
    @decoder.FieldValue::Unsigned(1UL),
    @decoder.FieldValue::Signed(-1L),
    @decoder.FieldValue::Float32(1.5F),
    @decoder.FieldValue::Float64(1.5),
    @decoder.FieldValue::Boolean(true),
    @decoder.FieldValue::String("x\ny"),
    @decoder.FieldValue::Octets(b"x"),
    @decoder.FieldValue::MacAddress(b"\x00\x11\x22\x33\x44\x55"),
    @decoder.FieldValue::Ipv4Address(b"\x7f\x00\x00\x01"),
    @decoder.FieldValue::Ipv6Address(
      b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
    ),
    @decoder.FieldValue::DateTimeSeconds(1U),
    @decoder.FieldValue::DateTimeMilliseconds(1UL),
    @decoder.FieldValue::DateTimeMicroseconds(1UL),
    @decoder.FieldValue::DateTimeNanoseconds(1UL),
  ]
  for value in values {
    let first = encode_value(value)
    assert_eq(first, encode_value(value))
    ignore(@json.parse(first))
  }
}
