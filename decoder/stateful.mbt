///|
/// Create a stateful decoder with the pinned standard IANA registry.
pub fn Decoder::new() -> Decoder {
  { registry: @registry.Registry::standard(), templates: @hashmap.HashMap([]) }
}

///|
/// Create a stateful decoder using standard IANA metadata plus caller-supplied
/// Enterprise metadata.
pub fn Decoder::with_registry(registry : @registry.Registry) -> Decoder {
  { registry, templates: @hashmap.HashMap([]) }
}

///|
/// Decode one caller-delimited Message and update Template state only after all
/// Template Records in that Message have been validated.
pub fn Decoder::decode_message(
  self : Decoder,
  data : Bytes,
  session : SessionKey,
) -> DecodeOutcome {
  match decode_message(data, session) {
    Decoded(message) => self.process_framed_message(data, message)
    NeedMoreData(need) => NeedMoreData(need)
    Rejected(diagnostics) => Rejected(diagnostics)
  }
}

///|
fn Decoder::process_framed_message(
  self : Decoder,
  data : Bytes,
  message : DecodedMessage,
) -> DecodeOutcome {
  let staged : Array[TemplateRecord] = []
  for set in message.sets {
    if set.kind == SetKind::Template {
      match parse_template_set(data, message, set) {
        Ok(records) =>
          for record in records {
            staged.push(record)
          }
        Err(diagnostic) => return Rejected([diagnostic])
      }
    }
  }
  for template in staged {
    self.templates.set(template.identity, template)
    message.templates.push(template)
  }
  for set in message.sets {
    if set.kind == SetKind::Data {
      let identity : TemplateIdentity = {
        session: message.session,
        observation_domain_id: message.header.observation_domain_id,
        template_id: set.set_id,
      }
      match self.templates.get(identity) {
        None =>
          message.diagnostics.push(
            make_diagnostic(
              message.session,
              DiagnosticCode::MissingTemplate,
              DiagnosticSeverity::Error,
              set.offset,
              Some(message.header.observation_domain_id),
              Some(set.set_id),
              "Data Set has no Template in this Session and Observation Domain",
            ),
          )
        Some(template) =>
          match self.decode_data_set(data, message, set, template) {
            Ok(records) =>
              for record in records {
                message.records.push(record)
              }
            Err(diagnostic) => return Rejected([diagnostic])
          }
      }
    }
  }
  Decoded(message)
}

///|
fn parse_template_set(
  data : Bytes,
  message : DecodedMessage,
  set : SetSummary,
) -> Result[Array[TemplateRecord], Diagnostic] {
  let records : Array[TemplateRecord] = []
  let end = set.offset + set.length
  let mut cursor = set.payload_offset
  while cursor < end {
    let remaining = end - cursor
    if remaining <= 3 && bytes_are_zero(data, cursor, remaining) {
      break
    }
    if remaining < 4 {
      return Err(
        template_diagnostic(
          message,
          set,
          DiagnosticCode::TruncatedTemplateRecord,
          cursor,
          "Template Record Header is incomplete",
        ),
      )
    }
    let template_id = read_u16_be(data, cursor)
    let field_count = read_u16_be(data, cursor + 2).reinterpret_as_int()
    if template_id < 256U {
      return Err(
        template_diagnostic(
          message,
          set,
          DiagnosticCode::InvalidTemplateId,
          cursor,
          "Template ID must be at least 256",
        ),
      )
    }
    if field_count == 0 {
      return Err(
        template_diagnostic(
          message,
          set,
          DiagnosticCode::InvalidTemplateFieldCount,
          cursor + 2,
          "zero-field Template Records are handled only as withdrawals",
        ),
      )
    }
    if field_count > (end - cursor - 4) / 4 {
      return Err(
        template_diagnostic(
          message,
          set,
          DiagnosticCode::TruncatedTemplateRecord,
          cursor + 4,
          "Field Specifiers exceed the containing Template Set",
        ),
      )
    }
    let fields : Array[FieldSpecifier] = []
    let mut record_length = 0
    let mut field_cursor = cursor + 4
    for _ in 0..<field_count {
      let raw_element_id = read_u16_be(data, field_cursor)
      let field_length = read_u16_be(data, field_cursor + 2).reinterpret_as_int()
      if raw_element_id >= 0x8000U {
        return Err(
          template_diagnostic(
            message,
            set,
            DiagnosticCode::UnsupportedEnterpriseField,
            field_cursor,
            "Enterprise Field Specifiers are implemented by the complete field-encoding slice",
          ),
        )
      }
      if field_length == 65535 {
        return Err(
          template_diagnostic(
            message,
            set,
            DiagnosticCode::UnsupportedVariableLengthField,
            field_cursor + 2,
            "variable-length fields are implemented by the complete field-encoding slice",
          ),
        )
      }
      if field_length == 0 {
        return Err(
          template_diagnostic(
            message,
            set,
            DiagnosticCode::InvalidFieldLength,
            field_cursor + 2,
            "fixed-length Field Specifiers must consume at least one octet",
          ),
        )
      }
      if field_length > 65535 - record_length {
        return Err(
          template_diagnostic(
            message,
            set,
            DiagnosticCode::TemplateRecordTooLarge,
            field_cursor + 2,
            "fixed Template record length exceeds one IPFIX Message",
          ),
        )
      }
      fields.push({
        identity: @registry.InformationElementIdentity::standard(raw_element_id),
        length: field_length,
      })
      record_length += field_length
      field_cursor += 4
    }
    if record_length == 0 {
      return Err(
        template_diagnostic(
          message,
          set,
          DiagnosticCode::InvalidTemplateFieldCount,
          cursor + 2,
          "a fixed Template Record must consume at least one octet",
        ),
      )
    }
    records.push({
      identity: {
        session: message.session,
        observation_domain_id: message.header.observation_domain_id,
        template_id,
      },
      fields,
      record_length,
    })
    cursor = field_cursor
  }
  Ok(records)
}

///|
fn Decoder::decode_data_set(
  self : Decoder,
  data : Bytes,
  message : DecodedMessage,
  set : SetSummary,
  template : TemplateRecord,
) -> Result[Array[DataRecord], Diagnostic] {
  let records : Array[DataRecord] = []
  let end = set.offset + set.length
  let mut cursor = set.payload_offset
  while end - cursor >= template.record_length {
    let record_offset = cursor
    let fields : Array[DecodedField] = []
    for specifier in template.fields {
      let metadata = self.registry.lookup(specifier.identity)
      let value = decode_fixed_value(metadata, data, cursor, specifier.length)
      fields.push({ specifier, metadata, value })
      cursor += specifier.length
    }
    records.push({ template: template.identity, offset: record_offset, fields })
  }
  let remainder = end - cursor
  if remainder > 0 &&
    (remainder > 3 || !bytes_are_zero(data, cursor, remainder)) {
    return Err(
      make_diagnostic(
        message.session,
        DiagnosticCode::IncompleteDataRecord,
        DiagnosticSeverity::Error,
        cursor,
        Some(message.header.observation_domain_id),
        Some(set.set_id),
        "Data Set ends with bytes that cannot be zero padding or a complete record",
      ),
    )
  }
  Ok(records)
}

///|
fn decode_fixed_value(
  metadata : @registry.LookupResult,
  data : Bytes,
  offset : Int,
  length : Int,
) -> FieldValue {
  match metadata {
    @registry.Resolved(element) =>
      match element.abstract_data_type {
        @registry.AbstractDataType::Unsigned8
        | @registry.AbstractDataType::Unsigned16
        | @registry.AbstractDataType::Unsigned32
        | @registry.AbstractDataType::Unsigned64 =>
          if length <= 8 {
            FieldValue::Unsigned(read_uint_be(data, offset, length))
          } else {
            FieldValue::Octets(copy_bytes(data, offset, length))
          }
        @registry.AbstractDataType::Signed8
        | @registry.AbstractDataType::Signed16
        | @registry.AbstractDataType::Signed32
        | @registry.AbstractDataType::Signed64 =>
          if length <= 8 {
            FieldValue::Signed(read_int_be(data, offset, length))
          } else {
            FieldValue::Octets(copy_bytes(data, offset, length))
          }
        @registry.AbstractDataType::Boolean =>
          if length == 1 && data[offset] == b'\x01' {
            FieldValue::Boolean(true)
          } else if length == 1 && data[offset] == b'\x02' {
            FieldValue::Boolean(false)
          } else {
            FieldValue::Octets(copy_bytes(data, offset, length))
          }
        @registry.AbstractDataType::MacAddress =>
          if length == 6 {
            FieldValue::MacAddress(copy_bytes(data, offset, length))
          } else {
            FieldValue::Octets(copy_bytes(data, offset, length))
          }
        @registry.AbstractDataType::Ipv4Address =>
          if length == 4 {
            FieldValue::Ipv4Address(copy_bytes(data, offset, length))
          } else {
            FieldValue::Octets(copy_bytes(data, offset, length))
          }
        @registry.AbstractDataType::Ipv6Address =>
          if length == 16 {
            FieldValue::Ipv6Address(copy_bytes(data, offset, length))
          } else {
            FieldValue::Octets(copy_bytes(data, offset, length))
          }
        @registry.AbstractDataType::DateTimeSeconds =>
          if length == 4 {
            FieldValue::DateTimeSeconds(read_u32_be(data, offset))
          } else {
            FieldValue::Octets(copy_bytes(data, offset, length))
          }
        @registry.AbstractDataType::DateTimeMilliseconds =>
          if length == 8 {
            FieldValue::DateTimeMilliseconds(read_uint_be(data, offset, length))
          } else {
            FieldValue::Octets(copy_bytes(data, offset, length))
          }
        @registry.AbstractDataType::DateTimeMicroseconds =>
          if length == 8 {
            FieldValue::DateTimeMicroseconds(read_uint_be(data, offset, length))
          } else {
            FieldValue::Octets(copy_bytes(data, offset, length))
          }
        @registry.AbstractDataType::DateTimeNanoseconds =>
          if length == 8 {
            FieldValue::DateTimeNanoseconds(read_uint_be(data, offset, length))
          } else {
            FieldValue::Octets(copy_bytes(data, offset, length))
          }
        @registry.AbstractDataType::String => {
          let text = @utf8.decode(data[offset:offset + length]) catch {
            _ => return FieldValue::Octets(copy_bytes(data, offset, length))
          }
          FieldValue::String(text)
        }
        _ => FieldValue::Octets(copy_bytes(data, offset, length))
      }
    @registry.Unresolved(_) =>
      FieldValue::Octets(copy_bytes(data, offset, length))
  }
}

///|
fn read_uint_be(data : Bytes, offset : Int, length : Int) -> UInt64 {
  let mut value = 0UL
  for index in 0..<length {
    value = value * 256UL + data[offset + index].to_uint64()
  }
  value
}

///|
fn read_int_be(data : Bytes, offset : Int, length : Int) -> Int64 {
  let unsigned = read_uint_be(data, offset, length)
  if length == 8 {
    unsigned.reinterpret_as_int64()
  } else if data[offset] >= b'\x80' {
    unsigned.reinterpret_as_int64() - (1L << (length * 8))
  } else {
    unsigned.reinterpret_as_int64()
  }
}

///|
fn copy_bytes(data : Bytes, offset : Int, length : Int) -> Bytes {
  Bytes::from_array(data[offset:offset + length].to_array())
}

///|
fn bytes_are_zero(data : Bytes, offset : Int, length : Int) -> Bool {
  for index in 0..<length {
    if data[offset + index] != b'\x00' {
      return false
    }
  }
  true
}

///|
fn template_diagnostic(
  message : DecodedMessage,
  set : SetSummary,
  code : DiagnosticCode,
  offset : Int,
  text : String,
) -> Diagnostic {
  make_diagnostic(
    message.session,
    code,
    DiagnosticSeverity::Error,
    offset,
    Some(message.header.observation_domain_id),
    Some(set.set_id),
    text,
  )
}

///|
fn make_diagnostic(
  session : SessionKey,
  code : DiagnosticCode,
  severity : DiagnosticSeverity,
  offset : Int,
  observation_domain_id : UInt?,
  set_id : UInt?,
  message : String,
) -> Diagnostic {
  {
    code,
    severity,
    offset,
    context: { session, observation_domain_id, set_id },
    message,
  }
}
