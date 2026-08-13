///|
let message_header_length : Int = 16

///|
let set_header_length : Int = 4

///|
/// Decode exactly one IPFIX Message from a caller-delimited byte buffer.
///
/// The function never scans for a replacement boundary and never ignores
/// trailing bytes. A short buffer reports the exact known extent required;
/// malformed complete input is rejected with structured diagnostics.
pub fn decode_message(data : Bytes, session : SessionKey) -> DecodeOutcome {
  if data.length() < message_header_length {
    return NeedMoreData({
      available: data.length(),
      required: message_header_length,
    })
  }
  let version = read_u16_be(data, 0)
  let declared_length = read_u16_be(data, 2).reinterpret_as_int()
  if declared_length < message_header_length {
    return reject(
      session,
      DiagnosticCode::InvalidMessageLength,
      2,
      None,
      None,
      "IPFIX Message Length is smaller than the 16-byte header",
    )
  }
  if data.length() < declared_length {
    return NeedMoreData({ available: data.length(), required: declared_length })
  }
  if data.length() > declared_length {
    return reject(
      session,
      DiagnosticCode::TrailingBytes,
      declared_length,
      None,
      None,
      "input contains bytes after the declared IPFIX Message extent",
    )
  }
  let observation_domain_id = read_u32_be(data, 12)
  if version != ipfix_version {
    return reject(
      session,
      DiagnosticCode::UnsupportedVersion,
      0,
      Some(observation_domain_id),
      None,
      "only IPFIX version 10 is supported",
    )
  }
  let header : MessageHeader = {
    version,
    length: declared_length,
    export_time: read_u32_be(data, 4),
    sequence_number: read_u32_be(data, 8),
    observation_domain_id,
  }
  let sets : Array[SetSummary] = []
  let diagnostics : Array[Diagnostic] = []
  let mut cursor = message_header_length
  while cursor < declared_length {
    if declared_length - cursor < set_header_length {
      return reject(
        session,
        DiagnosticCode::TruncatedSetHeader,
        cursor,
        Some(observation_domain_id),
        None,
        "remaining Message bytes cannot contain a complete Set Header",
      )
    }
    let set_id = read_u16_be(data, cursor)
    let set_length = read_u16_be(data, cursor + 2).reinterpret_as_int()
    if set_length < set_header_length {
      return reject(
        session,
        DiagnosticCode::InvalidSetLength,
        cursor + 2,
        Some(observation_domain_id),
        Some(set_id),
        "Set Length is smaller than the 4-byte Set Header",
      )
    }
    if set_length > declared_length - cursor {
      return reject(
        session,
        DiagnosticCode::SetExceedsMessage,
        cursor + 2,
        Some(observation_domain_id),
        Some(set_id),
        "Set extent exceeds the containing IPFIX Message",
      )
    }
    let kind = classify_set(set_id)
    sets.push({
      set_id,
      offset: cursor,
      length: set_length,
      payload_offset: cursor + set_header_length,
      payload_length: set_length - set_header_length,
      kind,
    })
    if kind == SetKind::Unknown {
      diagnostics.push({
        code: DiagnosticCode::UnknownSetId,
        severity: DiagnosticSeverity::Warning,
        offset: cursor,
        context: {
          session,
          observation_domain_id: Some(observation_domain_id),
          set_id: Some(set_id),
        },
        message: "reserved Set ID is retained as opaque payload",
      })
    }
    cursor += set_length
  }
  Decoded({ session, header, sets, diagnostics })
}

///|
fn classify_set(set_id : UInt) -> SetKind {
  if set_id == 2U {
    SetKind::Template
  } else if set_id == 3U {
    SetKind::OptionsTemplate
  } else if set_id >= 256U {
    SetKind::Data
  } else {
    SetKind::Unknown
  }
}

///|
fn reject(
  session : SessionKey,
  code : DiagnosticCode,
  offset : Int,
  observation_domain_id : UInt?,
  set_id : UInt?,
  message : String,
) -> DecodeOutcome {
  Rejected([
    {
      code,
      severity: DiagnosticSeverity::Error,
      offset,
      context: { session, observation_domain_id, set_id },
      message,
    },
  ])
}

///|
fn read_u16_be(data : Bytes, offset : Int) -> UInt {
  data[offset].to_uint() * 256U + data[offset + 1].to_uint()
}

///|
fn read_u32_be(data : Bytes, offset : Int) -> UInt {
  data[offset].to_uint() * 0x01000000U +
  data[offset + 1].to_uint() * 0x00010000U +
  data[offset + 2].to_uint() * 0x00000100U +
  data[offset + 3].to_uint()
}
