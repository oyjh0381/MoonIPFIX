///|
/// Encode one decoded Message as deterministic, newline-free JSON records.
pub fn encode_message(message : @decoder.DecodedMessage) -> Array[String] {
  let lines : Array[String] = []
  let session = json_string(message.session.to_string())
  lines.push(
    envelope(
      "message",
      "\"session\":\{session},\"observation_domain_id\":\{message.header.observation_domain_id},\"sequence_number\":\{message.header.sequence_number},\"export_time\":\{message.header.export_time},\"length\":\{message.header.length}",
    ),
  )
  for set in message.sets {
    lines.push(
      envelope(
        "set",
        "\"session\":\{session},\"observation_domain_id\":\{message.header.observation_domain_id},\"set_id\":\{set.set_id},\"offset\":\{set.offset},\"length\":\{set.length},\"set_kind\":\{json_string(set_kind(set.kind))}",
      ),
    )
  }
  for template in message.templates {
    lines.push(encode_template(template))
  }
  for lifecycle in message.lifecycle {
    lines.push(encode_lifecycle(lifecycle))
  }
  for record in message.records {
    lines.push(encode_record(record))
  }
  match message.sequence {
    Some(sequence) => lines.push(encode_sequence(sequence))
    None => ()
  }
  for diagnostic in message.diagnostics {
    lines.push(encode_diagnostic(diagnostic))
  }
  lines.push(encode_statistics(message.statistics, session))
  lines
}

///|
fn envelope(kind : String, body : String) -> String {
  "{\"schema_version\":\{schema_version},\"record_kind\":\{json_string(kind)},\{body}}"
}

///|
fn json_string(value : String) -> String {
  @json.to_json(value).stringify()
}

///|
fn encode_template(template : @decoder.TemplateRecord) -> String {
  let fields = StringBuilder::new()
  fields.write_char('[')
  for index in 0..<template.fields.length() {
    if index > 0 {
      fields.write_char(',')
    }
    let field = template.fields[index]
    fields.write_string(
      "{\"enterprise_number\":\{field.identity.enterprise_number},\"element_id\":\{field.identity.element_id},\"declared_length\":\{field.length},\"scope\":\{index < template.scope_fields.length()}}",
    )
  }
  fields.write_char(']')
  envelope(
    "template",
    "\"session\":\{json_string(template.identity.session.to_string())},\"observation_domain_id\":\{template.identity.observation_domain_id},\"template_id\":\{template.identity.template_id},\"template_kind\":\{json_string(template_kind(template.kind))},\"fields\":\{fields.to_string()}",
  )
}

///|
fn encode_lifecycle(event : @decoder.TemplateLifecycleEvent) -> String {
  envelope(
    "template_lifecycle",
    "\"session\":\{json_string(event.session.to_string())},\"observation_domain_id\":\{optional_uint(event.observation_domain_id)},\"template_id\":\{optional_uint(event.template_id)},\"action\":\{json_string(lifecycle_action(event.action))},\"affected\":\{event.affected},\"offset\":\{optional_int(event.offset)}",
  )
}

///|
fn encode_record(record : @decoder.DataRecord) -> String {
  let fields = StringBuilder::new()
  fields.write_char('[')
  for index in 0..<record.fields.length() {
    if index > 0 {
      fields.write_char(',')
    }
    let field = record.fields[index]
    fields.write_string(
      "{\"enterprise_number\":\{field.specifier.identity.enterprise_number},\"element_id\":\{field.specifier.identity.element_id},\"declared_length\":\{field.specifier.length},\"encoded_length\":\{field.encoded_length},\"offset\":\{field.offset},\"value\":\{encode_value(field.value)}}",
    )
  }
  fields.write_char(']')
  envelope(
    "data_record",
    "\"session\":\{json_string(record.template.session.to_string())},\"observation_domain_id\":\{record.template.observation_domain_id},\"template_id\":\{record.template.template_id},\"offset\":\{record.offset},\"fields\":\{fields.to_string()}",
  )
}

///|
pub fn encode_value(value : @decoder.FieldValue) -> String {
  match value {
    Unsigned(value) =>
      "{\"type\":\"unsigned\",\"decimal\":\{json_string(value.to_string())}}"
    Signed(value) =>
      "{\"type\":\"signed\",\"decimal\":\{json_string(value.to_string())}}"
    Float32(value) =>
      "{\"type\":\"float32\",\"value\":\{json_string(value.to_string())}}"
    Float64(value) =>
      "{\"type\":\"float64\",\"value\":\{json_string(value.to_string())}}"
    Boolean(value) => "{\"type\":\"boolean\",\"value\":\{value}}"
    String(value) => "{\"type\":\"string\",\"value\":\{json_string(value)}}"
    Octets(value) => bytes_value("octets", value)
    MacAddress(value) => bytes_value("mac_address", value)
    Ipv4Address(value) => bytes_value("ipv4_address", value)
    Ipv6Address(value) => bytes_value("ipv6_address", value)
    DateTimeSeconds(value) => time_value("date_time_seconds", value.to_string())
    DateTimeMilliseconds(value) =>
      time_value("date_time_milliseconds", value.to_string())
    DateTimeMicroseconds(value) =>
      time_value("date_time_microseconds", value.to_string())
    DateTimeNanoseconds(value) =>
      time_value("date_time_nanoseconds", value.to_string())
  }
}

///|
fn bytes_value(kind : String, value : Bytes) -> String {
  "{\"type\":\{json_string(kind)},\"encoding\":\"hex\",\"value\":\{json_string(hex(value))}}"
}

///|
fn time_value(kind : String, decimal : String) -> String {
  "{\"type\":\{json_string(kind)},\"decimal\":\{json_string(decimal)}}"
}

///|
fn hex(value : Bytes) -> String {
  let digits = "0123456789abcdef"
  let output = StringBuilder::new()
  for byte in value {
    output.write_char(digits[byte.to_int() / 16].to_int().unsafe_to_char())
    output.write_char(digits[byte.to_int() % 16].to_int().unsafe_to_char())
  }
  output.to_string()
}

///|
fn encode_sequence(audit : @decoder.SequenceAudit) -> String {
  envelope(
    "sequence_audit",
    "\"session\":\{json_string(audit.session.to_string())},\"observation_domain_id\":\{audit.observation_domain_id},\"continuity\":\{json_string(sequence_continuity(audit.continuity))},\"observed\":\{audit.observed},\"expected\":\{optional_uint(audit.expected)},\"missing\":\{optional_uint(audit.missing)},\"decoded_record_count\":\{audit.decoded_record_count},\"record_count_complete\":\{audit.record_count_complete},\"next_expected\":\{optional_uint(audit.next_expected)}",
  )
}

///|
pub fn encode_diagnostic(value : @decoder.Diagnostic) -> String {
  envelope(
    "diagnostic",
    "\"session\":\{json_string(value.context.session.to_string())},\"observation_domain_id\":\{optional_uint(value.context.observation_domain_id)},\"set_id\":\{optional_uint(value.context.set_id)},\"code\":\{json_string(diagnostic_code(value.code))},\"severity\":\{json_string(if value.severity == @decoder.DiagnosticSeverity::Warning { "warning" } else { "error" })},\"offset\":\{value.offset},\"message\":\{json_string(value.message)}",
  )
}

///|
fn encode_statistics(
  value : @decoder.MessageStatistics,
  session : String,
) -> String {
  envelope(
    "statistics",
    "\"session\":\{session},\"message_count\":\{value.message_count},\"set_count\":\{value.set_count},\"template_count\":\{value.template_count},\"lifecycle_count\":\{value.lifecycle_count},\"record_count\":\{value.record_count},\"field_count\":\{value.field_count},\"diagnostic_count\":\{value.diagnostic_count}",
  )
}

///|
fn optional_uint(value : UInt?) -> String {
  match value {
    Some(v) => v.to_string()
    None => "null"
  }
}

///|
fn optional_int(value : Int?) -> String {
  match value {
    Some(v) => v.to_string()
    None => "null"
  }
}

///|
fn set_kind(value : @decoder.SetKind) -> String {
  match value {
    Template => "template"
    OptionsTemplate => "options_template"
    Data => "data"
    Unknown => "unknown"
  }
}

///|
fn template_kind(value : @decoder.TemplateKind) -> String {
  match value {
    Regular => "regular"
    Options => "options"
  }
}

///|
fn lifecycle_action(value : @decoder.TemplateLifecycleAction) -> String {
  match value {
    Installed => "installed"
    Retransmitted => "retransmitted"
    Replaced => "replaced"
    Withdrawn => "withdrawn"
    WithdrawnAll => "withdrawn_all"
    WithdrawalMissing => "withdrawal_missing"
    WithdrawalIgnored => "withdrawal_ignored"
    SessionReset => "session_reset"
    DataSetUnresolved => "data_set_unresolved"
  }
}

///|
fn sequence_continuity(value : @decoder.SequenceContinuity) -> String {
  match value {
    Baseline => "baseline"
    Continuous => "continuous"
    Gap => "gap"
    Unverifiable => "unverifiable"
  }
}

///|
fn diagnostic_code(value : @decoder.DiagnosticCode) -> String {
  match value {
    UnsupportedVersion => "unsupported_version"
    InvalidMessageLength => "invalid_message_length"
    TrailingBytes => "trailing_bytes"
    TruncatedSetHeader => "truncated_set_header"
    InvalidSetLength => "invalid_set_length"
    SetExceedsMessage => "set_exceeds_message"
    UnknownSetId => "unknown_set_id"
    InvalidTemplateId => "invalid_template_id"
    InvalidTemplateFieldCount => "invalid_template_field_count"
    InvalidFieldLength => "invalid_field_length"
    InvalidVariableLengthPrefix => "invalid_variable_length_prefix"
    InvalidScopeFieldCount => "invalid_scope_field_count"
    TruncatedTemplateRecord => "truncated_template_record"
    UnsupportedEnterpriseField => "unsupported_enterprise_field"
    UnsupportedVariableLengthField => "unsupported_variable_length_field"
    TemplateRecordTooLarge => "template_record_too_large"
    MissingTemplate => "missing_template"
    IncompleteDataRecord => "incomplete_data_record"
    InvalidFieldEncoding => "invalid_field_encoding"
    TemplateRedefined => "template_redefined"
    TemplateWithdrawalMissing => "template_withdrawal_missing"
    TemplateWithdrawalIgnoredForUdp => "template_withdrawal_ignored_for_udp"
    SequenceGap => "sequence_gap"
    SequenceUnverifiable => "sequence_unverifiable"
    SessionLimitExceeded => "session_limit_exceeded"
    TemplateLimitExceeded => "template_limit_exceeded"
    FieldCountLimitExceeded => "field_count_limit_exceeded"
    FieldLengthLimitExceeded => "field_length_limit_exceeded"
    RecordLimitExceeded => "record_limit_exceeded"
    DiagnosticLimitExceeded => "diagnostic_limit_exceeded"
    StreamBufferLimitExceeded => "stream_buffer_limit_exceeded"
    StreamBoundaryLost => "stream_boundary_lost"
  }
}
