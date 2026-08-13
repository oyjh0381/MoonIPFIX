///|
/// Create a stateful decoder with the pinned standard IANA registry.
pub fn Decoder::new() -> Decoder {
  {
    registry: @registry.Registry::standard(),
    templates: @hashmap.HashMap([]),
    session_transports: @hashmap.HashMap([]),
  }
}

///|
/// Create a stateful decoder using standard IANA metadata plus caller-supplied
/// Enterprise metadata.
pub fn Decoder::with_registry(registry : @registry.Registry) -> Decoder {
  {
    registry,
    templates: @hashmap.HashMap([]),
    session_transports: @hashmap.HashMap([]),
  }
}

///|
/// Record transport semantics for a Session. Unspecified Sessions use
/// reliable-transport withdrawal behavior; UDP must be marked explicitly.
pub fn Decoder::set_session_transport(
  self : Decoder,
  session : SessionKey,
  transport : TransportProtocol,
) -> Unit {
  self.session_transports.set(session, transport)
}

///|
/// Drop every Template owned by one caller-defined Transport Session.
pub fn Decoder::reset_session(
  self : Decoder,
  session : SessionKey,
) -> TemplateLifecycleEvent {
  let keys = self.templates.keys().to_array()
  let mut removed = 0
  for key in keys {
    if key.session == session {
      self.templates.remove(key)
      removed += 1
    }
  }
  self.session_transports.remove(session)
  {
    action: TemplateLifecycleAction::SessionReset,
    session,
    observation_domain_id: None,
    template_id: None,
    template_kind: None,
    affected: removed,
    offset: None,
  }
}

///|
enum TemplateManagementAction {
  Define(TemplateRecord, Int)
  WithdrawOne(TemplateIdentity, TemplateKind, Int)
  WithdrawAll(SessionKey, UInt, TemplateKind, Int)
} derive(Debug, Eq)

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
  let management : Array[Array[TemplateManagementAction]?] = []
  for set in message.sets {
    if set.kind == SetKind::Template || set.kind == SetKind::OptionsTemplate {
      match parse_management_set(data, message, set) {
        Ok(actions) => management.push(Some(actions))
        Err(diagnostic) => return Rejected([diagnostic])
      }
    } else {
      management.push(None)
    }
  }
  for index in 0..<message.sets.length() {
    let set = message.sets[index]
    match management[index] {
      Some(actions) =>
        for action in actions {
          self.apply_management_action(message, action)
        }
      None => ()
    }
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
fn parse_management_set(
  data : Bytes,
  message : DecodedMessage,
  set : SetSummary,
) -> Result[Array[TemplateManagementAction], Diagnostic] {
  let actions : Array[TemplateManagementAction] = []
  let template_kind = if set.kind == SetKind::OptionsTemplate {
    TemplateKind::Options
  } else {
    TemplateKind::Regular
  }
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
    if field_count == 0 {
      if template_id == set.set_id {
        actions.push(
          WithdrawAll(
            message.session,
            message.header.observation_domain_id,
            template_kind,
            cursor,
          ),
        )
      } else if template_id >= 256U {
        actions.push(
          WithdrawOne(
            {
              session: message.session,
              observation_domain_id: message.header.observation_domain_id,
              template_id,
            },
            template_kind,
            cursor,
          ),
        )
      } else {
        return Err(
          template_diagnostic(
            message,
            set,
            DiagnosticCode::InvalidTemplateId,
            cursor,
            "withdrawal Template ID must match the Set ID or be at least 256",
          ),
        )
      }
      cursor += 4
      continue
    }
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
    let header_length = if template_kind == TemplateKind::Options {
      6
    } else {
      4
    }
    if end - cursor < header_length {
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
    let scope_field_count = if template_kind == TemplateKind::Options {
      read_u16_be(data, cursor + 4).reinterpret_as_int()
    } else {
      0
    }
    if template_kind == TemplateKind::Options &&
      (scope_field_count == 0 || scope_field_count > field_count) {
      return Err(
        template_diagnostic(
          message,
          set,
          DiagnosticCode::InvalidScopeFieldCount,
          cursor + 4,
          "Options Scope Field Count must be between one and Field Count",
        ),
      )
    }
    if field_count > (end - cursor - header_length) / 4 {
      return Err(
        template_diagnostic(
          message,
          set,
          DiagnosticCode::TruncatedTemplateRecord,
          cursor + header_length,
          "Field Specifiers exceed the containing Template Set",
        ),
      )
    }
    let fields : Array[FieldSpecifier] = []
    let mut fixed_record_length = 0
    let mut minimum_record_length = 0
    let mut has_variable_length = false
    let mut field_cursor = cursor + header_length
    for _ in 0..<field_count {
      if end - field_cursor < 4 {
        return Err(
          template_diagnostic(
            message,
            set,
            DiagnosticCode::TruncatedTemplateRecord,
            field_cursor,
            "Field Specifier Header exceeds the containing Template Set",
          ),
        )
      }
      let specifier_offset = field_cursor
      let raw_element_id = read_u16_be(data, field_cursor)
      let field_length = read_u16_be(data, field_cursor + 2).reinterpret_as_int()
      let enterprise = raw_element_id >= 0x8000U
      let identity = if enterprise {
        if end - field_cursor < 8 {
          return Err(
            template_diagnostic(
              message,
              set,
              DiagnosticCode::TruncatedTemplateRecord,
              specifier_offset + 4,
              "Enterprise Field Specifier is missing its Private Enterprise Number",
            ),
          )
        }
        let identity = @registry.InformationElementIdentity::enterprise(
          read_u32_be(data, field_cursor + 4),
          raw_element_id & 0x7fffU,
        )
        field_cursor += 4
        identity
      } else {
        @registry.InformationElementIdentity::standard(raw_element_id)
      }
      if field_length == 0 {
        return Err(
          template_diagnostic(
            message,
            set,
            DiagnosticCode::InvalidFieldLength,
            specifier_offset + 2,
            "Field Specifiers must be fixed nonzero length or 65535 for variable length",
          ),
        )
      }
      let minimum_field_length = if field_length == 65535 {
        has_variable_length = true
        1
      } else {
        field_length
      }
      if minimum_field_length > 65535 - minimum_record_length {
        return Err(
          template_diagnostic(
            message,
            set,
            DiagnosticCode::TemplateRecordTooLarge,
            specifier_offset + 2,
            "fixed Template record length exceeds one IPFIX Message",
          ),
        )
      }
      fields.push({ identity, length: field_length })
      minimum_record_length += minimum_field_length
      if field_length != 65535 {
        fixed_record_length += field_length
      }
      field_cursor += 4
    }
    if minimum_record_length == 0 {
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
    let scope_fields : Array[FieldSpecifier] = []
    let option_fields : Array[FieldSpecifier] = []
    if template_kind == TemplateKind::Options {
      for index in 0..<fields.length() {
        if index < scope_field_count {
          scope_fields.push(fields[index])
        } else {
          option_fields.push(fields[index])
        }
      }
    }
    actions.push(
      Define(
        {
          identity: {
            session: message.session,
            observation_domain_id: message.header.observation_domain_id,
            template_id,
          },
          kind: template_kind,
          fields,
          scope_fields,
          option_fields,
          record_length: if has_variable_length {
            -1
          } else {
            fixed_record_length
          },
          minimum_record_length,
          has_variable_length,
        },
        cursor,
      ),
    )
    cursor = field_cursor
  }
  Ok(actions)
}

///|
fn Decoder::apply_management_action(
  self : Decoder,
  message : DecodedMessage,
  action : TemplateManagementAction,
) -> Unit {
  match action {
    Define(template, offset) => {
      let lifecycle_action = match self.templates.get(template.identity) {
        None => {
          self.templates.set(template.identity, template)
          TemplateLifecycleAction::Installed
        }
        Some(existing) =>
          if existing == template {
            TemplateLifecycleAction::Retransmitted
          } else {
            self.templates.set(template.identity, template)
            message.diagnostics.push(
              make_diagnostic(
                message.session,
                DiagnosticCode::TemplateRedefined,
                DiagnosticSeverity::Warning,
                offset,
                Some(template.identity.observation_domain_id),
                Some(template.identity.template_id),
                "a different definition replaced the scoped Template",
              ),
            )
            TemplateLifecycleAction::Replaced
          }
      }
      message.templates.push(template)
      message.lifecycle.push({
        action: lifecycle_action,
        session: template.identity.session,
        observation_domain_id: Some(template.identity.observation_domain_id),
        template_id: Some(template.identity.template_id),
        template_kind: Some(template.kind),
        affected: 1,
        offset: Some(offset),
      })
    }
    WithdrawOne(identity, kind, offset) =>
      if self.session_uses_udp(identity.session) {
        message.diagnostics.push(
          make_diagnostic(
            message.session,
            DiagnosticCode::TemplateWithdrawalIgnoredForUdp,
            DiagnosticSeverity::Warning,
            offset,
            Some(identity.observation_domain_id),
            Some(identity.template_id),
            "RFC 7011 requires Collecting Processes to ignore UDP Template Withdrawals",
          ),
        )
        message.lifecycle.push({
          action: TemplateLifecycleAction::WithdrawalIgnored,
          session: identity.session,
          observation_domain_id: Some(identity.observation_domain_id),
          template_id: Some(identity.template_id),
          template_kind: Some(kind),
          affected: 0,
          offset: Some(offset),
        })
      } else {
        match self.templates.get(identity) {
          Some(existing) if existing.kind == kind => {
            self.templates.remove(identity)
            message.lifecycle.push({
              action: TemplateLifecycleAction::Withdrawn,
              session: identity.session,
              observation_domain_id: Some(identity.observation_domain_id),
              template_id: Some(identity.template_id),
              template_kind: Some(kind),
              affected: 1,
              offset: Some(offset),
            })
          }
          _ => {
            message.diagnostics.push(
              make_diagnostic(
                message.session,
                DiagnosticCode::TemplateWithdrawalMissing,
                DiagnosticSeverity::Warning,
                offset,
                Some(identity.observation_domain_id),
                Some(identity.template_id),
                "withdrawal was ignored because the scoped Template is not stored with this kind",
              ),
            )
            message.lifecycle.push({
              action: TemplateLifecycleAction::WithdrawalMissing,
              session: identity.session,
              observation_domain_id: Some(identity.observation_domain_id),
              template_id: Some(identity.template_id),
              template_kind: Some(kind),
              affected: 0,
              offset: Some(offset),
            })
          }
        }
      }
    WithdrawAll(session, observation_domain_id, kind, offset) => {
      if self.session_uses_udp(session) {
        message.diagnostics.push(
          make_diagnostic(
            message.session,
            DiagnosticCode::TemplateWithdrawalIgnoredForUdp,
            DiagnosticSeverity::Warning,
            offset,
            Some(observation_domain_id),
            None,
            "RFC 7011 requires Collecting Processes to ignore UDP Template Withdrawals",
          ),
        )
        message.lifecycle.push({
          action: TemplateLifecycleAction::WithdrawalIgnored,
          session,
          observation_domain_id: Some(observation_domain_id),
          template_id: None,
          template_kind: Some(kind),
          affected: 0,
          offset: Some(offset),
        })
        return
      }
      let keys = self.templates.keys().to_array()
      let mut removed = 0
      for key in keys {
        if key.session == session &&
          key.observation_domain_id == observation_domain_id {
          match self.templates.get(key) {
            Some(template) if template.kind == kind => {
              self.templates.remove(key)
              removed += 1
            }
            _ => ()
          }
        }
      }
      if removed == 0 {
        message.diagnostics.push(
          make_diagnostic(
            message.session,
            DiagnosticCode::TemplateWithdrawalMissing,
            DiagnosticSeverity::Warning,
            offset,
            Some(observation_domain_id),
            None,
            "all-Templates withdrawal matched no stored Templates of this kind",
          ),
        )
      }
      message.lifecycle.push({
        action: TemplateLifecycleAction::WithdrawnAll,
        session,
        observation_domain_id: Some(observation_domain_id),
        template_id: None,
        template_kind: Some(kind),
        affected: removed,
        offset: Some(offset),
      })
    }
  }
}

///|
fn Decoder::session_uses_udp(self : Decoder, session : SessionKey) -> Bool {
  self.session_transports.get(session) == Some(TransportProtocol::Udp)
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
  while end - cursor >= template.minimum_record_length {
    let record_offset = cursor
    let fields : Array[DecodedField] = []
    for specifier in template.fields {
      let mut value_offset = cursor
      let mut encoded_length = specifier.length
      if specifier.length == 65535 {
        if cursor >= end {
          return Err(
            data_diagnostic(
              message,
              set,
              DiagnosticCode::IncompleteDataRecord,
              cursor,
              "variable-length field is missing its length prefix",
            ),
          )
        }
        let short_length = data[cursor].to_int()
        if short_length < 255 {
          value_offset = cursor + 1
          encoded_length = short_length
        } else {
          if end - cursor < 3 {
            return Err(
              data_diagnostic(
                message,
                set,
                DiagnosticCode::IncompleteDataRecord,
                cursor,
                "three-octet variable-length prefix is incomplete",
              ),
            )
          }
          value_offset = cursor + 3
          encoded_length = read_u16_be(data, cursor + 1).reinterpret_as_int()
          if encoded_length < 255 {
            return Err(
              data_diagnostic(
                message,
                set,
                DiagnosticCode::InvalidVariableLengthPrefix,
                cursor,
                "lengths below 255 must use the one-octet variable-length prefix",
              ),
            )
          }
        }
      } else {
        value_offset = cursor
        encoded_length = specifier.length
      }
      if encoded_length > end - value_offset {
        return Err(
          data_diagnostic(
            message,
            set,
            DiagnosticCode::IncompleteDataRecord,
            value_offset,
            "field value exceeds the containing Data Set",
          ),
        )
      }
      let metadata = self.registry.lookup(specifier.identity)
      let (value, fallback_reason) = decode_field_value(
        metadata, data, value_offset, encoded_length,
      )
      match fallback_reason {
        Some(reason) =>
          message.diagnostics.push(
            make_diagnostic(
              message.session,
              DiagnosticCode::InvalidFieldEncoding,
              DiagnosticSeverity::Warning,
              value_offset,
              Some(message.header.observation_domain_id),
              Some(set.set_id),
              reason,
            ),
          )
        None => ()
      }
      fields.push({
        specifier,
        metadata,
        offset: value_offset,
        encoded_length,
        value,
      })
      cursor = value_offset + encoded_length
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
fn decode_field_value(
  metadata : @registry.LookupResult,
  data : Bytes,
  offset : Int,
  length : Int,
) -> (FieldValue, String?) {
  match metadata {
    @registry.Resolved(element) =>
      match element.abstract_data_type {
        @registry.AbstractDataType::Unsigned8 =>
          if length == 1 {
            (FieldValue::Unsigned(read_uint_be(data, offset, length)), None)
          } else {
            raw_fallback(
              data, offset, length, "unsigned8 requires exactly one octet",
            )
          }
        @registry.AbstractDataType::Unsigned16 =>
          decode_reduced_unsigned(data, offset, length, 2)
        @registry.AbstractDataType::Unsigned32 =>
          decode_reduced_unsigned(data, offset, length, 4)
        @registry.AbstractDataType::Unsigned64 =>
          decode_reduced_unsigned(data, offset, length, 8)
        @registry.AbstractDataType::Signed8 =>
          if length == 1 {
            (FieldValue::Signed(read_int_be(data, offset, length)), None)
          } else {
            raw_fallback(
              data, offset, length, "signed8 requires exactly one octet",
            )
          }
        @registry.AbstractDataType::Signed16 =>
          decode_reduced_signed(data, offset, length, 2)
        @registry.AbstractDataType::Signed32 =>
          decode_reduced_signed(data, offset, length, 4)
        @registry.AbstractDataType::Signed64 =>
          decode_reduced_signed(data, offset, length, 8)
        @registry.AbstractDataType::Float32 =>
          if length == 4 {
            (
              FieldValue::Float32(
                Float::reinterpret_from_uint(read_u32_be(data, offset)),
              ),
              None,
            )
          } else {
            raw_fallback(data, offset, length, "float32 requires four octets")
          }
        @registry.AbstractDataType::Float64 =>
          if length == 8 {
            (
              FieldValue::Float64(
                read_uint_be(data, offset, length).reinterpret_as_double(),
              ),
              None,
            )
          } else {
            raw_fallback(data, offset, length, "float64 requires eight octets")
          }
        @registry.AbstractDataType::Boolean =>
          if length == 1 && data[offset] == b'\x01' {
            (FieldValue::Boolean(true), None)
          } else if length == 1 && data[offset] == b'\x02' {
            (FieldValue::Boolean(false), None)
          } else {
            raw_fallback(
              data, offset, length, "boolean requires one octet with value 1 or 2",
            )
          }
        @registry.AbstractDataType::MacAddress =>
          if length == 6 {
            (FieldValue::MacAddress(copy_bytes(data, offset, length)), None)
          } else {
            raw_fallback(data, offset, length, "macAddress requires six octets")
          }
        @registry.AbstractDataType::Ipv4Address =>
          if length == 4 {
            (FieldValue::Ipv4Address(copy_bytes(data, offset, length)), None)
          } else {
            raw_fallback(
              data, offset, length, "ipv4Address requires four octets",
            )
          }
        @registry.AbstractDataType::Ipv6Address =>
          if length == 16 {
            (FieldValue::Ipv6Address(copy_bytes(data, offset, length)), None)
          } else {
            raw_fallback(
              data, offset, length, "ipv6Address requires sixteen octets",
            )
          }
        @registry.AbstractDataType::DateTimeSeconds =>
          if length == 4 {
            (FieldValue::DateTimeSeconds(read_u32_be(data, offset)), None)
          } else {
            raw_fallback(
              data, offset, length, "dateTimeSeconds requires four octets",
            )
          }
        @registry.AbstractDataType::DateTimeMilliseconds =>
          if length == 8 {
            (
              FieldValue::DateTimeMilliseconds(
                read_uint_be(data, offset, length),
              ),
              None,
            )
          } else {
            raw_fallback(
              data, offset, length, "dateTimeMilliseconds requires eight octets",
            )
          }
        @registry.AbstractDataType::DateTimeMicroseconds =>
          if length == 8 {
            (
              FieldValue::DateTimeMicroseconds(
                read_uint_be(data, offset, length),
              ),
              None,
            )
          } else {
            raw_fallback(
              data, offset, length, "dateTimeMicroseconds requires eight octets",
            )
          }
        @registry.AbstractDataType::DateTimeNanoseconds =>
          if length == 8 {
            (
              FieldValue::DateTimeNanoseconds(
                read_uint_be(data, offset, length),
              ),
              None,
            )
          } else {
            raw_fallback(
              data, offset, length, "dateTimeNanoseconds requires eight octets",
            )
          }
        @registry.AbstractDataType::String => {
          let text = @utf8.decode(data[offset:offset + length]) catch {
            _ =>
              return raw_fallback(
                data, offset, length, "string contains invalid UTF-8",
              )
          }
          (FieldValue::String(text), None)
        }
        @registry.AbstractDataType::OctetArray =>
          (FieldValue::Octets(copy_bytes(data, offset, length)), None)
        _ =>
          raw_fallback(
            data, offset, length, "resolved Information Element type is outside the v0.1 typed scalar scope",
          )
      }
    @registry.Unresolved(_) =>
      (FieldValue::Octets(copy_bytes(data, offset, length)), None)
  }
}

///|
fn decode_reduced_unsigned(
  data : Bytes,
  offset : Int,
  length : Int,
  canonical_length : Int,
) -> (FieldValue, String?) {
  if length > 0 && length <= canonical_length {
    (FieldValue::Unsigned(read_uint_be(data, offset, length)), None)
  } else {
    raw_fallback(
      data, offset, length, "unsigned integer Reduced-Size Encoding exceeds its canonical width",
    )
  }
}

///|
fn decode_reduced_signed(
  data : Bytes,
  offset : Int,
  length : Int,
  canonical_length : Int,
) -> (FieldValue, String?) {
  if length > 0 && length <= canonical_length {
    (FieldValue::Signed(read_int_be(data, offset, length)), None)
  } else {
    raw_fallback(
      data, offset, length, "signed integer Reduced-Size Encoding exceeds its canonical width",
    )
  }
}

///|
fn raw_fallback(
  data : Bytes,
  offset : Int,
  length : Int,
  reason : String,
) -> (FieldValue, String?) {
  (FieldValue::Octets(copy_bytes(data, offset, length)), Some(reason))
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
fn data_diagnostic(
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
