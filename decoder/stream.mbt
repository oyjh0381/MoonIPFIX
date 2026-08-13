///|
pub fn StreamDecoderConfig::default() -> StreamDecoderConfig {
  { max_buffered_bytes: 65535 }
}

///|
/// Create an arbitrary-chunk decoder with the pinned IANA registry.
pub fn StreamDecoder::new(session : SessionKey) -> StreamDecoder {
  {
    decoder: Decoder::new(),
    session,
    config: StreamDecoderConfig::default(),
    buffer: [],
    boundary_lost: false,
  }
}

///|
pub fn StreamDecoder::with_config(
  session : SessionKey,
  config : StreamDecoderConfig,
) -> Result[StreamDecoder, StreamConfigError] {
  StreamDecoder::with_registry_and_config(
    session,
    @registry.Registry::standard(),
    config,
  )
}

///|
pub fn StreamDecoder::set_transport(
  self : StreamDecoder,
  transport : TransportProtocol,
) -> Unit {
  self.decoder.set_session_transport(self.session, transport)
}

///|
/// Create an arbitrary-chunk decoder with Enterprise metadata and a validated
/// retained-buffer limit.
pub fn StreamDecoder::with_registry_and_config(
  session : SessionKey,
  registry : @registry.Registry,
  config : StreamDecoderConfig,
) -> Result[StreamDecoder, StreamConfigError] {
  if config.max_buffered_bytes < message_header_length {
    return Err(MaxBufferedBytesBelowHeader(config.max_buffered_bytes))
  }
  if config.max_buffered_bytes > 65535 {
    return Err(MaxBufferedBytesAboveProtocolMaximum(config.max_buffered_bytes))
  }
  Ok({
    decoder: Decoder::with_registry(registry),
    session,
    config,
    buffer: [],
    boundary_lost: false,
  })
}

///|
/// Combine protocol-state limits with the arbitrary-chunk retained-byte limit.
pub fn StreamDecoder::with_limits_and_config(
  session : SessionKey,
  registry : @registry.Registry,
  limits : DecoderLimits,
  config : StreamDecoderConfig,
) -> Result[StreamDecoder, StreamConstructionError] {
  if config.max_buffered_bytes < message_header_length {
    return Err(
      StreamConfig(MaxBufferedBytesBelowHeader(config.max_buffered_bytes)),
    )
  }
  if config.max_buffered_bytes > 65535 {
    return Err(
      StreamConfig(
        MaxBufferedBytesAboveProtocolMaximum(config.max_buffered_bytes),
      ),
    )
  }
  let decoder = match Decoder::with_registry_and_limits(registry, limits) {
    Ok(value) => value
    Err(error) => return Err(DecoderConfig(error))
  }
  Ok({ session, decoder, config, buffer: [], boundary_lost: false })
}

///|
pub fn StreamDecoder::buffered_len(self : StreamDecoder) -> Int {
  self.buffer.length()
}

///|
pub fn StreamDecoder::active_templates(
  self : StreamDecoder,
) -> Array[TemplateRecord] {
  self.decoder.active_templates(self.session)
}

///|
/// Push an arbitrary chunk. Complete Messages are passed through the same
/// stateful Decoder used by the caller-delimited API and are applied once.
pub fn StreamDecoder::push(self : StreamDecoder, chunk : Bytes) -> StreamBatch {
  let outcomes : Array[DecodeOutcome] = []
  if self.boundary_lost {
    outcomes.push(
      Rejected([
        stream_diagnostic(
          self.session,
          DiagnosticCode::StreamBoundaryLost,
          "stream cannot continue after an invalid Message Length destroyed framing",
        ),
      ]),
    )
    return { outcomes, need_more: None, buffered: 0 }
  }
  let mut chunk_cursor = 0
  while chunk_cursor < chunk.length() {
    if self.buffer.length() < message_header_length {
      let header_needed = message_header_length - self.buffer.length()
      let header_take = minimum(header_needed, chunk.length() - chunk_cursor)
      for index in 0..<header_take {
        self.buffer.push(chunk[chunk_cursor + index])
      }
      chunk_cursor += header_take
      if self.buffer.length() < message_header_length {
        break
      }
    }
    let declared_length = read_u16_be(Bytes::from_array(self.buffer), 2).reinterpret_as_int()
    if declared_length < message_header_length {
      let exact_header = Bytes::from_array(
        self.buffer[0:message_header_length].to_owned(),
      )
      outcomes.push(self.decoder.decode_message(exact_header, self.session))
      self.buffer = []
      self.boundary_lost = true
      return { outcomes, need_more: None, buffered: 0 }
    }
    if declared_length > self.config.max_buffered_bytes {
      outcomes.push(
        Rejected([
          stream_diagnostic(
            self.session,
            DiagnosticCode::StreamBufferLimitExceeded,
            "declared Message Length exceeds the configured retained-buffer limit",
          ),
        ]),
      )
      self.buffer = []
      self.boundary_lost = true
      return { outcomes, need_more: None, buffered: 0 }
    }
    let body_needed = declared_length - self.buffer.length()
    let body_take = minimum(body_needed, chunk.length() - chunk_cursor)
    for index in 0..<body_take {
      self.buffer.push(chunk[chunk_cursor + index])
    }
    chunk_cursor += body_take
    if self.buffer.length() < declared_length {
      break
    }
    let message_bytes = Bytes::from_array(self.buffer)
    self.buffer = []
    outcomes.push(self.decoder.decode_message(message_bytes, self.session))
  }
  {
    outcomes,
    need_more: stream_need_more(self.buffer),
    buffered: self.buffer.length(),
  }
}

///|
fn minimum(left : Int, right : Int) -> Int {
  if left < right {
    left
  } else {
    right
  }
}

///|
/// Report whether end-of-input is clean without mutating pending bytes.
pub fn StreamDecoder::finish(self : StreamDecoder) -> StreamEnd {
  if self.boundary_lost {
    BoundaryLost
  } else {
    match stream_need_more(self.buffer) {
      None => Complete
      Some(need) => Truncated(need)
    }
  }
}

///|
fn stream_need_more(buffer : Array[Byte]) -> NeedMore? {
  if buffer.length() == 0 {
    return None
  }
  if buffer.length() < message_header_length {
    return Some({ available: buffer.length(), required: message_header_length })
  }
  let declared_length = read_u16_be(Bytes::from_array(buffer), 2).reinterpret_as_int()
  Some({ available: buffer.length(), required: declared_length })
}

///|
fn stream_diagnostic(
  session : SessionKey,
  code : DiagnosticCode,
  text : String,
) -> Diagnostic {
  {
    code,
    severity: DiagnosticSeverity::Error,
    offset: 0,
    context: { session, observation_domain_id: None, set_id: None },
    message: text,
  }
}
