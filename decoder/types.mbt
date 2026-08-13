///|
/// Caller-supplied identity of one transport or exporter session.
///
/// MoonIPFIX never infers this value from packet bytes. Applications should use
/// a stable identity that separates template namespaces for distinct exporters.
pub struct SessionKey {
  value : String
} derive(Debug, Eq)

///|
pub fn SessionKey::new(value : String) -> SessionKey {
  { value, }
}

///|
pub fn SessionKey::to_string(self : SessionKey) -> String {
  self.value
}

///|
/// Severity attached to a structured decoder diagnostic.
pub(all) enum DiagnosticSeverity {
  Warning
  Error
} derive(Debug, Eq)

///|
/// Stable machine-readable diagnostic identifiers.
pub(all) enum DiagnosticCode {
  UnsupportedVersion
  InvalidMessageLength
  TrailingBytes
  TruncatedSetHeader
  InvalidSetLength
  SetExceedsMessage
  UnknownSetId
} derive(Debug, Eq)

///|
/// Protocol coordinates associated with a diagnostic when known.
pub(all) struct DiagnosticContext {
  session : SessionKey
  observation_domain_id : UInt?
  set_id : UInt?
} derive(Debug, Eq)

///|
/// A deterministic diagnostic with a byte offset into the supplied message.
pub(all) struct Diagnostic {
  code : DiagnosticCode
  severity : DiagnosticSeverity
  offset : Int
  context : DiagnosticContext
  message : String
} derive(Debug, Eq)

///|
/// RFC 7011 Message Header fields.
pub(all) struct MessageHeader {
  version : UInt
  length : Int
  export_time : UInt
  sequence_number : UInt
  observation_domain_id : UInt
} derive(Debug, Eq)

///|
/// Classification based only on the Set ID.
pub(all) enum SetKind {
  Template
  OptionsTemplate
  Data
  Unknown
} derive(Debug, Eq)

///|
/// Bounds-checked Set framing. Payload bytes are intentionally not interpreted
/// by this layer.
pub(all) struct SetSummary {
  set_id : UInt
  offset : Int
  length : Int
  payload_offset : Int
  payload_length : Int
  kind : SetKind
} derive(Debug, Eq)

///|
/// One completely framed IPFIX Message.
pub(all) struct DecodedMessage {
  session : SessionKey
  header : MessageHeader
  sets : Array[SetSummary]
  diagnostics : Array[Diagnostic]
} derive(Debug, Eq)

///|
/// Exact extent required before framing can make further progress.
pub(all) struct NeedMore {
  available : Int
  required : Int
} derive(Debug, Eq)

///|
/// Result of decoding one complete-message buffer.
pub(all) enum DecodeOutcome {
  Decoded(DecodedMessage)
  NeedMoreData(NeedMore)
  Rejected(Array[Diagnostic])
} derive(Debug, Eq)
