///|
/// Caller-supplied identity of one transport or exporter session.
///
/// MoonIPFIX never infers this value from packet bytes. Applications should use
/// a stable identity that separates template namespaces for distinct exporters.
pub struct SessionKey {
  value : String
} derive(Debug, Eq, Hash)

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
  InvalidTemplateId
  InvalidTemplateFieldCount
  InvalidFieldLength
  InvalidVariableLengthPrefix
  InvalidScopeFieldCount
  TruncatedTemplateRecord
  UnsupportedEnterpriseField
  UnsupportedVariableLengthField
  TemplateRecordTooLarge
  MissingTemplate
  IncompleteDataRecord
  InvalidFieldEncoding
  TemplateRedefined
  TemplateWithdrawalMissing
  TemplateWithdrawalIgnoredForUdp
  SequenceGap
  SequenceUnverifiable
  SessionLimitExceeded
  TemplateLimitExceeded
  FieldCountLimitExceeded
  FieldLengthLimitExceeded
  RecordLimitExceeded
  DiagnosticLimitExceeded
  StreamBufferLimitExceeded
  StreamBoundaryLost
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
  templates : Array[TemplateRecord]
  records : Array[DataRecord]
  lifecycle : Array[TemplateLifecycleEvent]
  mut sequence : SequenceAudit?
  mut statistics : MessageStatistics
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

///|
/// Full Template namespace required by RFC 7011.
pub(all) struct TemplateIdentity {
  session : SessionKey
  observation_domain_id : UInt
  template_id : UInt
} derive(Debug, Eq, Hash)

///|
/// One ordered field declaration from a Template Record.
pub(all) struct FieldSpecifier {
  identity : @registry.InformationElementIdentity
  length : Int
} derive(Debug, Eq)

///|
/// Validated fixed-length Template Record.
pub(all) struct TemplateRecord {
  identity : TemplateIdentity
  kind : TemplateKind
  fields : Array[FieldSpecifier]
  scope_fields : Array[FieldSpecifier]
  option_fields : Array[FieldSpecifier]
  /// Exact length for fixed Templates; -1 when any field is variable-length.
  record_length : Int
  /// Smallest possible encoded record, including variable-length prefixes.
  minimum_record_length : Int
  has_variable_length : Bool
} derive(Debug, Eq)

///|
pub(all) enum TemplateKind {
  Regular
  Options
} derive(Debug, Eq)

///|
pub(all) enum TemplateLifecycleAction {
  Installed
  Retransmitted
  Replaced
  Withdrawn
  WithdrawnAll
  WithdrawalMissing
  WithdrawalIgnored
  SessionReset
  DataSetUnresolved
} derive(Debug, Eq)

///|
/// Transport semantics relevant to RFC 7011 Template lifetime.
pub(all) enum TransportProtocol {
  Sctp
  Tcp
  Udp
} derive(Debug, Eq)

///|
/// Observable state transition caused by one Template management action.
pub(all) struct TemplateLifecycleEvent {
  action : TemplateLifecycleAction
  session : SessionKey
  observation_domain_id : UInt?
  template_id : UInt?
  template_kind : TemplateKind?
  affected : Int
  offset : Int?
} derive(Debug, Eq)

///|
pub(all) enum SequenceContinuity {
  Baseline
  Continuous
  Gap
  Unverifiable
} derive(Debug, Eq)

///|
/// Per-Message Sequence Number evidence. `missing` is the modulo-2^32 forward
/// distance from expected to observed and is present only for a detected gap.
pub(all) struct SequenceAudit {
  session : SessionKey
  observation_domain_id : UInt
  continuity : SequenceContinuity
  observed : UInt
  expected : UInt?
  missing : UInt?
  decoded_record_count : Int
  record_count_complete : Bool
  next_expected : UInt?
} derive(Debug, Eq)

///|
pub(all) struct MessageStatistics {
  message_count : Int
  set_count : Int
  template_count : Int
  lifecycle_count : Int
  record_count : Int
  field_count : Int
  diagnostic_count : Int
} derive(Debug, Eq)

///|
/// Typed values supported by the fixed-length decoding tracer bullet.
pub(all) enum FieldValue {
  Unsigned(UInt64)
  Signed(Int64)
  Float32(Float)
  Float64(Double)
  Boolean(Bool)
  MacAddress(Bytes)
  Ipv4Address(Bytes)
  Ipv6Address(Bytes)
  DateTimeSeconds(UInt)
  DateTimeMilliseconds(UInt64)
  DateTimeMicroseconds(UInt64)
  DateTimeNanoseconds(UInt64)
  String(String)
  Octets(Bytes)
} derive(Debug, Eq)

///|
pub(all) struct DecodedField {
  specifier : FieldSpecifier
  metadata : @registry.LookupResult
  /// Offset of the field value, after any variable-length prefix.
  offset : Int
  /// Actual value octets consumed for this record.
  encoded_length : Int
  value : FieldValue
} derive(Debug, Eq)

///|
pub(all) struct DataRecord {
  template : TemplateIdentity
  offset : Int
  fields : Array[DecodedField]
} derive(Debug, Eq)

///|
/// Stateful decoder retaining Templates between complete Messages.
pub struct Decoder {
  registry : @registry.Registry
  priv mut templates : @hashmap.HashMap[TemplateIdentity, TemplateRecord]
  session_transports : @hashmap.HashMap[SessionKey, TransportProtocol]
  priv mut sequence_state : @hashmap.HashMap[SequenceIdentity, UInt]
  priv mut active_sessions : @hashmap.HashMap[SessionKey, Unit]
  limits : DecoderLimits
}

///|
struct SequenceIdentity {
  session : SessionKey
  observation_domain_id : UInt
} derive(Debug, Eq, Hash)

///|
pub(all) struct DecoderLimits {
  max_sessions : Int
  max_templates_per_session : Int
  max_fields_per_template : Int
  max_field_length : Int
  max_records_per_message : Int
  max_diagnostics_per_message : Int
} derive(Debug, Eq)

///|
pub(all) enum LimitConfigError {
  NonPositive(String, Int)
  AboveHardCeiling(String, Int, Int)
} derive(Debug, Eq)

///|
/// Maximum retained incomplete-message bytes. A valid IPFIX Message can be at
/// most 65535 octets because its wire Length is unsigned 16-bit.
pub(all) struct StreamDecoderConfig {
  max_buffered_bytes : Int
} derive(Debug, Eq)

///|
pub(all) enum StreamConfigError {
  MaxBufferedBytesBelowHeader(Int)
  MaxBufferedBytesAboveProtocolMaximum(Int)
} derive(Debug, Eq)

///|
pub(all) enum StreamConstructionError {
  StreamConfig(StreamConfigError)
  DecoderConfig(LimitConfigError)
} derive(Debug, Eq)

///|
/// Outcomes completed by one push plus the exact pending extent, if any.
pub(all) struct StreamBatch {
  outcomes : Array[DecodeOutcome]
  need_more : NeedMore?
  buffered : Int
} derive(Debug, Eq)

///|
pub(all) enum StreamEnd {
  Complete
  Truncated(NeedMore)
  BoundaryLost
} derive(Debug, Eq)

///|
/// Stateful arbitrary-chunk adapter over the complete-message Decoder.
pub struct StreamDecoder {
  decoder : Decoder
  session : SessionKey
  config : StreamDecoderConfig
  priv mut buffer : Array[Byte]
  priv mut boundary_lost : Bool
}
