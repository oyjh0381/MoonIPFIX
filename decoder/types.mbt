///|
/// Caller-supplied identity of one transport or exporter session.
///
/// MoonIPFIX never infers this value from packet bytes. Applications should use
/// a stable identity that separates template namespaces for distinct exporters.
#derive(Debug, Eq, Hash)
pub struct SessionKey {
  value : String
}

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
#derive(Debug, Eq)
pub(all) enum DiagnosticSeverity {
  Warning
  Error
}

///|
/// Stable machine-readable diagnostic identifiers.
#derive(Debug, Eq)
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
}

///|
/// Protocol coordinates associated with a diagnostic when known.
#derive(Debug, Eq)
pub(all) struct DiagnosticContext {
  session : SessionKey
  observation_domain_id : UInt32?
  set_id : UInt32?
}

///|
/// A deterministic diagnostic with a byte offset into the supplied message.
#derive(Debug, Eq)
pub(all) struct Diagnostic {
  code : DiagnosticCode
  severity : DiagnosticSeverity
  offset : Int32
  context : DiagnosticContext
  message : String
}

///|
/// RFC 7011 Message Header fields.
#derive(Debug, Eq)
pub(all) struct MessageHeader {
  version : UInt32
  length : Int32
  export_time : UInt32
  sequence_number : UInt32
  observation_domain_id : UInt32
}

///|
/// Classification based only on the Set ID.
#derive(Debug, Eq)
pub(all) enum SetKind {
  Template
  OptionsTemplate
  Data
  Unknown
}

///|
/// Bounds-checked Set framing. Payload bytes are intentionally not interpreted
/// by this layer.
#derive(Debug, Eq)
pub(all) struct SetSummary {
  set_id : UInt32
  offset : Int32
  length : Int32
  payload_offset : Int32
  payload_length : Int32
  kind : SetKind
}

///|
/// One completely framed IPFIX Message.
#derive(Debug, Eq)
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
}

///|
/// Exact extent required before framing can make further progress.
#derive(Debug, Eq)
pub(all) struct NeedMore {
  available : Int32
  required : Int32
}

///|
/// Result of decoding one complete-message buffer.
#derive(Debug, Eq)
pub(all) enum DecodeOutcome {
  Decoded(DecodedMessage)
  NeedMoreData(NeedMore)
  Rejected(Array[Diagnostic])
}

///|
/// Full Template namespace required by RFC 7011.
#derive(Debug, Eq, Hash)
pub(all) struct TemplateIdentity {
  session : SessionKey
  observation_domain_id : UInt32
  template_id : UInt32
}

///|
/// One ordered field declaration from a Template Record.
#derive(Debug, Eq)
pub(all) struct FieldSpecifier {
  identity : @registry.InformationElementIdentity
  length : Int32
}

///|
/// Validated fixed-length Template Record.
#derive(Debug, Eq)
pub(all) struct TemplateRecord {
  identity : TemplateIdentity
  kind : TemplateKind
  fields : Array[FieldSpecifier]
  scope_fields : Array[FieldSpecifier]
  option_fields : Array[FieldSpecifier]
  /// Exact length for fixed Templates; -1 when any field is variable-length.
  record_length : Int32
  /// Smallest possible encoded record, including variable-length prefixes.
  minimum_record_length : Int32
  has_variable_length : Bool
}

///|
#derive(Debug, Eq)
pub(all) enum TemplateKind {
  Regular
  Options
}

///|
#derive(Debug, Eq)
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
}

///|
/// Transport semantics relevant to RFC 7011 Template lifetime.
#derive(Debug, Eq)
pub(all) enum TransportProtocol {
  Sctp
  Tcp
  Udp
}

///|
/// Observable state transition caused by one Template management action.
#derive(Debug, Eq)
pub(all) struct TemplateLifecycleEvent {
  action : TemplateLifecycleAction
  session : SessionKey
  observation_domain_id : UInt32?
  template_id : UInt32?
  template_kind : TemplateKind?
  affected : Int32
  offset : Int32?
}

///|
#derive(Debug, Eq)
pub(all) enum SequenceContinuity {
  Baseline
  Continuous
  Gap
  Unverifiable
}

///|
/// Per-Message Sequence Number evidence. `missing` is the modulo-2^32 forward
/// distance from expected to observed and is present only for a detected gap.
#derive(Debug, Eq)
pub(all) struct SequenceAudit {
  session : SessionKey
  observation_domain_id : UInt32
  continuity : SequenceContinuity
  observed : UInt32
  expected : UInt32?
  missing : UInt32?
  decoded_record_count : Int32
  record_count_complete : Bool
  next_expected : UInt32?
}

///|
#derive(Debug, Eq)
pub(all) struct MessageStatistics {
  message_count : Int32
  set_count : Int32
  template_count : Int32
  lifecycle_count : Int32
  record_count : Int32
  field_count : Int32
  diagnostic_count : Int32
}

///|
/// Typed values supported by the fixed-length decoding tracer bullet.
#derive(Debug, Eq)
pub(all) enum FieldValue {
  Unsigned(UInt64)
  Signed(Int64)
  Float32(Float)
  Float64(Double)
  Boolean(Bool)
  MacAddress(Bytes)
  Ipv4Address(Bytes)
  Ipv6Address(Bytes)
  DateTimeSeconds(UInt32)
  DateTimeMilliseconds(UInt64)
  DateTimeMicroseconds(UInt64)
  DateTimeNanoseconds(UInt64)
  String(String)
  Octets(Bytes)
}

///|
#derive(Debug, Eq)
pub(all) struct DecodedField {
  specifier : FieldSpecifier
  metadata : @registry.LookupResult
  /// Offset of the field value, after any variable-length prefix.
  offset : Int32
  /// Actual value octets consumed for this record.
  encoded_length : Int32
  value : FieldValue
}

///|
#derive(Debug, Eq)
pub(all) struct DataRecord {
  template : TemplateIdentity
  offset : Int32
  fields : Array[DecodedField]
}

///|
/// Stateful decoder retaining Templates between complete Messages.
pub struct Decoder {
  registry : @registry.Registry
  priv mut templates : @hashmap.HashMap[TemplateIdentity, TemplateRecord]
  session_transports : @hashmap.HashMap[SessionKey, TransportProtocol]
  priv mut sequence_state : @hashmap.HashMap[SequenceIdentity, UInt32]
  priv mut active_sessions : @hashmap.HashMap[SessionKey, Unit]
  limits : DecoderLimits
}

///|
#derive(Debug, Eq, Hash)
struct SequenceIdentity {
  session : SessionKey
  observation_domain_id : UInt32
}

///|
#derive(Debug, Eq)
pub(all) struct DecoderLimits {
  max_sessions : Int32
  max_templates_per_session : Int32
  max_fields_per_template : Int32
  max_field_length : Int32
  max_records_per_message : Int32
  max_diagnostics_per_message : Int32
}

///|
#derive(Debug, Eq)
pub(all) enum LimitConfigError {
  NonPositive(String, Int32)
  AboveHardCeiling(String, Int32, Int32)
}

///|
/// Maximum retained incomplete-message bytes. A valid IPFIX Message can be at
/// most 65535 octets because its wire Length is unsigned 16-bit.
#derive(Debug, Eq)
pub(all) struct StreamDecoderConfig {
  max_buffered_bytes : Int32
}

///|
#derive(Debug, Eq)
pub(all) enum StreamConfigError {
  MaxBufferedBytesBelowHeader(Int32)
  MaxBufferedBytesAboveProtocolMaximum(Int32)
}

///|
#derive(Debug, Eq)
pub(all) enum StreamConstructionError {
  StreamConfig(StreamConfigError)
  DecoderConfig(LimitConfigError)
}

///|
/// Outcomes completed by one push plus the exact pending extent, if any.
#derive(Debug, Eq)
pub(all) struct StreamBatch {
  outcomes : Array[DecodeOutcome]
  need_more : NeedMore?
  buffered : Int32
}

///|
#derive(Debug, Eq)
pub(all) enum StreamEnd {
  Complete
  Truncated(NeedMore)
  BoundaryLost
}

///|
/// Stateful arbitrary-chunk adapter over the complete-message Decoder.
pub struct StreamDecoder {
  decoder : Decoder
  session : SessionKey
  config : StreamDecoderConfig
  priv mut buffer : Array[Byte]
  priv mut boundary_lost : Bool
}

///|
pub extend DataRecord with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend DataRecord with Eq::{not_equal, equal}

///|
pub extend DecodeOutcome with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend DecodeOutcome with Eq::{not_equal, equal}

///|
pub extend DecodedField with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend DecodedField with Eq::{not_equal, equal}

///|
pub extend DecodedMessage with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend DecodedMessage with Eq::{not_equal, equal}

///|
pub extend DecoderLimits with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend DecoderLimits with Eq::{not_equal, equal}

///|
pub extend Diagnostic with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend Diagnostic with Eq::{not_equal, equal}

///|
pub extend DiagnosticCode with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend DiagnosticCode with Eq::{not_equal, equal}

///|
pub extend DiagnosticContext with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend DiagnosticContext with Eq::{not_equal, equal}

///|
pub extend DiagnosticSeverity with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend DiagnosticSeverity with Eq::{not_equal, equal}

///|
pub extend FieldSpecifier with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend FieldSpecifier with Eq::{not_equal, equal}

///|
pub extend FieldValue with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend FieldValue with Eq::{not_equal, equal}

///|
pub extend LimitConfigError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend LimitConfigError with Eq::{not_equal, equal}

///|
pub extend MessageHeader with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend MessageHeader with Eq::{not_equal, equal}

///|
pub extend MessageStatistics with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend MessageStatistics with Eq::{not_equal, equal}

///|
pub extend NeedMore with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend NeedMore with Eq::{not_equal, equal}

///|
pub extend SequenceAudit with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SequenceAudit with Eq::{not_equal, equal}

///|
pub extend SequenceContinuity with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SequenceContinuity with Eq::{not_equal, equal}

///|
pub extend SequenceIdentity with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SequenceIdentity with Eq::{not_equal, equal}

///|
pub extend SequenceIdentity with Hash::{hash, hash_combine}

///|
pub extend SessionKey with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SessionKey with Eq::{not_equal, equal}

///|
pub extend SessionKey with Hash::{hash, hash_combine}

///|
pub extend SetKind with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SetKind with Eq::{not_equal, equal}

///|
pub extend SetSummary with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SetSummary with Eq::{not_equal, equal}

///|
pub extend StreamBatch with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend StreamBatch with Eq::{not_equal, equal}

///|
pub extend StreamConfigError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend StreamConfigError with Eq::{not_equal, equal}

///|
pub extend StreamConstructionError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend StreamConstructionError with Eq::{not_equal, equal}

///|
pub extend StreamDecoderConfig with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend StreamDecoderConfig with Eq::{not_equal, equal}

///|
pub extend StreamEnd with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend StreamEnd with Eq::{not_equal, equal}

///|
pub extend TemplateIdentity with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend TemplateIdentity with Eq::{not_equal, equal}

///|
pub extend TemplateIdentity with Hash::{hash, hash_combine}

///|
pub extend TemplateKind with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend TemplateKind with Eq::{not_equal, equal}

///|
pub extend TemplateLifecycleAction with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend TemplateLifecycleAction with Eq::{not_equal, equal}

///|
pub extend TemplateLifecycleEvent with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend TemplateLifecycleEvent with Eq::{not_equal, equal}

///|
pub extend TemplateRecord with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend TemplateRecord with Eq::{not_equal, equal}

///|
pub extend TransportProtocol with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend TransportProtocol with Eq::{not_equal, equal}
