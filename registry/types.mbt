///|
/// Lossless IPFIX Information Element identity. Enterprise number zero denotes
/// the standard IANA namespace.
#derive(Debug, Eq)
pub(all) struct InformationElementIdentity {
  enterprise_number : UInt32
  element_id : UInt32
}

///|
pub fn InformationElementIdentity::standard(
  element_id : UInt32,
) -> InformationElementIdentity {
  { enterprise_number: 0U, element_id, }
}

///|
pub fn InformationElementIdentity::enterprise(
  enterprise_number : UInt32,
  element_id : UInt32,
) -> InformationElementIdentity {
  { enterprise_number, element_id, }
}

///|
/// RFC 7012/IANA abstract data types used to interpret field octets.
#derive(Debug, Eq)
pub(all) enum AbstractDataType {
  OctetArray
  Unsigned8
  Unsigned16
  Unsigned32
  Unsigned64
  Unsigned256
  Signed8
  Signed16
  Signed32
  Signed64
  Float32
  Float64
  Boolean
  MacAddress
  String
  DateTimeSeconds
  DateTimeMilliseconds
  DateTimeMicroseconds
  DateTimeNanoseconds
  Ipv4Address
  Ipv6Address
  BasicList
  SubTemplateList
  SubTemplateMultiList
  Unknown(String)
}

///|
#derive(Debug, Eq)
pub(all) enum RegistryStatus {
  Current
  Deprecated
  Unknown(String)
}

///|
/// Metadata sufficient for wire decoding and stable presentation.
#derive(Debug, Eq)
pub(all) struct ElementMetadata {
  identity : InformationElementIdentity
  name : String
  abstract_data_type : AbstractDataType
  semantics : String?
  units : String?
  status : RegistryStatus
  canonical_length : Int32?
}

///|
/// Lookup never fabricates metadata for unknown identities.
#derive(Debug, Eq)
pub(all) enum LookupResult {
  Resolved(ElementMetadata)
  Unresolved(InformationElementIdentity)
}

///|
#derive(Debug, Eq)
pub(all) enum RegistryError {
  StandardIdentityReserved(InformationElementIdentity)
  DuplicateIdentity(InformationElementIdentity)
}

///|
/// Standard IANA metadata plus a defensive copy of caller Enterprise metadata.
#derive(Debug, Eq)
pub struct Registry {
  enterprise_metadata : Array[ElementMetadata]
}

///|
pub extend AbstractDataType with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend AbstractDataType with Eq::{not_equal, equal}

///|
pub extend ElementMetadata with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend ElementMetadata with Eq::{not_equal, equal}

///|
pub extend InformationElementIdentity with @moonbitlang/core/debug.Debug::{
  to_repr,
}

///|
pub extend InformationElementIdentity with Eq::{not_equal, equal}

///|
pub extend LookupResult with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend LookupResult with Eq::{not_equal, equal}

///|
pub extend Registry with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend Registry with Eq::{not_equal, equal}

///|
pub extend RegistryError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend RegistryError with Eq::{not_equal, equal}

///|
pub extend RegistryStatus with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend RegistryStatus with Eq::{not_equal, equal}
