///|
/// Lossless IPFIX Information Element identity. Enterprise number zero denotes
/// the standard IANA namespace.
pub(all) struct InformationElementIdentity {
  enterprise_number : UInt
  element_id : UInt
} derive(Debug, Eq)

///|
pub fn InformationElementIdentity::standard(
  element_id : UInt,
) -> InformationElementIdentity {
  { enterprise_number: 0U, element_id }
}

///|
pub fn InformationElementIdentity::enterprise(
  enterprise_number : UInt,
  element_id : UInt,
) -> InformationElementIdentity {
  { enterprise_number, element_id }
}

///|
/// RFC 7012/IANA abstract data types used to interpret field octets.
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
} derive(Debug, Eq)

///|
pub(all) enum RegistryStatus {
  Current
  Deprecated
  Unknown(String)
} derive(Debug, Eq)

///|
/// Metadata sufficient for wire decoding and stable presentation.
pub(all) struct ElementMetadata {
  identity : InformationElementIdentity
  name : String
  abstract_data_type : AbstractDataType
  semantics : String?
  units : String?
  status : RegistryStatus
  canonical_length : Int?
} derive(Debug, Eq)

///|
/// Lookup never fabricates metadata for unknown identities.
pub(all) enum LookupResult {
  Resolved(ElementMetadata)
  Unresolved(InformationElementIdentity)
} derive(Debug, Eq)

///|
pub(all) enum RegistryError {
  StandardIdentityReserved(InformationElementIdentity)
  DuplicateIdentity(InformationElementIdentity)
} derive(Debug, Eq)

///|
/// Standard IANA metadata plus a defensive copy of caller Enterprise metadata.
pub struct Registry {
  enterprise_metadata : Array[ElementMetadata]
} derive(Debug, Eq)
