///|
test "pinned IANA snapshot resolves representative standard metadata" {
  assert_eq(
    iana_source_url, "https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv",
  )
  assert_eq(iana_retrieved_on, "2026-08-13")
  assert_eq(
    iana_sha256, "896357e0296d8541fa4b7e0afd2dce48b52562dcfdf5437ac36cea428ecdc930",
  )
  assert_eq(iana_entry_count, 502)
  let registry = Registry::standard()
  match registry.lookup(InformationElementIdentity::standard(8U)) {
    Resolved(metadata) => {
      assert_eq(metadata.name, "sourceIPv4Address")
      assert_eq(metadata.abstract_data_type, AbstractDataType::Ipv4Address)
      assert_eq(metadata.semantics, Some("default"))
      assert_eq(metadata.units, None)
      assert_eq(metadata.status, RegistryStatus::Current)
      assert_eq(metadata.canonical_length, Some(4))
    }
    _ => fail("IANA IE 8 must be present in the pinned snapshot")
  }
  match registry.lookup(InformationElementIdentity::standard(34U)) {
    Resolved(metadata) => {
      assert_eq(metadata.name, "samplingInterval")
      assert_eq(metadata.status, RegistryStatus::Deprecated)
    }
    _ => fail("deprecated IANA entries remain resolvable")
  }
  match registry.lookup(InformationElementIdentity::standard(515U)) {
    Resolved(metadata) => {
      assert_eq(metadata.name, "ipv6ExtensionHeadersFull")
      assert_eq(metadata.abstract_data_type, AbstractDataType::Unsigned256)
      assert_eq(metadata.canonical_length, Some(32))
    }
    _ => fail("post-RFC 7012 IANA entries must come from the pinned snapshot")
  }
}

///|
test "caller Enterprise metadata extends but cannot replace IANA metadata" {
  let identity = InformationElementIdentity::enterprise(32473U, 7U)
  let custom : ElementMetadata = {
    identity,
    name: "vendorQueueDepth",
    abstract_data_type: AbstractDataType::Unsigned32,
    semantics: Some("quantity"),
    units: Some("entries"),
    status: RegistryStatus::Current,
    canonical_length: Some(4),
  }
  match Registry::with_enterprise([custom]) {
    Ok(registry) => {
      match registry.lookup(identity) {
        Resolved(metadata) => assert_eq(metadata, custom)
        _ => fail("caller Enterprise metadata must resolve")
      }
      match registry.lookup(InformationElementIdentity::standard(4U)) {
        Resolved(metadata) => assert_eq(metadata.name, "protocolIdentifier")
        _ => fail("adding Enterprise metadata must retain IANA entries")
      }
    }
    Err(_) => fail("valid Enterprise metadata must be accepted")
  }
}

///|
test "unknown identities remain lossless and duplicates are rejected" {
  let registry = Registry::standard()
  let unknown_standard = InformationElementIdentity::standard(32767U)
  let unknown_enterprise = InformationElementIdentity::enterprise(
    4_294_967_295U, 32767U,
  )
  assert_eq(registry.lookup(unknown_standard), Unresolved(unknown_standard))
  assert_eq(registry.lookup(unknown_enterprise), Unresolved(unknown_enterprise))

  let identity = InformationElementIdentity::enterprise(32473U, 9U)
  let metadata : ElementMetadata = {
    identity,
    name: "duplicate",
    abstract_data_type: AbstractDataType::OctetArray,
    semantics: None,
    units: None,
    status: RegistryStatus::Current,
    canonical_length: None,
  }
  assert_eq(
    Registry::with_enterprise([metadata, metadata]),
    Err(RegistryError::DuplicateIdentity(identity)),
  )
  let standard_metadata : ElementMetadata = {
    ..metadata,
    identity: InformationElementIdentity::standard(8U),
  }
  assert_eq(
    Registry::with_enterprise([standard_metadata]),
    Err(
      RegistryError::StandardIdentityReserved(
        InformationElementIdentity::standard(8U),
      ),
    ),
  )
}
