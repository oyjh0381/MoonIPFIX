///|
pub fn Registry::standard() -> Registry {
  { enterprise_metadata: [] }
}

///|
/// Build a registry extended with caller-owned Enterprise metadata.
/// Standard identities cannot be replaced, and duplicate Enterprise identities
/// are rejected deterministically before the registry becomes observable.
pub fn Registry::with_enterprise(
  metadata : Array[ElementMetadata],
) -> Result[Registry, RegistryError] {
  let owned : Array[ElementMetadata] = []
  for candidate in metadata {
    if candidate.identity.enterprise_number == 0U {
      return Err(RegistryError::StandardIdentityReserved(candidate.identity))
    }
    for existing in owned {
      if existing.identity == candidate.identity {
        return Err(RegistryError::DuplicateIdentity(candidate.identity))
      }
    }
    owned.push(candidate)
  }
  Ok({ enterprise_metadata: owned })
}

///|
/// Resolve standard metadata in O(log n) and caller Enterprise metadata in
/// O(e), where e is the explicitly supplied extension count.
pub fn Registry::lookup(
  self : Registry,
  identity : InformationElementIdentity,
) -> LookupResult {
  if identity.enterprise_number == 0U {
    lookup_standard(identity)
  } else {
    for metadata in self.enterprise_metadata {
      if metadata.identity == identity {
        return Resolved(metadata)
      }
    }
    Unresolved(identity)
  }
}

///|
fn lookup_standard(identity : InformationElementIdentity) -> LookupResult {
  let mut low = 0
  let mut high = iana_entries.length()
  while low < high {
    let middle = low + (high - low) / 2
    let candidate = iana_entries[middle]
    if candidate.identity.element_id < identity.element_id {
      low = middle + 1
    } else {
      high = middle
    }
  }
  if low < iana_entries.length() &&
    iana_entries[low].identity.element_id == identity.element_id {
    Resolved(iana_entries[low])
  } else {
    Unresolved(identity)
  }
}
