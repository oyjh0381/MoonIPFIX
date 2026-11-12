///|
test "design baseline pins the registry source" {
  inspect(@registry.iana_snapshot_date, content="2026-07-22")
  inspect(
    @registry.iana_registry_url,
    content="https://www.iana.org/assignments/ipfix/ipfix.xhtml",
  )
}
