///|
test "design baseline publishes the protocol identity" {
  inspect(library_version, content="0.1.0-dev")
  inspect(ipfix_version, content="10")
}
