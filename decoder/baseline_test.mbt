///|
test "design baseline publishes the protocol identity" {
  inspect(@decoder.library_version, content="0.1.0-dev")
  inspect(@decoder.ipfix_version, content="10")
}
