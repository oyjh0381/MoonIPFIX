///|
fn main {
  let bytes = b"\x00\x0a\x00\x1c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x2a\x00\x02\x00\x0c\x01\x00\x00\x01\x00\x08\x00\x04"
  let decoder = @decoder.Decoder::new()
  match decoder.decode_message(bytes, @decoder.SessionKey::new("example")) {
    Decoded(message) =>
      for line in @jsonl.encode_message(message) {
        println(line)
      }
    NeedMoreData(need) =>
      println("need \{need.required - need.available} more bytes")
    Rejected(diagnostics) =>
      for diagnostic in diagnostics {
        println(@jsonl.encode_diagnostic(diagnostic))
      }
  }
}
