# `oyjh0381/moonipfix`

MoonIPFIX provides template-driven IPFIX flow telemetry decoding and auditing for MoonBit.

```moonbit check
test {
  inspect(@decoder.library_version, content="0.1.0-dev")
  inspect(@decoder.ipfix_version, content="10")
  inspect(@registry.iana_snapshot_date, content="2026-07-22")
  inspect(@jsonl.schema_version, content="1")
}
```

Use `@decoder.Decoder::new()` for complete Messages, `@decoder.StreamDecoder::new(session)` for arbitrary chunks, `@registry.Registry::with_enterprise` for caller metadata, and `@jsonl.encode_message` for schema-v1 output. Runnable code is in `examples/library_decode`.
