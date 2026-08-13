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

The design baseline exposes three public Module seams: `decoder` for complete-message and streaming behavior, `registry` for Information Element metadata, and `jsonl` for the versioned machine-output contract. Protocol implementation will proceed through the dependency-ordered GitHub specification.
