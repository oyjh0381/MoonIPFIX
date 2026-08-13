# Version JSONL separately from typed field values

Decoded values remain MoonBit algebraic data rather than JSON-shaped protocol state, and the `jsonl` Module publishes a separate schema-versioned Output Record adapter. This avoids JSON integer and byte-representation constraints leaking into decoding while giving CLI consumers a stable streaming contract on stdout and human Diagnostics on stderr.
