# MoonIPFIX

MoonIPFIX is an original Apache-2.0 MoonBit library for decoding and auditing template-driven IP Flow Information Export (IPFIX) telemetry. It targets applications that need to consume exporter-produced IPFIX Messages without embedding a network collector, packet-capture parser, database, or visualization system.

The project is currently at its design-baseline stage. The repository establishes the protocol scope, domain language, public Module seams, safety model, testing strategy, and implementation roadmap before protocol implementation begins.

## Planned v0.1 scope

- Decode RFC 7011 Message headers, Template Sets, Options Template Sets, Data Sets, and Data Records.
- Maintain Template state by caller-provided Session Key, Observation Domain ID, and Template ID.
- Support fixed-length and variable-length fields, Reduced-Size Encoding, Template Withdrawal, and Enterprise Information Elements.
- Interpret standard Information Elements from a reproducible IANA registry snapshot while preserving unknown fields without data loss.
- Expose both complete-message decoding and arbitrary-chunk streaming through one shared decoding implementation.
- Return typed field values and structured Diagnostics with exact input offsets.
- Enforce configurable limits for buffered bytes, sessions, Templates, fields, records, and Diagnostics.
- Provide a Native `moonipfix` CLI with `inspect`, `validate`, `templates`, and `stats` commands and versioned JSONL output.

## Public Module seams

- `decoder` owns complete-message and streaming decoding, Template lifecycle, typed records, configuration, and Diagnostics.
- `registry` owns the pinned IANA Information Element metadata and caller-supplied Enterprise metadata.
- `jsonl` owns the stable, versioned machine-output contract.
- `cmd/moonipfix` is the Native file/stdin and terminal adapter.

Wire readers, Template storage mechanics, and recovery details remain implementation-internal. Tests and callers use the same public Interfaces.

## Baseline verification

Install the current MoonBit toolchain and run:

```sh
moon fmt --check
moon check --target all --deny-warn
moon test --target wasm-gc --deny-warn
moon test --target js --deny-warn
moon test --target native --deny-warn
moon run cmd/moonipfix --target native -- version
```

## Standards and project boundaries

MoonIPFIX v0.1 is based on [RFC 7011](https://www.rfc-editor.org/info/rfc7011/), [RFC 7012](https://www.rfc-editor.org/info/rfc7012/), and the [IANA IPFIX Information Elements registry](https://www.iana.org/assignments/ipfix/ipfix.xhtml). See [protocol scope](docs/protocol-scope.md), [architecture](docs/architecture.md), [testing strategy](docs/testing.md), [security model](docs/security.md), and [ecosystem comparison](docs/ecosystem-review.md).

The first release does not implement an online Collector, Exporter encoding, NetFlow v9, RFC 6313 structured data, storage, or visualization. These are intentionally separate future decisions.

MoonIPFIX is not a packet-capture decoder. Projects such as MoonCap decode PCAP/PCAPNG packets and derive packet-level flows; MoonIPFIX consumes exporter-produced IPFIX Messages whose Data Records are interpreted through dynamic Templates.

## License

Source code is licensed under the [Apache License 2.0](LICENSE). Standards, registry data, generated artifacts, dependencies, and test-material provenance are tracked in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
