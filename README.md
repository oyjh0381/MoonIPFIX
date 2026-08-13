# MoonIPFIX

MoonIPFIX is an original Apache-2.0 MoonBit library and Native CLI for RFC 7011 IPFIX telemetry. It decodes Template/Options Template/Data Sets, maintains Session and Observation Domain state, audits Sequence Numbers, preserves unknown and Enterprise fields, and emits lossless schema-v1 JSONL.

Unlike MoonCap-style PCAP decoders, MoonIPFIX consumes exporter-aggregated IPFIX Messages and interprets Data Records through dynamic Templates. It does not capture packets, derive flows, listen on sockets, persist data, implement NetFlow v9, or decode RFC 6313 structured lists.

## Try it

```sh
moon run examples/library_decode
python tools/make_example_stream.py
moon run cmd/moonipfix --target native -- inspect .scratch/example.ipfix
moon run cmd/moonipfix --target native -- templates .scratch/example.ipfix
moon run cmd/moonipfix --target native -- stats .scratch/example.ipfix
```

`FILE` may be `-` for stdin. Add `--session KEY` to define the Template namespace and `--deny-warnings` to make warnings exit with code 3. See [CLI contract](docs/cli.md), [JSONL schema](docs/jsonl-schema.md), [field decoding](docs/field-decoding.md), [streaming](docs/streaming.md), [limits](docs/resource-limits.md), and [protocol scope](docs/protocol-scope.md).

## Library

Use `decoder::Decoder` for complete Messages or `decoder::StreamDecoder` for arbitrary chunks. Both share transactional Template/Sequence state. `registry::Registry::with_enterprise` adds caller-owned Enterprise metadata; unresolved identities remain raw. `jsonl::encode_message` creates deterministic single-line records.

## Verify and benchmark

```sh
python tools/generate_registry.py --check
moon fmt --check
moon check --target all --deny-warn
moon test --target wasm-gc --deny-warn
moon test --target js --deny-warn
moon test --target native --deny-warn
python tools/test_cli.py
python tools/benchmark_100k.py
```

CI runs on Ubuntu, macOS, and Windows. Tests include RFC-shaped vectors, lifecycle matrices, limits, every split point, 64 replayable generated streams, 40 mutations, JSONL goldens, and process exit contracts.

## Provenance and license

The implementation is original, based on public [RFC 7011](https://www.rfc-editor.org/info/rfc7011/), [RFC 7012](https://www.rfc-editor.org/info/rfc7012/), and a pinned [IANA IE registry](https://www.iana.org/assignments/ipfix/ipfix.xhtml). See [ecosystem review](docs/ecosystem-review.md), [test provenance](docs/test-provenance.md), and [third-party notices](THIRD_PARTY_NOTICES.md). Licensed under [Apache-2.0](LICENSE).
