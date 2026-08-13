# MoonBit ecosystem overlap review

Review date: 2026-08-13.

MoonIPFIX was selected after checking the official [Mooncakes registry](https://mooncakes.io/), [Awesome MoonBit](https://github.com/moonbitlang/awesome-moonbit), and GitHub repository and MoonBit source-code search.

## Result

- `MoonIPFIX` repository-name search returned no existing repository.
- `IPFIX language:MoonBit` and `NetFlow language:MoonBit` returned no repositories.
- MoonBit code searches for NetFlow, RFC 7011, and RFC 7012 returned no implementation; IPFIX text matches were unrelated MIME/test data.
- The Mooncakes package index contained no `moonipfix`, `ipfix`, `netflow`, `rfc7011`, or `rfc7012` entry.
- The intended repository name `oyjh0381/MoonIPFIX` was unoccupied at review time.

These are time-bounded search results, not a claim that private or future projects cannot exist. The registry and GitHub searches must be repeated before application submission and first release.

## Nearest public project

[MoonCap](https://github.com/usagi-star/mooncap) reads PCAP/PCAPNG captures and decodes link, IP, transport, and selected application protocols. Its flow-related behavior is derived from observed packets.

MoonIPFIX instead consumes IPFIX export Messages after an Exporting Process has already metered and aggregated flows. Its defining work is dynamic Template state, Observation Domain and Transport Session scope, Information Element interpretation, Template Withdrawal, Sequence Number audit, and safe record decoding. It does not read PCAP or derive flows from packets.

## Excluded crowded directions

The selection also explicitly avoids the mature or crowded MoonBit areas that caused the rejected MoonLab proposal or presented similar overlap risk: deterministic simulation, Actor runtimes, generic EventBus frameworks, JSON Schema/API validators, audio codecs, LSP, graph layout, generic web frameworks, databases, compression, CRDT/causal tooling, and OCI tooling.
