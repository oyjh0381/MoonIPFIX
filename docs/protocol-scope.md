# Protocol scope

## Normative baseline

MoonIPFIX v0.1 implements the decoding and Template-state portions of:

- [RFC 7011](https://www.rfc-editor.org/info/rfc7011/) — IPFIX Message, Set, Template, Options Template, Data Record, transport-session state, sequence semantics, and withdrawal behavior.
- [RFC 7012](https://www.rfc-editor.org/info/rfc7012/) — Information Element types and interpretation model.
- [IANA IPFIX Information Elements](https://www.iana.org/assignments/ipfix/ipfix.xhtml) — normative standard Information Element metadata. The baseline observed registry update date is 2026-07-22.

Verified RFC errata that affect encoded behavior will be documented with the implementation and tests. The checked-in Registry Snapshot will include its retrieval date and digest so builds do not depend on live network access.

## Included in v0.1

- IPFIX version 10 Message Header and declared Message length.
- Template Set ID 2, Options Template Set ID 3, and Data Set IDs 256–65535.
- Fixed-length and variable-length fields.
- Reduced-Size Encoding for eligible Information Element types.
- Enterprise bit and Private Enterprise Number handling.
- Template definition, replacement, withdrawal, Session reset, and Observation Domain scoping.
- Data Record boundaries, Set padding validation, unknown Template Diagnostics, and sequence continuity.
- Standard scalar types defined by the v0.1 information-model scope, with raw-byte preservation when a value cannot be interpreted safely.
- Unknown standard and Enterprise Information Elements retained without data loss.

## Explicitly excluded from v0.1

- NetFlow v9 compatibility.
- RFC 6313 `basicList`, `subTemplateList`, and `subTemplateMultiList` value decoding.
- Exporter encoding.
- UDP, TCP, or SCTP listening and online Collector lifecycle.
- Packet capture, packet protocol dissection, flow derivation, persistence, queries, dashboards, and visualization.
- Runtime download of IANA registry data.

## Transport lifecycle input

The portable decoder does not infer transport type from a Session Key. Sessions use reliable-transport (TCP/SCTP) Template Withdrawal semantics by default. A caller processing UDP exports must call `Decoder::set_session_transport(session, TransportProtocol::Udp)`; MoonIPFIX will then report and ignore Template Withdrawal records as required by RFC 7011 section 8.4. `Decoder::reset_session` removes only the selected Session's retained state.

Excluded capabilities may be proposed as separate milestones only after the v0.1 decoding contract is complete and verified.
