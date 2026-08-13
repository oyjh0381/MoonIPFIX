# Third-party notices

MoonIPFIX is an original implementation and does not copy or port an existing IPFIX library.

Normative and registry sources:

- RFC 7011, *Specification of the IP Flow Information Export (IPFIX) Protocol for the Exchange of Flow Information*, IETF Trust.
- RFC 7012, *Information Model for IP Flow Information Export (IPFIX)*, IETF Trust.
- IANA, *IP Flow Information Export (IPFIX) Entities*, including the IPFIX Information Elements registry. MoonIPFIX redistributes the interoperability metadata in `registry/data/ipfix-information-elements-2026-08-13.csv`, retrieved from <https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv> on 2026-08-13. SHA-256: `896357e0296d8541fa4b7e0afd2dce48b52562dcfdf5437ac36cea428ecdc930`.

The Registry Snapshot reflects the IANA registry state last updated 2026-07-22. `tools/generate_registry.py` deterministically derives the compact MoonBit table from the pinned CSV; CI rejects a stale generated file. Descriptions and RFC prose are deliberately omitted from generated source, retaining only identifiers and concise metadata needed for protocol interoperability.

Synthetic fixtures will be authored for this project. Any external packet or telemetry fixture added later must be documented here with its source, license, purpose, and redistribution status.

Any dependency added during implementation must be pinned in module metadata and documented here with its repository, version, license, and purpose.
