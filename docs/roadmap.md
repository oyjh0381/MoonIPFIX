# Roadmap

GitHub Issues labelled `ready-for-agent` are the maintained implementation specifications. Work should proceed in dependency order and produce meaningful, reviewable commits.

## v0.1 milestones

1. Safe wire cursor, Message/Set framing, and structured Diagnostics.
2. Information Element type model and reproducible IANA Registry Snapshot generation.
3. Template and Options Template parsing with Session/Observation Domain lifecycle.
4. Fixed, variable, Reduced-Size, Enterprise, and unknown field decoding.
5. Arbitrary-chunk `StreamDecoder` with complete-message equivalence.
6. Sequence audit, Template inspection, statistics, and resource limits.
7. Versioned JSONL adapter and Native `inspect`, `validate`, `templates`, and `stats` commands.
8. RFC vectors, corruption/property tests, cross-target evidence, benchmark, documentation, and release preparation.

## Post-v0.1 candidates

Each candidate requires a new specification and overlap review:

- RFC 6313 structured data.
- NetFlow v9 compatibility.
- Exporter encoding.
- Async online Collector adapter.
- Additional output and storage adapters.
