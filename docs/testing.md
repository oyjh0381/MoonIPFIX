# Testing strategy

Tests enter at the highest stable seam: `decoder` for protocol behavior, `registry` for metadata resolution, `jsonl` for the machine contract, and the Native CLI for process-level behavior. Tests assert observable results, state transitions, Diagnostics, offsets, JSONL, stderr, and exit classification rather than internal cursor or map representation.

## Evidence matrix

- Hand-authored byte vectors derived from RFC formats for Message, Template, Options Template, variable-length, Reduced-Size, Enterprise, withdrawal, and padding behavior.
- Every-prefix truncation tests that distinguish `Need More Data` from invalid complete Messages.
- Corruption matrices for lengths, Set IDs, Template field counts, variable-length prefixes, arithmetic overflow, illegal encodings, and trailing bytes.
- Template lifecycle tests across Sessions, Observation Domains, replacement, withdrawal, reset, unknown Templates, and interleaved Messages.
- Sequence Number tests based on exported Data Record counts, including gaps, wraparound, and messages without Data Records.
- Property and mutation tests that generate valid Template/Data pairs, split them at arbitrary chunk boundaries, and verify complete-message/streaming equivalence.
- Round-independent JSONL snapshots that check schema version, integer fidelity, byte encoding, context fields, and stdout/stderr separation.
- Cross-target summaries on Native, Wasm GC, and JavaScript for portable behavior.
- Native CLI integration tests for files, stdin, commands, malformed input, limits, and exit codes.
- A reproducible 100,000-record synthetic benchmark reporting environment, throughput, allocations where measurable, and retained Template/session state.

Absolute wall-clock thresholds are not CI correctness gates. Complexity regressions, unbounded state, output divergence, and benchmark methodology changes are reviewed explicitly.

Focused white-box tests are reserved for safe integer arithmetic and wire primitives only when public-interface failures cannot localize those invariants.
