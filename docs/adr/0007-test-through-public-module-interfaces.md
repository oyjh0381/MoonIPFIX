# Test through public Module Interfaces

Correctness evidence will enter through the `decoder`, `registry`, and `jsonl` Interfaces or the Native CLI and will compare externally observable results, state changes, Diagnostics, offsets, streams, and exit behavior. Focused internal tests are limited to wire arithmetic that cannot be localized at a higher seam, preventing test-only exposure of Template storage and cursor implementation.
