# Test and fixture provenance

All byte vectors, generators, mutation logic, CLI fixtures, and benchmark inputs in this repository are original project test material released under the repository's Apache-2.0 license. They are constructed directly from the public wire formats in RFC 7011 and RFC 7012; no packet capture, exporter output, third-party corpus, private code, or copied implementation is included.

The bounded property corpus uses deterministic integer seeds and independent byte construction. A failure reports `replay seed=N`; rerunning the named test reproduces the same Template, record values, chunk partition, or mutation. CI runs 64 valid-stream partitions and 40 mutations on Native, Wasm GC, and JavaScript. Larger local campaigns may increase these constants without changing the oracle: complete-message public results are compared to arbitrary-chunk public results, and malformed variants assert only documented outcome classes.

Cross-target semantic equality is enforced by the same independent JSONL golden literals and public `DecodeOutcome` comparisons on all three targets. Tests do not read the wall clock and never depend on HashMap iteration order; Template state snapshots are sorted by Observation Domain and Template ID.
