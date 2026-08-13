# Sequence and per-Message audit

Sequence continuity is scoped by Session Key and Observation Domain ID. The header Sequence Number denotes the number of Data Records exported before the current Message, modulo 2³². MoonIPFIX therefore advances the next expectation by decoded Data Record count, including Options Data Records, and never by Message, Set, or Template count. Template-only Messages keep the same expectation.

Each successful `DecodedMessage` carries a `SequenceAudit` classified as `Baseline`, `Continuous`, `Gap`, or `Unverifiable`. A gap includes expected and observed numbers and the modulo-2³² forward missing count. If any Data Set lacks an applicable Template, record count is unknown; the audit preserves the evidence but clears the next expectation instead of guessing. The next countable Message establishes a new baseline. `reset_session` clears continuity only for the selected Session.

`MessageStatistics` reports one Message plus its Set, installed Template, lifecycle-event, decoded-record, decoded-field, and retained-Diagnostic counts. Unknown-Template Data Sets also produce a `DataSetUnresolved` lifecycle event, so operational consumers can distinguish missing schema state from an empty Data Set.
