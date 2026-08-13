# Security model

MoonIPFIX treats all IPFIX bytes, declared lengths, Template metadata, strings, and Enterprise fields as untrusted input.

## Required protections

- Validate every offset and length against remaining input before slicing or advancing.
- Detect arithmetic overflow before addition, multiplication, allocation, or record-count updates.
- Reject structurally invalid record boundaries instead of guessing where a later record begins.
- Enforce limits for buffered bytes, Sessions, Templates per Session, fields per Template, field length, records per Message, and retained Diagnostics.
- Keep unknown fields as bounded bytes without evaluating or dynamically dispatching their content.
- Separate `Need More Data` from invalid complete input so streaming callers do not accept truncation as success.
- Bound JSONL expansion and encode opaque bytes safely.
- Avoid host network access, filesystem access, environment access, and wall-clock dependencies in portable Modules.

## Recovery policy

The decoder may continue at a verified IPFIX Message boundary after reporting a message-level error. It does not scan arbitrary bytes for a plausible header and does not invent Data Record boundaries after a Template or length failure. Warnings must never convert invalid data into a successfully decoded value.

MoonIPFIX does not authenticate exporters, decrypt transports, isolate callers, or make captured telemetry safe to publish. Applications remain responsible for transport security, access control, retention, and privacy policy.
