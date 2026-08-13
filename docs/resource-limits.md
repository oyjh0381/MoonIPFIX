# Resource limits and recovery

`DecoderLimits` bounds active Sessions, Templates per Session, fields per Template, fixed and variable field values, records per Message, and retained Diagnostics. `StreamDecoderConfig` independently bounds bytes retained for the current incomplete Message. Defaults are practical rather than unlimited, and constructor validation enforces protocol-derived hard ceilings even when a caller requests larger values.

Limit failures use dedicated `DiagnosticCode` variants and are distinct from malformed encoding and `NeedMoreData`. Complete-message processing is transactional: Template and sequence maps are copied, all Sets are parsed and applied to the isolated state, and only a fully accepted Message commits the new maps. A format, limit, or diagnostic-retention failure therefore cannot leave a Template replacement, withdrawal, Session registration, or Sequence expectation partially applied.

Streaming delegates complete extents to the same transactional decoder. It may continue after a rejected Message only when the declared extent established a verified next boundary. An invalid or over-limit Message Length loses that boundary, clears the retained prefix, and permanently marks the adapter `BoundaryLost`; MoonIPFIX never scans hostile bytes for a plausible replacement header.

The main decode loops check remaining Set and Message extents before advancing or slicing. Protocol widths cap arithmetic at 65535 Message bytes, 65535 fields in the wire count, and modulo-2³² Sequence operations. Field-count, field-length, record, and diagnostic limits are checked before output growth.
