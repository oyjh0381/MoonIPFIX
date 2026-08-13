# Field decoding contract

MoonIPFIX decodes each Data Record from the ordered Field Specifiers in its currently applicable Template. Fixed fields consume their declared length. A variable-length field consumes either a one-octet length in the range 0–254, or the marker 255 followed by one unsigned 16-bit length. The extended form is rejected when it encodes a value below 255, so one wire value has one canonical framing.

Enterprise Field Specifiers retain the lower 15-bit element ID and the following Private Enterprise Number. They become typed only when the caller supplies matching metadata through `Registry::with_enterprise`; unknown standard and Enterprise identities remain lossless raw octets.

Reduced-Size Encoding is interpreted only for the RFC-eligible signed and unsigned 16-, 32-, and 64-bit integer types. An encoded width from one octet through the canonical width is accepted. Eight-bit integers, floating-point values, addresses, MAC addresses, booleans, and timestamps require their exact widths. Illegal widths, illegal boolean values, invalid UTF-8, and scalar types outside the v0.1 typed model produce `InvalidFieldEncoding` warnings and retain bounded raw octets.

`DecodedField` exposes both the Template's declared length and the actual value offset and encoded length. This preserves enough evidence for callers to audit variable-length and raw-fallback values without retaining the whole input Message.

The decoder makes one pass over each Set. For `n` input octets and `f` fields, decoding uses `O(n + f)` time. Output storage is `O(f)` plus the copied field values; it performs no backtracking and never reads beyond the Message and Set bounds established by framing.
