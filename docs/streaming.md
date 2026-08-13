# Arbitrary-chunk decoding

`StreamDecoder` accepts empty chunks, partial headers, partial bodies, exact Messages, and chunks containing multiple Messages. It retains only the current incomplete Message and delegates each complete declared extent to the same stateful `Decoder::decode_message` implementation as the complete-message API. Template and record state therefore changes once, at the complete Message boundary.

`StreamBatch.outcomes` contains completed decode outcomes in wire order. `need_more` is present only when bytes are retained and reports the exact known requirement: 16 octets before a full header exists, then the declared Message Length. `finish()` returns `Complete` for an empty buffer and `Truncated(NeedMore)` for incomplete input.

The default retained limit is the IPFIX protocol maximum of 65535 octets. A smaller validated limit can be supplied with `StreamDecoder::with_config`. Large input chunks are consumed incrementally, so several complete Messages may exceed that limit in aggregate while the retained incomplete Message never does. A single Message declaring a length above the limit is rejected before its body is copied; because the adapter cannot retain or authenticate the skipped boundary, that stream then reports `BoundaryLost` instead of scanning for a plausible header.
