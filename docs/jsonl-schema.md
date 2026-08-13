# JSONL schema v1

Every output line is one standalone JSON object with integer `schema_version: 1` and a stable `record_kind`. The v1 kinds are `message`, `set`, `template`, `template_lifecycle`, `data_record`, `sequence_audit`, `diagnostic`, and `statistics`. Records repeat Session, Observation Domain, Template, Set, and byte-offset context where applicable so a line remains meaningful when filtered or streamed.

Unsigned and signed 64-bit values use a decimal string, avoiding JavaScript number precision loss. Times also use decimal strings and retain their declared unit in `type`. Raw octets, MAC addresses, and IP addresses use lowercase, even-length hexadecimal with explicit `encoding: "hex"`; they are never decoded through a locale. Floating-point values use a deterministic string, including non-finite representations. Strings use JSON escaping. A field preserves Enterprise Number, element ID, Template-declared length, actual encoded length, and value offset.

Object member order is deterministic but consumers must treat JSON member order as insignificant. Producers emit no embedded physical newline: one returned string is exactly one JSONL record, and a writer appends one `\n` separator.
