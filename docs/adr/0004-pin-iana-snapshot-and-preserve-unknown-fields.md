# Pin IANA metadata and preserve unknown fields

MoonIPFIX will check in generated metadata from a dated, hashed IANA Registry Snapshot rather than downloading registry state at runtime or hand-maintaining a small field subset. Standard metadata remains reproducible, while unknown standard and Enterprise Information Elements retain identity, declared length, and bounded raw bytes so registry age never causes silent data loss.
