# Reject ambiguous input and bound retained state

Malformed complete input will produce offset-anchored structured Diagnostics without scanning for plausible records or inventing boundaries; incomplete chunks return `Need More Data`. Configurable limits and hard ceilings apply to buffering, Sessions, Templates, fields, records, raw values, and Diagnostics because the 65,535-byte Message limit alone does not bound cross-message state.
