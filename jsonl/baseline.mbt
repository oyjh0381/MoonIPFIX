///|
/// Output Record schema version reserved by the design baseline.
pub let schema_version : Int = 1

///|
/// A stable baseline description used before protocol records are implemented.
pub fn baseline_identity() -> String {
  "moonipfix/\{@decoder.library_version};jsonl=\{schema_version};iana=\{@registry.iana_snapshot_date}"
}
