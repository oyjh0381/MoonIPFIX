///|
fn main {
  let args = @env.args()
  if args.length() == 2 &&
    (args[1] == "version" || args[1] == "--version" || args[1] == "-V") {
    println(
      "MoonIPFIX \{@decoder.library_version} (IPFIX v\{@decoder.ipfix_version}, JSONL v\{@jsonl.schema_version}, IANA \{@registry.iana_snapshot_date})",
    )
  } else {
    println(
      (
        #|MoonIPFIX design baseline
        #|
        #|Usage:
        #|  moonipfix version
        #|
        #|Planned v0.1 commands: inspect, validate, templates, stats
        #|
      ),
    )
  }
}
