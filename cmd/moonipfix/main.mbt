///|
extern "C" fn process_exit(code : Int) = "exit"

///|
struct CliOptions {
  command : String
  path : String
  session : String
  deny_warnings : Bool
}

///|
struct CliStatus {
  mut warnings : Int
  mut malformed : Bool
  mut resource_limit : Bool
  mut messages : Int
  mut sets : Int
  mut templates : Int
  mut records : Int
  mut fields : Int
  mut unknown_fields : Int
  mut diagnostics : Int
  mut sequence_gaps : Int
}

///|
async fn main {
  let args = @env.args()
  if args.length() == 2 &&
    (args[1] == "version" || args[1] == "--version" || args[1] == "-V") {
    @stdio.stdout.write(
      "MoonIPFIX \{@decoder.library_version} (IPFIX v\{@decoder.ipfix_version}, JSONL v\{@jsonl.schema_version}, IANA \{@registry.iana_snapshot_date})\n",
    )
    return
  }
  if args.length() == 1 ||
    (
      args.length() == 2 &&
      (args[1] == "help" || args[1] == "--help" || args[1] == "-h")
    ) {
    @stdio.stdout.write(usage())
    return
  }
  let options = match parse_options(args) {
    Ok(value) => value
    Err(message) => {
      @stdio.stderr.write("MOONIPFIX_USAGE: \{message}\n")
      @stdio.stderr.write(usage())
      process_exit(2)
      return
    }
  }
  try {
    let status = if options.path == "-" {
      process_input(@stdio.stdin, options)
    } else {
      let file = @fs.open(options.path, mode=ReadOnly)
      defer file.close()
      process_input(file, options)
    }
    if status.resource_limit {
      process_exit(5)
    } else if status.malformed {
      process_exit(4)
    } else if options.deny_warnings && status.warnings > 0 {
      process_exit(3)
    }
  } catch {
    error => {
      @stdio.stderr.write("MOONIPFIX_IO: \{error}\n") catch {
        _ => ()
      }
      process_exit(6)
    }
  }
}

///|
fn parse_options(args : Array[String]) -> Result[CliOptions, String] {
  let command = args[1]
  if command != "inspect" &&
    command != "validate" &&
    command != "templates" &&
    command != "stats" {
    return Err("unknown command: " + command)
  }
  let mut path = "-"
  let mut session = "cli:default"
  let mut deny_warnings = false
  let mut positional_seen = false
  let mut index = 2
  while index < args.length() {
    if args[index] == "--session" {
      if index + 1 >= args.length() {
        return Err("--session requires a value")
      }
      session = args[index + 1]
      index += 2
    } else if args[index] == "--deny-warnings" {
      deny_warnings = true
      index += 1
    } else if args[index].has_prefix("-") && args[index] != "-" {
      return Err("unknown option: " + args[index])
    } else if positional_seen {
      return Err("only one input file or '-' is accepted")
    } else {
      path = args[index]
      positional_seen = true
      index += 1
    }
  }
  Ok({ command, path, session, deny_warnings })
}

///|
async fn process_input(input : &@io.Reader, options : CliOptions) -> CliStatus {
  let stream = @decoder.StreamDecoder::new(
    @decoder.SessionKey::new(options.session),
  )
  let status : CliStatus = {
    warnings: 0,
    malformed: false,
    resource_limit: false,
    messages: 0,
    sets: 0,
    templates: 0,
    records: 0,
    fields: 0,
    unknown_fields: 0,
    diagnostics: 0,
    sequence_gaps: 0,
  }
  while input.read_some(max_len=8192) is Some(chunk) {
    consume_batch(stream.push(chunk), options.command, status)
  }
  match stream.finish() {
    Complete => ()
    Truncated(need) => {
      status.malformed = true
      @stdio.stderr.write(
        "MOONIPFIX_TRUNCATED: end of input at \{need.available} bytes; \{need.required} required\n",
      )
    }
    BoundaryLost => status.malformed = true
  }
  if options.command == "templates" {
    for template in stream.active_templates() {
      @stdio.stdout.write(@jsonl.encode_template_state(template) + "\n")
    }
  } else if options.command == "stats" {
    @stdio.stdout.write(
      @jsonl.encode_stream_statistics(
        options.session,
        status.messages,
        status.sets,
        status.templates,
        status.records,
        status.fields,
        status.unknown_fields,
        status.diagnostics,
        status.sequence_gaps,
      ) +
      "\n",
    )
  }
  status
}

///|
async fn consume_batch(
  batch : @decoder.StreamBatch,
  command : String,
  status : CliStatus,
) -> Unit {
  for outcome in batch.outcomes {
    match outcome {
      Decoded(message) => {
        status.messages += 1
        status.sets += message.statistics.set_count
        status.templates += message.statistics.template_count
        status.records += message.statistics.record_count
        status.fields += message.statistics.field_count
        status.diagnostics += message.statistics.diagnostic_count
        match message.sequence {
          Some(audit) if audit.continuity == @decoder.SequenceContinuity::Gap =>
            status.sequence_gaps += 1
          _ => ()
        }
        for record in message.records {
          for field in record.fields {
            match field.metadata {
              @registry.Unresolved(_) => status.unknown_fields += 1
              _ => ()
            }
          }
        }
        for diagnostic in message.diagnostics {
          emit_human_diagnostic(diagnostic)
          if diagnostic.severity == Warning {
            status.warnings += 1
          }
          if is_resource_limit(diagnostic.code) {
            status.resource_limit = true
          }
        }
        for line in @jsonl.encode_message(message) {
          if include_line(command, line) {
            @stdio.stdout.write(line + "\n")
          }
        }
      }
      Rejected(diagnostics) => {
        status.malformed = true
        status.diagnostics += diagnostics.length()
        for diagnostic in diagnostics {
          emit_human_diagnostic(diagnostic)
          if is_resource_limit(diagnostic.code) {
            status.resource_limit = true
          }
          if command == "inspect" ||
            command == "validate" ||
            command == "templates" ||
            command == "stats" {
            @stdio.stdout.write(@jsonl.encode_diagnostic(diagnostic) + "\n")
          }
        }
      }
      NeedMoreData(_) => ()
    }
  }
}

///|
fn include_line(command : String, line : String) -> Bool {
  if command == "inspect" {
    true
  } else if command == "validate" {
    line.contains("\"record_kind\":\"diagnostic\"") ||
    line.contains("\"record_kind\":\"sequence_audit\"") ||
    line.contains("\"record_kind\":\"statistics\"")
  } else if command == "templates" {
    line.contains("\"record_kind\":\"template\"") ||
    line.contains("\"record_kind\":\"template_lifecycle\"")
  } else {
    line.contains("\"record_kind\":\"sequence_audit\"")
  }
}

///|
async fn emit_human_diagnostic(value : @decoder.Diagnostic) -> Unit {
  let severity = if value.severity == @decoder.DiagnosticSeverity::Warning {
    "warning"
  } else {
    "error"
  }
  @stdio.stderr.write(
    "MoonIPFIX \{severity} at byte \{value.offset}: \{value.message}\n",
  )
}

///|
fn is_resource_limit(code : @decoder.DiagnosticCode) -> Bool {
  match code {
    SessionLimitExceeded
    | TemplateLimitExceeded
    | FieldCountLimitExceeded
    | FieldLengthLimitExceeded
    | RecordLimitExceeded
    | DiagnosticLimitExceeded
    | StreamBufferLimitExceeded => true
    _ => false
  }
}

///|
fn usage() -> String {
  (
    #|MoonIPFIX — offline IPFIX stream decoder and audit tool
    #|
    #|Usage:
    #|  moonipfix inspect   [--session KEY] [--deny-warnings] [FILE|-]
    #|  moonipfix validate  [--session KEY] [--deny-warnings] [FILE|-]
    #|  moonipfix templates [--session KEY] [FILE|-]
    #|  moonipfix stats     [--session KEY] [FILE|-]
    #|  moonipfix version
    #|
    #|FILE defaults to stdin (-); the deterministic Session Key is cli:default.
    #|Exit: 0 success, 2 usage, 3 denied warning, 4 malformed/truncated,
    #|      5 resource limit, 6 I/O (including a broken output pipe).
    #|This is an offline decoder, not an online IPFIX Collector or listener.
    #|
  )
}
