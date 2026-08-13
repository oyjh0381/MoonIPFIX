///|
pub fn DecoderLimits::default() -> DecoderLimits {
  {
    max_sessions: 1024,
    max_templates_per_session: 4096,
    max_fields_per_template: 1024,
    max_field_length: 65535,
    max_records_per_message: 65535,
    max_diagnostics_per_message: 1024,
  }
}

///|
fn validate_limits(limits : DecoderLimits) -> Result[Unit, LimitConfigError] {
  let checks = [
    validate_limit("max_sessions", limits.max_sessions, 65535),
    validate_limit(
      "max_templates_per_session",
      limits.max_templates_per_session,
      65535,
    ),
    validate_limit(
      "max_fields_per_template",
      limits.max_fields_per_template,
      4096,
    ),
    validate_limit("max_field_length", limits.max_field_length, 65535),
    validate_limit(
      "max_records_per_message",
      limits.max_records_per_message,
      65535,
    ),
    validate_limit(
      "max_diagnostics_per_message",
      limits.max_diagnostics_per_message,
      4096,
    ),
  ]
  for check in checks {
    match check {
      Ok(_) => ()
      Err(error) => return Err(error)
    }
  }
  Ok(())
}

///|
fn validate_limit(
  name : String,
  value : Int,
  hard_ceiling : Int,
) -> Result[Unit, LimitConfigError] {
  if value <= 0 {
    Err(NonPositive(name, value))
  } else if value > hard_ceiling {
    Err(AboveHardCeiling(name, value, hard_ceiling))
  } else {
    Ok(())
  }
}
