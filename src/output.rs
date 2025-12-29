//! Output formatting for diagnostic results
//!
//! Supports pretty (colored terminal), JSON, and compact formats.

use crate::probe::ProbeResult;

pub fn print_pretty(_result: &ProbeResult) {
    // TODO: Implement pretty output with colored
    todo!("Pretty output not yet implemented")
}

pub fn print_json(result: &ProbeResult) -> String {
    serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".to_string())
}

pub fn print_compact(_result: &ProbeResult) -> String {
    // TODO: Implement compact single-line output
    todo!("Compact output not yet implemented")
}
