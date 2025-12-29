//! Security header diagnostic checks
//!
//! - HSTS presence and configuration
//! - CSP analysis
//! - COOP/COEP headers
//! - X-Frame-Options, X-Content-Type-Options
//! - Header contradiction detection

use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct HeadersResult {
    pub hsts: Option<HstsInfo>,
    pub csp: Option<CspInfo>,
    pub coop: Option<String>,
    pub coep: Option<String>,
    pub x_frame_options: Option<String>,
    pub x_content_type_options: Option<String>,
    pub issues: Vec<HeaderIssue>,
}

#[derive(Debug, Serialize)]
pub struct HstsInfo {
    pub max_age: u64,
    pub include_subdomains: bool,
    pub preload: bool,
}

#[derive(Debug, Serialize)]
pub struct CspInfo {
    pub raw: String,
    pub has_default_src: bool,
    pub has_script_src: bool,
    pub allows_unsafe_inline: bool,
    pub allows_unsafe_eval: bool,
}

#[derive(Debug, Serialize)]
pub struct HeaderIssue {
    pub severity: super::tls::Severity,
    pub header: String,
    pub message: String,
}

pub async fn check_headers(_target: &str) -> Result<HeadersResult> {
    // TODO: Implement security header checks
    todo!("Security header checks not yet implemented")
}
