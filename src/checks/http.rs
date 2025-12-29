//! HTTP protocol diagnostic checks
//!
//! - HTTP/1.1, HTTP/2, HTTP/3 support detection
//! - ALPN advertisement vs actual negotiation
//! - Redirect chain analysis
//! - Response header normalization

use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct HttpResult {
    pub http1_supported: bool,
    pub http2_supported: bool,
    pub http3_advertised: bool,
    pub http3_negotiated: bool,
    pub redirect_chain: Vec<String>,
    pub issues: Vec<HttpIssue>,
}

#[derive(Debug, Serialize)]
pub struct HttpIssue {
    pub severity: super::tls::Severity,
    pub message: String,
}

pub async fn check_http(_target: &str) -> Result<HttpResult> {
    // TODO: Implement HTTP checks
    todo!("HTTP checks not yet implemented")
}
