//! Latency breakdown diagnostic checks
//!
//! - DNS resolution time
//! - TCP connect time
//! - TLS handshake time
//! - Time to first byte (TTFB)
//! - Total request time

use anyhow::Result;
use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Serialize)]
pub struct LatencyResult {
    pub dns_lookup: Duration,
    pub tcp_connect: Duration,
    pub tls_handshake: Duration,
    pub time_to_first_byte: Duration,
    pub total: Duration,
    pub issues: Vec<LatencyIssue>,
}

#[derive(Debug, Serialize)]
pub struct LatencyIssue {
    pub severity: super::tls::Severity,
    pub phase: String,
    pub message: String,
}

pub async fn check_latency(_target: &str) -> Result<LatencyResult> {
    // TODO: Implement latency breakdown
    todo!("Latency checks not yet implemented")
}
