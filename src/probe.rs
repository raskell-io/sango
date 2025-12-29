//! Active probing infrastructure
//!
//! Coordinates diagnostic checks against a target endpoint.

use anyhow::Result;
use serde::Serialize;

use crate::checks::{headers, http, latency, tls};

#[derive(Debug, Serialize)]
pub struct ProbeResult {
    pub target: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub tls: Option<tls::TlsResult>,
    pub http: Option<http::HttpResult>,
    pub headers: Option<headers::HeadersResult>,
    pub latency: Option<latency::LatencyResult>,
    pub overall_health: Health,
}

#[derive(Debug, Serialize)]
pub enum Health {
    Healthy,
    Degraded,
    Unhealthy,
}

pub struct ProbeConfig {
    pub skip_tls: bool,
    pub skip_http: bool,
    pub skip_headers: bool,
    pub timeout: std::time::Duration,
}

pub async fn run_probe(_target: &str, _config: ProbeConfig) -> Result<ProbeResult> {
    // TODO: Implement probe orchestration
    todo!("Probe orchestration not yet implemented")
}
