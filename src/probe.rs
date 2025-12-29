//! Active probing infrastructure
//!
//! Coordinates diagnostic checks against a target endpoint.

use anyhow::Result;
use serde::Serialize;
use std::time::Duration;

use crate::checks::{headers, http, latency, tls};

/// Result of all diagnostic probes
#[derive(Debug, Serialize)]
pub struct ProbeResult {
    /// The target that was probed
    pub target: String,
    /// Timestamp of the probe
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// TLS diagnostic results
    pub tls: Option<tls::TlsResult>,
    /// HTTP diagnostic results
    pub http: Option<http::HttpResult>,
    /// Security header results
    pub headers: Option<headers::HeadersResult>,
    /// Latency breakdown results
    pub latency: Option<latency::LatencyResult>,
    /// Overall health assessment
    pub overall_health: Health,
    /// Error message if probe failed
    pub error: Option<String>,
}

/// Overall health assessment
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// No issues found
    Healthy,
    /// Some non-critical issues found
    Degraded,
    /// Critical issues found
    Unhealthy,
    /// Probe failed to complete
    Unknown,
}

impl std::fmt::Display for Health {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Health::Healthy => write!(f, "Healthy"),
            Health::Degraded => write!(f, "Degraded"),
            Health::Unhealthy => write!(f, "Unhealthy"),
            Health::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Configuration for probe execution
pub struct ProbeConfig {
    /// Skip TLS checks
    pub skip_tls: bool,
    /// Skip HTTP protocol checks
    pub skip_http: bool,
    /// Skip security header checks
    pub skip_headers: bool,
    /// Connection timeout
    pub timeout: Duration,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            skip_tls: false,
            skip_http: false,
            skip_headers: false,
            timeout: Duration::from_secs(10),
        }
    }
}

/// Run all enabled probes against a target
pub async fn run_probe(target: &str, config: ProbeConfig) -> Result<ProbeResult> {
    let timestamp = chrono::Utc::now();
    let mut result = ProbeResult {
        target: target.to_string(),
        timestamp,
        tls: None,
        http: None,
        headers: None,
        latency: None,
        overall_health: Health::Unknown,
        error: None,
    };

    // Run TLS check
    if !config.skip_tls {
        match tls::check_tls(target, config.timeout).await {
            Ok(tls_result) => {
                result.tls = Some(tls_result);
            }
            Err(e) => {
                result.error = Some(format!("TLS check failed: {}", e));
                result.overall_health = Health::Unhealthy;
                return Ok(result);
            }
        }
    }

    // TODO: Run HTTP check when implemented
    // if !config.skip_http {
    //     result.http = Some(http::check_http(target).await?);
    // }

    // TODO: Run headers check when implemented
    // if !config.skip_headers {
    //     result.headers = Some(headers::check_headers(target).await?);
    // }

    // Calculate overall health based on results
    result.overall_health = calculate_health(&result);

    Ok(result)
}

/// Calculate overall health from probe results
fn calculate_health(result: &ProbeResult) -> Health {
    let mut has_critical = false;
    let mut has_high = false;
    let mut has_medium_or_low = false;

    // Check TLS issues
    if let Some(ref tls) = result.tls {
        for issue in &tls.issues {
            match issue.severity {
                tls::Severity::Critical => has_critical = true,
                tls::Severity::High => has_high = true,
                tls::Severity::Medium | tls::Severity::Low => has_medium_or_low = true,
            }
        }
    }

    // TODO: Check HTTP issues when implemented
    // TODO: Check header issues when implemented

    if has_critical || has_high {
        Health::Unhealthy
    } else if has_medium_or_low {
        Health::Degraded
    } else if result.tls.is_some() {
        Health::Healthy
    } else {
        Health::Unknown
    }
}
