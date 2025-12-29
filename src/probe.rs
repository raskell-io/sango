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
    /// Error messages from failed checks
    pub errors: Vec<String>,
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
    /// Skip latency checks
    pub skip_latency: bool,
    /// Connection timeout
    pub timeout: Duration,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            skip_tls: false,
            skip_http: false,
            skip_headers: false,
            skip_latency: false,
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
        errors: Vec::new(),
    };

    // Run TLS check first - if this fails, we likely can't proceed
    if !config.skip_tls {
        match tls::check_tls(target, config.timeout).await {
            Ok(tls_result) => {
                result.tls = Some(tls_result);
            }
            Err(e) => {
                result.errors.push(format!("TLS: {}", e));
                // TLS failure is critical - calculate health and return
                result.overall_health = Health::Unhealthy;
                return Ok(result);
            }
        }
    }

    // Run HTTP check
    if !config.skip_http {
        match http::check_http(target, config.timeout).await {
            Ok(http_result) => {
                result.http = Some(http_result);
            }
            Err(e) => {
                result.errors.push(format!("HTTP: {}", e));
            }
        }
    }

    // Run security headers check
    if !config.skip_headers {
        match headers::check_headers(target, config.timeout).await {
            Ok(headers_result) => {
                result.headers = Some(headers_result);
            }
            Err(e) => {
                result.errors.push(format!("Headers: {}", e));
            }
        }
    }

    // Run latency check
    if !config.skip_latency {
        match latency::check_latency(target, config.timeout).await {
            Ok(latency_result) => {
                result.latency = Some(latency_result);
            }
            Err(e) => {
                result.errors.push(format!("Latency: {}", e));
            }
        }
    }

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
    if let Some(ref tls_result) = result.tls {
        for issue in &tls_result.issues {
            match issue.severity {
                tls::Severity::Critical => has_critical = true,
                tls::Severity::High => has_high = true,
                tls::Severity::Medium | tls::Severity::Low => has_medium_or_low = true,
            }
        }
    }

    // Check HTTP issues
    if let Some(ref http_result) = result.http {
        for issue in &http_result.issues {
            match issue.severity {
                tls::Severity::Critical => has_critical = true,
                tls::Severity::High => has_high = true,
                tls::Severity::Medium | tls::Severity::Low => has_medium_or_low = true,
            }
        }
    }

    // Check header issues
    if let Some(ref headers_result) = result.headers {
        for issue in &headers_result.issues {
            match issue.severity {
                tls::Severity::Critical => has_critical = true,
                tls::Severity::High => has_high = true,
                tls::Severity::Medium | tls::Severity::Low => has_medium_or_low = true,
            }
        }
    }

    // Check latency issues
    if let Some(ref latency_result) = result.latency {
        for issue in &latency_result.issues {
            match issue.severity {
                tls::Severity::Critical => has_critical = true,
                tls::Severity::High => has_high = true,
                tls::Severity::Medium | tls::Severity::Low => has_medium_or_low = true,
            }
        }
    }

    // Include errors in health calculation
    if !result.errors.is_empty() {
        has_high = true;
    }

    if has_critical || has_high {
        Health::Unhealthy
    } else if has_medium_or_low {
        Health::Degraded
    } else if result.tls.is_some() || result.http.is_some() {
        Health::Healthy
    } else {
        Health::Unknown
    }
}
