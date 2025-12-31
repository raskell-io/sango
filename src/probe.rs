//! Active probing infrastructure
//!
//! Coordinates diagnostic checks against a target endpoint.

use anyhow::Result;
use serde::Serialize;
use std::time::Duration;

use crate::checks::{aeo, content, discovery, headers, http, latency, seo, techstack, tls};

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
    /// Discovery results
    pub discovery: Option<discovery::DiscoveryResult>,
    /// Tech stack results
    pub techstack: Option<techstack::TechStackResult>,
    /// SEO results
    pub seo: Option<seo::SeoResult>,
    /// AEO results
    pub aeo: Option<aeo::AeoResult>,
    /// Content analysis results
    pub content: Option<content::ContentResult>,
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
    /// Skip discovery checks
    pub skip_discovery: bool,
    /// Skip tech stack detection
    pub skip_techstack: bool,
    /// Skip SEO checks
    pub skip_seo: bool,
    /// Skip AEO checks
    pub skip_aeo: bool,
    /// Skip content analysis
    pub skip_content: bool,
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
            skip_discovery: false,
            skip_techstack: false,
            skip_seo: false,
            skip_aeo: false,
            skip_content: false,
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
        discovery: None,
        techstack: None,
        seo: None,
        aeo: None,
        content: None,
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

    // Run discovery check
    if !config.skip_discovery {
        match discovery::check_discovery(target, config.timeout).await {
            Ok(discovery_result) => {
                result.discovery = Some(discovery_result);
            }
            Err(e) => {
                result.errors.push(format!("Discovery: {}", e));
            }
        }
    }

    // Run tech stack detection
    if !config.skip_techstack {
        match techstack::check_techstack(target, config.timeout).await {
            Ok(techstack_result) => {
                result.techstack = Some(techstack_result);
            }
            Err(e) => {
                result.errors.push(format!("TechStack: {}", e));
            }
        }
    }

    // Run SEO checks
    if !config.skip_seo {
        match seo::check_seo(target, config.timeout).await {
            Ok(seo_result) => {
                result.seo = Some(seo_result);
            }
            Err(e) => {
                result.errors.push(format!("SEO: {}", e));
            }
        }
    }

    // Run AEO checks
    if !config.skip_aeo {
        match aeo::check_aeo(target, config.timeout).await {
            Ok(aeo_result) => {
                result.aeo = Some(aeo_result);
            }
            Err(e) => {
                result.errors.push(format!("AEO: {}", e));
            }
        }
    }

    // Run content analysis
    if !config.skip_content {
        match content::check_content(target, config.timeout).await {
            Ok(content_result) => {
                result.content = Some(content_result);
            }
            Err(e) => {
                result.errors.push(format!("Content: {}", e));
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

    // Check discovery issues
    if let Some(ref discovery_result) = result.discovery {
        for issue in &discovery_result.issues {
            match issue.severity {
                tls::Severity::Critical => has_critical = true,
                tls::Severity::High => has_high = true,
                tls::Severity::Medium | tls::Severity::Low => has_medium_or_low = true,
            }
        }
    }

    // Check tech stack issues
    if let Some(ref techstack_result) = result.techstack {
        for issue in &techstack_result.issues {
            match issue.severity {
                tls::Severity::Critical => has_critical = true,
                tls::Severity::High => has_high = true,
                tls::Severity::Medium | tls::Severity::Low => has_medium_or_low = true,
            }
        }
    }

    // Check SEO issues
    if let Some(ref seo_result) = result.seo {
        for issue in &seo_result.issues {
            match issue.severity {
                tls::Severity::Critical => has_critical = true,
                tls::Severity::High => has_high = true,
                tls::Severity::Medium | tls::Severity::Low => has_medium_or_low = true,
            }
        }
    }

    // Check AEO issues
    if let Some(ref aeo_result) = result.aeo {
        for issue in &aeo_result.issues {
            match issue.severity {
                tls::Severity::Critical => has_critical = true,
                tls::Severity::High => has_high = true,
                tls::Severity::Medium | tls::Severity::Low => has_medium_or_low = true,
            }
        }
    }

    // Check content issues
    if let Some(ref content_result) = result.content {
        for issue in &content_result.issues {
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
