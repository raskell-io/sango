//! HTTP headers analysis
//!
//! Analyzes security headers and other HTTP headers from response.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::{Issue, Severity};

/// Result of headers analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeadersAnalysis {
    /// HSTS header present and valid
    pub has_hsts: bool,
    /// HSTS max-age value
    pub hsts_max_age: Option<u64>,
    /// HSTS includes subdomains
    pub hsts_include_subdomains: bool,
    /// HSTS has preload
    pub hsts_preload: bool,

    /// CSP header present
    pub has_csp: bool,
    /// CSP policy (truncated if long)
    pub csp_summary: Option<String>,

    /// X-Frame-Options present
    pub has_xfo: bool,
    /// X-Frame-Options value
    pub xfo_value: Option<String>,

    /// X-Content-Type-Options present
    pub has_xcto: bool,

    /// X-XSS-Protection present (deprecated but still checked)
    pub has_xss_protection: bool,

    /// Referrer-Policy present
    pub has_referrer_policy: bool,
    /// Referrer-Policy value
    pub referrer_policy: Option<String>,

    /// Permissions-Policy present
    pub has_permissions_policy: bool,

    /// Server header value
    pub server: Option<String>,

    /// X-Powered-By header (security concern if present)
    pub x_powered_by: Option<String>,

    /// Content-Type header
    pub content_type: Option<String>,

    /// Cache-Control header
    pub cache_control: Option<String>,

    /// Detected issues
    pub issues: Vec<Issue>,
}

/// Raw header values for analysis
#[derive(Debug, Clone, Default)]
pub struct RawHeaders {
    pub headers: HashMap<String, String>,
}

impl RawHeaders {
    pub fn new() -> Self {
        Self { headers: HashMap::new() }
    }

    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.headers.insert(key.into().to_lowercase(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.headers.get(&key.to_lowercase())
    }
}

/// Analyze HTTP headers for security and configuration
pub fn analyze_headers(raw: &RawHeaders) -> HeadersAnalysis {
    let mut result = HeadersAnalysis::default();

    // HSTS
    if let Some(hsts) = raw.get("strict-transport-security") {
        result.has_hsts = true;
        parse_hsts(hsts, &mut result);
    }

    // CSP
    if let Some(csp) = raw.get("content-security-policy") {
        result.has_csp = true;
        result.csp_summary = Some(summarize_csp(csp));
    } else if raw.get("content-security-policy-report-only").is_some() {
        result.has_csp = true;
        result.csp_summary = Some("report-only".to_string());
    }

    // X-Frame-Options
    if let Some(xfo) = raw.get("x-frame-options") {
        result.has_xfo = true;
        result.xfo_value = Some(xfo.clone());
    }

    // X-Content-Type-Options
    result.has_xcto = raw.get("x-content-type-options").is_some();

    // X-XSS-Protection
    result.has_xss_protection = raw.get("x-xss-protection").is_some();

    // Referrer-Policy
    if let Some(rp) = raw.get("referrer-policy") {
        result.has_referrer_policy = true;
        result.referrer_policy = Some(rp.clone());
    }

    // Permissions-Policy
    result.has_permissions_policy = raw.get("permissions-policy").is_some()
        || raw.get("feature-policy").is_some();

    // Server
    result.server = raw.get("server").cloned();

    // X-Powered-By
    result.x_powered_by = raw.get("x-powered-by").cloned();

    // Content-Type
    result.content_type = raw.get("content-type").cloned();

    // Cache-Control
    result.cache_control = raw.get("cache-control").cloned();

    // Generate issues
    result.issues = generate_issues(&result);

    result
}

fn parse_hsts(value: &str, result: &mut HeadersAnalysis) {
    let lower = value.to_lowercase();

    // Extract max-age
    if let Some(start) = lower.find("max-age=") {
        let after = &lower[start + 8..];
        let end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
        if let Ok(age) = after[..end].parse::<u64>() {
            result.hsts_max_age = Some(age);
        }
    }

    result.hsts_include_subdomains = lower.contains("includesubdomains");
    result.hsts_preload = lower.contains("preload");
}

fn summarize_csp(csp: &str) -> String {
    // Extract key directives
    let mut summary = Vec::new();

    if csp.contains("default-src") { summary.push("default-src"); }
    if csp.contains("script-src") { summary.push("script-src"); }
    if csp.contains("style-src") { summary.push("style-src"); }
    if csp.contains("img-src") { summary.push("img-src"); }
    if csp.contains("frame-ancestors") { summary.push("frame-ancestors"); }
    if csp.contains("upgrade-insecure-requests") { summary.push("upgrade-insecure"); }

    if summary.is_empty() {
        if csp.len() > 50 {
            format!("{}...", &csp[..50])
        } else {
            csp.to_string()
        }
    } else {
        summary.join(", ")
    }
}

fn generate_issues(result: &HeadersAnalysis) -> Vec<Issue> {
    let mut issues = Vec::new();

    // HSTS
    if !result.has_hsts {
        issues.push(Issue::new(Severity::High, "security", "HSTS header missing")
            .with_recommendation("Add Strict-Transport-Security header to prevent downgrade attacks"));
    } else if let Some(age) = result.hsts_max_age {
        if age < 31536000 {
            issues.push(Issue::new(Severity::Medium, "security",
                format!("HSTS max-age too short ({} seconds)", age))
                .with_recommendation("Set max-age to at least 31536000 (1 year)"));
        }
    }

    // CSP
    if !result.has_csp {
        issues.push(Issue::new(Severity::Medium, "security", "CSP header missing")
            .with_recommendation("Add Content-Security-Policy to mitigate XSS attacks"));
    }

    // X-Content-Type-Options
    if !result.has_xcto {
        issues.push(Issue::new(Severity::Low, "security", "X-Content-Type-Options header missing")
            .with_recommendation("Add X-Content-Type-Options: nosniff"));
    }

    // X-Powered-By (information disclosure)
    if result.x_powered_by.is_some() {
        issues.push(Issue::new(Severity::Low, "security", "X-Powered-By header exposes technology stack")
            .with_recommendation("Remove X-Powered-By header to reduce information disclosure"));
    }

    // Referrer-Policy
    if !result.has_referrer_policy {
        issues.push(Issue::new(Severity::Low, "security", "Referrer-Policy header missing")
            .with_recommendation("Add Referrer-Policy to control referrer information"));
    }

    issues.sort_by(|a, b| b.severity.cmp(&a.severity));
    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hsts_parsing() {
        let mut raw = RawHeaders::new();
        raw.insert("strict-transport-security", "max-age=31536000; includeSubDomains; preload");

        let result = analyze_headers(&raw);
        assert!(result.has_hsts);
        assert_eq!(result.hsts_max_age, Some(31536000));
        assert!(result.hsts_include_subdomains);
        assert!(result.hsts_preload);
    }

    #[test]
    fn test_missing_headers() {
        let raw = RawHeaders::new();
        let result = analyze_headers(&raw);

        assert!(!result.has_hsts);
        assert!(!result.has_csp);
        assert!(result.issues.len() >= 2);
    }
}
