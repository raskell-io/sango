//! Security header diagnostic checks
//!
//! - HSTS presence and configuration
//! - CSP analysis
//! - COOP/COEP headers
//! - X-Frame-Options, X-Content-Type-Options
//! - Header contradiction detection

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;

use super::tls::Severity;

/// Result of security header checks
#[derive(Debug, Serialize)]
pub struct HeadersResult {
    /// HSTS configuration if present
    pub hsts: Option<HstsInfo>,
    /// Content Security Policy if present
    pub csp: Option<CspInfo>,
    /// Cross-Origin-Opener-Policy header value
    pub coop: Option<String>,
    /// Cross-Origin-Embedder-Policy header value
    pub coep: Option<String>,
    /// X-Frame-Options header value
    pub x_frame_options: Option<String>,
    /// X-Content-Type-Options header value
    pub x_content_type_options: Option<String>,
    /// X-XSS-Protection header value (deprecated)
    pub x_xss_protection: Option<String>,
    /// Referrer-Policy header value
    pub referrer_policy: Option<String>,
    /// Permissions-Policy header value
    pub permissions_policy: Option<String>,
    /// Detected issues
    pub issues: Vec<HeaderIssue>,
}

/// HSTS header information
#[derive(Debug, Serialize, Clone)]
pub struct HstsInfo {
    /// max-age value in seconds
    pub max_age: u64,
    /// includeSubDomains directive present
    pub include_subdomains: bool,
    /// preload directive present
    pub preload: bool,
    /// Raw header value
    pub raw: String,
}

/// Content Security Policy information
#[derive(Debug, Serialize, Clone)]
pub struct CspInfo {
    /// Raw header value
    pub raw: String,
    /// Has default-src directive
    pub has_default_src: bool,
    /// Has script-src directive
    pub has_script_src: bool,
    /// Has style-src directive
    pub has_style_src: bool,
    /// Allows 'unsafe-inline' for scripts
    pub allows_unsafe_inline: bool,
    /// Allows 'unsafe-eval' for scripts
    pub allows_unsafe_eval: bool,
    /// Has frame-ancestors directive
    pub has_frame_ancestors: bool,
    /// Report-only mode (not enforced)
    pub report_only: bool,
}

/// A security header issue
#[derive(Debug, Serialize, Clone)]
pub struct HeaderIssue {
    pub severity: Severity,
    pub header: String,
    pub message: String,
}

/// Check security headers
pub async fn check_headers(target: &str, timeout: Duration) -> Result<HeadersResult> {
    let url = normalize_url(target);

    let client = Client::builder()
        .timeout(timeout)
        .build()
        .context("Failed to build HTTP client")?;

    let response = client
        .get(&url)
        .send()
        .await
        .context(format!("Failed to fetch {}", url))?;

    let headers = response.headers();

    // Parse HSTS
    let hsts = headers
        .get("strict-transport-security")
        .and_then(|v| v.to_str().ok())
        .map(parse_hsts);

    // Parse CSP (check both enforcing and report-only)
    let csp = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| parse_csp(s, false))
        .or_else(|| {
            headers
                .get("content-security-policy-report-only")
                .and_then(|v| v.to_str().ok())
                .map(|s| parse_csp(s, true))
        });

    // Get other security headers
    let coop = headers
        .get("cross-origin-opener-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let coep = headers
        .get("cross-origin-embedder-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let x_frame_options = headers
        .get("x-frame-options")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let x_content_type_options = headers
        .get("x-content-type-options")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let x_xss_protection = headers
        .get("x-xss-protection")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let referrer_policy = headers
        .get("referrer-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let permissions_policy = headers
        .get("permissions-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Generate issues
    let mut issues = generate_issues(
        &hsts,
        &csp,
        &coop,
        &coep,
        &x_frame_options,
        &x_content_type_options,
        &x_xss_protection,
        &referrer_policy,
    );

    // Sort by severity
    issues.sort_by(|a, b| b.severity.cmp(&a.severity));

    Ok(HeadersResult {
        hsts,
        csp,
        coop,
        coep,
        x_frame_options,
        x_content_type_options,
        x_xss_protection,
        referrer_policy,
        permissions_policy,
        issues,
    })
}

/// Parse HSTS header
fn parse_hsts(value: &str) -> HstsInfo {
    let value_lower = value.to_lowercase();
    let mut max_age = 0u64;
    let mut include_subdomains = false;
    let mut preload = false;

    for part in value_lower.split(';') {
        let part = part.trim();
        if part.starts_with("max-age=") {
            if let Ok(age) = part[8..].trim().parse::<u64>() {
                max_age = age;
            }
        } else if part == "includesubdomains" {
            include_subdomains = true;
        } else if part == "preload" {
            preload = true;
        }
    }

    HstsInfo {
        max_age,
        include_subdomains,
        preload,
        raw: value.to_string(),
    }
}

/// Parse CSP header
fn parse_csp(value: &str, report_only: bool) -> CspInfo {
    let value_lower = value.to_lowercase();

    let has_default_src = value_lower.contains("default-src");
    let has_script_src = value_lower.contains("script-src");
    let has_style_src = value_lower.contains("style-src");
    let has_frame_ancestors = value_lower.contains("frame-ancestors");

    // Check for unsafe directives in script-src or default-src
    let script_section = extract_directive(&value_lower, "script-src")
        .or_else(|| extract_directive(&value_lower, "default-src"))
        .unwrap_or_default();

    let allows_unsafe_inline = script_section.contains("'unsafe-inline'");
    let allows_unsafe_eval = script_section.contains("'unsafe-eval'");

    CspInfo {
        raw: value.to_string(),
        has_default_src,
        has_script_src,
        has_style_src,
        allows_unsafe_inline,
        allows_unsafe_eval,
        has_frame_ancestors,
        report_only,
    }
}

/// Extract a CSP directive value
fn extract_directive(csp: &str, directive: &str) -> Option<String> {
    for part in csp.split(';') {
        let part = part.trim();
        if part.starts_with(directive) {
            return Some(part.to_string());
        }
    }
    None
}

/// Generate issues based on header analysis
fn generate_issues(
    hsts: &Option<HstsInfo>,
    csp: &Option<CspInfo>,
    coop: &Option<String>,
    coep: &Option<String>,
    x_frame_options: &Option<String>,
    x_content_type_options: &Option<String>,
    x_xss_protection: &Option<String>,
    referrer_policy: &Option<String>,
) -> Vec<HeaderIssue> {
    let mut issues = Vec::new();

    // HSTS checks
    match hsts {
        None => {
            issues.push(HeaderIssue {
                severity: Severity::High,
                header: "Strict-Transport-Security".to_string(),
                message: "HSTS header missing".to_string(),
            });
        }
        Some(hsts_info) => {
            // Minimum recommended max-age is 1 year (31536000 seconds)
            if hsts_info.max_age < 31536000 {
                issues.push(HeaderIssue {
                    severity: Severity::Medium,
                    header: "Strict-Transport-Security".to_string(),
                    message: format!(
                        "HSTS max-age is {} seconds (recommended: 31536000+)",
                        hsts_info.max_age
                    ),
                });
            }
            if !hsts_info.include_subdomains {
                issues.push(HeaderIssue {
                    severity: Severity::Low,
                    header: "Strict-Transport-Security".to_string(),
                    message: "HSTS does not include subdomains".to_string(),
                });
            }
        }
    }

    // CSP checks
    match csp {
        None => {
            issues.push(HeaderIssue {
                severity: Severity::Medium,
                header: "Content-Security-Policy".to_string(),
                message: "CSP header missing".to_string(),
            });
        }
        Some(csp_info) => {
            if csp_info.report_only {
                issues.push(HeaderIssue {
                    severity: Severity::Medium,
                    header: "Content-Security-Policy".to_string(),
                    message: "CSP is report-only (not enforced)".to_string(),
                });
            }
            if !csp_info.has_default_src && !csp_info.has_script_src {
                issues.push(HeaderIssue {
                    severity: Severity::Medium,
                    header: "Content-Security-Policy".to_string(),
                    message: "CSP missing default-src or script-src".to_string(),
                });
            }
            if csp_info.allows_unsafe_inline {
                issues.push(HeaderIssue {
                    severity: Severity::Medium,
                    header: "Content-Security-Policy".to_string(),
                    message: "CSP allows 'unsafe-inline' for scripts".to_string(),
                });
            }
            if csp_info.allows_unsafe_eval {
                issues.push(HeaderIssue {
                    severity: Severity::Medium,
                    header: "Content-Security-Policy".to_string(),
                    message: "CSP allows 'unsafe-eval' for scripts".to_string(),
                });
            }
            if !csp_info.has_frame_ancestors && x_frame_options.is_none() {
                issues.push(HeaderIssue {
                    severity: Severity::Low,
                    header: "Content-Security-Policy".to_string(),
                    message: "CSP missing frame-ancestors (and no X-Frame-Options)".to_string(),
                });
            }
        }
    }

    // X-Content-Type-Options check
    match x_content_type_options {
        None => {
            issues.push(HeaderIssue {
                severity: Severity::Low,
                header: "X-Content-Type-Options".to_string(),
                message: "X-Content-Type-Options header missing".to_string(),
            });
        }
        Some(value) => {
            if value.to_lowercase() != "nosniff" {
                issues.push(HeaderIssue {
                    severity: Severity::Low,
                    header: "X-Content-Type-Options".to_string(),
                    message: format!(
                        "X-Content-Type-Options should be 'nosniff', got '{}'",
                        value
                    ),
                });
            }
        }
    }

    // X-XSS-Protection check (deprecated but still relevant)
    if let Some(value) = x_xss_protection {
        // Modern browsers ignore this header, and "1; mode=block" can cause issues
        if value.contains("1") {
            issues.push(HeaderIssue {
                severity: Severity::Low,
                header: "X-XSS-Protection".to_string(),
                message: "X-XSS-Protection is deprecated; rely on CSP instead".to_string(),
            });
        }
    }

    // COOP/COEP checks for cross-origin isolation
    if coop.is_none() {
        issues.push(HeaderIssue {
            severity: Severity::Low,
            header: "Cross-Origin-Opener-Policy".to_string(),
            message: "COOP header missing (needed for cross-origin isolation)".to_string(),
        });
    }

    if coep.is_none() {
        issues.push(HeaderIssue {
            severity: Severity::Low,
            header: "Cross-Origin-Embedder-Policy".to_string(),
            message: "COEP header missing (needed for cross-origin isolation)".to_string(),
        });
    }

    // Referrer-Policy check
    if referrer_policy.is_none() {
        issues.push(HeaderIssue {
            severity: Severity::Low,
            header: "Referrer-Policy".to_string(),
            message: "Referrer-Policy header missing".to_string(),
        });
    }

    issues
}

/// Normalize target to URL
fn normalize_url(target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("https://{}", target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hsts() {
        let hsts = parse_hsts("max-age=31536000; includeSubDomains; preload");
        assert_eq!(hsts.max_age, 31536000);
        assert!(hsts.include_subdomains);
        assert!(hsts.preload);
    }

    #[test]
    fn test_parse_hsts_simple() {
        let hsts = parse_hsts("max-age=86400");
        assert_eq!(hsts.max_age, 86400);
        assert!(!hsts.include_subdomains);
        assert!(!hsts.preload);
    }

    #[test]
    fn test_parse_csp() {
        let csp = parse_csp(
            "default-src 'self'; script-src 'self' 'unsafe-inline'",
            false,
        );
        assert!(csp.has_default_src);
        assert!(csp.has_script_src);
        assert!(csp.allows_unsafe_inline);
        assert!(!csp.allows_unsafe_eval);
        assert!(!csp.report_only);
    }
}
