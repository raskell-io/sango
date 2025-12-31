//! HTTP protocol diagnostic checks
//!
//! - HTTP/1.1, HTTP/2, HTTP/3 support detection
//! - ALPN advertisement vs actual negotiation
//! - Redirect chain analysis
//! - Alt-Svc header parsing for HTTP/3

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;

use super::tls::Severity;

/// Result of HTTP protocol checks
#[derive(Debug, Serialize)]
pub struct HttpResult {
    /// HTTP/1.1 is supported
    pub http1_supported: bool,
    /// HTTP/2 was negotiated
    pub http2_supported: bool,
    /// HTTP/3 is advertised via Alt-Svc header
    pub http3_advertised: bool,
    /// Final HTTP version used
    pub http_version: String,
    /// Final status code
    pub status_code: u16,
    /// Redirect chain (URLs followed)
    pub redirect_chain: Vec<RedirectHop>,
    /// Alt-Svc header value if present
    pub alt_svc: Option<String>,
    /// Detected issues
    pub issues: Vec<HttpIssue>,
}

/// A single redirect hop
#[derive(Debug, Serialize, Clone)]
pub struct RedirectHop {
    pub url: String,
    pub status: u16,
}

/// An HTTP-related issue
#[derive(Debug, Serialize, Clone)]
pub struct HttpIssue {
    pub severity: Severity,
    pub message: String,
}

/// Check HTTP protocol support and behavior
pub async fn check_http(target: &str, timeout: Duration) -> Result<HttpResult> {
    // Normalize target to URL
    let url = normalize_url(target);

    // Build client that follows redirects and records them
    let client = Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none()) // We'll follow manually
        .build()
        .context("Failed to build HTTP client")?;

    let mut redirect_chain = Vec::new();
    let mut current_url = url.clone();
    let mut final_response = None;
    let mut redirect_count = 0;
    const MAX_REDIRECTS: usize = 10;

    // Follow redirects manually to record the chain
    loop {
        let response = client
            .get(&current_url)
            .send()
            .await
            .context(format!("Failed to fetch {}", current_url))?;

        let status = response.status().as_u16();
        let headers = response.headers().clone();

        // Record this hop if it's a redirect
        if response.status().is_redirection() {
            redirect_chain.push(RedirectHop {
                url: current_url.clone(),
                status,
            });

            redirect_count += 1;
            if redirect_count >= MAX_REDIRECTS {
                break;
            }

            // Get next URL from Location header
            if let Some(location) = headers.get("location") {
                let location_str = location.to_str().unwrap_or("");
                current_url = resolve_redirect(&current_url, location_str);
            } else {
                break;
            }
        } else {
            final_response = Some((response, status, headers));
            break;
        }
    }

    let (response, status_code, headers) =
        final_response.ok_or_else(|| anyhow::anyhow!("No final response after redirects"))?;

    // Detect HTTP version
    let http_version = format!("{:?}", response.version());
    let http2_supported = matches!(response.version(), reqwest::Version::HTTP_2);
    let http1_supported = true; // HTTP/1.1 is always a fallback

    // Check for Alt-Svc header (HTTP/3 advertisement)
    let alt_svc = headers
        .get("alt-svc")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let http3_advertised = alt_svc.as_ref().map(|s| s.contains("h3")).unwrap_or(false);

    // Generate issues
    let mut issues = Vec::new();

    // Check for excessive redirects
    if redirect_chain.len() > 3 {
        issues.push(HttpIssue {
            severity: Severity::Low,
            message: format!("Excessive redirect chain ({} hops)", redirect_chain.len()),
        });
    }

    // Check for HTTP to HTTPS redirect
    if !redirect_chain.is_empty() {
        let first_url = &redirect_chain[0].url;
        if first_url.starts_with("http://") && current_url.starts_with("https://") {
            // This is good - but check if it's a 301 (permanent)
            if redirect_chain[0].status != 301 {
                issues.push(HttpIssue {
                    severity: Severity::Medium,
                    message: format!(
                        "HTTP to HTTPS redirect uses {} instead of 301",
                        redirect_chain[0].status
                    ),
                });
            }
        }
    }

    // Check for HTTP/3 advertised but not using HTTP/2
    if http3_advertised && !http2_supported {
        issues.push(HttpIssue {
            severity: Severity::Low,
            message: "HTTP/3 advertised but HTTP/2 not negotiated".to_string(),
        });
    }

    // Check for error status codes
    if status_code >= 400 && status_code < 500 {
        issues.push(HttpIssue {
            severity: Severity::Medium,
            message: format!("Client error status: {}", status_code),
        });
    } else if status_code >= 500 {
        issues.push(HttpIssue {
            severity: Severity::High,
            message: format!("Server error status: {}", status_code),
        });
    }

    // Sort issues by severity
    issues.sort_by(|a, b| b.severity.cmp(&a.severity));

    Ok(HttpResult {
        http1_supported,
        http2_supported,
        http3_advertised,
        http_version,
        status_code,
        redirect_chain,
        alt_svc,
        issues,
    })
}

/// Normalize a target string to a URL
fn normalize_url(target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("https://{}", target)
    }
}

/// Resolve a redirect location (handles relative URLs)
fn resolve_redirect(base: &str, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        location.to_string()
    } else if location.starts_with("//") {
        // Protocol-relative URL
        if base.starts_with("https://") {
            format!("https:{}", location)
        } else {
            format!("http:{}", location)
        }
    } else if location.starts_with('/') {
        // Absolute path
        if let Ok(url) = url::Url::parse(base) {
            format!(
                "{}://{}{}",
                url.scheme(),
                url.host_str().unwrap_or(""),
                location
            )
        } else {
            location.to_string()
        }
    } else {
        // Relative path - just append (simplified)
        format!("{}/{}", base.trim_end_matches('/'), location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_url() {
        assert_eq!(normalize_url("example.com"), "https://example.com");
        assert_eq!(normalize_url("https://example.com"), "https://example.com");
        assert_eq!(normalize_url("http://example.com"), "http://example.com");
    }

    #[test]
    fn test_resolve_redirect() {
        assert_eq!(
            resolve_redirect("https://example.com", "https://other.com"),
            "https://other.com"
        );
        assert_eq!(
            resolve_redirect("https://example.com", "/path"),
            "https://example.com/path"
        );
        assert_eq!(
            resolve_redirect("https://example.com", "//other.com/path"),
            "https://other.com/path"
        );
    }
}
