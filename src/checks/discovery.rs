//! Subpath and resource discovery
//!
//! - robots.txt parsing and analysis
//! - sitemap.xml parsing
//! - Common path probing
//! - Structure reporting

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;

use super::tls::Severity;

/// Result of discovery checks
#[derive(Debug, Serialize)]
pub struct DiscoveryResult {
    /// robots.txt analysis if present
    pub robots: Option<RobotsInfo>,
    /// Sitemap information if present
    pub sitemap: Option<SitemapInfo>,
    /// Discovered paths from probing
    pub discovered_paths: Vec<DiscoveredPath>,
    /// Well-known endpoints found
    pub well_known: Vec<WellKnownEndpoint>,
    /// Detected issues
    pub issues: Vec<DiscoveryIssue>,
}

/// robots.txt information
#[derive(Debug, Serialize, Clone)]
pub struct RobotsInfo {
    /// Whether robots.txt exists
    pub exists: bool,
    /// HTTP status code
    pub status_code: u16,
    /// Allowed paths (for all user-agents or *)
    pub allowed: Vec<String>,
    /// Disallowed paths (for all user-agents or *)
    pub disallowed: Vec<String>,
    /// Sitemap URLs referenced
    pub sitemaps: Vec<String>,
    /// Crawl-delay if specified (in seconds)
    pub crawl_delay: Option<u64>,
    /// Whether the entire site is blocked
    pub blocks_all: bool,
    /// Raw content (truncated for large files)
    pub raw_preview: String,
}

/// Sitemap information
#[derive(Debug, Serialize, Clone)]
pub struct SitemapInfo {
    /// Whether a sitemap was found
    pub exists: bool,
    /// Sitemap URL that was found
    pub url: String,
    /// Type of sitemap (sitemap, sitemapindex)
    pub sitemap_type: SitemapType,
    /// Number of URLs in sitemap (or sitemaps in index)
    pub entry_count: usize,
    /// Sample URLs from sitemap (first 10)
    pub sample_urls: Vec<SitemapEntry>,
    /// Is the sitemap gzipped
    pub is_gzipped: bool,
    /// Child sitemaps if this is an index
    pub child_sitemaps: Vec<String>,
}

/// Type of sitemap
#[derive(Debug, Serialize, Clone, PartialEq)]
pub enum SitemapType {
    /// Standard sitemap with URLs
    Sitemap,
    /// Sitemap index referencing other sitemaps
    SitemapIndex,
    /// Unknown or invalid format
    Unknown,
}

/// A single entry from a sitemap
#[derive(Debug, Serialize, Clone)]
pub struct SitemapEntry {
    /// URL location
    pub loc: String,
    /// Last modification date if present
    pub lastmod: Option<String>,
    /// Change frequency if present
    pub changefreq: Option<String>,
    /// Priority if present
    pub priority: Option<f32>,
}

/// A discovered path from probing
#[derive(Debug, Serialize, Clone)]
pub struct DiscoveredPath {
    /// Path that was probed
    pub path: String,
    /// HTTP status code
    pub status_code: u16,
    /// Content-Type header if present
    pub content_type: Option<String>,
    /// Content-Length if present
    pub content_length: Option<u64>,
    /// Whether this is a redirect
    pub is_redirect: bool,
    /// Redirect location if applicable
    pub redirect_location: Option<String>,
}

/// A well-known endpoint
#[derive(Debug, Serialize, Clone)]
pub struct WellKnownEndpoint {
    /// Endpoint path
    pub path: String,
    /// HTTP status code
    pub status_code: u16,
    /// Content-Type if present
    pub content_type: Option<String>,
    /// Description of what this endpoint is for
    pub description: String,
}

/// A discovery issue
#[derive(Debug, Serialize, Clone)]
pub struct DiscoveryIssue {
    pub severity: Severity,
    pub category: String,
    pub message: String,
}

/// Common paths to probe
const COMMON_PATHS: &[&str] = &[
    "/api",
    "/api/v1",
    "/graphql",
    "/health",
    "/healthz",
    "/ready",
    "/metrics",
    "/status",
    "/version",
    "/favicon.ico",
    "/manifest.json",
    "/humans.txt",
    "/security.txt",
    "/ads.txt",
    "/app-ads.txt",
];

/// Well-known endpoints to check
const WELL_KNOWN_PATHS: &[(&str, &str)] = &[
    ("/.well-known/security.txt", "Security contact information"),
    (
        "/.well-known/openid-configuration",
        "OpenID Connect discovery",
    ),
    ("/.well-known/jwks.json", "JSON Web Key Set"),
    ("/.well-known/assetlinks.json", "Android App Links"),
    (
        "/.well-known/apple-app-site-association",
        "Apple Universal Links",
    ),
    ("/.well-known/change-password", "Password change URL"),
    ("/.well-known/host-meta", "Web Host Metadata"),
    ("/.well-known/nodeinfo", "NodeInfo for federated services"),
    ("/.well-known/webfinger", "WebFinger discovery"),
];

/// Check discovery endpoints
pub async fn check_discovery(target: &str, timeout: Duration) -> Result<DiscoveryResult> {
    let base_url = normalize_url(target);

    let client = Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none()) // Don't follow redirects automatically
        .build()
        .context("Failed to build HTTP client")?;

    // Fetch robots.txt
    let robots = fetch_robots(&client, &base_url).await;

    // Determine sitemap URLs to check
    let sitemap_urls = get_sitemap_urls(&robots, &base_url);

    // Fetch sitemap
    let sitemap = fetch_sitemap(&client, &sitemap_urls, timeout).await;

    // Probe common paths
    let discovered_paths = probe_common_paths(&client, &base_url).await;

    // Check well-known endpoints
    let well_known = check_well_known(&client, &base_url).await;

    // Generate issues
    let issues = generate_issues(&robots, &sitemap, &discovered_paths, &well_known);

    Ok(DiscoveryResult {
        robots,
        sitemap,
        discovered_paths,
        well_known,
        issues,
    })
}

/// Normalize target to base URL
fn normalize_url(target: &str) -> String {
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("https://{}", target)
    };

    // Remove trailing slash and path to get base URL
    if let Ok(parsed) = url::Url::parse(&url) {
        format!(
            "{}://{}",
            parsed.scheme(),
            parsed.host_str().unwrap_or(target)
        )
    } else {
        url
    }
}

/// Fetch and parse robots.txt
async fn fetch_robots(client: &Client, base_url: &str) -> Option<RobotsInfo> {
    let robots_url = format!("{}/robots.txt", base_url);

    let response = match client.get(&robots_url).send().await {
        Ok(r) => r,
        Err(_) => return None,
    };

    let status_code = response.status().as_u16();

    if !response.status().is_success() {
        return Some(RobotsInfo {
            exists: false,
            status_code,
            allowed: vec![],
            disallowed: vec![],
            sitemaps: vec![],
            crawl_delay: None,
            blocks_all: false,
            raw_preview: String::new(),
        });
    }

    let content = match response.text().await {
        Ok(t) => t,
        Err(_) => return None,
    };

    parse_robots_txt(&content, status_code)
}

/// Parse robots.txt content
fn parse_robots_txt(content: &str, status_code: u16) -> Option<RobotsInfo> {
    let mut allowed = Vec::new();
    let mut disallowed = Vec::new();
    let mut sitemaps = Vec::new();
    let mut crawl_delay = None;
    let mut blocks_all = false;
    let mut in_relevant_section = false; // For User-agent: * or all

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let lower = line.to_lowercase();

        // Check for User-agent
        if lower.starts_with("user-agent:") {
            let agent = line[11..].trim().to_lowercase();
            in_relevant_section = agent == "*" || agent.is_empty();
            continue;
        }

        // Parse Sitemap (always relevant, not user-agent specific)
        if lower.starts_with("sitemap:") {
            let url = line[8..].trim().to_string();
            if !url.is_empty() {
                sitemaps.push(url);
            }
            continue;
        }

        // Only process other directives if in relevant section
        if !in_relevant_section {
            continue;
        }

        if lower.starts_with("disallow:") {
            let path = line[9..].trim().to_string();
            if !path.is_empty() {
                if path == "/" {
                    blocks_all = true;
                }
                disallowed.push(path);
            }
        } else if lower.starts_with("allow:") {
            let path = line[6..].trim().to_string();
            if !path.is_empty() {
                allowed.push(path);
            }
        } else if lower.starts_with("crawl-delay:") {
            if let Ok(delay) = line[12..].trim().parse::<u64>() {
                crawl_delay = Some(delay);
            }
        }
    }

    // Create raw preview (first 500 chars)
    let raw_preview = if content.len() > 500 {
        format!("{}...", &content[..500])
    } else {
        content.to_string()
    };

    Some(RobotsInfo {
        exists: true,
        status_code,
        allowed,
        disallowed,
        sitemaps,
        crawl_delay,
        blocks_all,
        raw_preview,
    })
}

/// Get sitemap URLs to check
fn get_sitemap_urls(robots: &Option<RobotsInfo>, base_url: &str) -> Vec<String> {
    let mut urls = Vec::new();

    // Add sitemaps from robots.txt
    if let Some(ref r) = robots {
        urls.extend(r.sitemaps.clone());
    }

    // Add default locations if no sitemaps found
    if urls.is_empty() {
        urls.push(format!("{}/sitemap.xml", base_url));
        urls.push(format!("{}/sitemap_index.xml", base_url));
    }

    urls
}

/// Fetch and parse sitemap
async fn fetch_sitemap(
    client: &Client,
    urls: &[String],
    _timeout: Duration,
) -> Option<SitemapInfo> {
    for url in urls {
        let is_gzipped = url.ends_with(".gz");

        let response = match client.get(url).send().await {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };

        let content = if is_gzipped {
            // For gzipped sitemaps, we'd need to decompress
            // For now, just note that it exists
            match response.bytes().await {
                Ok(_bytes) => {
                    // TODO: decompress gzipped sitemaps with flate2
                    // For now, return basic info that it exists
                    return Some(SitemapInfo {
                        exists: true,
                        url: url.clone(),
                        sitemap_type: SitemapType::Unknown,
                        entry_count: 0,
                        sample_urls: vec![],
                        is_gzipped: true,
                        child_sitemaps: vec![],
                    });
                }
                Err(_) => continue,
            }
        } else {
            match response.text().await {
                Ok(t) => t,
                Err(_) => continue,
            }
        };

        if let Some(info) = parse_sitemap(&content, url) {
            return Some(info);
        }
    }

    None
}

/// Parse sitemap XML content
fn parse_sitemap(content: &str, url: &str) -> Option<SitemapInfo> {
    // Simple XML parsing without external dependency
    // Look for <sitemapindex> or <urlset>

    let content_lower = content.to_lowercase();

    let sitemap_type = if content_lower.contains("<sitemapindex") {
        SitemapType::SitemapIndex
    } else if content_lower.contains("<urlset") {
        SitemapType::Sitemap
    } else {
        return None;
    };

    let mut sample_urls = Vec::new();
    let mut child_sitemaps = Vec::new();
    let mut entry_count = 0;

    match sitemap_type {
        SitemapType::SitemapIndex => {
            // Parse sitemap index - look for <sitemap><loc>
            for sitemap_match in content.split("<sitemap>").skip(1) {
                entry_count += 1;
                if let Some(loc) = extract_xml_tag(sitemap_match, "loc") {
                    child_sitemaps.push(loc);
                }
            }
        }
        SitemapType::Sitemap => {
            // Parse urlset - look for <url><loc>
            for url_match in content.split("<url>").skip(1) {
                entry_count += 1;

                if sample_urls.len() < 10 {
                    let loc = extract_xml_tag(url_match, "loc");
                    let lastmod = extract_xml_tag(url_match, "lastmod");
                    let changefreq = extract_xml_tag(url_match, "changefreq");
                    let priority =
                        extract_xml_tag(url_match, "priority").and_then(|p| p.parse::<f32>().ok());

                    if let Some(loc) = loc {
                        sample_urls.push(SitemapEntry {
                            loc,
                            lastmod,
                            changefreq,
                            priority,
                        });
                    }
                }
            }
        }
        SitemapType::Unknown => {}
    }

    Some(SitemapInfo {
        exists: true,
        url: url.to_string(),
        sitemap_type,
        entry_count,
        sample_urls,
        is_gzipped: false,
        child_sitemaps,
    })
}

/// Extract content from an XML tag
fn extract_xml_tag(content: &str, tag: &str) -> Option<String> {
    let open_tag = format!("<{}>", tag);
    let close_tag = format!("</{}>", tag);

    let start = content.find(&open_tag)? + open_tag.len();
    let end = content.find(&close_tag)?;

    if start < end {
        Some(content[start..end].trim().to_string())
    } else {
        None
    }
}

/// Probe common paths
async fn probe_common_paths(client: &Client, base_url: &str) -> Vec<DiscoveredPath> {
    let mut results = Vec::new();

    // Probe paths concurrently in batches
    let futures: Vec<_> = COMMON_PATHS
        .iter()
        .map(|path| probe_path(client, base_url, path))
        .collect();

    let responses = futures::future::join_all(futures).await;

    for result in responses {
        if let Some(path_info) = result {
            // Only include if we got a meaningful response (not 404)
            if path_info.status_code != 404 {
                results.push(path_info);
            }
        }
    }

    results
}

/// Probe a single path
async fn probe_path(client: &Client, base_url: &str, path: &str) -> Option<DiscoveredPath> {
    let url = format!("{}{}", base_url, path);

    let response = client.head(&url).send().await.ok()?;

    let status_code = response.status().as_u16();
    let is_redirect = response.status().is_redirection();

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let content_length = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    let redirect_location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    Some(DiscoveredPath {
        path: path.to_string(),
        status_code,
        content_type,
        content_length,
        is_redirect,
        redirect_location,
    })
}

/// Check well-known endpoints
async fn check_well_known(client: &Client, base_url: &str) -> Vec<WellKnownEndpoint> {
    let mut results = Vec::new();

    let futures: Vec<_> = WELL_KNOWN_PATHS
        .iter()
        .map(|(path, desc)| check_well_known_path(client, base_url, path, desc))
        .collect();

    let responses = futures::future::join_all(futures).await;

    for result in responses {
        if let Some(endpoint) = result {
            // Only include successful responses
            if endpoint.status_code == 200 {
                results.push(endpoint);
            }
        }
    }

    results
}

/// Check a single well-known path
async fn check_well_known_path(
    client: &Client,
    base_url: &str,
    path: &str,
    description: &str,
) -> Option<WellKnownEndpoint> {
    let url = format!("{}{}", base_url, path);

    let response = client.head(&url).send().await.ok()?;

    let status_code = response.status().as_u16();

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    Some(WellKnownEndpoint {
        path: path.to_string(),
        status_code,
        content_type,
        description: description.to_string(),
    })
}

/// Generate issues based on discovery results
fn generate_issues(
    robots: &Option<RobotsInfo>,
    sitemap: &Option<SitemapInfo>,
    discovered_paths: &[DiscoveredPath],
    well_known: &[WellKnownEndpoint],
) -> Vec<DiscoveryIssue> {
    let mut issues = Vec::new();

    // robots.txt issues
    match robots {
        None => {
            issues.push(DiscoveryIssue {
                severity: Severity::Low,
                category: "robots.txt".to_string(),
                message: "Could not fetch robots.txt".to_string(),
            });
        }
        Some(r) if !r.exists => {
            issues.push(DiscoveryIssue {
                severity: Severity::Low,
                category: "robots.txt".to_string(),
                message: format!("robots.txt not found (status {})", r.status_code),
            });
        }
        Some(r) => {
            if r.blocks_all {
                issues.push(DiscoveryIssue {
                    severity: Severity::Medium,
                    category: "robots.txt".to_string(),
                    message: "robots.txt blocks all crawlers (Disallow: /)".to_string(),
                });
            }
            if r.sitemaps.is_empty() {
                issues.push(DiscoveryIssue {
                    severity: Severity::Low,
                    category: "robots.txt".to_string(),
                    message: "No sitemap referenced in robots.txt".to_string(),
                });
            }
        }
    }

    // Sitemap issues
    match sitemap {
        None => {
            issues.push(DiscoveryIssue {
                severity: Severity::Medium,
                category: "sitemap".to_string(),
                message: "No sitemap found at standard locations".to_string(),
            });
        }
        Some(s) => {
            if s.entry_count == 0 {
                issues.push(DiscoveryIssue {
                    severity: Severity::Low,
                    category: "sitemap".to_string(),
                    message: "Sitemap exists but contains no entries".to_string(),
                });
            }
            if s.entry_count > 50000 {
                issues.push(DiscoveryIssue {
                    severity: Severity::Low,
                    category: "sitemap".to_string(),
                    message: format!(
                        "Sitemap exceeds recommended limit ({} entries, max 50000)",
                        s.entry_count
                    ),
                });
            }
        }
    }

    // Security.txt check
    let has_security_txt = well_known.iter().any(|w| w.path.contains("security.txt"));

    if !has_security_txt {
        issues.push(DiscoveryIssue {
            severity: Severity::Low,
            category: "well-known".to_string(),
            message: "No security.txt found (recommended for security contact info)".to_string(),
        });
    }

    // Check for exposed sensitive paths
    for path in discovered_paths {
        if path.status_code == 200 {
            if path.path == "/metrics" || path.path == "/healthz" || path.path == "/status" {
                issues.push(DiscoveryIssue {
                    severity: Severity::Low,
                    category: "exposure".to_string(),
                    message: format!(
                        "{} is publicly accessible (consider restricting)",
                        path.path
                    ),
                });
            }
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_robots_txt() {
        let content = r#"
User-agent: *
Disallow: /admin
Disallow: /private/
Allow: /public

Sitemap: https://example.com/sitemap.xml
Crawl-delay: 10
"#;

        let info = parse_robots_txt(content, 200).unwrap();
        assert!(info.exists);
        assert_eq!(info.disallowed, vec!["/admin", "/private/"]);
        assert_eq!(info.allowed, vec!["/public"]);
        assert_eq!(info.sitemaps, vec!["https://example.com/sitemap.xml"]);
        assert_eq!(info.crawl_delay, Some(10));
        assert!(!info.blocks_all);
    }

    #[test]
    fn test_parse_robots_blocks_all() {
        let content = r#"
User-agent: *
Disallow: /
"#;

        let info = parse_robots_txt(content, 200).unwrap();
        assert!(info.blocks_all);
    }

    #[test]
    fn test_parse_sitemap_urlset() {
        let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://example.com/page1</loc>
    <lastmod>2024-01-01</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://example.com/page2</loc>
  </url>
</urlset>"#;

        let info = parse_sitemap(content, "https://example.com/sitemap.xml").unwrap();
        assert!(info.exists);
        assert_eq!(info.sitemap_type, SitemapType::Sitemap);
        assert_eq!(info.entry_count, 2);
        assert_eq!(info.sample_urls.len(), 2);
        assert_eq!(info.sample_urls[0].loc, "https://example.com/page1");
        assert_eq!(info.sample_urls[0].lastmod, Some("2024-01-01".to_string()));
        assert_eq!(info.sample_urls[0].priority, Some(0.8));
    }

    #[test]
    fn test_parse_sitemap_index() {
        let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap>
    <loc>https://example.com/sitemap1.xml</loc>
  </sitemap>
  <sitemap>
    <loc>https://example.com/sitemap2.xml</loc>
  </sitemap>
</sitemapindex>"#;

        let info = parse_sitemap(content, "https://example.com/sitemap_index.xml").unwrap();
        assert_eq!(info.sitemap_type, SitemapType::SitemapIndex);
        assert_eq!(info.entry_count, 2);
        assert_eq!(info.child_sitemaps.len(), 2);
    }

    #[test]
    fn test_normalize_url() {
        assert_eq!(normalize_url("example.com"), "https://example.com");
        assert_eq!(
            normalize_url("https://example.com/path"),
            "https://example.com"
        );
        assert_eq!(normalize_url("http://example.com"), "http://example.com");
    }

    #[test]
    fn test_extract_xml_tag() {
        let content = "<loc>https://example.com</loc><lastmod>2024-01-01</lastmod>";
        assert_eq!(
            extract_xml_tag(content, "loc"),
            Some("https://example.com".to_string())
        );
        assert_eq!(
            extract_xml_tag(content, "lastmod"),
            Some("2024-01-01".to_string())
        );
        assert_eq!(extract_xml_tag(content, "missing"), None);
    }
}
