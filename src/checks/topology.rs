//! Link spidering and site topology discovery
//!
//! - Discovers same-origin internal links from the target page
//! - Probes discovered URLs to build a site structure map
//! - Identifies broken links and redirect chains

use anyhow::{Context, Result};
use reqwest::Client;
use scraper::{Html, Selector};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use url::Url;

use super::tls::Severity;

/// Configuration for topology check
#[derive(Debug, Clone)]
pub struct TopologyConfig {
    /// Maximum URLs to probe
    pub max_urls: usize,
    /// Include sitemap URLs
    pub include_sitemap: bool,
    /// Count external links
    pub count_external: bool,
    /// Request timeout
    pub timeout: Duration,
}

impl Default for TopologyConfig {
    fn default() -> Self {
        Self {
            max_urls: 50,
            include_sitemap: true,
            count_external: true,
            timeout: Duration::from_secs(10),
        }
    }
}

/// Result of topology/link spidering check
#[derive(Debug, Serialize)]
pub struct TopologyResult {
    /// Base URL that was crawled
    pub base_url: String,
    /// Total number of unique internal URLs discovered
    pub total_internal_urls: usize,
    /// Total number of external URLs found (not probed)
    pub total_external_urls: usize,
    /// URLs discovered and probed
    pub discovered_urls: Vec<DiscoveredUrl>,
    /// Site structure grouped by path segments
    pub structure: SiteStructure,
    /// Broken links (4xx/5xx responses)
    pub broken_links: Vec<BrokenLink>,
    /// Redirect chains detected
    pub redirect_chains: Vec<RedirectChain>,
    /// Detected issues
    pub issues: Vec<TopologyIssue>,
}

/// A discovered URL with its metadata
#[derive(Debug, Serialize, Clone)]
pub struct DiscoveredUrl {
    /// The URL path (relative to base)
    pub path: String,
    /// Full URL
    pub full_url: String,
    /// HTTP status code from HEAD request
    pub status_code: u16,
    /// Content-Type if available
    pub content_type: Option<String>,
    /// How this URL was discovered
    pub source: DiscoverySource,
    /// Redirect location if 3xx
    pub redirect_to: Option<String>,
}

/// How a URL was discovered
#[derive(Debug, Serialize, Clone, PartialEq)]
pub enum DiscoverySource {
    /// From <a href="...">
    Anchor,
    /// From <link href="..."> (canonical, alternate, etc.)
    Link,
    /// From sitemap.xml
    Sitemap,
    /// The root page itself
    Root,
}

impl std::fmt::Display for DiscoverySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoverySource::Anchor => write!(f, "anchor"),
            DiscoverySource::Link => write!(f, "link"),
            DiscoverySource::Sitemap => write!(f, "sitemap"),
            DiscoverySource::Root => write!(f, "root"),
        }
    }
}

/// Site structure grouped by path segments
#[derive(Debug, Serialize, Clone, Default)]
pub struct SiteStructure {
    /// Root-level path segments with counts
    pub paths: Vec<PathSegment>,
    /// Maximum depth observed
    pub max_depth: u8,
}

/// A path segment with count
#[derive(Debug, Serialize, Clone)]
pub struct PathSegment {
    /// Path segment name (e.g., "blog", "products")
    pub name: String,
    /// Number of pages under this path
    pub count: usize,
}

/// Information about a broken link
#[derive(Debug, Serialize, Clone)]
pub struct BrokenLink {
    /// The broken URL
    pub url: String,
    /// HTTP status code
    pub status_code: u16,
    /// How the link was discovered
    pub source: DiscoverySource,
}

/// Information about a redirect chain
#[derive(Debug, Serialize, Clone)]
pub struct RedirectChain {
    /// Original URL
    pub from: String,
    /// Redirect destination
    pub to: String,
    /// HTTP status code (301, 302, etc.)
    pub status_code: u16,
}

/// A topology issue
#[derive(Debug, Serialize, Clone)]
pub struct TopologyIssue {
    pub severity: Severity,
    pub category: String,
    pub message: String,
}

/// Check site topology by spidering links
pub async fn check_topology(target: &str, config: TopologyConfig) -> Result<TopologyResult> {
    let base_url = normalize_url(target);
    let base_parsed = Url::parse(&base_url).context("Invalid base URL")?;
    let base_host = base_parsed.host_str().unwrap_or("").to_lowercase();

    let client = Client::builder()
        .timeout(config.timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Mozilla/5.0 (compatible; Sango/1.0; +https://github.com/raskell-io/sango)")
        .build()
        .context("Failed to build HTTP client")?;

    // Track discovered URLs
    let mut internal_urls: Vec<(String, DiscoverySource)> = Vec::new();
    let mut external_count = 0usize;
    let mut seen: HashSet<String> = HashSet::new();

    // Step 1: Fetch the main page
    let response = client
        .get(&base_url)
        .send()
        .await
        .context("Failed to fetch target page")?;

    if !response.status().is_success() && !response.status().is_redirection() {
        return Err(anyhow::anyhow!(
            "Target returned status {}",
            response.status().as_u16()
        ));
    }

    let html_content = response.text().await.unwrap_or_default();
    let document = Html::parse_document(&html_content);

    // Add root page
    seen.insert(base_url.clone());

    // Extract links from HTML
    let (html_internal, html_external) = extract_links_from_html(&document, &base_url, &base_host);
    if config.count_external {
        external_count += html_external;
    }

    for (url, source) in html_internal {
        let normalized = normalize_link_url(&url);
        if !seen.contains(&normalized) {
            seen.insert(normalized.clone());
            internal_urls.push((normalized, source));
        }
    }

    // Step 2: Try to get sitemap URLs (if enabled)
    if config.include_sitemap {
        let sitemap_urls = fetch_sitemap_urls(&client, &base_url).await;
        for url in sitemap_urls {
            let normalized = normalize_link_url(&url);
            if !seen.contains(&normalized) && is_same_origin(&normalized, &base_host) {
                seen.insert(normalized.clone());
                internal_urls.push((normalized, DiscoverySource::Sitemap));
            }
        }
    }

    // Step 3: Probe discovered URLs with HEAD requests (up to max_urls)
    let urls_to_probe: Vec<_> = internal_urls.into_iter().take(config.max_urls).collect();

    let mut discovered_urls: Vec<DiscoveredUrl> = Vec::new();
    let mut broken_links: Vec<BrokenLink> = Vec::new();
    let mut redirect_chains: Vec<RedirectChain> = Vec::new();

    // Add root page as first discovered URL
    discovered_urls.push(DiscoveredUrl {
        path: "/".to_string(),
        full_url: base_url.clone(),
        status_code: 200,
        content_type: Some("text/html".to_string()),
        source: DiscoverySource::Root,
        redirect_to: None,
    });

    // Probe URLs in parallel
    let probe_results = probe_urls_parallel(&client, &urls_to_probe).await;

    for result in probe_results {
        // Check for broken links
        if result.status_code >= 400 {
            broken_links.push(BrokenLink {
                url: result.full_url.clone(),
                status_code: result.status_code,
                source: result.source.clone(),
            });
        }

        // Check for redirects
        if result.status_code >= 300 && result.status_code < 400 {
            if let Some(ref redirect_to) = result.redirect_to {
                redirect_chains.push(RedirectChain {
                    from: result.full_url.clone(),
                    to: redirect_to.clone(),
                    status_code: result.status_code,
                });
            }
        }

        discovered_urls.push(result);
    }

    // Step 4: Build site structure
    let structure = build_site_structure(&discovered_urls);

    // Step 5: Generate issues
    let issues = generate_issues(&broken_links, &redirect_chains, discovered_urls.len());

    Ok(TopologyResult {
        base_url,
        total_internal_urls: discovered_urls.len(),
        total_external_urls: external_count,
        discovered_urls,
        structure,
        broken_links,
        redirect_chains,
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

    // Remove trailing slash and path to get base URL with path
    if let Ok(parsed) = Url::parse(&url) {
        format!(
            "{}://{}{}",
            parsed.scheme(),
            parsed.host_str().unwrap_or(target),
            parsed.path().trim_end_matches('/')
        )
    } else {
        url
    }
}

/// Normalize a discovered link URL
fn normalize_link_url(url: &str) -> String {
    // Remove fragment
    url.split('#').next().unwrap_or(url).to_string()
}

/// Check if URL is same-origin
fn is_same_origin(url: &str, base_host: &str) -> bool {
    if let Ok(parsed) = Url::parse(url) {
        let host = parsed.host_str().unwrap_or("").to_lowercase();
        host == base_host
    } else {
        false
    }
}

/// Extract links from HTML document
/// Returns (internal_links, external_count)
fn extract_links_from_html(
    document: &Html,
    base_url: &str,
    base_host: &str,
) -> (Vec<(String, DiscoverySource)>, usize) {
    let mut internal_links = Vec::new();
    let mut external_count = 0usize;

    // Extract <a href="...">
    if let Ok(selector) = Selector::parse("a[href]") {
        for element in document.select(&selector) {
            if let Some(href) = element.value().attr("href") {
                if let Some(url) = resolve_url(href, base_url) {
                    if is_same_origin(&url, base_host) {
                        internal_links.push((url, DiscoverySource::Anchor));
                    } else if url.starts_with("http") {
                        external_count += 1;
                    }
                }
            }
        }
    }

    // Extract <link href="..."> (canonical, alternate, etc., not stylesheets)
    if let Ok(selector) = Selector::parse("link[href][rel]:not([rel='stylesheet']):not([rel='preload']):not([rel='icon']):not([rel='preconnect']):not([rel='dns-prefetch'])") {
        for element in document.select(&selector) {
            if let Some(href) = element.value().attr("href") {
                if let Some(url) = resolve_url(href, base_url) {
                    if is_same_origin(&url, base_host) {
                        internal_links.push((url, DiscoverySource::Link));
                    }
                }
            }
        }
    }

    (internal_links, external_count)
}

/// Resolve a potentially relative URL against a base
fn resolve_url(href: &str, base_url: &str) -> Option<String> {
    let href = href.trim();

    // Skip empty, javascript:, mailto:, tel:, data:
    if href.is_empty()
        || href.starts_with("javascript:")
        || href.starts_with("mailto:")
        || href.starts_with("tel:")
        || href.starts_with("data:")
        || href.starts_with('#')
    {
        return None;
    }

    // Absolute URL
    if href.starts_with("http://") || href.starts_with("https://") {
        return Some(href.to_string());
    }

    // Protocol-relative URL
    if href.starts_with("//") {
        return Some(format!("https:{}", href));
    }

    // Relative URL - resolve against base
    if let Ok(base) = Url::parse(base_url) {
        if let Ok(resolved) = base.join(href) {
            return Some(resolved.to_string());
        }
    }

    None
}

/// Fetch sitemap URLs from sitemap.xml
async fn fetch_sitemap_urls(client: &Client, base_url: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let base = if let Ok(parsed) = Url::parse(base_url) {
        format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""))
    } else {
        return urls;
    };

    // Try standard sitemap locations
    let sitemap_locations = [
        format!("{}/sitemap.xml", base),
        format!("{}/sitemap_index.xml", base),
    ];

    for sitemap_url in &sitemap_locations {
        if let Ok(response) = client.get(sitemap_url).send().await {
            if response.status().is_success() {
                if let Ok(content) = response.text().await {
                    // Simple extraction of <loc> tags
                    for loc in extract_sitemap_locs(&content) {
                        urls.push(loc);
                    }
                    // If we found URLs, don't try other locations
                    if !urls.is_empty() {
                        break;
                    }
                }
            }
        }
    }

    // Limit sitemap URLs
    urls.truncate(100);
    urls
}

/// Extract <loc> values from sitemap XML
fn extract_sitemap_locs(content: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut remaining = content;

    while let Some(start) = remaining.find("<loc>") {
        let after_open = &remaining[start + 5..];
        if let Some(end) = after_open.find("</loc>") {
            let url = after_open[..end].trim().to_string();
            if url.starts_with("http") {
                urls.push(url);
            }
            remaining = &after_open[end + 6..];
        } else {
            break;
        }
    }

    urls
}

/// Probe URLs with HEAD requests in parallel
async fn probe_urls_parallel(
    client: &Client,
    urls: &[(String, DiscoverySource)],
) -> Vec<DiscoveredUrl> {
    use futures::future::join_all;

    let futures: Vec<_> = urls
        .iter()
        .map(|(url, source)| probe_single_url(client, url, source.clone()))
        .collect();

    let results = join_all(futures).await;
    results.into_iter().filter_map(|r| r.ok()).collect()
}

/// Probe a single URL with HEAD request
async fn probe_single_url(
    client: &Client,
    url: &str,
    source: DiscoverySource,
) -> Result<DiscoveredUrl> {
    let response = client.head(url).send().await?;

    let status_code = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(';').next().unwrap_or(s).trim().to_string());

    let redirect_to = if response.status().is_redirection() {
        response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    } else {
        None
    };

    let path = Url::parse(url)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| url.to_string());

    Ok(DiscoveredUrl {
        path,
        full_url: url.to_string(),
        status_code,
        content_type,
        source,
        redirect_to,
    })
}

/// Build site structure from discovered URLs
fn build_site_structure(urls: &[DiscoveredUrl]) -> SiteStructure {
    let mut path_counts: HashMap<String, usize> = HashMap::new();
    let mut max_depth: u8 = 0;

    for url in urls {
        // Count segments
        let segments: Vec<&str> = url
            .path
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let depth = segments.len() as u8;
        if depth > max_depth {
            max_depth = depth;
        }

        // Count first-level path segment
        if let Some(first_segment) = segments.first() {
            *path_counts.entry(first_segment.to_string()).or_insert(0) += 1;
        } else {
            *path_counts.entry("/".to_string()).or_insert(0) += 1;
        }
    }

    // Convert to sorted list
    let mut paths: Vec<PathSegment> = path_counts
        .into_iter()
        .map(|(name, count)| PathSegment { name, count })
        .collect();

    paths.sort_by(|a, b| b.count.cmp(&a.count));

    SiteStructure { paths, max_depth }
}

/// Generate issues based on topology results
fn generate_issues(
    broken_links: &[BrokenLink],
    redirect_chains: &[RedirectChain],
    total_urls: usize,
) -> Vec<TopologyIssue> {
    let mut issues = Vec::new();

    // Broken links
    if !broken_links.is_empty() {
        let severity = if broken_links.len() > 5 {
            Severity::High
        } else {
            Severity::Medium
        };

        issues.push(TopologyIssue {
            severity,
            category: "broken-links".to_string(),
            message: format!(
                "{} broken links found (4xx/5xx responses)",
                broken_links.len()
            ),
        });
    }

    // Redirect chains
    let permanent_redirects: Vec<_> = redirect_chains
        .iter()
        .filter(|r| r.status_code == 301 || r.status_code == 308)
        .collect();

    let temporary_redirects: Vec<_> = redirect_chains
        .iter()
        .filter(|r| r.status_code == 302 || r.status_code == 307)
        .collect();

    if !permanent_redirects.is_empty() {
        issues.push(TopologyIssue {
            severity: Severity::Low,
            category: "redirects".to_string(),
            message: format!(
                "{} permanent redirects found - consider updating links",
                permanent_redirects.len()
            ),
        });
    }

    if !temporary_redirects.is_empty() {
        issues.push(TopologyIssue {
            severity: Severity::Medium,
            category: "redirects".to_string(),
            message: format!(
                "{} temporary redirects found - may indicate configuration issues",
                temporary_redirects.len()
            ),
        });
    }

    // Very few internal links
    if total_urls <= 1 {
        issues.push(TopologyIssue {
            severity: Severity::Low,
            category: "structure".to_string(),
            message: "No internal links discovered - page may be orphaned or standalone"
                .to_string(),
        });
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_url() {
        assert_eq!(normalize_url("example.com"), "https://example.com");
        assert_eq!(
            normalize_url("https://example.com/path/"),
            "https://example.com/path"
        );
        assert_eq!(normalize_url("http://example.com"), "http://example.com");
    }

    #[test]
    fn test_is_same_origin() {
        assert!(is_same_origin("https://example.com/page", "example.com"));
        assert!(is_same_origin("https://EXAMPLE.COM/page", "example.com"));
        assert!(!is_same_origin("https://other.com/page", "example.com"));
        assert!(!is_same_origin(
            "https://sub.example.com/page",
            "example.com"
        ));
    }

    #[test]
    fn test_resolve_url() {
        let base = "https://example.com/blog/post";

        assert_eq!(
            resolve_url("/about", base),
            Some("https://example.com/about".to_string())
        );
        assert_eq!(
            resolve_url("../contact", base),
            Some("https://example.com/contact".to_string())
        );
        assert_eq!(
            resolve_url("https://other.com/page", base),
            Some("https://other.com/page".to_string())
        );
        assert_eq!(resolve_url("javascript:void(0)", base), None);
        assert_eq!(resolve_url("mailto:test@test.com", base), None);
        assert_eq!(resolve_url("#section", base), None);
    }

    #[test]
    fn test_extract_sitemap_locs() {
        let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/page1</loc></url>
  <url><loc>https://example.com/page2</loc></url>
</urlset>"#;

        let urls = extract_sitemap_locs(content);
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], "https://example.com/page1");
        assert_eq!(urls[1], "https://example.com/page2");
    }

    #[test]
    fn test_build_site_structure() {
        let urls = vec![
            DiscoveredUrl {
                path: "/".to_string(),
                full_url: "https://example.com/".to_string(),
                status_code: 200,
                content_type: Some("text/html".to_string()),
                source: DiscoverySource::Root,
                redirect_to: None,
            },
            DiscoveredUrl {
                path: "/blog/post1".to_string(),
                full_url: "https://example.com/blog/post1".to_string(),
                status_code: 200,
                content_type: Some("text/html".to_string()),
                source: DiscoverySource::Anchor,
                redirect_to: None,
            },
            DiscoveredUrl {
                path: "/blog/post2".to_string(),
                full_url: "https://example.com/blog/post2".to_string(),
                status_code: 200,
                content_type: Some("text/html".to_string()),
                source: DiscoverySource::Anchor,
                redirect_to: None,
            },
            DiscoveredUrl {
                path: "/about".to_string(),
                full_url: "https://example.com/about".to_string(),
                status_code: 200,
                content_type: Some("text/html".to_string()),
                source: DiscoverySource::Anchor,
                redirect_to: None,
            },
        ];

        let structure = build_site_structure(&urls);
        assert_eq!(structure.max_depth, 2);
        assert!(structure
            .paths
            .iter()
            .any(|p| p.name == "blog" && p.count == 2));
    }
}
