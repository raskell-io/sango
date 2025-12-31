//! Asset loading analysis
//!
//! - Extracts all assets from HTML (scripts, stylesheets, images, fonts, media)
//! - Measures timing for each asset (similar to Lighthouse)
//! - Classifies provenance (same-origin, CDN, third-party)
//! - Analyzes cache headers and sizes

use anyhow::{Context, Result};
use reqwest::Client;
use scraper::{Html, Selector};
use serde::Serialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use url::Url;

use super::tls::Severity;

/// Configuration for asset analysis
#[derive(Debug, Clone)]
pub struct AssetsConfig {
    /// Maximum assets to analyze
    pub max_assets: usize,
    /// Request timeout
    pub timeout: Duration,
    /// Slow asset threshold in ms
    pub slow_threshold_ms: u64,
    /// Very slow asset threshold in ms
    pub very_slow_threshold_ms: u64,
    /// Large JS threshold in bytes
    pub large_js_bytes: u64,
    /// Large image threshold in bytes
    pub large_image_bytes: u64,
    /// Third-party warning threshold (0-100)
    pub third_party_threshold: u64,
    /// Include font assets
    pub include_fonts: bool,
    /// Include media assets
    pub include_media: bool,
}

impl Default for AssetsConfig {
    fn default() -> Self {
        Self {
            max_assets: 50,
            timeout: Duration::from_secs(10),
            slow_threshold_ms: 500,
            very_slow_threshold_ms: 2000,
            large_js_bytes: 100 * 1024,    // 100KB
            large_image_bytes: 500 * 1024, // 500KB
            third_party_threshold: 50,
            include_fonts: true,
            include_media: true,
        }
    }
}

/// Result of asset analysis
#[derive(Debug, Serialize)]
pub struct AssetsResult {
    /// Total number of assets analyzed
    pub total_assets: usize,
    /// Total size of all assets in bytes
    pub total_size: u64,
    /// Total size formatted (e.g., "1.5 MB")
    pub total_size_formatted: String,
    /// Total load time in milliseconds
    pub total_load_time_ms: u64,
    /// List of analyzed assets
    pub assets: Vec<AssetInfo>,
    /// Breakdown by asset type
    pub by_type: HashMap<String, TypeBreakdown>,
    /// Breakdown by provenance
    pub by_provenance: HashMap<String, ProvenanceBreakdown>,
    /// Third-party percentage (0-100)
    pub third_party_percentage: f32,
    /// Slowest assets (top 5)
    pub slowest: Vec<AssetSummary>,
    /// Largest assets (top 5)
    pub largest: Vec<AssetSummary>,
    /// Assets missing cache headers
    pub uncached_count: usize,
    /// Detected issues
    pub issues: Vec<AssetIssue>,
}

/// Information about a single asset
#[derive(Debug, Serialize, Clone)]
pub struct AssetInfo {
    /// Asset URL
    pub url: String,
    /// Asset type
    pub asset_type: AssetType,
    /// Asset size in bytes
    pub size: u64,
    /// Size formatted
    pub size_formatted: String,
    /// Total load time in milliseconds
    pub load_time_ms: u64,
    /// Provenance
    pub provenance: Provenance,
    /// CDN name if detected
    pub cdn_name: Option<String>,
    /// Has cache headers
    pub is_cached: bool,
    /// Cache max-age if present
    pub cache_max_age: Option<u64>,
    /// HTTP status code
    pub status_code: u16,
    /// How the asset was discovered
    pub source: AssetSource,
}

/// Simplified asset info for top-N lists
#[derive(Debug, Serialize, Clone)]
pub struct AssetSummary {
    /// Asset URL (truncated)
    pub url: String,
    /// Asset type
    pub asset_type: AssetType,
    /// Size in bytes
    pub size: u64,
    /// Load time in ms
    pub load_time_ms: u64,
}

/// Asset type classification
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssetType {
    JavaScript,
    CSS,
    Image,
    Font,
    Media,
    Other,
}

impl std::fmt::Display for AssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetType::JavaScript => write!(f, "JavaScript"),
            AssetType::CSS => write!(f, "CSS"),
            AssetType::Image => write!(f, "Image"),
            AssetType::Font => write!(f, "Font"),
            AssetType::Media => write!(f, "Media"),
            AssetType::Other => write!(f, "Other"),
        }
    }
}

/// Asset provenance classification
#[derive(Debug, Serialize, Clone, PartialEq, Eq, Hash)]
pub enum Provenance {
    /// Same origin as the page
    SameOrigin,
    /// Subdomain of the page origin
    Subdomain,
    /// Known CDN
    Cdn,
    /// Unknown third-party
    ThirdParty,
}

impl std::fmt::Display for Provenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Provenance::SameOrigin => write!(f, "Same Origin"),
            Provenance::Subdomain => write!(f, "Subdomain"),
            Provenance::Cdn => write!(f, "CDN"),
            Provenance::ThirdParty => write!(f, "Third Party"),
        }
    }
}

/// How the asset was discovered
#[derive(Debug, Serialize, Clone)]
pub enum AssetSource {
    Script,
    Stylesheet,
    Image,
    Media,
    Preload,
    Font,
}

impl std::fmt::Display for AssetSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetSource::Script => write!(f, "script"),
            AssetSource::Stylesheet => write!(f, "stylesheet"),
            AssetSource::Image => write!(f, "image"),
            AssetSource::Media => write!(f, "media"),
            AssetSource::Preload => write!(f, "preload"),
            AssetSource::Font => write!(f, "font"),
        }
    }
}

/// Breakdown by asset type
#[derive(Debug, Serialize, Clone, Default)]
pub struct TypeBreakdown {
    /// Number of assets
    pub count: usize,
    /// Total size in bytes
    pub total_size: u64,
    /// Average load time in ms
    pub avg_load_time_ms: u64,
}

/// Breakdown by provenance
#[derive(Debug, Serialize, Clone, Default)]
pub struct ProvenanceBreakdown {
    /// Number of assets
    pub count: usize,
    /// Total size in bytes
    pub total_size: u64,
    /// Domains involved
    pub domains: Vec<String>,
}

/// An asset issue
#[derive(Debug, Serialize, Clone)]
pub struct AssetIssue {
    pub severity: Severity,
    pub category: String,
    pub message: String,
    pub recommendation: Option<String>,
}

/// Known CDN patterns for classification
const KNOWN_CDNS: &[(&str, &str)] = &[
    ("cdnjs.cloudflare.com", "cdnjs"),
    ("cdn.jsdelivr.net", "jsDelivr"),
    ("unpkg.com", "unpkg"),
    ("ajax.googleapis.com", "Google"),
    ("fonts.googleapis.com", "Google Fonts"),
    ("fonts.gstatic.com", "Google Fonts"),
    ("stackpath.bootstrapcdn.com", "StackPath"),
    ("cdn.tailwindcss.com", "Tailwind"),
    ("maxcdn.bootstrapcdn.com", "MaxCDN"),
    ("code.jquery.com", "jQuery CDN"),
    ("use.fontawesome.com", "FontAwesome"),
    ("kit.fontawesome.com", "FontAwesome"),
    ("cdn.cloudflare.com", "Cloudflare"),
    ("polyfill.io", "Polyfill.io"),
    ("esm.sh", "esm.sh"),
    ("cdn.shopify.com", "Shopify"),
    ("static.cloudflareinsights.com", "Cloudflare"),
    ("www.googletagmanager.com", "Google"),
    ("www.google-analytics.com", "Google"),
    ("connect.facebook.net", "Facebook"),
    ("platform.twitter.com", "Twitter"),
];

/// Check assets for the page
pub async fn check_assets(target: &str, config: AssetsConfig) -> Result<AssetsResult> {
    let base_url = normalize_url(target);
    let base_parsed = Url::parse(&base_url).context("Invalid base URL")?;
    let base_host = base_parsed.host_str().unwrap_or("").to_lowercase();

    let client = Client::builder()
        .timeout(config.timeout)
        .user_agent("Mozilla/5.0 (compatible; Sango/1.0; +https://github.com/raskell-io/sango)")
        .build()
        .context("Failed to build HTTP client")?;

    // Step 1: Fetch the main page
    let response = client
        .get(&base_url)
        .send()
        .await
        .context("Failed to fetch page")?;

    let html_content = response.text().await.unwrap_or_default();
    let document = Html::parse_document(&html_content);

    // Step 2: Extract all asset URLs from HTML
    let mut asset_urls: Vec<(String, AssetType, AssetSource)> = Vec::new();

    extract_script_assets(&document, &base_url, &mut asset_urls);
    extract_stylesheet_assets(&document, &base_url, &mut asset_urls);
    extract_image_assets(&document, &base_url, &mut asset_urls);
    extract_media_assets(&document, &base_url, &mut asset_urls);
    extract_preload_assets(&document, &base_url, &mut asset_urls);

    // Deduplicate by URL
    let mut seen = std::collections::HashSet::new();
    asset_urls.retain(|(url, _, _)| seen.insert(url.clone()));

    // Limit to max_assets
    asset_urls.truncate(config.max_assets);

    // Step 3: Analyze each asset
    let assets = analyze_assets(&client, &asset_urls, &base_host).await;

    // Step 4: Calculate breakdowns and statistics
    let by_type = calculate_type_breakdown(&assets);
    let by_provenance = calculate_provenance_breakdown(&assets, &base_host);
    let third_party_percentage = calculate_third_party_percentage(&assets);

    let total_size: u64 = assets.iter().map(|a| a.size).sum();
    let total_size_formatted = format_size(total_size);
    let total_load_time_ms: u64 = assets.iter().map(|a| a.load_time_ms).max().unwrap_or(0);

    let slowest = find_slowest_assets(&assets, 5);
    let largest = find_largest_assets(&assets, 5);
    let uncached_count = assets.iter().filter(|a| !a.is_cached).count();

    let issues = generate_issues(&assets, third_party_percentage, uncached_count, &config);

    Ok(AssetsResult {
        total_assets: assets.len(),
        total_size,
        total_size_formatted,
        total_load_time_ms,
        assets,
        by_type,
        by_provenance,
        third_party_percentage,
        slowest,
        largest,
        uncached_count,
        issues,
    })
}

/// Normalize target URL
fn normalize_url(target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("https://{}", target)
    }
}

/// Extract script assets from HTML
fn extract_script_assets(
    document: &Html,
    base_url: &str,
    assets: &mut Vec<(String, AssetType, AssetSource)>,
) {
    if let Ok(selector) = Selector::parse("script[src]") {
        for element in document.select(&selector) {
            if let Some(src) = element.value().attr("src") {
                if let Some(url) = resolve_asset_url(src, base_url) {
                    assets.push((url, AssetType::JavaScript, AssetSource::Script));
                }
            }
        }
    }
}

/// Extract stylesheet assets from HTML
fn extract_stylesheet_assets(
    document: &Html,
    base_url: &str,
    assets: &mut Vec<(String, AssetType, AssetSource)>,
) {
    if let Ok(selector) = Selector::parse("link[rel='stylesheet'][href]") {
        for element in document.select(&selector) {
            if let Some(href) = element.value().attr("href") {
                if let Some(url) = resolve_asset_url(href, base_url) {
                    assets.push((url, AssetType::CSS, AssetSource::Stylesheet));
                }
            }
        }
    }
}

/// Extract image assets from HTML
fn extract_image_assets(
    document: &Html,
    base_url: &str,
    assets: &mut Vec<(String, AssetType, AssetSource)>,
) {
    // <img src="...">
    if let Ok(selector) = Selector::parse("img[src]") {
        for element in document.select(&selector) {
            if let Some(src) = element.value().attr("src") {
                // Skip data URIs
                if !src.starts_with("data:") {
                    if let Some(url) = resolve_asset_url(src, base_url) {
                        assets.push((url, AssetType::Image, AssetSource::Image));
                    }
                }
            }
        }
    }

    // <picture><source srcset="...">
    if let Ok(selector) = Selector::parse("picture source[srcset]") {
        for element in document.select(&selector) {
            if let Some(srcset) = element.value().attr("srcset") {
                // Parse srcset - take first URL
                if let Some(first_src) = srcset.split(',').next() {
                    let url_part = first_src.split_whitespace().next().unwrap_or("");
                    if !url_part.is_empty() && !url_part.starts_with("data:") {
                        if let Some(url) = resolve_asset_url(url_part, base_url) {
                            assets.push((url, AssetType::Image, AssetSource::Image));
                        }
                    }
                }
            }
        }
    }
}

/// Extract media assets from HTML
fn extract_media_assets(
    document: &Html,
    base_url: &str,
    assets: &mut Vec<(String, AssetType, AssetSource)>,
) {
    // <video src="..."> and <audio src="...">
    if let Ok(selector) = Selector::parse("video[src], audio[src]") {
        for element in document.select(&selector) {
            if let Some(src) = element.value().attr("src") {
                if let Some(url) = resolve_asset_url(src, base_url) {
                    assets.push((url, AssetType::Media, AssetSource::Media));
                }
            }
        }
    }

    // <source src="..."> inside video/audio
    if let Ok(selector) = Selector::parse("video source[src], audio source[src]") {
        for element in document.select(&selector) {
            if let Some(src) = element.value().attr("src") {
                if let Some(url) = resolve_asset_url(src, base_url) {
                    assets.push((url, AssetType::Media, AssetSource::Media));
                }
            }
        }
    }
}

/// Extract preload assets from HTML
fn extract_preload_assets(
    document: &Html,
    base_url: &str,
    assets: &mut Vec<(String, AssetType, AssetSource)>,
) {
    if let Ok(selector) = Selector::parse("link[rel='preload'][href]") {
        for element in document.select(&selector) {
            if let Some(href) = element.value().attr("href") {
                if let Some(url) = resolve_asset_url(href, base_url) {
                    // Determine type from 'as' attribute
                    let asset_type = match element.value().attr("as") {
                        Some("script") => AssetType::JavaScript,
                        Some("style") => AssetType::CSS,
                        Some("image") => AssetType::Image,
                        Some("font") => AssetType::Font,
                        Some("video") | Some("audio") => AssetType::Media,
                        _ => AssetType::Other,
                    };
                    assets.push((url, asset_type, AssetSource::Preload));
                }
            }
        }
    }

    // Also check for font preloads specifically
    if let Ok(selector) = Selector::parse("link[rel='preload'][as='font'][href]") {
        for element in document.select(&selector) {
            if let Some(href) = element.value().attr("href") {
                if let Some(url) = resolve_asset_url(href, base_url) {
                    assets.push((url, AssetType::Font, AssetSource::Font));
                }
            }
        }
    }
}

/// Resolve a potentially relative URL
fn resolve_asset_url(href: &str, base_url: &str) -> Option<String> {
    let href = href.trim();

    if href.is_empty() || href.starts_with("data:") {
        return None;
    }

    // Absolute URL
    if href.starts_with("http://") || href.starts_with("https://") {
        return Some(href.to_string());
    }

    // Protocol-relative
    if href.starts_with("//") {
        return Some(format!("https:{}", href));
    }

    // Relative URL
    if let Ok(base) = Url::parse(base_url) {
        if let Ok(resolved) = base.join(href) {
            return Some(resolved.to_string());
        }
    }

    None
}

/// Analyze assets in parallel
async fn analyze_assets(
    client: &Client,
    asset_urls: &[(String, AssetType, AssetSource)],
    base_host: &str,
) -> Vec<AssetInfo> {
    use futures::future::join_all;

    let futures: Vec<_> = asset_urls
        .iter()
        .map(|(url, asset_type, source)| {
            analyze_single_asset(client, url, *asset_type, source.clone(), base_host)
        })
        .collect();

    let results = join_all(futures).await;
    results.into_iter().filter_map(|r| r.ok()).collect()
}

/// Analyze a single asset
async fn analyze_single_asset(
    client: &Client,
    url: &str,
    asset_type: AssetType,
    source: AssetSource,
    base_host: &str,
) -> Result<AssetInfo> {
    let start = Instant::now();

    let response = client.get(url).send().await?;
    let elapsed = start.elapsed();

    let status_code = response.status().as_u16();
    let headers = response.headers().clone();

    // Get size from Content-Length or response body
    let content_length = headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    let size = if let Some(len) = content_length {
        // Don't read body if we have Content-Length
        len
    } else {
        // Read body to get size
        response.bytes().await.map(|b| b.len() as u64).unwrap_or(0)
    };

    // Check cache headers
    let cache_control = headers
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let cache_max_age = cache_control.as_ref().and_then(|cc| {
        cc.split(',').find_map(|part| {
            let part = part.trim();
            if part.starts_with("max-age=") {
                part[8..].parse::<u64>().ok()
            } else {
                None
            }
        })
    });

    let is_cached = cache_control.is_some()
        || headers.get("etag").is_some()
        || headers.get("last-modified").is_some();

    // Classify provenance
    let (provenance, cdn_name) = classify_provenance(url, base_host);

    Ok(AssetInfo {
        url: url.to_string(),
        asset_type,
        size,
        size_formatted: format_size(size),
        load_time_ms: elapsed.as_millis() as u64,
        provenance,
        cdn_name,
        is_cached,
        cache_max_age,
        status_code,
        source,
    })
}

/// Classify asset provenance
fn classify_provenance(url: &str, base_host: &str) -> (Provenance, Option<String>) {
    if let Ok(parsed) = Url::parse(url) {
        let host = parsed.host_str().unwrap_or("").to_lowercase();

        // Same origin
        if host == base_host {
            return (Provenance::SameOrigin, None);
        }

        // Subdomain check
        if host.ends_with(&format!(".{}", base_host)) {
            return (Provenance::Subdomain, None);
        }

        // Check base host ends with asset host (e.g., www.example.com vs example.com)
        if base_host.ends_with(&format!(".{}", host)) || base_host == format!("www.{}", host) {
            return (Provenance::SameOrigin, None);
        }

        // Known CDN check
        for (pattern, name) in KNOWN_CDNS {
            if host == *pattern || host.ends_with(&format!(".{}", pattern)) {
                return (Provenance::Cdn, Some(name.to_string()));
            }
        }

        // Unknown third-party
        (Provenance::ThirdParty, None)
    } else {
        (Provenance::ThirdParty, None)
    }
}

/// Format size in human-readable form
fn format_size(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

/// Calculate breakdown by asset type
fn calculate_type_breakdown(assets: &[AssetInfo]) -> HashMap<String, TypeBreakdown> {
    let mut breakdown: HashMap<String, TypeBreakdown> = HashMap::new();

    for asset in assets {
        let key = asset.asset_type.to_string();
        let entry = breakdown.entry(key).or_default();
        entry.count += 1;
        entry.total_size += asset.size;
    }

    // Calculate averages
    for (_, entry) in breakdown.iter_mut() {
        if entry.count > 0 {
            let total_time: u64 = assets
                .iter()
                .filter(|a| a.asset_type.to_string() == entry.count.to_string())
                .map(|a| a.load_time_ms)
                .sum();
            entry.avg_load_time_ms = total_time / entry.count as u64;
        }
    }

    breakdown
}

/// Calculate breakdown by provenance
fn calculate_provenance_breakdown(
    assets: &[AssetInfo],
    _base_host: &str,
) -> HashMap<String, ProvenanceBreakdown> {
    let mut breakdown: HashMap<String, ProvenanceBreakdown> = HashMap::new();
    let mut domain_sets: HashMap<String, std::collections::HashSet<String>> = HashMap::new();

    for asset in assets {
        let key = asset.provenance.to_string();
        let entry = breakdown.entry(key.clone()).or_default();
        entry.count += 1;
        entry.total_size += asset.size;

        // Track domains
        if let Ok(parsed) = Url::parse(&asset.url) {
            if let Some(host) = parsed.host_str() {
                domain_sets.entry(key).or_default().insert(host.to_string());
            }
        }
    }

    // Convert domain sets to vecs
    for (key, domains) in domain_sets {
        if let Some(entry) = breakdown.get_mut(&key) {
            entry.domains = domains.into_iter().collect();
            entry.domains.sort();
        }
    }

    breakdown
}

/// Calculate third-party percentage
fn calculate_third_party_percentage(assets: &[AssetInfo]) -> f32 {
    if assets.is_empty() {
        return 0.0;
    }

    let third_party_count = assets
        .iter()
        .filter(|a| a.provenance == Provenance::ThirdParty || a.provenance == Provenance::Cdn)
        .count();

    (third_party_count as f32 / assets.len() as f32) * 100.0
}

/// Find slowest assets
fn find_slowest_assets(assets: &[AssetInfo], n: usize) -> Vec<AssetSummary> {
    let mut sorted: Vec<_> = assets.iter().collect();
    sorted.sort_by(|a, b| b.load_time_ms.cmp(&a.load_time_ms));

    sorted
        .into_iter()
        .take(n)
        .map(|a| AssetSummary {
            url: truncate_url(&a.url, 50),
            asset_type: a.asset_type,
            size: a.size,
            load_time_ms: a.load_time_ms,
        })
        .collect()
}

/// Find largest assets
fn find_largest_assets(assets: &[AssetInfo], n: usize) -> Vec<AssetSummary> {
    let mut sorted: Vec<_> = assets.iter().collect();
    sorted.sort_by(|a, b| b.size.cmp(&a.size));

    sorted
        .into_iter()
        .take(n)
        .map(|a| AssetSummary {
            url: truncate_url(&a.url, 50),
            asset_type: a.asset_type,
            size: a.size,
            load_time_ms: a.load_time_ms,
        })
        .collect()
}

/// Truncate URL for display
fn truncate_url(url: &str, max_len: usize) -> String {
    if url.len() <= max_len {
        return url.to_string();
    }

    // Try to show meaningful parts
    if let Ok(parsed) = Url::parse(url) {
        let path = parsed.path();
        if path.len() < max_len - 10 {
            return format!("...{}", &url[url.len().saturating_sub(max_len - 3)..]);
        }
    }

    format!("{}...", &url[..max_len - 3])
}

/// Generate issues based on asset analysis
fn generate_issues(
    assets: &[AssetInfo],
    third_party_pct: f32,
    uncached_count: usize,
    config: &AssetsConfig,
) -> Vec<AssetIssue> {
    let mut issues = Vec::new();

    // Slow assets (configurable threshold)
    let slow_count = assets
        .iter()
        .filter(|a| a.load_time_ms > config.slow_threshold_ms)
        .count();
    if slow_count > 0 {
        issues.push(AssetIssue {
            severity: Severity::Medium,
            category: "performance".to_string(),
            message: format!(
                "{} assets took >{}ms to load",
                slow_count, config.slow_threshold_ms
            ),
            recommendation: Some("Consider lazy-loading or optimizing slow assets".to_string()),
        });
    }

    // Very slow assets (configurable threshold)
    let very_slow_count = assets
        .iter()
        .filter(|a| a.load_time_ms > config.very_slow_threshold_ms)
        .count();
    if very_slow_count > 0 {
        issues.push(AssetIssue {
            severity: Severity::High,
            category: "performance".to_string(),
            message: format!(
                "{} assets took >{}ms to load",
                very_slow_count, config.very_slow_threshold_ms
            ),
            recommendation: Some(
                "Critical performance issue - investigate slow assets immediately".to_string(),
            ),
        });
    }

    // Large JS files (configurable threshold)
    let large_js: Vec<_> = assets
        .iter()
        .filter(|a| a.asset_type == AssetType::JavaScript && a.size > config.large_js_bytes)
        .collect();
    if !large_js.is_empty() {
        let kb = config.large_js_bytes / 1024;
        issues.push(AssetIssue {
            severity: Severity::Medium,
            category: "size".to_string(),
            message: format!("{} JavaScript files exceed {}KB", large_js.len(), kb),
            recommendation: Some("Consider code splitting or tree shaking".to_string()),
        });
    }

    // Large images (configurable threshold)
    let large_images: Vec<_> = assets
        .iter()
        .filter(|a| a.asset_type == AssetType::Image && a.size > config.large_image_bytes)
        .collect();
    if !large_images.is_empty() {
        let kb = config.large_image_bytes / 1024;
        issues.push(AssetIssue {
            severity: Severity::Medium,
            category: "size".to_string(),
            message: format!("{} images exceed {}KB", large_images.len(), kb),
            recommendation: Some("Optimize images or use modern formats (WebP, AVIF)".to_string()),
        });
    }

    // Missing cache headers
    if uncached_count > 0 && !assets.is_empty() {
        let pct = (uncached_count as f32 / assets.len() as f32) * 100.0;
        if pct > 50.0 {
            issues.push(AssetIssue {
                severity: Severity::Medium,
                category: "caching".to_string(),
                message: format!(
                    "{} assets ({:.0}%) missing cache headers",
                    uncached_count, pct
                ),
                recommendation: Some("Add Cache-Control headers for static assets".to_string()),
            });
        } else if uncached_count > 0 {
            issues.push(AssetIssue {
                severity: Severity::Low,
                category: "caching".to_string(),
                message: format!("{} assets missing cache headers", uncached_count),
                recommendation: Some("Add Cache-Control headers for static assets".to_string()),
            });
        }
    }

    // Too many third-party assets (configurable threshold)
    if third_party_pct > config.third_party_threshold as f32 {
        issues.push(AssetIssue {
            severity: Severity::Medium,
            category: "third-party".to_string(),
            message: format!(
                "{:.0}% of assets from third parties (threshold: {}%)",
                third_party_pct, config.third_party_threshold
            ),
            recommendation: Some(
                "Consider self-hosting critical assets for reliability".to_string(),
            ),
        });
    }

    // Too many assets total
    if assets.len() > 50 {
        issues.push(AssetIssue {
            severity: Severity::Low,
            category: "quantity".to_string(),
            message: format!("{} total assets - consider reducing", assets.len()),
            recommendation: Some("Bundle assets or use HTTP/2 server push".to_string()),
        });
    }

    // Sort by severity
    issues.sort_by(|a, b| {
        let severity_order = |s: &Severity| match s {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
        };
        severity_order(&a.severity).cmp(&severity_order(&b.severity))
    });

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(1048576), "1.0 MB");
        assert_eq!(format_size(1572864), "1.5 MB");
    }

    #[test]
    fn test_classify_provenance() {
        // Same origin
        let (prov, cdn) = classify_provenance("https://example.com/app.js", "example.com");
        assert_eq!(prov, Provenance::SameOrigin);
        assert!(cdn.is_none());

        // Subdomain
        let (prov, cdn) = classify_provenance("https://cdn.example.com/app.js", "example.com");
        assert_eq!(prov, Provenance::Subdomain);
        assert!(cdn.is_none());

        // Known CDN
        let (prov, cdn) = classify_provenance(
            "https://cdnjs.cloudflare.com/ajax/libs/jquery.js",
            "example.com",
        );
        assert_eq!(prov, Provenance::Cdn);
        assert_eq!(cdn, Some("cdnjs".to_string()));

        // Third party
        let (prov, cdn) = classify_provenance("https://unknown-cdn.com/lib.js", "example.com");
        assert_eq!(prov, Provenance::ThirdParty);
        assert!(cdn.is_none());
    }

    #[test]
    fn test_resolve_asset_url() {
        let base = "https://example.com/page/";

        assert_eq!(
            resolve_asset_url("/assets/app.js", base),
            Some("https://example.com/assets/app.js".to_string())
        );
        assert_eq!(
            resolve_asset_url("../shared/lib.js", base),
            Some("https://example.com/shared/lib.js".to_string())
        );
        assert_eq!(
            resolve_asset_url("https://cdn.com/lib.js", base),
            Some("https://cdn.com/lib.js".to_string())
        );
        assert_eq!(
            resolve_asset_url("//cdn.com/lib.js", base),
            Some("https://cdn.com/lib.js".to_string())
        );
        assert_eq!(resolve_asset_url("data:image/png;base64,...", base), None);
    }
}
