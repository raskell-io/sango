//! Content analysis module
//!
//! Analyzes the content served by an endpoint:
//! - Content-type detection and MIME sniffing
//! - Response size and compression analysis
//! - Cache header analysis
//! - Resource hints (preload, prefetch, preconnect)

use anyhow::{Context, Result};
use reqwest::Client;
use scraper::{Html, Selector};
use serde::Serialize;
use std::time::Duration;

use super::tls::Severity;

/// Result of content analysis
#[derive(Debug, Serialize)]
pub struct ContentResult {
    /// Content-type information
    pub content_type: ContentTypeInfo,
    /// Response size information
    pub size: SizeInfo,
    /// Compression information
    pub compression: CompressionInfo,
    /// Cache header analysis
    pub cache: CacheInfo,
    /// Resource hints found
    pub resource_hints: ResourceHints,
    /// Character encoding information
    pub encoding: EncodingInfo,
    /// Detected issues
    pub issues: Vec<ContentIssue>,
}

/// Content-type information
#[derive(Debug, Serialize, Clone, Default)]
pub struct ContentTypeInfo {
    /// Content-Type header value
    pub header_value: Option<String>,
    /// Parsed MIME type
    pub mime_type: Option<String>,
    /// MIME type category (text, image, application, etc.)
    pub category: Option<String>,
    /// Sniffed content type (from actual content)
    pub sniffed_type: Option<String>,
    /// Whether header and sniffed type match
    pub types_match: bool,
    /// Whether X-Content-Type-Options: nosniff is set
    pub nosniff_enabled: bool,
}

/// Response size information
#[derive(Debug, Serialize, Clone, Default)]
pub struct SizeInfo {
    /// Content-Length header value (if present)
    pub content_length: Option<u64>,
    /// Actual body size in bytes
    pub body_size: u64,
    /// Transfer size (compressed, if applicable)
    pub transfer_size: Option<u64>,
    /// Human-readable body size
    pub body_size_formatted: String,
    /// Size category (tiny, small, medium, large, huge)
    pub size_category: String,
}

/// Compression information
#[derive(Debug, Serialize, Clone, Default)]
pub struct CompressionInfo {
    /// Content-Encoding header value
    pub encoding: Option<String>,
    /// Whether response is compressed
    pub is_compressed: bool,
    /// Compression algorithm used
    pub algorithm: Option<String>,
    /// Estimated compression ratio (if determinable)
    pub ratio: Option<f32>,
    /// Whether compression is recommended but missing
    pub should_compress: bool,
    /// Supported encodings from Accept-Encoding response
    pub supported_encodings: Vec<String>,
}

/// Cache header analysis
#[derive(Debug, Serialize, Clone, Default)]
pub struct CacheInfo {
    /// Cache-Control header value
    pub cache_control: Option<String>,
    /// Parsed Cache-Control directives
    pub directives: CacheDirectives,
    /// ETag header value
    pub etag: Option<String>,
    /// Last-Modified header value
    pub last_modified: Option<String>,
    /// Expires header value
    pub expires: Option<String>,
    /// Age header value (seconds)
    pub age: Option<u64>,
    /// Vary header value
    pub vary: Option<String>,
    /// Whether response is cacheable
    pub is_cacheable: bool,
    /// Effective max-age in seconds
    pub effective_max_age: Option<u64>,
    /// Cache status (HIT, MISS, etc.) from CDN headers
    pub cdn_cache_status: Option<String>,
    /// Cacheability rating
    pub rating: CacheRating,
}

/// Parsed Cache-Control directives
#[derive(Debug, Serialize, Clone, Default)]
pub struct CacheDirectives {
    pub max_age: Option<u64>,
    pub s_maxage: Option<u64>,
    pub no_cache: bool,
    pub no_store: bool,
    pub must_revalidate: bool,
    pub proxy_revalidate: bool,
    pub private: bool,
    pub public: bool,
    pub immutable: bool,
    pub stale_while_revalidate: Option<u64>,
    pub stale_if_error: Option<u64>,
}

/// Cache rating
#[derive(Debug, Serialize, Clone, PartialEq)]
pub enum CacheRating {
    /// Excellent caching strategy
    Excellent,
    /// Good caching with room for improvement
    Good,
    /// Basic caching
    Basic,
    /// Poor or no caching
    Poor,
    /// Explicitly not cached (may be intentional)
    NotCached,
}

impl Default for CacheRating {
    fn default() -> Self {
        CacheRating::Poor
    }
}

/// Resource hints found in response
#[derive(Debug, Serialize, Clone, Default)]
pub struct ResourceHints {
    /// Preload hints
    pub preload: Vec<ResourceHint>,
    /// Prefetch hints
    pub prefetch: Vec<ResourceHint>,
    /// Preconnect hints
    pub preconnect: Vec<ResourceHint>,
    /// DNS prefetch hints
    pub dns_prefetch: Vec<ResourceHint>,
    /// Modulepreload hints
    pub modulepreload: Vec<ResourceHint>,
    /// Total hint count
    pub total_count: usize,
}

/// A single resource hint
#[derive(Debug, Serialize, Clone)]
pub struct ResourceHint {
    /// Resource URL
    pub href: String,
    /// Resource type (for preload)
    pub as_type: Option<String>,
    /// Crossorigin attribute
    pub crossorigin: Option<String>,
    /// Source (header or html)
    pub source: HintSource,
}

/// Source of resource hint
#[derive(Debug, Serialize, Clone)]
pub enum HintSource {
    /// From Link header
    Header,
    /// From HTML <link> element
    Html,
}

/// Character encoding information
#[derive(Debug, Serialize, Clone, Default)]
pub struct EncodingInfo {
    /// Charset from Content-Type header
    pub header_charset: Option<String>,
    /// Charset from HTML meta tag
    pub meta_charset: Option<String>,
    /// Detected charset (BOM or heuristics)
    pub detected_charset: Option<String>,
    /// Whether charsets are consistent
    pub is_consistent: bool,
    /// Recommended charset
    pub recommended: String,
}

/// A content issue
#[derive(Debug, Serialize, Clone)]
pub struct ContentIssue {
    pub severity: Severity,
    pub category: String,
    pub message: String,
    pub recommendation: Option<String>,
}

/// Compressible MIME types
const COMPRESSIBLE_TYPES: &[&str] = &[
    "text/html",
    "text/css",
    "text/javascript",
    "text/plain",
    "text/xml",
    "application/javascript",
    "application/json",
    "application/xml",
    "application/xhtml+xml",
    "application/rss+xml",
    "application/atom+xml",
    "image/svg+xml",
    "font/ttf",
    "font/otf",
    "application/font-woff",
];

/// Check content
pub async fn check_content(target: &str, timeout: Duration) -> Result<ContentResult> {
    let base_url = normalize_url(target);

    let client = Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .context("Failed to build HTTP client")?;

    // Fetch with Accept-Encoding to test compression
    let response = client
        .get(&base_url)
        .header(
            "User-Agent",
            "Mozilla/5.0 (compatible; Sango/1.0; +https://github.com/raskell-io/sango)",
        )
        .header("Accept-Encoding", "gzip, deflate, br")
        .send()
        .await
        .context(format!("Failed to fetch {}", base_url))?;

    let headers = response.headers().clone();
    let body_bytes = response.bytes().await.unwrap_or_default();
    let body_size = body_bytes.len() as u64;
    let body_str = String::from_utf8_lossy(&body_bytes);

    // Parse HTML if applicable
    let document = Html::parse_document(&body_str);

    // Analyze content type
    let content_type = analyze_content_type(&headers, &body_bytes);

    // Analyze size
    let size = analyze_size(&headers, body_size);

    // Analyze compression
    let compression = analyze_compression(&headers, &content_type, body_size);

    // Analyze cache headers
    let cache = analyze_cache(&headers);

    // Extract resource hints
    let resource_hints = extract_resource_hints(&headers, &document);

    // Analyze encoding
    let encoding = analyze_encoding(&headers, &document, &body_bytes);

    // Generate issues
    let issues = generate_issues(&content_type, &size, &compression, &cache, &encoding);

    Ok(ContentResult {
        content_type,
        size,
        compression,
        cache,
        resource_hints,
        encoding,
        issues,
    })
}

/// Normalize target to base URL
fn normalize_url(target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("https://{}", target)
    }
}

/// Analyze content type
fn analyze_content_type(headers: &reqwest::header::HeaderMap, body: &[u8]) -> ContentTypeInfo {
    let header_value = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let mime_type = header_value
        .as_ref()
        .map(|ct| ct.split(';').next().unwrap_or(ct).trim().to_lowercase());

    let category = mime_type
        .as_ref()
        .map(|mt| mt.split('/').next().unwrap_or("unknown").to_string());

    let sniffed_type = sniff_content_type(body);

    let types_match = match (&mime_type, &sniffed_type) {
        (Some(declared), Some(sniffed)) => {
            // Allow some flexibility in matching
            declared == sniffed
                || (declared.contains("html") && sniffed.contains("html"))
                || (declared.contains("json") && sniffed.contains("json"))
                || (declared.contains("xml") && sniffed.contains("xml"))
                || (declared.contains("javascript") && sniffed.contains("javascript"))
        }
        (None, _) => false,
        (_, None) => true, // Can't sniff, assume match
    };

    let nosniff_enabled = headers
        .get("x-content-type-options")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase().contains("nosniff"))
        .unwrap_or(false);

    ContentTypeInfo {
        header_value,
        mime_type,
        category,
        sniffed_type,
        types_match,
        nosniff_enabled,
    }
}

/// Sniff content type from body
fn sniff_content_type(body: &[u8]) -> Option<String> {
    if body.is_empty() {
        return None;
    }

    // Check for common signatures
    let prefix: Vec<u8> = body.iter().take(512).cloned().collect();
    let prefix_str = String::from_utf8_lossy(&prefix).to_lowercase();

    // HTML
    if prefix_str.trim_start().starts_with("<!doctype html")
        || prefix_str.trim_start().starts_with("<html")
        || prefix_str.contains("<head")
        || prefix_str.contains("<body")
    {
        return Some("text/html".to_string());
    }

    // XML
    if prefix_str.trim_start().starts_with("<?xml") {
        if prefix_str.contains("<svg") {
            return Some("image/svg+xml".to_string());
        }
        if prefix_str.contains("<rss") || prefix_str.contains("<feed") {
            return Some("application/rss+xml".to_string());
        }
        return Some("application/xml".to_string());
    }

    // JSON
    let trimmed = prefix_str.trim_start();
    if (trimmed.starts_with('{') && trimmed.contains('"'))
        || (trimmed.starts_with('[') && (trimmed.contains('{') || trimmed.contains('"')))
    {
        return Some("application/json".to_string());
    }

    // JavaScript
    if prefix_str.contains("function ")
        || prefix_str.contains("const ")
        || prefix_str.contains("let ")
        || prefix_str.contains("var ")
        || prefix_str.contains("import ")
        || prefix_str.contains("export ")
    {
        return Some("application/javascript".to_string());
    }

    // CSS
    if prefix_str.contains("@charset")
        || prefix_str.contains("@import")
        || prefix_str.contains("@media")
        || (prefix_str.contains('{') && prefix_str.contains(':') && prefix_str.contains(';'))
    {
        return Some("text/css".to_string());
    }

    // Binary signatures
    if prefix.len() >= 4 {
        // PNG
        if prefix.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
            return Some("image/png".to_string());
        }
        // JPEG
        if prefix.starts_with(&[0xFF, 0xD8, 0xFF]) {
            return Some("image/jpeg".to_string());
        }
        // GIF
        if prefix.starts_with(b"GIF87a") || prefix.starts_with(b"GIF89a") {
            return Some("image/gif".to_string());
        }
        // WebP
        if prefix.len() >= 12 && prefix.starts_with(b"RIFF") && &prefix[8..12] == b"WEBP" {
            return Some("image/webp".to_string());
        }
        // PDF
        if prefix.starts_with(b"%PDF") {
            return Some("application/pdf".to_string());
        }
        // ZIP
        if prefix.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
            return Some("application/zip".to_string());
        }
        // GZIP
        if prefix.starts_with(&[0x1F, 0x8B]) {
            return Some("application/gzip".to_string());
        }
        // WOFF
        if prefix.starts_with(b"wOFF") {
            return Some("font/woff".to_string());
        }
        // WOFF2
        if prefix.starts_with(b"wOF2") {
            return Some("font/woff2".to_string());
        }
    }

    // Plain text fallback
    if prefix.iter().all(|&b| b.is_ascii() || b > 0x7F) {
        return Some("text/plain".to_string());
    }

    None
}

/// Analyze response size
fn analyze_size(headers: &reqwest::header::HeaderMap, body_size: u64) -> SizeInfo {
    let content_length = headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    let transfer_size = headers
        .get("x-transfer-size")
        .or_else(|| headers.get("x-original-content-length"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    let body_size_formatted = format_size(body_size);

    let size_category = match body_size {
        0..=1024 => "tiny",          // < 1KB
        1025..=10240 => "small",     // 1-10KB
        10241..=102400 => "medium",  // 10-100KB
        102401..=1048576 => "large", // 100KB-1MB
        _ => "huge",                 // > 1MB
    }
    .to_string();

    SizeInfo {
        content_length,
        body_size,
        transfer_size,
        body_size_formatted,
        size_category,
    }
}

/// Format size for display
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

/// Analyze compression
fn analyze_compression(
    headers: &reqwest::header::HeaderMap,
    content_type: &ContentTypeInfo,
    body_size: u64,
) -> CompressionInfo {
    let encoding = headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase());

    let is_compressed = encoding
        .as_ref()
        .map(|e| {
            e.contains("gzip") || e.contains("br") || e.contains("deflate") || e.contains("zstd")
        })
        .unwrap_or(false);

    let algorithm = if is_compressed {
        encoding.as_ref().map(|e| {
            if e.contains("br") {
                "Brotli".to_string()
            } else if e.contains("gzip") {
                "gzip".to_string()
            } else if e.contains("zstd") {
                "zstd".to_string()
            } else if e.contains("deflate") {
                "deflate".to_string()
            } else {
                e.clone()
            }
        })
    } else {
        None
    };

    // Check if content should be compressed
    let mime = content_type.mime_type.as_deref().unwrap_or("");
    let is_compressible = COMPRESSIBLE_TYPES.iter().any(|&t| mime.contains(t))
        || mime.starts_with("text/")
        || mime.contains("json")
        || mime.contains("xml")
        || mime.contains("javascript");

    let should_compress = !is_compressed && is_compressible && body_size > 1024;

    // Parse supported encodings from Vary header or other indicators
    let supported_encodings = headers
        .get("vary")
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.to_lowercase().contains("accept-encoding"))
        .map(|_| vec!["gzip".to_string(), "br".to_string(), "deflate".to_string()])
        .unwrap_or_default();

    CompressionInfo {
        encoding,
        is_compressed,
        algorithm,
        ratio: None, // Would need uncompressed size to calculate
        should_compress,
        supported_encodings,
    }
}

/// Analyze cache headers
fn analyze_cache(headers: &reqwest::header::HeaderMap) -> CacheInfo {
    let cache_control = headers
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let directives = parse_cache_control(cache_control.as_deref());

    let etag = headers
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let last_modified = headers
        .get("last-modified")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let expires = headers
        .get("expires")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let age = headers
        .get("age")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    let vary = headers
        .get("vary")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Check CDN cache status headers
    let cdn_cache_status = headers
        .get("cf-cache-status")
        .or_else(|| headers.get("x-cache"))
        .or_else(|| headers.get("x-cache-status"))
        .or_else(|| headers.get("x-vercel-cache"))
        .or_else(|| headers.get("x-fastly-cache"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Determine if cacheable
    let is_cacheable = !directives.no_store
        && (directives.max_age.is_some()
            || directives.s_maxage.is_some()
            || directives.public
            || etag.is_some()
            || last_modified.is_some()
            || expires.is_some());

    // Calculate effective max-age
    let effective_max_age = directives.s_maxage.or(directives.max_age);

    // Rate the caching strategy
    let rating = rate_cache_strategy(&directives, &etag, &last_modified, is_cacheable);

    CacheInfo {
        cache_control,
        directives,
        etag,
        last_modified,
        expires,
        age,
        vary,
        is_cacheable,
        effective_max_age,
        cdn_cache_status,
        rating,
    }
}

/// Parse Cache-Control header
fn parse_cache_control(header: Option<&str>) -> CacheDirectives {
    let mut directives = CacheDirectives::default();

    let Some(header) = header else {
        return directives;
    };

    for part in header.split(',') {
        let part = part.trim().to_lowercase();

        if part == "no-cache" {
            directives.no_cache = true;
        } else if part == "no-store" {
            directives.no_store = true;
        } else if part == "must-revalidate" {
            directives.must_revalidate = true;
        } else if part == "proxy-revalidate" {
            directives.proxy_revalidate = true;
        } else if part == "private" {
            directives.private = true;
        } else if part == "public" {
            directives.public = true;
        } else if part == "immutable" {
            directives.immutable = true;
        } else if part.starts_with("max-age=") {
            directives.max_age = part[8..].parse().ok();
        } else if part.starts_with("s-maxage=") {
            directives.s_maxage = part[9..].parse().ok();
        } else if part.starts_with("stale-while-revalidate=") {
            directives.stale_while_revalidate = part[23..].parse().ok();
        } else if part.starts_with("stale-if-error=") {
            directives.stale_if_error = part[15..].parse().ok();
        }
    }

    directives
}

/// Rate cache strategy
fn rate_cache_strategy(
    directives: &CacheDirectives,
    etag: &Option<String>,
    last_modified: &Option<String>,
    is_cacheable: bool,
) -> CacheRating {
    if directives.no_store {
        return CacheRating::NotCached;
    }

    if !is_cacheable {
        return CacheRating::Poor;
    }

    let mut score = 0;

    // Long max-age is good for static assets
    if let Some(max_age) = directives.max_age.or(directives.s_maxage) {
        if max_age >= 31536000 {
            // 1 year
            score += 3;
        } else if max_age >= 86400 {
            // 1 day
            score += 2;
        } else if max_age >= 3600 {
            // 1 hour
            score += 1;
        }
    }

    // Immutable is excellent for versioned assets
    if directives.immutable {
        score += 2;
    }

    // Revalidation validators
    if etag.is_some() {
        score += 1;
    }
    if last_modified.is_some() {
        score += 1;
    }

    // Stale-while-revalidate is a nice bonus
    if directives.stale_while_revalidate.is_some() {
        score += 1;
    }

    match score {
        0..=1 => CacheRating::Poor,
        2..=3 => CacheRating::Basic,
        4..=5 => CacheRating::Good,
        _ => CacheRating::Excellent,
    }
}

/// Extract resource hints from headers and HTML
fn extract_resource_hints(headers: &reqwest::header::HeaderMap, document: &Html) -> ResourceHints {
    let mut hints = ResourceHints::default();

    // Extract from Link headers
    if let Some(link_header) = headers.get("link").and_then(|v| v.to_str().ok()) {
        parse_link_header(link_header, &mut hints);
    }

    // Extract from HTML
    extract_html_hints(document, &mut hints);

    hints.total_count = hints.preload.len()
        + hints.prefetch.len()
        + hints.preconnect.len()
        + hints.dns_prefetch.len()
        + hints.modulepreload.len();

    hints
}

/// Parse Link header for resource hints
fn parse_link_header(header: &str, hints: &mut ResourceHints) {
    for link in header.split(',') {
        let link = link.trim();

        // Extract URL
        let url_end = link.find('>').unwrap_or(0);
        if !link.starts_with('<') || url_end == 0 {
            continue;
        }
        let href = link[1..url_end].to_string();
        let rest = &link[url_end + 1..];

        // Extract rel type
        let rel = extract_link_param(rest, "rel");
        let as_type = extract_link_param(rest, "as");
        let crossorigin = extract_link_param(rest, "crossorigin");

        let hint = ResourceHint {
            href,
            as_type,
            crossorigin,
            source: HintSource::Header,
        };

        match rel.as_deref() {
            Some("preload") => hints.preload.push(hint),
            Some("prefetch") => hints.prefetch.push(hint),
            Some("preconnect") => hints.preconnect.push(hint),
            Some("dns-prefetch") => hints.dns_prefetch.push(hint),
            Some("modulepreload") => hints.modulepreload.push(hint),
            _ => {}
        }
    }
}

/// Extract parameter from Link header segment
fn extract_link_param(segment: &str, param: &str) -> Option<String> {
    let search = format!("{}=", param);
    segment.find(&search).map(|pos| {
        let start = pos + search.len();
        let value = &segment[start..];
        let value = value.trim_start_matches('"').trim_start_matches('\'');
        let end = value
            .find(|c: char| c == '"' || c == '\'' || c == ';' || c == ',')
            .unwrap_or(value.len());
        value[..end].to_string()
    })
}

/// Extract resource hints from HTML
fn extract_html_hints(document: &Html, hints: &mut ResourceHints) {
    let link_selector = match Selector::parse("link[rel]") {
        Ok(s) => s,
        Err(_) => return,
    };

    for element in document.select(&link_selector) {
        let rel = element.value().attr("rel").unwrap_or("");
        let href = match element.value().attr("href") {
            Some(h) => h.to_string(),
            None => continue,
        };

        let as_type = element.value().attr("as").map(|s| s.to_string());
        let crossorigin = element.value().attr("crossorigin").map(|s| s.to_string());

        let hint = ResourceHint {
            href,
            as_type,
            crossorigin,
            source: HintSource::Html,
        };

        match rel {
            "preload" => hints.preload.push(hint),
            "prefetch" => hints.prefetch.push(hint),
            "preconnect" => hints.preconnect.push(hint),
            "dns-prefetch" => hints.dns_prefetch.push(hint),
            "modulepreload" => hints.modulepreload.push(hint),
            _ => {}
        }
    }
}

/// Analyze character encoding
fn analyze_encoding(
    headers: &reqwest::header::HeaderMap,
    document: &Html,
    body: &[u8],
) -> EncodingInfo {
    // From Content-Type header
    let header_charset = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .and_then(|ct| {
            ct.to_lowercase()
                .split(';')
                .find(|part| part.trim().starts_with("charset="))
                .map(|part| part.trim()[8..].trim_matches('"').to_string())
        });

    // From HTML meta tag
    let meta_charset = extract_meta_charset(document);

    // Detect from BOM or content
    let detected_charset = detect_charset(body);

    // Check consistency
    let charsets: Vec<&String> = [&header_charset, &meta_charset, &detected_charset]
        .iter()
        .filter_map(|c| c.as_ref())
        .collect();

    let is_consistent = if charsets.len() <= 1 {
        true
    } else {
        let normalized: Vec<String> = charsets
            .iter()
            .map(|c| c.to_lowercase().replace('-', ""))
            .collect();
        normalized.windows(2).all(|w| w[0] == w[1])
    };

    EncodingInfo {
        header_charset,
        meta_charset,
        detected_charset,
        is_consistent,
        recommended: "utf-8".to_string(),
    }
}

/// Extract charset from HTML meta tags
fn extract_meta_charset(document: &Html) -> Option<String> {
    // Try <meta charset="...">
    if let Ok(selector) = Selector::parse("meta[charset]") {
        if let Some(element) = document.select(&selector).next() {
            if let Some(charset) = element.value().attr("charset") {
                return Some(charset.to_string());
            }
        }
    }

    // Try <meta http-equiv="Content-Type" content="...">
    if let Ok(selector) = Selector::parse("meta[http-equiv='Content-Type']") {
        if let Some(element) = document.select(&selector).next() {
            if let Some(content) = element.value().attr("content") {
                if let Some(pos) = content.to_lowercase().find("charset=") {
                    let charset = &content[pos + 8..];
                    let end = charset
                        .find(|c: char| c == ';' || c == ' ')
                        .unwrap_or(charset.len());
                    return Some(charset[..end].to_string());
                }
            }
        }
    }

    None
}

/// Detect charset from BOM or content
fn detect_charset(body: &[u8]) -> Option<String> {
    if body.len() < 3 {
        return None;
    }

    // Check for BOM
    if body.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Some("utf-8".to_string());
    }
    if body.starts_with(&[0xFE, 0xFF]) {
        return Some("utf-16be".to_string());
    }
    if body.starts_with(&[0xFF, 0xFE]) {
        return Some("utf-16le".to_string());
    }

    // Simple UTF-8 validation
    if std::str::from_utf8(body).is_ok() {
        return Some("utf-8".to_string());
    }

    None
}

/// Generate content issues
fn generate_issues(
    content_type: &ContentTypeInfo,
    size: &SizeInfo,
    compression: &CompressionInfo,
    cache: &CacheInfo,
    encoding: &EncodingInfo,
) -> Vec<ContentIssue> {
    let mut issues = Vec::new();

    // Content-type issues
    if content_type.header_value.is_none() {
        issues.push(ContentIssue {
            severity: Severity::Medium,
            category: "content-type".to_string(),
            message: "Content-Type header missing".to_string(),
            recommendation: Some("Always specify Content-Type header".to_string()),
        });
    }

    if !content_type.types_match && content_type.sniffed_type.is_some() {
        issues.push(ContentIssue {
            severity: Severity::Medium,
            category: "content-type".to_string(),
            message: format!(
                "Content-Type mismatch: header says '{}', content appears to be '{}'",
                content_type.mime_type.as_deref().unwrap_or("unknown"),
                content_type.sniffed_type.as_deref().unwrap_or("unknown")
            ),
            recommendation: Some("Ensure Content-Type header matches actual content".to_string()),
        });
    }

    if !content_type.nosniff_enabled && content_type.mime_type.is_some() {
        issues.push(ContentIssue {
            severity: Severity::Low,
            category: "content-type".to_string(),
            message: "X-Content-Type-Options: nosniff not set".to_string(),
            recommendation: Some(
                "Add 'X-Content-Type-Options: nosniff' to prevent MIME sniffing".to_string(),
            ),
        });
    }

    // Size issues
    if size.body_size > 1_048_576 {
        // > 1MB
        issues.push(ContentIssue {
            severity: Severity::Medium,
            category: "size".to_string(),
            message: format!("Response is large ({})", size.body_size_formatted),
            recommendation: Some("Consider optimizing or lazy-loading large content".to_string()),
        });
    }

    // Compression issues
    if compression.should_compress {
        issues.push(ContentIssue {
            severity: Severity::Medium,
            category: "compression".to_string(),
            message: "Response should be compressed but isn't".to_string(),
            recommendation: Some(
                "Enable gzip or Brotli compression for text-based content".to_string(),
            ),
        });
    }

    // Cache issues
    match cache.rating {
        CacheRating::Poor => {
            if !cache.directives.no_store {
                issues.push(ContentIssue {
                    severity: Severity::Medium,
                    category: "cache".to_string(),
                    message: "Poor caching strategy".to_string(),
                    recommendation: Some(
                        "Add Cache-Control headers with appropriate max-age".to_string(),
                    ),
                });
            }
        }
        CacheRating::Basic => {
            issues.push(ContentIssue {
                severity: Severity::Low,
                category: "cache".to_string(),
                message: "Basic caching could be improved".to_string(),
                recommendation: Some(
                    "Consider adding ETag, immutable, or stale-while-revalidate".to_string(),
                ),
            });
        }
        _ => {}
    }

    if cache.etag.is_none() && cache.last_modified.is_none() && cache.is_cacheable {
        issues.push(ContentIssue {
            severity: Severity::Low,
            category: "cache".to_string(),
            message: "No cache validators (ETag or Last-Modified)".to_string(),
            recommendation: Some("Add ETag or Last-Modified for conditional requests".to_string()),
        });
    }

    // Encoding issues
    if !encoding.is_consistent {
        issues.push(ContentIssue {
            severity: Severity::Medium,
            category: "encoding".to_string(),
            message: "Inconsistent character encoding declarations".to_string(),
            recommendation: Some("Ensure charset is consistent across header and HTML".to_string()),
        });
    }

    if encoding.header_charset.is_none() && encoding.meta_charset.is_none() {
        let mime = content_type.mime_type.as_deref().unwrap_or("");
        if mime.starts_with("text/") || mime.contains("html") || mime.contains("xml") {
            issues.push(ContentIssue {
                severity: Severity::Low,
                category: "encoding".to_string(),
                message: "No charset specified".to_string(),
                recommendation: Some("Specify charset=utf-8 in Content-Type header".to_string()),
            });
        }
    }

    // Sort by severity
    issues.sort_by(|a, b| b.severity.cmp(&a.severity));

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sniff_html() {
        let html = b"<!DOCTYPE html><html><head></head><body></body></html>";
        assert_eq!(sniff_content_type(html), Some("text/html".to_string()));
    }

    #[test]
    fn test_sniff_json() {
        let json = b"{\"key\": \"value\"}";
        assert_eq!(
            sniff_content_type(json),
            Some("application/json".to_string())
        );
    }

    #[test]
    fn test_sniff_png() {
        let png = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(sniff_content_type(png), Some("image/png".to_string()));
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500 bytes");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1536), "1.50 KB");
        assert_eq!(format_size(1048576), "1.00 MB");
    }

    #[test]
    fn test_parse_cache_control() {
        let directives = parse_cache_control(Some("max-age=31536000, immutable, public"));
        assert_eq!(directives.max_age, Some(31536000));
        assert!(directives.immutable);
        assert!(directives.public);
    }

    #[test]
    fn test_parse_cache_control_no_store() {
        let directives = parse_cache_control(Some("no-store, no-cache"));
        assert!(directives.no_store);
        assert!(directives.no_cache);
    }

    #[test]
    fn test_cache_rating_excellent() {
        let directives = CacheDirectives {
            max_age: Some(31536000),
            immutable: true,
            public: true,
            ..Default::default()
        };
        let rating = rate_cache_strategy(
            &directives,
            &Some("abc".to_string()),
            &Some("Mon, 01 Jan 2024".to_string()),
            true,
        );
        assert_eq!(rating, CacheRating::Excellent);
    }

    #[test]
    fn test_cache_rating_not_cached() {
        let directives = CacheDirectives {
            no_store: true,
            ..Default::default()
        };
        let rating = rate_cache_strategy(&directives, &None, &None, false);
        assert_eq!(rating, CacheRating::NotCached);
    }
}
