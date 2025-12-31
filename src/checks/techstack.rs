//! Technology stack detection
//!
//! - Server identification (nginx, Apache, etc.)
//! - CDN detection (Cloudflare, Fastly, Akamai, etc.)
//! - Framework fingerprinting (Next.js, Rails, Django, etc.)
//! - CMS detection (WordPress, Drupal, etc.)

use anyhow::{Context, Result};
use reqwest::Client;
use scraper::{Html, Selector};
use serde::Serialize;
use std::collections::HashMap;
use std::time::Duration;

use super::tls::Severity;

/// Result of tech stack detection
#[derive(Debug, Serialize)]
pub struct TechStackResult {
    /// Detected server software
    pub server: Option<ServerInfo>,
    /// Detected CDN
    pub cdn: Option<CdnInfo>,
    /// Detected frameworks
    pub frameworks: Vec<FrameworkInfo>,
    /// Detected CMS
    pub cms: Option<CmsInfo>,
    /// JavaScript libraries detected
    pub js_libraries: Vec<JsLibraryInfo>,
    /// Analytics and tracking
    pub analytics: Vec<AnalyticsInfo>,
    /// Detected issues
    pub issues: Vec<TechStackIssue>,
    /// Raw signals used for detection (for debugging/transparency)
    pub signals: TechSignals,
}

/// Server software information
#[derive(Debug, Serialize, Clone)]
pub struct ServerInfo {
    /// Server name (e.g., "nginx", "Apache")
    pub name: String,
    /// Version if detected
    pub version: Option<String>,
    /// Raw Server header value
    pub raw_header: Option<String>,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
}

/// CDN information
#[derive(Debug, Serialize, Clone)]
pub struct CdnInfo {
    /// CDN name (e.g., "Cloudflare", "Fastly")
    pub name: String,
    /// CDN-specific features detected
    pub features: Vec<String>,
    /// Edge location if available
    pub edge_location: Option<String>,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
}

/// Framework information
#[derive(Debug, Serialize, Clone)]
pub struct FrameworkInfo {
    /// Framework name (e.g., "Next.js", "Rails")
    pub name: String,
    /// Category (frontend, backend, fullstack)
    pub category: FrameworkCategory,
    /// Version if detected
    pub version: Option<String>,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
    /// Evidence that led to detection
    pub evidence: Vec<String>,
}

/// Framework category
#[derive(Debug, Serialize, Clone, PartialEq)]
pub enum FrameworkCategory {
    Frontend,
    Backend,
    Fullstack,
    Static,
}

/// CMS information
#[derive(Debug, Serialize, Clone)]
pub struct CmsInfo {
    /// CMS name (e.g., "WordPress", "Drupal")
    pub name: String,
    /// Version if detected
    pub version: Option<String>,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
    /// Evidence that led to detection
    pub evidence: Vec<String>,
}

/// JavaScript library information
#[derive(Debug, Serialize, Clone)]
pub struct JsLibraryInfo {
    /// Library name
    pub name: String,
    /// Version if detected
    pub version: Option<String>,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
}

/// Analytics/tracking information
#[derive(Debug, Serialize, Clone)]
pub struct AnalyticsInfo {
    /// Service name (e.g., "Google Analytics", "Segment")
    pub name: String,
    /// Tracking ID if detected
    pub tracking_id: Option<String>,
}

/// Raw signals collected during detection
#[derive(Debug, Serialize, Clone, Default)]
pub struct TechSignals {
    /// Response headers of interest
    pub headers: HashMap<String, String>,
    /// Cookies set by the response
    pub cookies: Vec<String>,
    /// Meta tags found
    pub meta_tags: HashMap<String, String>,
    /// Script sources found
    pub script_sources: Vec<String>,
    /// Generator meta tag if present
    pub generator: Option<String>,
}

/// A tech stack issue
#[derive(Debug, Serialize, Clone)]
pub struct TechStackIssue {
    pub severity: Severity,
    pub category: String,
    pub message: String,
}

/// Check tech stack
pub async fn check_techstack(target: &str, timeout: Duration) -> Result<TechStackResult> {
    let url = normalize_url(target);

    let client = Client::builder()
        .timeout(timeout)
        .build()
        .context("Failed to build HTTP client")?;

    // Fetch the page
    let response = client
        .get(&url)
        .header(
            "User-Agent",
            "Mozilla/5.0 (compatible; Sango/1.0; +https://github.com/raskell-io/sango)",
        )
        .send()
        .await
        .context(format!("Failed to fetch {}", url))?;

    // Collect signals from headers
    let mut signals = TechSignals::default();

    // Extract relevant headers
    for (name, value) in response.headers() {
        let name_lower = name.as_str().to_lowercase();
        if let Ok(v) = value.to_str() {
            match name_lower.as_str() {
                "server"
                | "x-powered-by"
                | "x-aspnet-version"
                | "x-aspnetmvc-version"
                | "x-drupal-cache"
                | "x-generator"
                | "x-shopify-stage"
                | "x-wix-request-id"
                | "x-vercel-id"
                | "x-vercel-cache"
                | "x-netlify-request-id"
                | "x-nf-request-id"
                | "cf-ray"
                | "cf-cache-status"
                | "x-amz-cf-id"
                | "x-amz-cf-pop"
                | "x-cache"
                | "x-served-by"
                | "x-timer"
                | "fastly-debug-digest"
                | "x-akamai-transformed"
                | "x-cdn"
                | "x-edge-location"
                | "x-frame-options"
                | "x-xss-protection"
                | "x-content-type-options"
                | "x-runtime"
                | "x-request-id"
                | "x-github-request-id"
                | "x-nextjs-cache"
                | "x-nextjs-matched-path" => {
                    signals.headers.insert(name_lower, v.to_string());
                }
                "set-cookie" => {
                    signals.cookies.push(v.to_string());
                }
                _ => {}
            }
        }
    }

    // Get response body
    let body = response.text().await.unwrap_or_default();

    // Parse HTML and extract signals
    let document = Html::parse_document(&body);
    extract_html_signals(&document, &mut signals);

    // Detect technologies based on signals
    let server = detect_server(&signals);
    let cdn = detect_cdn(&signals);
    let frameworks = detect_frameworks(&signals, &body);
    let cms = detect_cms(&signals, &body);
    let js_libraries = detect_js_libraries(&signals, &body);
    let analytics = detect_analytics(&signals, &body);

    // Generate issues
    let issues = generate_issues(&server, &cdn, &frameworks, &signals);

    Ok(TechStackResult {
        server,
        cdn,
        frameworks,
        cms,
        js_libraries,
        analytics,
        issues,
        signals,
    })
}

/// Normalize target to URL
fn normalize_url(target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("https://{}", target)
    }
}

/// Extract signals from HTML document
fn extract_html_signals(document: &Html, signals: &mut TechSignals) {
    // Extract meta tags
    if let Ok(selector) = Selector::parse("meta") {
        for element in document.select(&selector) {
            let name = element
                .value()
                .attr("name")
                .or_else(|| element.value().attr("property"))
                .unwrap_or_default();
            let content = element.value().attr("content").unwrap_or_default();

            if !name.is_empty() && !content.is_empty() {
                signals
                    .meta_tags
                    .insert(name.to_string(), content.to_string());
            }

            // Check for generator
            if name.to_lowercase() == "generator" {
                signals.generator = Some(content.to_string());
            }
        }
    }

    // Extract script sources
    if let Ok(selector) = Selector::parse("script[src]") {
        for element in document.select(&selector) {
            if let Some(src) = element.value().attr("src") {
                signals.script_sources.push(src.to_string());
            }
        }
    }

    // Also check for inline script patterns
    if let Ok(selector) = Selector::parse("script:not([src])") {
        for element in document.select(&selector) {
            let text = element.text().collect::<String>();
            // Store first 500 chars of inline scripts for pattern matching
            if !text.trim().is_empty() {
                let preview = if text.len() > 500 {
                    &text[..500]
                } else {
                    &text
                };
                signals.script_sources.push(format!("inline:{}", preview));
            }
        }
    }
}

/// Detect server software
fn detect_server(signals: &TechSignals) -> Option<ServerInfo> {
    // Check Server header
    if let Some(server_header) = signals.headers.get("server") {
        // Parse common server strings
        let (name, version) = parse_server_string(server_header);

        return Some(ServerInfo {
            name,
            version,
            raw_header: Some(server_header.clone()),
            confidence: 1.0,
        });
    }

    // Check X-Powered-By
    if let Some(powered_by) = signals.headers.get("x-powered-by") {
        let lower = powered_by.to_lowercase();

        if lower.contains("php") {
            return Some(ServerInfo {
                name: "PHP".to_string(),
                version: extract_version(powered_by),
                raw_header: Some(powered_by.clone()),
                confidence: 0.9,
            });
        }
        if lower.contains("asp.net") || lower.contains("aspnet") {
            return Some(ServerInfo {
                name: "ASP.NET".to_string(),
                version: extract_version(powered_by),
                raw_header: Some(powered_by.clone()),
                confidence: 0.9,
            });
        }
        if lower.contains("express") {
            return Some(ServerInfo {
                name: "Express".to_string(),
                version: extract_version(powered_by),
                raw_header: Some(powered_by.clone()),
                confidence: 0.9,
            });
        }
    }

    None
}

/// Parse server string to extract name and version
fn parse_server_string(server: &str) -> (String, Option<String>) {
    let lower = server.to_lowercase();

    // Common server patterns
    let patterns = [
        ("nginx", "nginx"),
        ("apache", "Apache"),
        ("cloudflare", "Cloudflare"),
        ("microsoft-iis", "IIS"),
        ("lighttpd", "lighttpd"),
        ("litespeed", "LiteSpeed"),
        ("openresty", "OpenResty"),
        ("caddy", "Caddy"),
        ("gunicorn", "Gunicorn"),
        ("uvicorn", "Uvicorn"),
        ("deno", "Deno"),
        ("cowboy", "Cowboy"),
        ("kestrel", "Kestrel"),
        ("jetty", "Jetty"),
        ("tomcat", "Tomcat"),
        ("envoy", "Envoy"),
    ];

    for (pattern, name) in patterns {
        if lower.contains(pattern) {
            return (name.to_string(), extract_version(server));
        }
    }

    // Return raw value if no match
    (
        server.split('/').next().unwrap_or(server).to_string(),
        extract_version(server),
    )
}

/// Extract version from a string like "nginx/1.21.0" or "PHP/8.1.0"
fn extract_version(s: &str) -> Option<String> {
    // Look for /version pattern
    if let Some(idx) = s.find('/') {
        let version_part = &s[idx + 1..];
        let version = version_part
            .split_whitespace()
            .next()
            .unwrap_or(version_part);
        if version
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            return Some(version.to_string());
        }
    }

    // Look for version in parentheses or after space
    for part in s.split_whitespace() {
        if part
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            return Some(part.trim_matches(|c| c == '(' || c == ')').to_string());
        }
    }

    None
}

/// Detect CDN
fn detect_cdn(signals: &TechSignals) -> Option<CdnInfo> {
    let mut features = Vec::new();

    // Cloudflare
    if signals.headers.contains_key("cf-ray") {
        if let Some(ray) = signals.headers.get("cf-ray") {
            // CF-Ray format: <ray-id>-<colo>
            let edge = ray.split('-').last().map(|s| s.to_string());
            if let Some(cache_status) = signals.headers.get("cf-cache-status") {
                features.push(format!("cache: {}", cache_status));
            }
            return Some(CdnInfo {
                name: "Cloudflare".to_string(),
                features,
                edge_location: edge,
                confidence: 1.0,
            });
        }
    }

    // Fastly
    if signals.headers.contains_key("x-served-by") || signals.headers.contains_key("x-timer") {
        if let Some(served_by) = signals.headers.get("x-served-by") {
            features.push(format!("served-by: {}", served_by));
        }
        if let Some(cache) = signals.headers.get("x-cache") {
            features.push(format!("cache: {}", cache));
        }
        return Some(CdnInfo {
            name: "Fastly".to_string(),
            features,
            edge_location: signals
                .headers
                .get("x-served-by")
                .and_then(|s| s.split(',').next())
                .map(|s| s.trim().to_string()),
            confidence: 0.95,
        });
    }

    // AWS CloudFront
    if signals.headers.contains_key("x-amz-cf-id") || signals.headers.contains_key("x-amz-cf-pop") {
        if let Some(pop) = signals.headers.get("x-amz-cf-pop") {
            features.push(format!("pop: {}", pop));
        }
        if let Some(cache) = signals.headers.get("x-cache") {
            features.push(format!("cache: {}", cache));
        }
        return Some(CdnInfo {
            name: "CloudFront".to_string(),
            features,
            edge_location: signals.headers.get("x-amz-cf-pop").cloned(),
            confidence: 1.0,
        });
    }

    // Akamai
    if signals.headers.contains_key("x-akamai-transformed") {
        return Some(CdnInfo {
            name: "Akamai".to_string(),
            features,
            edge_location: None,
            confidence: 0.95,
        });
    }

    // Vercel
    if signals.headers.contains_key("x-vercel-id") {
        if let Some(cache) = signals.headers.get("x-vercel-cache") {
            features.push(format!("cache: {}", cache));
        }
        return Some(CdnInfo {
            name: "Vercel".to_string(),
            features,
            edge_location: signals
                .headers
                .get("x-vercel-id")
                .and_then(|s| s.split("::").nth(1))
                .map(|s| s.to_string()),
            confidence: 1.0,
        });
    }

    // Netlify
    if signals.headers.contains_key("x-nf-request-id")
        || signals.headers.contains_key("x-netlify-request-id")
    {
        return Some(CdnInfo {
            name: "Netlify".to_string(),
            features,
            edge_location: None,
            confidence: 1.0,
        });
    }

    // Generic CDN detection via x-cdn header
    if let Some(cdn) = signals.headers.get("x-cdn") {
        return Some(CdnInfo {
            name: cdn.clone(),
            features,
            edge_location: None,
            confidence: 0.8,
        });
    }

    None
}

/// Detect frameworks
fn detect_frameworks(signals: &TechSignals, body: &str) -> Vec<FrameworkInfo> {
    let mut frameworks = Vec::new();

    // Next.js
    if signals.headers.contains_key("x-nextjs-cache")
        || signals.headers.contains_key("x-nextjs-matched-path")
        || body.contains("/_next/")
        || body.contains("__NEXT_DATA__")
    {
        let mut evidence = Vec::new();
        if signals.headers.contains_key("x-nextjs-cache") {
            evidence.push("x-nextjs-cache header".to_string());
        }
        if body.contains("/_next/") {
            evidence.push("/_next/ paths".to_string());
        }
        if body.contains("__NEXT_DATA__") {
            evidence.push("__NEXT_DATA__ script".to_string());
        }
        frameworks.push(FrameworkInfo {
            name: "Next.js".to_string(),
            category: FrameworkCategory::Fullstack,
            version: extract_nextjs_version(body),
            confidence: 0.95,
            evidence,
        });
    }

    // Nuxt.js
    if body.contains("/_nuxt/") || body.contains("__NUXT__") {
        let mut evidence = Vec::new();
        if body.contains("/_nuxt/") {
            evidence.push("/_nuxt/ paths".to_string());
        }
        if body.contains("__NUXT__") {
            evidence.push("__NUXT__ script".to_string());
        }
        frameworks.push(FrameworkInfo {
            name: "Nuxt.js".to_string(),
            category: FrameworkCategory::Fullstack,
            version: None,
            confidence: 0.95,
            evidence,
        });
    }

    // React (generic, lower confidence than Next.js)
    if (body.contains("react") || body.contains("React")) && body.contains("data-reactroot")
        || body.contains("__REACT_DEVTOOLS")
    {
        let mut evidence = Vec::new();
        if body.contains("data-reactroot") {
            evidence.push("data-reactroot attribute".to_string());
        }
        // Only add if not already detected as Next.js
        if !frameworks.iter().any(|f| f.name == "Next.js") {
            frameworks.push(FrameworkInfo {
                name: "React".to_string(),
                category: FrameworkCategory::Frontend,
                version: None,
                confidence: 0.7,
                evidence,
            });
        }
    }

    // Vue.js
    if body.contains("__VUE__") || body.contains("data-v-") || body.contains("vue.") {
        let mut evidence = Vec::new();
        if body.contains("data-v-") {
            evidence.push("data-v- attributes".to_string());
        }
        if body.contains("__VUE__") {
            evidence.push("__VUE__ global".to_string());
        }
        // Only add if not already detected as Nuxt.js
        if !frameworks.iter().any(|f| f.name == "Nuxt.js") {
            frameworks.push(FrameworkInfo {
                name: "Vue.js".to_string(),
                category: FrameworkCategory::Frontend,
                version: None,
                confidence: 0.7,
                evidence,
            });
        }
    }

    // Angular
    if body.contains("ng-version") || body.contains("ng-app") || body.contains("angular") {
        let mut evidence = Vec::new();
        if body.contains("ng-version") {
            evidence.push("ng-version attribute".to_string());
        }
        if body.contains("ng-app") {
            evidence.push("ng-app attribute".to_string());
        }
        frameworks.push(FrameworkInfo {
            name: "Angular".to_string(),
            category: FrameworkCategory::Frontend,
            version: extract_angular_version(body),
            confidence: 0.8,
            evidence,
        });
    }

    // Svelte/SvelteKit
    if body.contains("svelte") || body.contains("__sveltekit") {
        let mut evidence = Vec::new();
        let is_kit = body.contains("__sveltekit");
        if is_kit {
            evidence.push("__sveltekit global".to_string());
        }
        frameworks.push(FrameworkInfo {
            name: if is_kit { "SvelteKit" } else { "Svelte" }.to_string(),
            category: if is_kit {
                FrameworkCategory::Fullstack
            } else {
                FrameworkCategory::Frontend
            },
            version: None,
            confidence: 0.8,
            evidence,
        });
    }

    // Ruby on Rails
    if signals
        .headers
        .get("x-runtime")
        .map(|v| v.contains("."))
        .unwrap_or(false)
        || signals.cookies.iter().any(|c| c.contains("_session"))
        || body.contains("csrf-token") && body.contains("csrf-param")
    {
        let mut evidence = Vec::new();
        if signals.headers.contains_key("x-runtime") {
            evidence.push("X-Runtime header".to_string());
        }
        if body.contains("csrf-token") {
            evidence.push("Rails CSRF meta tags".to_string());
        }
        frameworks.push(FrameworkInfo {
            name: "Ruby on Rails".to_string(),
            category: FrameworkCategory::Backend,
            version: None,
            confidence: 0.7,
            evidence,
        });
    }

    // Django
    if signals
        .cookies
        .iter()
        .any(|c| c.contains("csrftoken") || c.contains("django"))
    {
        let mut evidence = Vec::new();
        if signals.cookies.iter().any(|c| c.contains("csrftoken")) {
            evidence.push("csrftoken cookie".to_string());
        }
        frameworks.push(FrameworkInfo {
            name: "Django".to_string(),
            category: FrameworkCategory::Backend,
            version: None,
            confidence: 0.7,
            evidence,
        });
    }

    // Laravel
    if signals
        .cookies
        .iter()
        .any(|c| c.contains("laravel_session") || c.contains("XSRF-TOKEN"))
    {
        let mut evidence = Vec::new();
        if signals
            .cookies
            .iter()
            .any(|c| c.contains("laravel_session"))
        {
            evidence.push("laravel_session cookie".to_string());
        }
        frameworks.push(FrameworkInfo {
            name: "Laravel".to_string(),
            category: FrameworkCategory::Backend,
            version: None,
            confidence: 0.8,
            evidence,
        });
    }

    // Express.js (often detected via X-Powered-By)
    if signals
        .headers
        .get("x-powered-by")
        .map(|v| v.to_lowercase().contains("express"))
        .unwrap_or(false)
    {
        frameworks.push(FrameworkInfo {
            name: "Express.js".to_string(),
            category: FrameworkCategory::Backend,
            version: None,
            confidence: 0.9,
            evidence: vec!["X-Powered-By header".to_string()],
        });
    }

    // Gatsby
    if body.contains("gatsby") || body.contains("___gatsby") {
        let mut evidence = Vec::new();
        if body.contains("___gatsby") {
            evidence.push("___gatsby element".to_string());
        }
        frameworks.push(FrameworkInfo {
            name: "Gatsby".to_string(),
            category: FrameworkCategory::Static,
            version: None,
            confidence: 0.85,
            evidence,
        });
    }

    // Remix
    if body.contains("__remix") || body.contains("remix") && body.contains("data-remix") {
        frameworks.push(FrameworkInfo {
            name: "Remix".to_string(),
            category: FrameworkCategory::Fullstack,
            version: None,
            confidence: 0.8,
            evidence: vec!["Remix markers".to_string()],
        });
    }

    // Astro
    if body.contains("astro") || signals.script_sources.iter().any(|s| s.contains("astro")) {
        frameworks.push(FrameworkInfo {
            name: "Astro".to_string(),
            category: FrameworkCategory::Static,
            version: None,
            confidence: 0.75,
            evidence: vec!["Astro markers".to_string()],
        });
    }

    frameworks
}

/// Extract Next.js version from build manifest if available
fn extract_nextjs_version(_body: &str) -> Option<String> {
    // Next.js version detection is complex - would need to parse build manifest
    // For now, return None
    None
}

/// Extract Angular version
fn extract_angular_version(body: &str) -> Option<String> {
    if let Some(idx) = body.find("ng-version=\"") {
        let start = idx + 12;
        if let Some(end) = body[start..].find('"') {
            return Some(body[start..start + end].to_string());
        }
    }
    None
}

/// Detect CMS
fn detect_cms(signals: &TechSignals, body: &str) -> Option<CmsInfo> {
    // WordPress
    if body.contains("/wp-content/")
        || body.contains("/wp-includes/")
        || signals
            .generator
            .as_ref()
            .map(|g| g.to_lowercase().contains("wordpress"))
            .unwrap_or(false)
    {
        let mut evidence = Vec::new();
        let mut version = None;

        if body.contains("/wp-content/") {
            evidence.push("/wp-content/ paths".to_string());
        }
        if let Some(ref gen) = signals.generator {
            if gen.to_lowercase().contains("wordpress") {
                evidence.push(format!("generator: {}", gen));
                version = extract_version(gen);
            }
        }

        return Some(CmsInfo {
            name: "WordPress".to_string(),
            version,
            confidence: 0.95,
            evidence,
        });
    }

    // Drupal
    if signals.headers.contains_key("x-drupal-cache")
        || body.contains("Drupal.settings")
        || signals
            .generator
            .as_ref()
            .map(|g| g.to_lowercase().contains("drupal"))
            .unwrap_or(false)
    {
        let mut evidence = Vec::new();
        if signals.headers.contains_key("x-drupal-cache") {
            evidence.push("X-Drupal-Cache header".to_string());
        }
        return Some(CmsInfo {
            name: "Drupal".to_string(),
            version: signals.generator.as_ref().and_then(|g| extract_version(g)),
            confidence: 0.9,
            evidence,
        });
    }

    // Shopify
    if signals.headers.contains_key("x-shopify-stage")
        || body.contains("cdn.shopify.com")
        || body.contains("Shopify.theme")
    {
        let mut evidence = Vec::new();
        if signals.headers.contains_key("x-shopify-stage") {
            evidence.push("X-Shopify-Stage header".to_string());
        }
        if body.contains("cdn.shopify.com") {
            evidence.push("Shopify CDN".to_string());
        }
        return Some(CmsInfo {
            name: "Shopify".to_string(),
            version: None,
            confidence: 0.95,
            evidence,
        });
    }

    // Wix
    if signals.headers.contains_key("x-wix-request-id") || body.contains("wix.com") {
        return Some(CmsInfo {
            name: "Wix".to_string(),
            version: None,
            confidence: 0.9,
            evidence: vec!["Wix markers".to_string()],
        });
    }

    // Squarespace
    if body.contains("squarespace") || body.contains("static.squarespace.com") {
        return Some(CmsInfo {
            name: "Squarespace".to_string(),
            version: None,
            confidence: 0.9,
            evidence: vec!["Squarespace markers".to_string()],
        });
    }

    // Ghost
    if signals
        .generator
        .as_ref()
        .map(|g| g.to_lowercase().contains("ghost"))
        .unwrap_or(false)
        || body.contains("ghost.io")
    {
        return Some(CmsInfo {
            name: "Ghost".to_string(),
            version: signals.generator.as_ref().and_then(|g| extract_version(g)),
            confidence: 0.9,
            evidence: vec!["Ghost markers".to_string()],
        });
    }

    // Webflow
    if body.contains("webflow.com") || body.contains("data-wf-") {
        return Some(CmsInfo {
            name: "Webflow".to_string(),
            version: None,
            confidence: 0.9,
            evidence: vec!["Webflow markers".to_string()],
        });
    }

    // Hugo (static site generator often used as CMS)
    if signals
        .generator
        .as_ref()
        .map(|g| g.to_lowercase().contains("hugo"))
        .unwrap_or(false)
    {
        return Some(CmsInfo {
            name: "Hugo".to_string(),
            version: signals.generator.as_ref().and_then(|g| extract_version(g)),
            confidence: 0.9,
            evidence: vec!["Hugo generator".to_string()],
        });
    }

    // Jekyll
    if signals
        .generator
        .as_ref()
        .map(|g| g.to_lowercase().contains("jekyll"))
        .unwrap_or(false)
    {
        return Some(CmsInfo {
            name: "Jekyll".to_string(),
            version: signals.generator.as_ref().and_then(|g| extract_version(g)),
            confidence: 0.9,
            evidence: vec!["Jekyll generator".to_string()],
        });
    }

    None
}

/// Detect JavaScript libraries
fn detect_js_libraries(signals: &TechSignals, body: &str) -> Vec<JsLibraryInfo> {
    let mut libraries = Vec::new();

    // jQuery
    if signals.script_sources.iter().any(|s| s.contains("jquery")) || body.contains("jQuery") {
        libraries.push(JsLibraryInfo {
            name: "jQuery".to_string(),
            version: extract_jquery_version(signals, body),
            confidence: 0.9,
        });
    }

    // Lodash
    if signals.script_sources.iter().any(|s| s.contains("lodash")) || body.contains("lodash") {
        libraries.push(JsLibraryInfo {
            name: "Lodash".to_string(),
            version: None,
            confidence: 0.8,
        });
    }

    // Bootstrap
    if signals
        .script_sources
        .iter()
        .any(|s| s.contains("bootstrap"))
        || body.contains("bootstrap")
    {
        libraries.push(JsLibraryInfo {
            name: "Bootstrap".to_string(),
            version: None,
            confidence: 0.7,
        });
    }

    // Tailwind CSS (check for typical Tailwind classes)
    if body.contains("class=\"")
        && (body.contains(" flex ")
            || body.contains(" grid ")
            || body.contains(" bg-")
            || body.contains(" text-"))
    {
        // This is a weak signal, many sites use these class names
        // Look for more specific Tailwind patterns
        if body.contains("tailwind")
            || signals
                .script_sources
                .iter()
                .any(|s| s.contains("tailwind"))
            || body.contains("hover:")
            || body.contains("focus:")
            || body.contains("md:")
            || body.contains("lg:")
        {
            libraries.push(JsLibraryInfo {
                name: "Tailwind CSS".to_string(),
                version: None,
                confidence: 0.7,
            });
        }
    }

    // HTMX
    if body.contains("hx-") || signals.script_sources.iter().any(|s| s.contains("htmx")) {
        libraries.push(JsLibraryInfo {
            name: "htmx".to_string(),
            version: None,
            confidence: 0.85,
        });
    }

    // Alpine.js
    if body.contains("x-data")
        || body.contains("x-init")
        || signals.script_sources.iter().any(|s| s.contains("alpine"))
    {
        libraries.push(JsLibraryInfo {
            name: "Alpine.js".to_string(),
            version: None,
            confidence: 0.8,
        });
    }

    libraries
}

/// Extract jQuery version
fn extract_jquery_version(signals: &TechSignals, _body: &str) -> Option<String> {
    // Look in script sources for version
    for src in &signals.script_sources {
        if src.contains("jquery") {
            // Pattern: jquery-3.6.0.min.js or jquery/3.6.0/
            if let Some(version) = extract_version_from_path(src, "jquery") {
                return Some(version);
            }
        }
    }
    None
}

/// Extract version from a path like "jquery-3.6.0.min.js"
fn extract_version_from_path(path: &str, lib_name: &str) -> Option<String> {
    let lower = path.to_lowercase();
    if let Some(idx) = lower.find(lib_name) {
        let after = &path[idx + lib_name.len()..];
        // Look for version pattern: -3.6.0, /3.6.0/, @3.6.0
        let version_start = after.find(|c: char| c.is_ascii_digit())?;
        let version_part = &after[version_start..];
        let version_end = version_part.find(|c: char| !c.is_ascii_digit() && c != '.')?;
        let version = &version_part[..version_end];
        if version.contains('.') {
            return Some(version.to_string());
        }
    }
    None
}

/// Detect analytics services
fn detect_analytics(_signals: &TechSignals, body: &str) -> Vec<AnalyticsInfo> {
    let mut analytics = Vec::new();

    // Google Analytics (GA4)
    if body.contains("gtag")
        || body.contains("googletagmanager")
        || body.contains("G-") && body.contains("google")
    {
        let tracking_id = extract_ga_tracking_id(body);
        analytics.push(AnalyticsInfo {
            name: "Google Analytics".to_string(),
            tracking_id,
        });
    }

    // Google Tag Manager
    if body.contains("GTM-") {
        let tracking_id = extract_pattern(body, "GTM-", 10);
        analytics.push(AnalyticsInfo {
            name: "Google Tag Manager".to_string(),
            tracking_id,
        });
    }

    // Facebook Pixel
    if body.contains("facebook.com/tr") || body.contains("fbq(") || body.contains("fbevents.js") {
        analytics.push(AnalyticsInfo {
            name: "Facebook Pixel".to_string(),
            tracking_id: None,
        });
    }

    // Segment
    if body.contains("segment.com") || body.contains("analytics.js") && body.contains("segment") {
        analytics.push(AnalyticsInfo {
            name: "Segment".to_string(),
            tracking_id: None,
        });
    }

    // Hotjar
    if body.contains("hotjar.com") || body.contains("static.hotjar.com") {
        analytics.push(AnalyticsInfo {
            name: "Hotjar".to_string(),
            tracking_id: None,
        });
    }

    // Mixpanel
    if body.contains("mixpanel.com") || body.contains("mixpanel.init") {
        analytics.push(AnalyticsInfo {
            name: "Mixpanel".to_string(),
            tracking_id: None,
        });
    }

    // Plausible
    if body.contains("plausible.io") {
        analytics.push(AnalyticsInfo {
            name: "Plausible".to_string(),
            tracking_id: None,
        });
    }

    // Fathom
    if body.contains("usefathom.com") || body.contains("cdn.usefathom.com") {
        analytics.push(AnalyticsInfo {
            name: "Fathom".to_string(),
            tracking_id: None,
        });
    }

    analytics
}

/// Extract Google Analytics tracking ID
fn extract_ga_tracking_id(body: &str) -> Option<String> {
    // GA4 format: G-XXXXXXXXXX
    if let Some(id) = extract_pattern(body, "G-", 12) {
        return Some(id);
    }
    // Universal Analytics format: UA-XXXXXXXX-X
    if let Some(id) = extract_pattern(body, "UA-", 15) {
        return Some(id);
    }
    None
}

/// Extract a pattern from body
fn extract_pattern(body: &str, prefix: &str, max_len: usize) -> Option<String> {
    if let Some(idx) = body.find(prefix) {
        let start = idx;
        let remaining = &body[start..];
        let end = remaining
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '-')
            .unwrap_or(remaining.len().min(max_len));
        let result = &remaining[..end];
        if result.len() > prefix.len() {
            return Some(result.to_string());
        }
    }
    None
}

/// Generate issues based on tech stack detection
fn generate_issues(
    server: &Option<ServerInfo>,
    cdn: &Option<CdnInfo>,
    _frameworks: &[FrameworkInfo],
    signals: &TechSignals,
) -> Vec<TechStackIssue> {
    let mut issues = Vec::new();

    // Server version disclosure
    if let Some(ref s) = server {
        if s.version.is_some() {
            issues.push(TechStackIssue {
                severity: Severity::Low,
                category: "disclosure".to_string(),
                message: format!(
                    "Server version disclosed: {} {}",
                    s.name,
                    s.version.as_ref().unwrap()
                ),
            });
        }
    }

    // X-Powered-By header (information disclosure)
    if signals.headers.contains_key("x-powered-by") {
        issues.push(TechStackIssue {
            severity: Severity::Low,
            category: "disclosure".to_string(),
            message: format!(
                "X-Powered-By header exposes technology: {}",
                signals.headers.get("x-powered-by").unwrap()
            ),
        });
    }

    // No CDN detected
    if cdn.is_none() {
        issues.push(TechStackIssue {
            severity: Severity::Low,
            category: "performance".to_string(),
            message: "No CDN detected (consider using one for performance)".to_string(),
        });
    }

    // Generator meta tag disclosure
    if let Some(ref gen) = signals.generator {
        issues.push(TechStackIssue {
            severity: Severity::Low,
            category: "disclosure".to_string(),
            message: format!("Generator meta tag exposes: {}", gen),
        });
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_server_string() {
        let (name, version) = parse_server_string("nginx/1.21.0");
        assert_eq!(name, "nginx");
        assert_eq!(version, Some("1.21.0".to_string()));

        let (name, version) = parse_server_string("Apache/2.4.41 (Ubuntu)");
        assert_eq!(name, "Apache");
        assert_eq!(version, Some("2.4.41".to_string()));

        let (name, version) = parse_server_string("cloudflare");
        assert_eq!(name, "Cloudflare");
        assert_eq!(version, None);
    }

    #[test]
    fn test_extract_version() {
        assert_eq!(extract_version("nginx/1.21.0"), Some("1.21.0".to_string()));
        assert_eq!(extract_version("PHP/8.1.0"), Some("8.1.0".to_string()));
        assert_eq!(extract_version("Apache"), None);
    }

    #[test]
    fn test_detect_cdn_cloudflare() {
        let mut signals = TechSignals::default();
        signals
            .headers
            .insert("cf-ray".to_string(), "12345-SJC".to_string());
        signals
            .headers
            .insert("cf-cache-status".to_string(), "HIT".to_string());

        let cdn = detect_cdn(&signals);
        assert!(cdn.is_some());
        let cdn = cdn.unwrap();
        assert_eq!(cdn.name, "Cloudflare");
        assert_eq!(cdn.edge_location, Some("SJC".to_string()));
    }

    #[test]
    fn test_detect_cdn_vercel() {
        let mut signals = TechSignals::default();
        signals
            .headers
            .insert("x-vercel-id".to_string(), "iad1::abc123".to_string());

        let cdn = detect_cdn(&signals);
        assert!(cdn.is_some());
        assert_eq!(cdn.unwrap().name, "Vercel");
    }

    #[test]
    fn test_extract_angular_version() {
        let body = r#"<html ng-version="15.2.0"></html>"#;
        assert_eq!(extract_angular_version(body), Some("15.2.0".to_string()));
    }

    #[test]
    fn test_extract_pattern() {
        let body = "window.ga('create', 'UA-12345678-1', 'auto');";
        assert_eq!(
            extract_pattern(body, "UA-", 15),
            Some("UA-12345678-1".to_string())
        );

        let body = "gtag('config', 'G-ABC123DEF4');";
        assert_eq!(
            extract_pattern(body, "G-", 12),
            Some("G-ABC123DEF4".to_string())
        );
    }

    #[test]
    fn test_detect_wordpress() {
        let signals = TechSignals {
            generator: Some("WordPress 6.4.2".to_string()),
            ..Default::default()
        };
        let body = "<link href='/wp-content/themes/theme/style.css'>";

        let cms = detect_cms(&signals, body);
        assert!(cms.is_some());
        let cms = cms.unwrap();
        assert_eq!(cms.name, "WordPress");
        assert_eq!(cms.version, Some("6.4.2".to_string()));
    }
}
