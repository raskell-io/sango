//! Content analysis for browser-based probes

use scraper::{Html, Selector};
use web_sys::Response;

use crate::{AeoResult, ContentResult, HeadersResult, Issue, SeoResult, TechStackResult};

/// Analyze response headers
pub fn analyze_headers(response: &Response) -> HeadersResult {
    let headers = response.headers();

    let get_header = |name: &str| -> Option<String> {
        headers.get(name).ok().flatten()
    };

    let content_type = get_header("content-type");
    let content_length = get_header("content-length");
    let server = get_header("server");
    let cache_control = get_header("cache-control");

    let has_hsts = get_header("strict-transport-security").is_some();
    let has_csp = get_header("content-security-policy").is_some()
        || get_header("content-security-policy-report-only").is_some();
    let has_xfo = get_header("x-frame-options").is_some();
    let has_xcto = get_header("x-content-type-options").is_some();

    // Collect all headers
    let mut all = serde_json::Map::new();
    // Note: We can't iterate headers in web-sys, so we check common ones
    for name in &[
        "content-type", "content-length", "server", "cache-control",
        "strict-transport-security", "content-security-policy",
        "x-frame-options", "x-content-type-options", "x-xss-protection",
        "referrer-policy", "permissions-policy", "content-encoding",
        "vary", "etag", "last-modified", "expires", "age",
        "cf-ray", "x-vercel-id", "x-powered-by",
    ] {
        if let Some(value) = get_header(name) {
            all.insert(name.to_string(), serde_json::Value::String(value));
        }
    }

    HeadersResult {
        content_type,
        content_length,
        server,
        cache_control,
        has_hsts,
        has_csp,
        has_xfo,
        has_xcto,
        all_headers: serde_json::to_string(&all).unwrap_or_default(),
    }
}

/// Analyze content
pub fn analyze_content(body: &str, headers: &HeadersResult) -> ContentResult {
    let size_bytes = body.len();
    let size_formatted = format_size(size_bytes);

    let mime_type = headers.content_type.as_ref().map(|ct| {
        ct.split(';').next().unwrap_or(ct).trim().to_string()
    });

    let charset = headers.content_type.as_ref().and_then(|ct| {
        ct.to_lowercase()
            .split(';')
            .find(|part| part.trim().starts_with("charset="))
            .map(|part| part.trim()[8..].trim_matches('"').to_string())
    });

    // Check for compression in headers (this is what the browser received)
    let compression = None; // Browser decompresses automatically
    let is_compressed = false; // We see decompressed content

    ContentResult {
        size_bytes,
        size_formatted,
        mime_type,
        charset,
        is_compressed,
        compression,
    }
}

/// Format size for display
fn format_size(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;

    if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

/// Analyze SEO signals
pub fn analyze_seo(body: &str) -> SeoResult {
    let document = Html::parse_document(body);

    // Title
    let title = extract_text(&document, "title");
    let title_length = title.as_ref().map(|t| t.len()).unwrap_or(0);

    // Meta description
    let description = extract_meta(&document, "description");
    let description_length = description.as_ref().map(|d| d.len()).unwrap_or(0);

    // Canonical
    let canonical = extract_link_href(&document, "canonical");

    // Open Graph
    let has_open_graph = extract_meta_property(&document, "og:title").is_some();

    // Twitter Card
    let has_twitter_card = extract_meta(&document, "twitter:card").is_some()
        || extract_meta_property(&document, "twitter:card").is_some();

    // H1 count
    let h1_count = count_elements(&document, "h1");

    // Structured data
    let has_structured_data = has_json_ld(&document);

    // Language
    let language = extract_html_lang(&document);

    // Calculate score
    let mut score: u8 = 0;
    if title.is_some() && title_length >= 30 && title_length <= 60 { score += 15; }
    else if title.is_some() { score += 10; }
    if description.is_some() && description_length >= 120 && description_length <= 160 { score += 15; }
    else if description.is_some() { score += 10; }
    if canonical.is_some() { score += 10; }
    if has_open_graph { score += 15; }
    if has_twitter_card { score += 10; }
    if h1_count == 1 { score += 15; }
    else if h1_count > 0 { score += 5; }
    if has_structured_data { score += 15; }
    if language.is_some() { score += 5; }

    SeoResult {
        score,
        title,
        title_length,
        description,
        description_length,
        canonical,
        has_open_graph,
        has_twitter_card,
        h1_count,
        has_structured_data,
        language,
    }
}

/// Analyze AEO signals
pub fn analyze_aeo(body: &str) -> AeoResult {
    let document = Html::parse_document(body);

    // JSON-LD
    let json_ld_blocks = extract_json_ld_blocks(&document);
    let json_ld_count = json_ld_blocks.len();

    // Schema types
    let schema_types = extract_schema_types(&json_ld_blocks);

    // llms.txt would require another fetch, so we skip it in browser version
    let has_llms_txt = false;

    // Text ratio
    let text_ratio = calculate_text_ratio(body);

    // Semantic score
    let semantic_score = calculate_semantic_score(&document);

    // Word count
    let word_count = count_words(&document);

    // Calculate score
    let mut score: u8 = 0;
    if json_ld_count > 0 { score += 25; }
    if !schema_types.is_empty() { score += 15; }
    if text_ratio > 0.15 { score += 15; }
    else if text_ratio > 0.05 { score += 10; }
    if semantic_score >= 70 { score += 20; }
    else if semantic_score >= 50 { score += 10; }
    if word_count > 300 { score += 15; }
    else if word_count > 100 { score += 10; }
    // llms.txt would add 10

    let readiness = match score {
        80..=100 => "Excellent",
        60..=79 => "Good",
        40..=59 => "Basic",
        _ => "Poor",
    }.to_string();

    AeoResult {
        score,
        readiness,
        json_ld_count,
        schema_types,
        has_llms_txt,
        text_ratio,
        semantic_score,
        word_count,
    }
}

/// Analyze tech stack
pub fn analyze_techstack(body: &str, headers: &HeadersResult) -> TechStackResult {
    let document = Html::parse_document(body);
    let body_lower = body.to_lowercase();

    // Server from header
    let server = headers.server.clone();

    // CDN detection
    let cdn = detect_cdn(headers);

    // Framework detection
    let frameworks = detect_frameworks(&document, &body_lower);

    // CMS detection
    let cms = detect_cms(&document, &body_lower, headers);

    // JS libraries
    let js_libraries = detect_js_libraries(&body_lower);

    // Analytics
    let analytics = detect_analytics(&body_lower);

    TechStackResult {
        server,
        cdn,
        frameworks,
        cms,
        js_libraries,
        analytics,
    }
}

// === Helper functions ===

fn extract_text(document: &Html, selector: &str) -> Option<String> {
    Selector::parse(selector).ok().and_then(|sel| {
        document.select(&sel).next().map(|el| {
            el.text().collect::<Vec<_>>().join(" ").trim().to_string()
        })
    }).filter(|s| !s.is_empty())
}

fn extract_meta(document: &Html, name: &str) -> Option<String> {
    let selector = format!("meta[name='{}']", name);
    Selector::parse(&selector).ok().and_then(|sel| {
        document.select(&sel).next().and_then(|el| {
            el.value().attr("content").map(|s| s.to_string())
        })
    })
}

fn extract_meta_property(document: &Html, property: &str) -> Option<String> {
    let selector = format!("meta[property='{}']", property);
    Selector::parse(&selector).ok().and_then(|sel| {
        document.select(&sel).next().and_then(|el| {
            el.value().attr("content").map(|s| s.to_string())
        })
    })
}

fn extract_link_href(document: &Html, rel: &str) -> Option<String> {
    let selector = format!("link[rel='{}']", rel);
    Selector::parse(&selector).ok().and_then(|sel| {
        document.select(&sel).next().and_then(|el| {
            el.value().attr("href").map(|s| s.to_string())
        })
    })
}

fn extract_html_lang(document: &Html) -> Option<String> {
    Selector::parse("html").ok().and_then(|sel| {
        document.select(&sel).next().and_then(|el| {
            el.value().attr("lang").map(|s| s.to_string())
        })
    })
}

fn count_elements(document: &Html, selector: &str) -> usize {
    Selector::parse(selector)
        .map(|sel| document.select(&sel).count())
        .unwrap_or(0)
}

fn has_json_ld(document: &Html) -> bool {
    Selector::parse("script[type='application/ld+json']")
        .map(|sel| document.select(&sel).next().is_some())
        .unwrap_or(false)
}

fn extract_json_ld_blocks(document: &Html) -> Vec<String> {
    Selector::parse("script[type='application/ld+json']")
        .map(|sel| {
            document.select(&sel)
                .map(|el| el.text().collect::<String>())
                .collect()
        })
        .unwrap_or_default()
}

fn extract_schema_types(blocks: &[String]) -> Vec<String> {
    let mut types = Vec::new();
    for block in blocks {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(block) {
            extract_types_from_json(&json, &mut types);
        }
    }
    types.sort();
    types.dedup();
    types
}

fn extract_types_from_json(value: &serde_json::Value, types: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(t) = map.get("@type") {
                match t {
                    serde_json::Value::String(s) => types.push(s.clone()),
                    serde_json::Value::Array(arr) => {
                        for item in arr {
                            if let serde_json::Value::String(s) = item {
                                types.push(s.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }
            for v in map.values() {
                extract_types_from_json(v, types);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                extract_types_from_json(item, types);
            }
        }
        _ => {}
    }
}

fn calculate_text_ratio(body: &str) -> f32 {
    let total_len = body.len() as f32;
    if total_len == 0.0 {
        return 0.0;
    }

    let document = Html::parse_document(body);
    let text_len: usize = document.root_element()
        .text()
        .map(|t| t.trim().len())
        .sum();

    text_len as f32 / total_len
}

fn calculate_semantic_score(document: &Html) -> u8 {
    let mut score: u8 = 0;

    // Check for semantic elements
    let semantic_elements = [
        ("main", 15),
        ("article", 15),
        ("header", 10),
        ("nav", 10),
        ("footer", 10),
        ("section", 10),
        ("aside", 5),
        ("figure", 5),
        ("figcaption", 5),
    ];

    for (element, points) in semantic_elements {
        if count_elements(document, element) > 0 {
            score = score.saturating_add(points);
        }
    }

    score.min(100)
}

fn count_words(document: &Html) -> usize {
    document.root_element()
        .text()
        .flat_map(|t| t.split_whitespace())
        .count()
}

fn detect_cdn(headers: &HeadersResult) -> Option<String> {
    let all: serde_json::Value = serde_json::from_str(&headers.all_headers).unwrap_or_default();

    if all.get("cf-ray").is_some() {
        return Some("Cloudflare".to_string());
    }
    if all.get("x-vercel-id").is_some() {
        return Some("Vercel".to_string());
    }
    if headers.server.as_ref().map(|s| s.to_lowercase().contains("cloudflare")).unwrap_or(false) {
        return Some("Cloudflare".to_string());
    }
    if headers.server.as_ref().map(|s| s.contains("Netlify")).unwrap_or(false) {
        return Some("Netlify".to_string());
    }

    None
}

fn detect_frameworks(_document: &Html, body: &str) -> Vec<String> {
    let mut frameworks = Vec::new();

    // Next.js
    if body.contains("__next") || body.contains("/_next/") {
        frameworks.push("Next.js".to_string());
    }

    // React
    if body.contains("__react") || body.contains("data-reactroot") || body.contains("react-dom") {
        frameworks.push("React".to_string());
    }

    // Vue
    if body.contains("__vue") || body.contains("data-v-") {
        frameworks.push("Vue.js".to_string());
    }

    // Nuxt
    if body.contains("__nuxt") || body.contains("/_nuxt/") {
        frameworks.push("Nuxt.js".to_string());
    }

    // Angular
    if body.contains("ng-version") || body.contains("ng-app") {
        frameworks.push("Angular".to_string());
    }

    // Svelte
    if body.contains("svelte") {
        frameworks.push("Svelte".to_string());
    }

    // Tailwind CSS
    if body.contains("tailwindcss") || count_tailwind_classes(body) > 10 {
        frameworks.push("Tailwind CSS".to_string());
    }

    frameworks
}

fn count_tailwind_classes(body: &str) -> usize {
    let patterns = ["flex", "grid", "p-", "m-", "text-", "bg-", "w-", "h-"];
    patterns.iter().filter(|p| body.contains(*p)).count()
}

fn detect_cms(document: &Html, body: &str, _headers: &HeadersResult) -> Option<String> {
    // WordPress
    if body.contains("wp-content") || body.contains("wp-includes") {
        return Some("WordPress".to_string());
    }

    // Webflow
    if body.contains("webflow") {
        return Some("Webflow".to_string());
    }

    // Shopify
    if body.contains("shopify") || body.contains("cdn.shopify.com") {
        return Some("Shopify".to_string());
    }

    // Squarespace
    if body.contains("squarespace") {
        return Some("Squarespace".to_string());
    }

    // Wix
    if body.contains("wix.com") || body.contains("wixstatic") {
        return Some("Wix".to_string());
    }

    // Ghost
    if extract_meta(document, "generator")
        .map(|g| g.to_lowercase().contains("ghost"))
        .unwrap_or(false)
    {
        return Some("Ghost".to_string());
    }

    None
}

fn detect_js_libraries(body: &str) -> Vec<String> {
    let mut libs = Vec::new();

    if body.contains("jquery") {
        libs.push("jQuery".to_string());
    }
    if body.contains("lodash") {
        libs.push("Lodash".to_string());
    }
    if body.contains("axios") {
        libs.push("Axios".to_string());
    }
    if body.contains("moment") {
        libs.push("Moment.js".to_string());
    }

    libs
}

fn detect_analytics(body: &str) -> Vec<String> {
    let mut analytics = Vec::new();

    if body.contains("google-analytics") || body.contains("googletagmanager") || body.contains("gtag") {
        analytics.push("Google Analytics".to_string());
    }
    if body.contains("segment.com") || body.contains("analytics.js") {
        analytics.push("Segment".to_string());
    }
    if body.contains("hotjar") {
        analytics.push("Hotjar".to_string());
    }
    if body.contains("plausible") {
        analytics.push("Plausible".to_string());
    }

    analytics
}

// === Issue generation ===

pub fn generate_header_issues(headers: &HeadersResult) -> Vec<Issue> {
    let mut issues = Vec::new();

    if !headers.has_hsts {
        issues.push(Issue {
            severity: "high".to_string(),
            category: "security".to_string(),
            message: "HSTS header missing - site vulnerable to downgrade attacks".to_string(),
        });
    }

    if !headers.has_csp {
        issues.push(Issue {
            severity: "medium".to_string(),
            category: "security".to_string(),
            message: "CSP header missing - reduced XSS protection".to_string(),
        });
    }

    if !headers.has_xcto {
        issues.push(Issue {
            severity: "low".to_string(),
            category: "security".to_string(),
            message: "X-Content-Type-Options header missing".to_string(),
        });
    }

    issues
}

pub fn generate_seo_issues(seo: &SeoResult) -> Vec<Issue> {
    let mut issues = Vec::new();

    if seo.title.is_none() {
        issues.push(Issue {
            severity: "high".to_string(),
            category: "seo".to_string(),
            message: "Missing page title".to_string(),
        });
    } else if seo.title_length < 30 {
        issues.push(Issue {
            severity: "medium".to_string(),
            category: "seo".to_string(),
            message: format!("Title too short ({} chars, recommend 30-60)", seo.title_length),
        });
    }

    if seo.description.is_none() {
        issues.push(Issue {
            severity: "medium".to_string(),
            category: "seo".to_string(),
            message: "Missing meta description".to_string(),
        });
    }

    if seo.h1_count == 0 {
        issues.push(Issue {
            severity: "medium".to_string(),
            category: "seo".to_string(),
            message: "No H1 heading found".to_string(),
        });
    } else if seo.h1_count > 1 {
        issues.push(Issue {
            severity: "low".to_string(),
            category: "seo".to_string(),
            message: format!("Multiple H1 tags ({})", seo.h1_count),
        });
    }

    if !seo.has_structured_data {
        issues.push(Issue {
            severity: "low".to_string(),
            category: "seo".to_string(),
            message: "No structured data (JSON-LD) found".to_string(),
        });
    }

    issues
}

pub fn generate_aeo_issues(aeo: &AeoResult) -> Vec<Issue> {
    let mut issues = Vec::new();

    if aeo.json_ld_count == 0 {
        issues.push(Issue {
            severity: "medium".to_string(),
            category: "aeo".to_string(),
            message: "No JSON-LD structured data for AI understanding".to_string(),
        });
    }

    if aeo.text_ratio < 0.1 {
        issues.push(Issue {
            severity: "low".to_string(),
            category: "aeo".to_string(),
            message: format!("Low text-to-HTML ratio ({:.1}%)", aeo.text_ratio * 100.0),
        });
    }

    if aeo.semantic_score < 50 {
        issues.push(Issue {
            severity: "low".to_string(),
            category: "aeo".to_string(),
            message: format!("Low semantic HTML usage ({}%)", aeo.semantic_score),
        });
    }

    issues
}

pub fn generate_content_issues(content: &ContentResult) -> Vec<Issue> {
    let mut issues = Vec::new();

    if content.size_bytes > 1_000_000 {
        issues.push(Issue {
            severity: "medium".to_string(),
            category: "performance".to_string(),
            message: format!("Large response size ({})", content.size_formatted),
        });
    }

    issues
}
