//! SEO (Search Engine Optimization) analysis
//!
//! - Meta tags audit (title, description, canonical, robots)
//! - Open Graph / Social media tags
//! - Technical SEO (viewport, headings, hreflang)
//! - Performance signals affecting SEO

use anyhow::{Context, Result};
use reqwest::Client;
use scraper::{Html, Selector};
use serde::Serialize;
use std::collections::HashMap;
use std::time::Duration;

use super::tls::Severity;

/// Result of SEO analysis
#[derive(Debug, Serialize)]
pub struct SeoResult {
    /// Page title analysis
    pub title: Option<TitleInfo>,
    /// Meta description analysis
    pub description: Option<DescriptionInfo>,
    /// Canonical URL
    pub canonical: Option<CanonicalInfo>,
    /// Robots directives
    pub robots: RobotsInfo,
    /// Open Graph metadata
    pub open_graph: OpenGraphInfo,
    /// Twitter Card metadata
    pub twitter_card: TwitterCardInfo,
    /// Heading structure
    pub headings: HeadingStructure,
    /// Technical SEO signals
    pub technical: TechnicalSeo,
    /// Internationalization
    pub i18n: I18nInfo,
    /// Structured data presence
    pub structured_data: StructuredDataInfo,
    /// SEO score (0-100)
    pub score: u8,
    /// Detected issues
    pub issues: Vec<SeoIssue>,
}

/// Title tag analysis
#[derive(Debug, Serialize, Clone)]
pub struct TitleInfo {
    /// Title content
    pub content: String,
    /// Character length
    pub length: usize,
    /// Whether length is optimal (50-60 chars)
    pub length_optimal: bool,
    /// Whether title appears truncated
    pub may_truncate: bool,
}

/// Meta description analysis
#[derive(Debug, Serialize, Clone)]
pub struct DescriptionInfo {
    /// Description content
    pub content: String,
    /// Character length
    pub length: usize,
    /// Whether length is optimal (150-160 chars)
    pub length_optimal: bool,
    /// Whether description may truncate in SERPs
    pub may_truncate: bool,
}

/// Canonical URL analysis
#[derive(Debug, Serialize, Clone)]
pub struct CanonicalInfo {
    /// Canonical URL
    pub url: String,
    /// Whether it's self-referencing
    pub is_self_referencing: bool,
    /// Whether it's a valid absolute URL
    pub is_absolute: bool,
}

/// Robots directives
#[derive(Debug, Serialize, Clone, Default)]
pub struct RobotsInfo {
    /// Meta robots content
    pub meta_robots: Option<String>,
    /// X-Robots-Tag header
    pub x_robots_tag: Option<String>,
    /// Is indexing allowed
    pub index_allowed: bool,
    /// Is following allowed
    pub follow_allowed: bool,
    /// Other directives present
    pub other_directives: Vec<String>,
}

/// Open Graph metadata
#[derive(Debug, Serialize, Clone, Default)]
pub struct OpenGraphInfo {
    /// og:title
    pub title: Option<String>,
    /// og:description
    pub description: Option<String>,
    /// og:image
    pub image: Option<String>,
    /// og:url
    pub url: Option<String>,
    /// og:type
    pub og_type: Option<String>,
    /// og:site_name
    pub site_name: Option<String>,
    /// Whether OG tags are complete
    pub is_complete: bool,
}

/// Twitter Card metadata
#[derive(Debug, Serialize, Clone, Default)]
pub struct TwitterCardInfo {
    /// twitter:card type
    pub card_type: Option<String>,
    /// twitter:title
    pub title: Option<String>,
    /// twitter:description
    pub description: Option<String>,
    /// twitter:image
    pub image: Option<String>,
    /// twitter:site
    pub site: Option<String>,
    /// Whether Twitter Card is valid
    pub is_valid: bool,
}

/// Heading structure analysis
#[derive(Debug, Serialize, Clone, Default)]
pub struct HeadingStructure {
    /// Number of H1 tags
    pub h1_count: usize,
    /// H1 content (first one if multiple)
    pub h1_content: Option<String>,
    /// Heading hierarchy (h1, h2, h3, etc. counts)
    pub hierarchy: HashMap<String, usize>,
    /// Whether hierarchy is properly structured
    pub is_valid_hierarchy: bool,
    /// Issues with heading structure
    pub hierarchy_issues: Vec<String>,
}

/// Technical SEO signals
#[derive(Debug, Serialize, Clone, Default)]
pub struct TechnicalSeo {
    /// Viewport meta tag present
    pub has_viewport: bool,
    /// Viewport content
    pub viewport_content: Option<String>,
    /// Is mobile-friendly (based on viewport)
    pub is_mobile_friendly: bool,
    /// Character encoding
    pub charset: Option<String>,
    /// Language attribute on html tag
    pub html_lang: Option<String>,
    /// Content-Language header
    pub content_language: Option<String>,
    /// Has favicon
    pub has_favicon: bool,
    /// Document size in bytes
    pub document_size: usize,
    /// Number of internal links
    pub internal_links: usize,
    /// Number of external links
    pub external_links: usize,
    /// Number of images
    pub image_count: usize,
    /// Images without alt text
    pub images_without_alt: usize,
}

/// Internationalization info
#[derive(Debug, Serialize, Clone, Default)]
pub struct I18nInfo {
    /// Hreflang tags found
    pub hreflang_tags: Vec<HreflangTag>,
    /// Default language
    pub default_language: Option<String>,
    /// Has x-default
    pub has_x_default: bool,
}

/// Single hreflang tag
#[derive(Debug, Serialize, Clone)]
pub struct HreflangTag {
    /// Language/region code
    pub hreflang: String,
    /// URL
    pub href: String,
}

/// Structured data information
#[derive(Debug, Serialize, Clone, Default)]
pub struct StructuredDataInfo {
    /// Has JSON-LD
    pub has_json_ld: bool,
    /// JSON-LD types found
    pub json_ld_types: Vec<String>,
    /// Has microdata
    pub has_microdata: bool,
    /// Has RDFa
    pub has_rdfa: bool,
}

/// An SEO issue
#[derive(Debug, Serialize, Clone)]
pub struct SeoIssue {
    pub severity: Severity,
    pub category: String,
    pub message: String,
    pub recommendation: Option<String>,
}

/// Check SEO
pub async fn check_seo(target: &str, timeout: Duration) -> Result<SeoResult> {
    let url = normalize_url(target);

    let client = Client::builder()
        .timeout(timeout)
        .build()
        .context("Failed to build HTTP client")?;

    // Fetch the page
    let response = client
        .get(&url)
        .header("User-Agent", "Mozilla/5.0 (compatible; Sango/1.0; +https://github.com/raskell-io/sango)")
        .send()
        .await
        .context(format!("Failed to fetch {}", url))?;

    // Collect headers
    let x_robots_tag = response
        .headers()
        .get("x-robots-tag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let content_language = response
        .headers()
        .get("content-language")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Get response body
    let body = response.text().await.unwrap_or_default();
    let document_size = body.len();

    // Parse HTML
    let document = Html::parse_document(&body);

    // Extract all SEO signals
    let title = extract_title(&document);
    let description = extract_description(&document);
    let canonical = extract_canonical(&document, &url);
    let robots = extract_robots(&document, x_robots_tag);
    let open_graph = extract_open_graph(&document);
    let twitter_card = extract_twitter_card(&document);
    let headings = extract_headings(&document);
    let technical = extract_technical_seo(&document, &url, document_size, content_language);
    let i18n = extract_i18n(&document);
    let structured_data = extract_structured_data(&document, &body);

    // Generate issues
    let issues = generate_issues(
        &title,
        &description,
        &canonical,
        &robots,
        &open_graph,
        &twitter_card,
        &headings,
        &technical,
        &structured_data,
    );

    // Calculate score
    let score = calculate_score(
        &title,
        &description,
        &canonical,
        &robots,
        &open_graph,
        &headings,
        &technical,
        &structured_data,
        &issues,
    );

    Ok(SeoResult {
        title,
        description,
        canonical,
        robots,
        open_graph,
        twitter_card,
        headings,
        technical,
        i18n,
        structured_data,
        score,
        issues,
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

/// Extract title tag
fn extract_title(document: &Html) -> Option<TitleInfo> {
    let selector = Selector::parse("title").ok()?;
    let element = document.select(&selector).next()?;
    let content = element.text().collect::<String>().trim().to_string();

    if content.is_empty() {
        return None;
    }

    let length = content.chars().count();
    let length_optimal = length >= 50 && length <= 60;
    let may_truncate = length > 60;

    Some(TitleInfo {
        content,
        length,
        length_optimal,
        may_truncate,
    })
}

/// Extract meta description
fn extract_description(document: &Html) -> Option<DescriptionInfo> {
    let selector = Selector::parse("meta[name='description']").ok()?;
    let element = document.select(&selector).next()?;
    let content = element.value().attr("content")?.trim().to_string();

    if content.is_empty() {
        return None;
    }

    let length = content.chars().count();
    let length_optimal = length >= 150 && length <= 160;
    let may_truncate = length > 160;

    Some(DescriptionInfo {
        content,
        length,
        length_optimal,
        may_truncate,
    })
}

/// Extract canonical URL
fn extract_canonical(document: &Html, page_url: &str) -> Option<CanonicalInfo> {
    let selector = Selector::parse("link[rel='canonical']").ok()?;
    let element = document.select(&selector).next()?;
    let url = element.value().attr("href")?.trim().to_string();

    if url.is_empty() {
        return None;
    }

    let is_absolute = url.starts_with("http://") || url.starts_with("https://");
    let is_self_referencing = normalize_url_for_comparison(&url) == normalize_url_for_comparison(page_url);

    Some(CanonicalInfo {
        url,
        is_self_referencing,
        is_absolute,
    })
}

/// Normalize URL for comparison (remove trailing slash, etc.)
fn normalize_url_for_comparison(url: &str) -> String {
    url.trim_end_matches('/').to_lowercase()
}

/// Extract robots directives
fn extract_robots(document: &Html, x_robots_tag: Option<String>) -> RobotsInfo {
    let mut info = RobotsInfo {
        x_robots_tag,
        index_allowed: true,
        follow_allowed: true,
        ..Default::default()
    };

    // Check meta robots
    if let Ok(selector) = Selector::parse("meta[name='robots']") {
        if let Some(element) = document.select(&selector).next() {
            if let Some(content) = element.value().attr("content") {
                info.meta_robots = Some(content.to_string());
                parse_robots_directives(content, &mut info);
            }
        }
    }

    // Also check X-Robots-Tag header
    if let Some(tag) = info.x_robots_tag.clone() {
        parse_robots_directives(&tag, &mut info);
    }

    info
}

/// Parse robots directives string
fn parse_robots_directives(content: &str, info: &mut RobotsInfo) {
    let lower = content.to_lowercase();

    for directive in lower.split(',').map(|s| s.trim()) {
        match directive {
            "noindex" => info.index_allowed = false,
            "nofollow" => info.follow_allowed = false,
            "none" => {
                info.index_allowed = false;
                info.follow_allowed = false;
            }
            "index" | "follow" | "all" => {}
            other if !other.is_empty() => {
                info.other_directives.push(other.to_string());
            }
            _ => {}
        }
    }
}

/// Extract Open Graph metadata
fn extract_open_graph(document: &Html) -> OpenGraphInfo {
    let mut og = OpenGraphInfo::default();

    if let Ok(selector) = Selector::parse("meta[property^='og:']") {
        for element in document.select(&selector) {
            let property = element.value().attr("property").unwrap_or_default();
            let content = element.value().attr("content").unwrap_or_default().to_string();

            match property {
                "og:title" => og.title = Some(content),
                "og:description" => og.description = Some(content),
                "og:image" => og.image = Some(content),
                "og:url" => og.url = Some(content),
                "og:type" => og.og_type = Some(content),
                "og:site_name" => og.site_name = Some(content),
                _ => {}
            }
        }
    }

    // Check if OG is complete (has required tags)
    og.is_complete = og.title.is_some() && og.description.is_some() && og.image.is_some();

    og
}

/// Extract Twitter Card metadata
fn extract_twitter_card(document: &Html) -> TwitterCardInfo {
    let mut tc = TwitterCardInfo::default();

    if let Ok(selector) = Selector::parse("meta[name^='twitter:']") {
        for element in document.select(&selector) {
            let name = element.value().attr("name").unwrap_or_default();
            let content = element.value().attr("content").unwrap_or_default().to_string();

            match name {
                "twitter:card" => tc.card_type = Some(content),
                "twitter:title" => tc.title = Some(content),
                "twitter:description" => tc.description = Some(content),
                "twitter:image" => tc.image = Some(content),
                "twitter:site" => tc.site = Some(content),
                _ => {}
            }
        }
    }

    // Twitter Card is valid if it has at least card type
    tc.is_valid = tc.card_type.is_some();

    tc
}

/// Extract heading structure
fn extract_headings(document: &Html) -> HeadingStructure {
    let mut structure = HeadingStructure::default();
    let mut hierarchy_issues = Vec::new();

    // Count headings by level
    for level in 1..=6 {
        let tag = format!("h{}", level);
        let selector = match Selector::parse(&tag) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let count = document.select(&selector).count();
        if count > 0 {
            structure.hierarchy.insert(tag.clone(), count);

            // Get H1 content
            if level == 1 {
                structure.h1_count = count;
                if let Some(h1) = document.select(&selector).next() {
                    structure.h1_content = Some(h1.text().collect::<String>().trim().to_string());
                }
            }
        }
    }

    // Check hierarchy validity
    let h1_count = *structure.hierarchy.get("h1").unwrap_or(&0);
    let h2_count = *structure.hierarchy.get("h2").unwrap_or(&0);
    let h3_count = *structure.hierarchy.get("h3").unwrap_or(&0);

    if h1_count == 0 {
        hierarchy_issues.push("Missing H1 tag".to_string());
    } else if h1_count > 1 {
        hierarchy_issues.push(format!("Multiple H1 tags ({})", h1_count));
    }

    // Check for skipped levels
    if h3_count > 0 && h2_count == 0 {
        hierarchy_issues.push("H3 used without H2 (skipped heading level)".to_string());
    }

    structure.is_valid_hierarchy = hierarchy_issues.is_empty() && h1_count == 1;
    structure.hierarchy_issues = hierarchy_issues;

    structure
}

/// Extract technical SEO signals
fn extract_technical_seo(
    document: &Html,
    page_url: &str,
    document_size: usize,
    content_language: Option<String>,
) -> TechnicalSeo {
    let mut tech = TechnicalSeo {
        document_size,
        content_language,
        ..Default::default()
    };

    // Viewport
    if let Ok(selector) = Selector::parse("meta[name='viewport']") {
        if let Some(element) = document.select(&selector).next() {
            tech.has_viewport = true;
            tech.viewport_content = element.value().attr("content").map(|s| s.to_string());
            // Check if mobile-friendly
            if let Some(ref content) = tech.viewport_content {
                tech.is_mobile_friendly = content.contains("width=device-width");
            }
        }
    }

    // Charset
    if let Ok(selector) = Selector::parse("meta[charset]") {
        if let Some(element) = document.select(&selector).next() {
            tech.charset = element.value().attr("charset").map(|s| s.to_string());
        }
    }
    // Also check http-equiv
    if tech.charset.is_none() {
        if let Ok(selector) = Selector::parse("meta[http-equiv='Content-Type']") {
            if let Some(element) = document.select(&selector).next() {
                if let Some(content) = element.value().attr("content") {
                    if let Some(charset_start) = content.find("charset=") {
                        let charset = content[charset_start + 8..].split(';').next().unwrap_or("");
                        tech.charset = Some(charset.trim().to_string());
                    }
                }
            }
        }
    }

    // HTML lang attribute
    if let Ok(selector) = Selector::parse("html") {
        if let Some(element) = document.select(&selector).next() {
            tech.html_lang = element.value().attr("lang").map(|s| s.to_string());
        }
    }

    // Favicon
    if let Ok(selector) = Selector::parse("link[rel='icon'], link[rel='shortcut icon']") {
        tech.has_favicon = document.select(&selector).next().is_some();
    }

    // Count links
    let base_domain = extract_domain(page_url);
    if let Ok(selector) = Selector::parse("a[href]") {
        for element in document.select(&selector) {
            if let Some(href) = element.value().attr("href") {
                if href.starts_with("http://") || href.starts_with("https://") {
                    let link_domain = extract_domain(href);
                    if link_domain == base_domain {
                        tech.internal_links += 1;
                    } else {
                        tech.external_links += 1;
                    }
                } else if href.starts_with("/") || href.starts_with("#") || !href.contains("://") {
                    tech.internal_links += 1;
                }
            }
        }
    }

    // Count images and check alt text
    if let Ok(selector) = Selector::parse("img") {
        for element in document.select(&selector) {
            tech.image_count += 1;
            let alt = element.value().attr("alt").unwrap_or("");
            if alt.is_empty() {
                tech.images_without_alt += 1;
            }
        }
    }

    tech
}

/// Extract domain from URL
fn extract_domain(url: &str) -> String {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .to_lowercase()
}

/// Extract internationalization info
fn extract_i18n(document: &Html) -> I18nInfo {
    let mut i18n = I18nInfo::default();

    if let Ok(selector) = Selector::parse("link[rel='alternate'][hreflang]") {
        for element in document.select(&selector) {
            if let (Some(hreflang), Some(href)) = (
                element.value().attr("hreflang"),
                element.value().attr("href"),
            ) {
                if hreflang == "x-default" {
                    i18n.has_x_default = true;
                    i18n.default_language = Some(href.to_string());
                } else {
                    i18n.hreflang_tags.push(HreflangTag {
                        hreflang: hreflang.to_string(),
                        href: href.to_string(),
                    });
                }
            }
        }
    }

    i18n
}

/// Extract structured data information
fn extract_structured_data(document: &Html, body: &str) -> StructuredDataInfo {
    let mut sd = StructuredDataInfo::default();

    // Check for JSON-LD
    if let Ok(selector) = Selector::parse("script[type='application/ld+json']") {
        for element in document.select(&selector) {
            sd.has_json_ld = true;
            let content = element.text().collect::<String>();
            // Try to extract @type
            if let Some(type_start) = content.find("\"@type\"") {
                let after = &content[type_start + 7..];
                if let Some(colon) = after.find(':') {
                    let after_colon = &after[colon + 1..];
                    // Find the type value
                    let trimmed = after_colon.trim_start();
                    if trimmed.starts_with('"') {
                        if let Some(end) = trimmed[1..].find('"') {
                            let type_value = &trimmed[1..end + 1];
                            if !sd.json_ld_types.contains(&type_value.to_string()) {
                                sd.json_ld_types.push(type_value.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Check for microdata
    sd.has_microdata = body.contains("itemscope") || body.contains("itemprop");

    // Check for RDFa
    sd.has_rdfa = body.contains("vocab=") || body.contains("typeof=") || body.contains("property=");

    sd
}

/// Generate SEO issues
fn generate_issues(
    title: &Option<TitleInfo>,
    description: &Option<DescriptionInfo>,
    canonical: &Option<CanonicalInfo>,
    robots: &RobotsInfo,
    open_graph: &OpenGraphInfo,
    twitter_card: &TwitterCardInfo,
    headings: &HeadingStructure,
    technical: &TechnicalSeo,
    structured_data: &StructuredDataInfo,
) -> Vec<SeoIssue> {
    let mut issues = Vec::new();

    // Title issues
    match title {
        None => {
            issues.push(SeoIssue {
                severity: Severity::High,
                category: "title".to_string(),
                message: "Missing title tag".to_string(),
                recommendation: Some("Add a unique, descriptive title tag (50-60 characters)".to_string()),
            });
        }
        Some(t) => {
            if t.length < 30 {
                issues.push(SeoIssue {
                    severity: Severity::Medium,
                    category: "title".to_string(),
                    message: format!("Title too short ({} characters)", t.length),
                    recommendation: Some("Aim for 50-60 characters for optimal display".to_string()),
                });
            } else if t.may_truncate {
                issues.push(SeoIssue {
                    severity: Severity::Low,
                    category: "title".to_string(),
                    message: format!("Title may truncate in SERPs ({} characters)", t.length),
                    recommendation: Some("Keep title under 60 characters".to_string()),
                });
            }
        }
    }

    // Description issues
    match description {
        None => {
            issues.push(SeoIssue {
                severity: Severity::High,
                category: "description".to_string(),
                message: "Missing meta description".to_string(),
                recommendation: Some("Add a compelling meta description (150-160 characters)".to_string()),
            });
        }
        Some(d) => {
            if d.length < 70 {
                issues.push(SeoIssue {
                    severity: Severity::Medium,
                    category: "description".to_string(),
                    message: format!("Meta description too short ({} characters)", d.length),
                    recommendation: Some("Aim for 150-160 characters".to_string()),
                });
            } else if d.may_truncate {
                issues.push(SeoIssue {
                    severity: Severity::Low,
                    category: "description".to_string(),
                    message: format!("Meta description may truncate ({} characters)", d.length),
                    recommendation: Some("Keep under 160 characters".to_string()),
                });
            }
        }
    }

    // Canonical issues
    match canonical {
        None => {
            issues.push(SeoIssue {
                severity: Severity::Medium,
                category: "canonical".to_string(),
                message: "Missing canonical URL".to_string(),
                recommendation: Some("Add a canonical link to prevent duplicate content issues".to_string()),
            });
        }
        Some(c) => {
            if !c.is_absolute {
                issues.push(SeoIssue {
                    severity: Severity::Medium,
                    category: "canonical".to_string(),
                    message: "Canonical URL is not absolute".to_string(),
                    recommendation: Some("Use absolute URLs for canonical tags".to_string()),
                });
            }
        }
    }

    // Robots issues
    if !robots.index_allowed {
        issues.push(SeoIssue {
            severity: Severity::High,
            category: "robots".to_string(),
            message: "Page is set to noindex".to_string(),
            recommendation: Some("Remove noindex if this page should appear in search results".to_string()),
        });
    }

    // Open Graph issues
    if !open_graph.is_complete {
        let mut missing = Vec::new();
        if open_graph.title.is_none() {
            missing.push("og:title");
        }
        if open_graph.description.is_none() {
            missing.push("og:description");
        }
        if open_graph.image.is_none() {
            missing.push("og:image");
        }
        if !missing.is_empty() {
            issues.push(SeoIssue {
                severity: Severity::Low,
                category: "social".to_string(),
                message: format!("Incomplete Open Graph tags (missing: {})", missing.join(", ")),
                recommendation: Some("Add all required OG tags for better social sharing".to_string()),
            });
        }
    }

    // Twitter Card issues
    if !twitter_card.is_valid {
        issues.push(SeoIssue {
            severity: Severity::Low,
            category: "social".to_string(),
            message: "Missing Twitter Card tags".to_string(),
            recommendation: Some("Add twitter:card meta tag for better Twitter sharing".to_string()),
        });
    }

    // Heading issues
    for issue in &headings.hierarchy_issues {
        issues.push(SeoIssue {
            severity: if issue.contains("Missing H1") {
                Severity::High
            } else {
                Severity::Medium
            },
            category: "headings".to_string(),
            message: issue.clone(),
            recommendation: Some("Ensure proper heading hierarchy (one H1, followed by H2s, etc.)".to_string()),
        });
    }

    // Technical SEO issues
    if !technical.has_viewport {
        issues.push(SeoIssue {
            severity: Severity::High,
            category: "mobile".to_string(),
            message: "Missing viewport meta tag".to_string(),
            recommendation: Some("Add <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">".to_string()),
        });
    }

    if technical.html_lang.is_none() {
        issues.push(SeoIssue {
            severity: Severity::Medium,
            category: "technical".to_string(),
            message: "Missing lang attribute on <html> tag".to_string(),
            recommendation: Some("Add lang attribute (e.g., <html lang=\"en\">)".to_string()),
        });
    }

    if technical.images_without_alt > 0 {
        issues.push(SeoIssue {
            severity: Severity::Medium,
            category: "accessibility".to_string(),
            message: format!("{} images missing alt text", technical.images_without_alt),
            recommendation: Some("Add descriptive alt text to all images".to_string()),
        });
    }

    // Structured data
    if !structured_data.has_json_ld && !structured_data.has_microdata {
        issues.push(SeoIssue {
            severity: Severity::Low,
            category: "structured-data".to_string(),
            message: "No structured data found".to_string(),
            recommendation: Some("Add JSON-LD structured data for rich snippets".to_string()),
        });
    }

    // Sort by severity
    issues.sort_by(|a, b| b.severity.cmp(&a.severity));

    issues
}

/// Calculate SEO score (0-100)
fn calculate_score(
    title: &Option<TitleInfo>,
    description: &Option<DescriptionInfo>,
    canonical: &Option<CanonicalInfo>,
    robots: &RobotsInfo,
    open_graph: &OpenGraphInfo,
    headings: &HeadingStructure,
    technical: &TechnicalSeo,
    structured_data: &StructuredDataInfo,
    _issues: &[SeoIssue],
) -> u8 {
    let mut score: i32 = 100;

    // Deduct for missing/poor title (max -20)
    match title {
        None => score -= 20,
        Some(t) => {
            if t.length < 30 {
                score -= 10;
            } else if !t.length_optimal {
                score -= 5;
            }
        }
    }

    // Deduct for missing/poor description (max -15)
    match description {
        None => score -= 15,
        Some(d) => {
            if d.length < 70 {
                score -= 8;
            } else if !d.length_optimal {
                score -= 3;
            }
        }
    }

    // Deduct for missing canonical (max -10)
    if canonical.is_none() {
        score -= 10;
    }

    // Deduct for noindex (max -25)
    if !robots.index_allowed {
        score -= 25;
    }

    // Deduct for incomplete OG (max -5)
    if !open_graph.is_complete {
        score -= 5;
    }

    // Deduct for heading issues (max -15)
    if headings.h1_count == 0 {
        score -= 10;
    } else if headings.h1_count > 1 {
        score -= 5;
    }
    if !headings.is_valid_hierarchy {
        score -= 5;
    }

    // Deduct for technical issues (max -15)
    if !technical.has_viewport {
        score -= 10;
    }
    if technical.html_lang.is_none() {
        score -= 5;
    }

    // Deduct for missing structured data (max -5)
    if !structured_data.has_json_ld && !structured_data.has_microdata {
        score -= 5;
    }

    // Bonus for good practices (max +10, but cap at 100)
    if structured_data.has_json_ld && !structured_data.json_ld_types.is_empty() {
        score += 5;
    }
    if technical.is_mobile_friendly {
        score += 3;
    }

    score.clamp(0, 100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_title_extraction() {
        let html = r#"<html><head><title>Test Page Title</title></head></html>"#;
        let document = Html::parse_document(html);
        let title = extract_title(&document);

        assert!(title.is_some());
        let title = title.unwrap();
        assert_eq!(title.content, "Test Page Title");
        assert_eq!(title.length, 15);
    }

    #[test]
    fn test_description_extraction() {
        let html = r#"<html><head><meta name="description" content="This is a test description"></head></html>"#;
        let document = Html::parse_document(html);
        let desc = extract_description(&document);

        assert!(desc.is_some());
        assert_eq!(desc.unwrap().content, "This is a test description");
    }

    #[test]
    fn test_canonical_extraction() {
        let html = r#"<html><head><link rel="canonical" href="https://example.com/page"></head></html>"#;
        let document = Html::parse_document(html);
        let canonical = extract_canonical(&document, "https://example.com/page");

        assert!(canonical.is_some());
        let canonical = canonical.unwrap();
        assert!(canonical.is_absolute);
        assert!(canonical.is_self_referencing);
    }

    #[test]
    fn test_robots_parsing() {
        let html = r#"<html><head><meta name="robots" content="noindex, nofollow"></head></html>"#;
        let document = Html::parse_document(html);
        let robots = extract_robots(&document, None);

        assert!(!robots.index_allowed);
        assert!(!robots.follow_allowed);
    }

    #[test]
    fn test_open_graph_extraction() {
        let html = r#"<html><head>
            <meta property="og:title" content="OG Title">
            <meta property="og:description" content="OG Description">
            <meta property="og:image" content="https://example.com/image.jpg">
        </head></html>"#;
        let document = Html::parse_document(html);
        let og = extract_open_graph(&document);

        assert!(og.is_complete);
        assert_eq!(og.title, Some("OG Title".to_string()));
    }

    #[test]
    fn test_heading_structure() {
        let html = r#"<html><body>
            <h1>Main Title</h1>
            <h2>Section 1</h2>
            <h2>Section 2</h2>
            <h3>Subsection</h3>
        </body></html>"#;
        let document = Html::parse_document(html);
        let headings = extract_headings(&document);

        assert_eq!(headings.h1_count, 1);
        assert!(headings.is_valid_hierarchy);
        assert_eq!(headings.h1_content, Some("Main Title".to_string()));
    }

    #[test]
    fn test_structured_data_detection() {
        let html = r#"<html><head>
            <script type="application/ld+json">{"@type": "Organization"}</script>
        </head></html>"#;
        let document = Html::parse_document(html);
        let sd = extract_structured_data(&document, html);

        assert!(sd.has_json_ld);
        assert!(sd.json_ld_types.contains(&"Organization".to_string()));
    }

    #[test]
    fn test_score_calculation() {
        let title = Some(TitleInfo {
            content: "Good Title Here".to_string(),
            length: 55,
            length_optimal: true,
            may_truncate: false,
        });
        let desc = Some(DescriptionInfo {
            content: "Good description".to_string(),
            length: 155,
            length_optimal: true,
            may_truncate: false,
        });
        let canonical = Some(CanonicalInfo {
            url: "https://example.com".to_string(),
            is_self_referencing: true,
            is_absolute: true,
        });
        let robots = RobotsInfo {
            index_allowed: true,
            follow_allowed: true,
            ..Default::default()
        };
        let og = OpenGraphInfo {
            is_complete: true,
            ..Default::default()
        };
        let headings = HeadingStructure {
            h1_count: 1,
            is_valid_hierarchy: true,
            ..Default::default()
        };
        let tech = TechnicalSeo {
            has_viewport: true,
            is_mobile_friendly: true,
            html_lang: Some("en".to_string()),
            ..Default::default()
        };
        let sd = StructuredDataInfo {
            has_json_ld: true,
            json_ld_types: vec!["Organization".to_string()],
            ..Default::default()
        };

        let score = calculate_score(&title, &desc, &canonical, &robots, &og, &headings, &tech, &sd, &[]);
        assert!(score >= 95); // Should be high for a well-optimized page
    }
}
