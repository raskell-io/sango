//! SEO (Search Engine Optimization) analysis
//!
//! Pure HTML parsing for SEO signals - no HTTP client needed.

use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::{extract_domain, Issue, Severity};

/// Result of SEO analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeoAnalysis {
    /// Page title
    pub title: Option<TitleInfo>,
    /// Meta description
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
    /// Structured data
    pub structured_data: StructuredDataInfo,
    /// SEO score (0-100)
    pub score: u8,
    /// Detected issues
    pub issues: Vec<Issue>,
}

/// Title tag analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TitleInfo {
    pub content: String,
    pub length: usize,
    pub length_optimal: bool,
    pub may_truncate: bool,
}

/// Meta description analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptionInfo {
    pub content: String,
    pub length: usize,
    pub length_optimal: bool,
    pub may_truncate: bool,
}

/// Canonical URL analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalInfo {
    pub url: String,
    pub is_self_referencing: bool,
    pub is_absolute: bool,
}

/// Robots directives
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RobotsInfo {
    pub meta_robots: Option<String>,
    pub x_robots_tag: Option<String>,
    pub index_allowed: bool,
    pub follow_allowed: bool,
    pub other_directives: Vec<String>,
}

/// Open Graph metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpenGraphInfo {
    pub title: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
    pub url: Option<String>,
    pub og_type: Option<String>,
    pub site_name: Option<String>,
    pub is_complete: bool,
}

/// Twitter Card metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TwitterCardInfo {
    pub card_type: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
    pub site: Option<String>,
    pub is_valid: bool,
}

/// Heading structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeadingStructure {
    pub h1_count: usize,
    pub h1_content: Option<String>,
    pub hierarchy: HashMap<String, usize>,
    pub is_valid_hierarchy: bool,
    pub hierarchy_issues: Vec<String>,
}

/// Technical SEO signals
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TechnicalSeo {
    pub has_viewport: bool,
    pub viewport_content: Option<String>,
    pub is_mobile_friendly: bool,
    pub charset: Option<String>,
    pub html_lang: Option<String>,
    pub content_language: Option<String>,
    pub has_favicon: bool,
    pub document_size: usize,
    pub internal_links: usize,
    pub external_links: usize,
    pub image_count: usize,
    pub images_without_alt: usize,
}

/// Internationalization info
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct I18nInfo {
    pub hreflang_tags: Vec<HreflangTag>,
    pub default_language: Option<String>,
    pub has_x_default: bool,
}

/// Single hreflang tag
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HreflangTag {
    pub hreflang: String,
    pub href: String,
}

/// Structured data info
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StructuredDataInfo {
    pub has_json_ld: bool,
    pub json_ld_types: Vec<String>,
    pub has_microdata: bool,
    pub has_rdfa: bool,
}

/// Configuration for SEO analysis
#[derive(Debug, Clone, Default)]
pub struct SeoConfig {
    /// X-Robots-Tag header value (if present)
    pub x_robots_tag: Option<String>,
    /// Content-Language header value (if present)
    pub content_language: Option<String>,
}

/// Analyze SEO signals from HTML content
pub fn analyze_seo(html: &str, page_url: &str, config: SeoConfig) -> SeoAnalysis {
    let document = Html::parse_document(html);
    let document_size = html.len();

    let title = extract_title(&document);
    let description = extract_description(&document);
    let canonical = extract_canonical(&document, page_url);
    let robots = extract_robots(&document, config.x_robots_tag);
    let open_graph = extract_open_graph(&document);
    let twitter_card = extract_twitter_card(&document);
    let headings = extract_headings(&document);
    let technical = extract_technical_seo(&document, page_url, document_size, config.content_language);
    let i18n = extract_i18n(&document);
    let structured_data = extract_structured_data(&document, html);

    let issues = generate_issues(
        &title, &description, &canonical, &robots,
        &open_graph, &twitter_card, &headings, &technical, &structured_data,
    );

    let score = calculate_score(
        &title, &description, &canonical, &robots,
        &open_graph, &headings, &technical, &structured_data,
    );

    SeoAnalysis {
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
    }
}

fn extract_title(document: &Html) -> Option<TitleInfo> {
    let selector = Selector::parse("title").ok()?;
    let element = document.select(&selector).next()?;
    let content = element.text().collect::<String>().trim().to_string();

    if content.is_empty() {
        return None;
    }

    let length = content.chars().count();
    Some(TitleInfo {
        content,
        length,
        length_optimal: (50..=60).contains(&length),
        may_truncate: length > 60,
    })
}

fn extract_description(document: &Html) -> Option<DescriptionInfo> {
    let selector = Selector::parse("meta[name='description']").ok()?;
    let element = document.select(&selector).next()?;
    let content = element.value().attr("content")?.trim().to_string();

    if content.is_empty() {
        return None;
    }

    let length = content.chars().count();
    Some(DescriptionInfo {
        content,
        length,
        length_optimal: (150..=160).contains(&length),
        may_truncate: length > 160,
    })
}

fn extract_canonical(document: &Html, page_url: &str) -> Option<CanonicalInfo> {
    let selector = Selector::parse("link[rel='canonical']").ok()?;
    let element = document.select(&selector).next()?;
    let url = element.value().attr("href")?.trim().to_string();

    if url.is_empty() {
        return None;
    }

    let is_absolute = url.starts_with("http://") || url.starts_with("https://");
    let is_self_referencing = normalize_url_for_comparison(&url) == normalize_url_for_comparison(page_url);

    Some(CanonicalInfo { url, is_self_referencing, is_absolute })
}

fn normalize_url_for_comparison(url: &str) -> String {
    url.trim_end_matches('/').to_lowercase()
}

fn extract_robots(document: &Html, x_robots_tag: Option<String>) -> RobotsInfo {
    let mut info = RobotsInfo {
        x_robots_tag,
        index_allowed: true,
        follow_allowed: true,
        ..Default::default()
    };

    if let Ok(selector) = Selector::parse("meta[name='robots']") {
        if let Some(element) = document.select(&selector).next() {
            if let Some(content) = element.value().attr("content") {
                info.meta_robots = Some(content.to_string());
                parse_robots_directives(content, &mut info);
            }
        }
    }

    if let Some(tag) = info.x_robots_tag.clone() {
        parse_robots_directives(&tag, &mut info);
    }

    info
}

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

    og.is_complete = og.title.is_some() && og.description.is_some() && og.image.is_some();
    og
}

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

    tc.is_valid = tc.card_type.is_some();
    tc
}

fn extract_headings(document: &Html) -> HeadingStructure {
    let mut structure = HeadingStructure::default();
    let mut hierarchy_issues = Vec::new();

    for level in 1..=6 {
        let tag = format!("h{}", level);
        let selector = match Selector::parse(&tag) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let count = document.select(&selector).count();
        if count > 0 {
            structure.hierarchy.insert(tag.clone(), count);
            if level == 1 {
                structure.h1_count = count;
                if let Some(h1) = document.select(&selector).next() {
                    structure.h1_content = Some(h1.text().collect::<String>().trim().to_string());
                }
            }
        }
    }

    let h1_count = *structure.hierarchy.get("h1").unwrap_or(&0);
    let h2_count = *structure.hierarchy.get("h2").unwrap_or(&0);
    let h3_count = *structure.hierarchy.get("h3").unwrap_or(&0);

    if h1_count == 0 {
        hierarchy_issues.push("Missing H1 tag".to_string());
    } else if h1_count > 1 {
        hierarchy_issues.push(format!("Multiple H1 tags ({})", h1_count));
    }

    if h3_count > 0 && h2_count == 0 {
        hierarchy_issues.push("H3 used without H2 (skipped heading level)".to_string());
    }

    structure.is_valid_hierarchy = hierarchy_issues.is_empty() && h1_count == 1;
    structure.hierarchy_issues = hierarchy_issues;
    structure
}

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

    // HTML lang
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
                    if extract_domain(href) == base_domain {
                        tech.internal_links += 1;
                    } else {
                        tech.external_links += 1;
                    }
                } else if href.starts_with('/') || href.starts_with('#') || !href.contains("://") {
                    tech.internal_links += 1;
                }
            }
        }
    }

    // Count images
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

fn extract_structured_data(document: &Html, body: &str) -> StructuredDataInfo {
    let mut sd = StructuredDataInfo::default();

    if let Ok(selector) = Selector::parse("script[type='application/ld+json']") {
        for element in document.select(&selector) {
            sd.has_json_ld = true;
            let content = element.text().collect::<String>();
            if let Some(type_start) = content.find("\"@type\"") {
                let after = &content[type_start + 7..];
                if let Some(colon) = after.find(':') {
                    let after_colon = &after[colon + 1..];
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

    sd.has_microdata = body.contains("itemscope") || body.contains("itemprop");
    sd.has_rdfa = body.contains("vocab=") || body.contains("typeof=") || body.contains("property=");

    sd
}

fn generate_issues(
    title: &Option<TitleInfo>,
    description: &Option<DescriptionInfo>,
    canonical: &Option<CanonicalInfo>,
    robots: &RobotsInfo,
    open_graph: &OpenGraphInfo,
    _twitter_card: &TwitterCardInfo,
    headings: &HeadingStructure,
    technical: &TechnicalSeo,
    structured_data: &StructuredDataInfo,
) -> Vec<Issue> {
    let mut issues = Vec::new();

    // Title
    match title {
        None => issues.push(Issue::new(Severity::High, "title", "Missing title tag")
            .with_recommendation("Add a unique, descriptive title tag (50-60 characters)")),
        Some(t) if t.length < 30 => issues.push(Issue::new(Severity::Medium, "title",
            format!("Title too short ({} characters)", t.length))
            .with_recommendation("Aim for 50-60 characters for optimal display")),
        Some(t) if t.may_truncate => issues.push(Issue::new(Severity::Low, "title",
            format!("Title may truncate in SERPs ({} characters)", t.length))
            .with_recommendation("Keep title under 60 characters")),
        _ => {}
    }

    // Description
    match description {
        None => issues.push(Issue::new(Severity::High, "description", "Missing meta description")
            .with_recommendation("Add a compelling meta description (150-160 characters)")),
        Some(d) if d.length < 70 => issues.push(Issue::new(Severity::Medium, "description",
            format!("Meta description too short ({} characters)", d.length))
            .with_recommendation("Aim for 150-160 characters")),
        _ => {}
    }

    // Canonical
    if canonical.is_none() {
        issues.push(Issue::new(Severity::Medium, "canonical", "Missing canonical URL")
            .with_recommendation("Add a canonical link to prevent duplicate content issues"));
    }

    // Robots
    if !robots.index_allowed {
        issues.push(Issue::new(Severity::High, "robots", "Page is set to noindex")
            .with_recommendation("Remove noindex if this page should appear in search results"));
    }

    // Open Graph
    if !open_graph.is_complete {
        let mut missing = Vec::new();
        if open_graph.title.is_none() { missing.push("og:title"); }
        if open_graph.description.is_none() { missing.push("og:description"); }
        if open_graph.image.is_none() { missing.push("og:image"); }
        if !missing.is_empty() {
            issues.push(Issue::new(Severity::Low, "social",
                format!("Incomplete Open Graph tags (missing: {})", missing.join(", ")))
                .with_recommendation("Add all required OG tags for better social sharing"));
        }
    }

    // Headings
    for issue in &headings.hierarchy_issues {
        let severity = if issue.contains("Missing H1") { Severity::High } else { Severity::Medium };
        issues.push(Issue::new(severity, "headings", issue.clone())
            .with_recommendation("Ensure proper heading hierarchy (one H1, followed by H2s, etc.)"));
    }

    // Technical
    if !technical.has_viewport {
        issues.push(Issue::new(Severity::High, "mobile", "Missing viewport meta tag")
            .with_recommendation("Add <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"));
    }

    if technical.html_lang.is_none() {
        issues.push(Issue::new(Severity::Medium, "technical", "Missing lang attribute on <html> tag")
            .with_recommendation("Add lang attribute (e.g., <html lang=\"en\">)"));
    }

    if technical.images_without_alt > 0 {
        issues.push(Issue::new(Severity::Medium, "accessibility",
            format!("{} images missing alt text", technical.images_without_alt))
            .with_recommendation("Add descriptive alt text to all images"));
    }

    // Structured data
    if !structured_data.has_json_ld && !structured_data.has_microdata {
        issues.push(Issue::new(Severity::Low, "structured-data", "No structured data found")
            .with_recommendation("Add JSON-LD structured data for rich snippets"));
    }

    issues.sort_by(|a, b| b.severity.cmp(&a.severity));
    issues
}

fn calculate_score(
    title: &Option<TitleInfo>,
    description: &Option<DescriptionInfo>,
    canonical: &Option<CanonicalInfo>,
    robots: &RobotsInfo,
    open_graph: &OpenGraphInfo,
    headings: &HeadingStructure,
    technical: &TechnicalSeo,
    structured_data: &StructuredDataInfo,
) -> u8 {
    let mut score: i32 = 100;

    // Title (max -20)
    match title {
        None => score -= 20,
        Some(t) if t.length < 30 => score -= 10,
        Some(t) if !t.length_optimal => score -= 5,
        _ => {}
    }

    // Description (max -15)
    match description {
        None => score -= 15,
        Some(d) if d.length < 70 => score -= 8,
        Some(d) if !d.length_optimal => score -= 3,
        _ => {}
    }

    // Canonical (max -10)
    if canonical.is_none() { score -= 10; }

    // Noindex (max -25)
    if !robots.index_allowed { score -= 25; }

    // OG (max -5)
    if !open_graph.is_complete { score -= 5; }

    // Headings (max -15)
    if headings.h1_count == 0 { score -= 10; }
    else if headings.h1_count > 1 { score -= 5; }
    if !headings.is_valid_hierarchy { score -= 5; }

    // Technical (max -15)
    if !technical.has_viewport { score -= 10; }
    if technical.html_lang.is_none() { score -= 5; }

    // Structured data (max -5)
    if !structured_data.has_json_ld && !structured_data.has_microdata { score -= 5; }

    // Bonus
    if structured_data.has_json_ld && !structured_data.json_ld_types.is_empty() { score += 5; }
    if technical.is_mobile_friendly { score += 3; }

    score.clamp(0, 100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_title_extraction() {
        let html = r#"<html><head><title>Test Page Title</title></head></html>"#;
        let result = analyze_seo(html, "https://example.com", SeoConfig::default());
        assert!(result.title.is_some());
        assert_eq!(result.title.unwrap().content, "Test Page Title");
    }

    #[test]
    fn test_heading_structure() {
        let html = r#"<html><body><h1>Main</h1><h2>Sub</h2></body></html>"#;
        let result = analyze_seo(html, "https://example.com", SeoConfig::default());
        assert_eq!(result.headings.h1_count, 1);
        assert!(result.headings.is_valid_hierarchy);
    }
}
