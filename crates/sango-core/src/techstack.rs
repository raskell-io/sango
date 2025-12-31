//! Tech stack detection
//!
//! Fingerprints frameworks, CMS, CDN, and libraries from HTML and headers.

use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};

/// Result of tech stack analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TechStackAnalysis {
    /// Detected server
    pub server: Option<String>,
    /// Detected CDN
    pub cdn: Option<String>,
    /// Detected frameworks
    pub frameworks: Vec<String>,
    /// Detected CMS
    pub cms: Option<String>,
    /// Detected JavaScript libraries
    pub js_libraries: Vec<String>,
    /// Detected analytics
    pub analytics: Vec<String>,
}

/// Headers information for tech detection
#[derive(Debug, Clone, Default)]
pub struct TechStackHeaders {
    pub server: Option<String>,
    pub x_powered_by: Option<String>,
    pub via: Option<String>,
    pub cf_ray: Option<String>,
    pub x_vercel_id: Option<String>,
    pub x_amz_cf_id: Option<String>,
    pub x_cache: Option<String>,
}

/// Analyze tech stack from HTML and headers
pub fn analyze_techstack(html: &str, headers: TechStackHeaders) -> TechStackAnalysis {
    let document = Html::parse_document(html);
    let body_lower = html.to_lowercase();

    TechStackAnalysis {
        server: detect_server(&headers),
        cdn: detect_cdn(&headers, &body_lower),
        frameworks: detect_frameworks(&document, &body_lower),
        cms: detect_cms(&document, &body_lower),
        js_libraries: detect_js_libraries(&body_lower),
        analytics: detect_analytics(&body_lower),
    }
}

fn detect_server(headers: &TechStackHeaders) -> Option<String> {
    headers.server.clone()
}

fn detect_cdn(headers: &TechStackHeaders, body: &str) -> Option<String> {
    // Check headers first
    if headers.cf_ray.is_some() {
        return Some("Cloudflare".to_string());
    }
    if headers.x_vercel_id.is_some() {
        return Some("Vercel".to_string());
    }
    if headers.x_amz_cf_id.is_some() {
        return Some("CloudFront".to_string());
    }

    // Check server header
    if let Some(ref server) = headers.server {
        let server_lower = server.to_lowercase();
        if server_lower.contains("cloudflare") {
            return Some("Cloudflare".to_string());
        }
        if server_lower.contains("netlify") {
            return Some("Netlify".to_string());
        }
        if server_lower.contains("vercel") {
            return Some("Vercel".to_string());
        }
    }

    // Check via header
    if let Some(ref via) = headers.via {
        let via_lower = via.to_lowercase();
        if via_lower.contains("cloudfront") {
            return Some("CloudFront".to_string());
        }
        if via_lower.contains("fastly") {
            return Some("Fastly".to_string());
        }
        if via_lower.contains("akamai") {
            return Some("Akamai".to_string());
        }
    }

    // Check body for CDN patterns
    if body.contains("cdn.cloudflare.com") {
        return Some("Cloudflare".to_string());
    }
    if body.contains("cdn.jsdelivr.net") {
        return Some("jsDelivr".to_string());
    }

    None
}

fn detect_frameworks(document: &Html, body: &str) -> Vec<String> {
    let mut frameworks = Vec::new();

    // Next.js
    if body.contains("__next") || body.contains("/_next/") {
        frameworks.push("Next.js".to_string());
    }

    // React (check if not already detected via Next.js)
    if !frameworks.contains(&"Next.js".to_string())
        && (body.contains("__react") || body.contains("data-reactroot") || body.contains("react-dom"))
    {
        frameworks.push("React".to_string());
    }

    // Vue.js / Nuxt
    if body.contains("__nuxt") || body.contains("/_nuxt/") {
        frameworks.push("Nuxt.js".to_string());
    } else if body.contains("__vue") || body.contains("data-v-") {
        frameworks.push("Vue.js".to_string());
    }

    // Angular
    if body.contains("ng-version") || body.contains("ng-app") || body.contains("angular") {
        frameworks.push("Angular".to_string());
    }

    // Svelte / SvelteKit
    if body.contains("__sveltekit") || body.contains("sveltekit") {
        frameworks.push("SvelteKit".to_string());
    } else if body.contains("svelte") {
        frameworks.push("Svelte".to_string());
    }

    // Astro
    if body.contains("astro-") || body.contains("/_astro/") {
        frameworks.push("Astro".to_string());
    }

    // Remix
    if body.contains("__remix") || body.contains("remix") {
        frameworks.push("Remix".to_string());
    }

    // Tailwind CSS
    if body.contains("tailwindcss") || count_tailwind_classes(body) > 10 {
        frameworks.push("Tailwind CSS".to_string());
    }

    // Bootstrap
    if body.contains("bootstrap") {
        frameworks.push("Bootstrap".to_string());
    }

    // Check meta generator
    if let Ok(selector) = Selector::parse("meta[name='generator']") {
        if let Some(element) = document.select(&selector).next() {
            if let Some(content) = element.value().attr("content") {
                let gen_lower = content.to_lowercase();
                if gen_lower.contains("gatsby") {
                    frameworks.push("Gatsby".to_string());
                }
                if gen_lower.contains("hugo") {
                    frameworks.push("Hugo".to_string());
                }
                if gen_lower.contains("jekyll") {
                    frameworks.push("Jekyll".to_string());
                }
                if gen_lower.contains("eleventy") || gen_lower.contains("11ty") {
                    frameworks.push("Eleventy".to_string());
                }
            }
        }
    }

    frameworks
}

fn count_tailwind_classes(body: &str) -> usize {
    let patterns = [
        "flex ", "grid ", "p-", "m-", "text-", "bg-", "w-", "h-",
        "rounded-", "shadow-", "border-", "gap-",
    ];
    patterns.iter().filter(|p| body.contains(*p)).count()
}

fn detect_cms(document: &Html, body: &str) -> Option<String> {
    // WordPress
    if body.contains("wp-content") || body.contains("wp-includes") || body.contains("wp-json") {
        return Some("WordPress".to_string());
    }

    // Drupal
    if body.contains("drupal") || body.contains("/sites/default/files") {
        return Some("Drupal".to_string());
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
    if body.contains("squarespace") || body.contains("static.squarespace") {
        return Some("Squarespace".to_string());
    }

    // Wix
    if body.contains("wix.com") || body.contains("wixstatic") {
        return Some("Wix".to_string());
    }

    // Ghost
    if let Ok(selector) = Selector::parse("meta[name='generator']") {
        if let Some(element) = document.select(&selector).next() {
            if let Some(content) = element.value().attr("content") {
                if content.to_lowercase().contains("ghost") {
                    return Some("Ghost".to_string());
                }
            }
        }
    }

    // Contentful
    if body.contains("contentful") || body.contains("ctfassets.net") {
        return Some("Contentful".to_string());
    }

    // Sanity
    if body.contains("sanity.io") || body.contains("cdn.sanity.io") {
        return Some("Sanity".to_string());
    }

    None
}

fn detect_js_libraries(body: &str) -> Vec<String> {
    let mut libs = Vec::new();

    let patterns = [
        ("jquery", "jQuery"),
        ("lodash", "Lodash"),
        ("underscore", "Underscore.js"),
        ("axios", "Axios"),
        ("moment", "Moment.js"),
        ("dayjs", "Day.js"),
        ("gsap", "GSAP"),
        ("three.js", "Three.js"),
        ("d3.js", "D3.js"),
        ("chart.js", "Chart.js"),
        ("alpine", "Alpine.js"),
        ("htmx", "HTMX"),
    ];

    for (pattern, name) in patterns {
        if body.contains(pattern) {
            libs.push(name.to_string());
        }
    }

    libs
}

fn detect_analytics(body: &str) -> Vec<String> {
    let mut analytics = Vec::new();

    let patterns = [
        (vec!["google-analytics", "googletagmanager", "gtag(", "gtm.js"], "Google Analytics"),
        (vec!["segment.com", "analytics.min.js"], "Segment"),
        (vec!["hotjar"], "Hotjar"),
        (vec!["plausible.io", "plausible"], "Plausible"),
        (vec!["fathom"], "Fathom"),
        (vec!["mixpanel"], "Mixpanel"),
        (vec!["amplitude"], "Amplitude"),
        (vec!["heap"], "Heap"),
        (vec!["fullstory"], "FullStory"),
        (vec!["clarity.ms"], "Microsoft Clarity"),
        (vec!["posthog"], "PostHog"),
        (vec!["matomo", "piwik"], "Matomo"),
    ];

    for (keywords, name) in patterns {
        if keywords.iter().any(|k| body.contains(k)) {
            analytics.push(name.to_string());
        }
    }

    analytics
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_framework_detection() {
        let html = r#"<html><body><div id="__next">Content</div></body></html>"#;
        let result = analyze_techstack(html, TechStackHeaders::default());
        assert!(result.frameworks.contains(&"Next.js".to_string()));
    }

    #[test]
    fn test_cms_detection() {
        let html = r#"<html><body><link href="/wp-content/themes/test/style.css"></body></html>"#;
        let result = analyze_techstack(html, TechStackHeaders::default());
        assert_eq!(result.cms, Some("WordPress".to_string()));
    }

    #[test]
    fn test_cdn_detection() {
        let headers = TechStackHeaders {
            cf_ray: Some("abc123".to_string()),
            ..Default::default()
        };
        let result = analyze_techstack("<html></html>", headers);
        assert_eq!(result.cdn, Some("Cloudflare".to_string()));
    }
}
