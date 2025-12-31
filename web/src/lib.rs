//! Sango Web - Browser-based edge diagnostics via WebAssembly
//!
//! Uses sango-core for shared analysis logic, with browser-specific
//! HTTP fetching via the Fetch API and timing via Performance API.

use sango_core::{
    aeo::{analyze_aeo, AeoAnalysis, AeoConfig},
    content::{analyze_content, ContentAnalysis, ContentInfo},
    headers::{analyze_headers, HeadersAnalysis, RawHeaders},
    seo::{analyze_seo, SeoAnalysis, SeoConfig},
    techstack::{analyze_techstack, TechStackAnalysis, TechStackHeaders},
    Issue, Severity,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

mod timing;
pub use timing::*;

/// Result of a browser-based probe
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Target URL that was probed
    pub target: String,
    /// Timestamp of the probe
    pub timestamp: String,
    /// Overall health status
    pub health: String,
    /// HTTP status code
    pub status_code: u16,
    /// Timing breakdown
    pub timing: Option<TimingResult>,
    /// Response headers analysis
    pub headers: HeadersAnalysis,
    /// Content analysis
    pub content: ContentAnalysis,
    /// SEO analysis
    pub seo: SeoAnalysis,
    /// AEO analysis
    pub aeo: AeoAnalysis,
    /// Tech stack detection
    pub techstack: TechStackAnalysis,
    /// Issues found
    pub issues: Vec<Issue>,
    /// Limitations (what couldn't be checked in browser)
    pub limitations: Vec<String>,
}

/// Timing breakdown from Performance API
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TimingResult {
    /// DNS lookup time in ms
    pub dns_ms: f64,
    /// TCP connection time in ms
    pub tcp_ms: f64,
    /// TLS handshake time in ms
    pub tls_ms: f64,
    /// Time to first byte in ms
    pub ttfb_ms: f64,
    /// Total request time in ms
    pub total_ms: f64,
    /// Whether timing was available
    pub available: bool,
}

/// Initialize the WASM module
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Run a probe against a target URL
#[wasm_bindgen]
pub async fn probe(target: String) -> Result<JsValue, JsValue> {
    let result = run_probe(&target).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Run a probe and return JSON string
#[wasm_bindgen]
pub async fn probe_json(target: String) -> Result<String, JsValue> {
    let result = run_probe(&target).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_json::to_string_pretty(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Internal probe implementation
async fn run_probe(target: &str) -> Result<ProbeResult, String> {
    let url = normalize_url(target);
    let timestamp = js_sys::Date::new_0().to_iso_string().as_string().unwrap_or_default();

    // Clear performance entries for accurate timing
    if let Some(performance) = web_sys::window().and_then(|w| w.performance()) {
        performance.clear_resource_timings();
    }

    // Fetch the target
    let window = web_sys::window().ok_or_else(|| "No window object".to_string())?;

    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(&url, &opts)
        .map_err(|e| format!("Failed to create request: {:?}", e))?;
    request.headers().set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .map_err(|e| format!("Failed to set headers: {:?}", e))?;

    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await
        .map_err(|e| format!("Fetch failed: {:?}", e))?;
    let response: Response = resp_value.dyn_into()
        .map_err(|e| format!("Invalid response: {:?}", e))?;

    let status_code = response.status();

    // Extract headers
    let raw_headers = extract_raw_headers(&response);
    let tech_headers = extract_tech_headers(&response);

    // Get response body
    let body_promise = response.text()
        .map_err(|e| format!("Failed to get response text: {:?}", e))?;
    let body_value = JsFuture::from(body_promise).await
        .map_err(|e| format!("Failed to read response body: {:?}", e))?;
    let body = body_value.as_string().unwrap_or_default();

    // Get timing information
    let timing = timing::get_resource_timing(&url).await;

    // Use sango-core analysis functions
    let headers = analyze_headers(&raw_headers);

    let content_info = ContentInfo {
        content_type: headers.content_type.clone(),
        content_encoding: None, // Browser decompresses automatically
        content_length: None,
        body_size: body.len() as u64,
    };
    let content = analyze_content(content_info);

    let seo_config = SeoConfig {
        x_robots_tag: raw_headers.get("x-robots-tag").cloned(),
        content_language: raw_headers.get("content-language").cloned(),
    };
    let seo = analyze_seo(&body, &url, seo_config);

    let aeo_config = AeoConfig {
        has_llms_txt: false, // Can't check in browser due to CORS
    };
    let aeo = analyze_aeo(&body, aeo_config);

    let techstack = analyze_techstack(&body, tech_headers);

    // Collect all issues
    let mut issues: Vec<Issue> = Vec::new();
    issues.extend(headers.issues.clone());
    issues.extend(seo.issues.clone());
    issues.extend(aeo.issues.clone());

    // Calculate health
    let health = calculate_health(&issues);

    // Document limitations
    let limitations = vec![
        "TLS certificate details not accessible in browser".to_string(),
        "HTTP/2 vs HTTP/3 protocol not detectable".to_string(),
        "Cross-origin requests may be blocked by CORS".to_string(),
        "llms.txt check skipped due to CORS".to_string(),
    ];

    Ok(ProbeResult {
        target: url,
        timestamp,
        health,
        status_code,
        timing,
        headers,
        content,
        seo,
        aeo,
        techstack,
        issues,
        limitations,
    })
}

/// Extract raw headers from response for analysis
fn extract_raw_headers(response: &Response) -> RawHeaders {
    let mut raw = RawHeaders::new();
    let headers = response.headers();

    // Check common headers (can't iterate in web-sys)
    let header_names = [
        "content-type", "content-length", "server", "cache-control",
        "strict-transport-security", "content-security-policy",
        "content-security-policy-report-only",
        "x-frame-options", "x-content-type-options", "x-xss-protection",
        "referrer-policy", "permissions-policy", "feature-policy",
        "content-encoding", "x-robots-tag", "content-language",
        "x-powered-by",
    ];

    for name in header_names {
        if let Ok(Some(value)) = headers.get(name) {
            raw.insert(name, value);
        }
    }

    raw
}

/// Extract tech-related headers for techstack analysis
fn extract_tech_headers(response: &Response) -> TechStackHeaders {
    let headers = response.headers();

    let get = |name: &str| -> Option<String> {
        headers.get(name).ok().flatten()
    };

    TechStackHeaders {
        server: get("server"),
        x_powered_by: get("x-powered-by"),
        via: get("via"),
        cf_ray: get("cf-ray"),
        x_vercel_id: get("x-vercel-id"),
        x_amz_cf_id: get("x-amz-cf-id"),
        x_cache: get("x-cache"),
    }
}

/// Normalize URL to ensure it has a scheme
fn normalize_url(target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("https://{}", target)
    }
}

/// Calculate overall health from issues
fn calculate_health(issues: &[Issue]) -> String {
    let has_critical = issues.iter().any(|i| i.severity == Severity::Critical);
    let has_high = issues.iter().any(|i| i.severity == Severity::High);
    let has_medium = issues.iter().any(|i| i.severity == Severity::Medium);

    if has_critical || has_high {
        "Unhealthy".to_string()
    } else if has_medium {
        "Degraded".to_string()
    } else {
        "Healthy".to_string()
    }
}

pub use console_error_panic_hook;
