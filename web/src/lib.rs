//! Sango Web - Browser-based edge diagnostics via WebAssembly
//!
//! A WASM build of Sango that runs entirely in the browser using the Fetch API
//! and Performance API for timing measurements.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

mod analysis;
mod timing;

pub use analysis::*;
pub use timing::*;

/// Result of a browser-based probe
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
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
    /// Response headers
    pub headers: HeadersResult,
    /// Content analysis
    pub content: ContentResult,
    /// SEO analysis
    pub seo: SeoResult,
    /// AEO analysis
    pub aeo: AeoResult,
    /// Tech stack detection
    pub techstack: TechStackResult,
    /// Issues found
    pub issues: Vec<Issue>,
    /// Limitations (what couldn't be checked in browser)
    pub limitations: Vec<String>,
}

/// Timing breakdown from Performance API
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[wasm_bindgen(getter_with_clone)]
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

/// HTTP headers analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[wasm_bindgen(getter_with_clone)]
pub struct HeadersResult {
    /// Content-Type header
    pub content_type: Option<String>,
    /// Content-Length header
    pub content_length: Option<String>,
    /// Server header
    pub server: Option<String>,
    /// Cache-Control header
    pub cache_control: Option<String>,
    /// HSTS header present
    pub has_hsts: bool,
    /// CSP header present
    pub has_csp: bool,
    /// X-Frame-Options present
    pub has_xfo: bool,
    /// X-Content-Type-Options present
    pub has_xcto: bool,
    /// All headers as JSON string
    pub all_headers: String,
}

/// Content analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[wasm_bindgen(getter_with_clone)]
pub struct ContentResult {
    /// Response size in bytes
    pub size_bytes: usize,
    /// Human-readable size
    pub size_formatted: String,
    /// Detected MIME type
    pub mime_type: Option<String>,
    /// Character encoding
    pub charset: Option<String>,
    /// Whether compression is used
    pub is_compressed: bool,
    /// Compression algorithm
    pub compression: Option<String>,
}

/// SEO analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[wasm_bindgen(getter_with_clone)]
pub struct SeoResult {
    /// SEO score 0-100
    pub score: u8,
    /// Page title
    pub title: Option<String>,
    /// Title length
    pub title_length: usize,
    /// Meta description
    pub description: Option<String>,
    /// Description length
    pub description_length: usize,
    /// Canonical URL
    pub canonical: Option<String>,
    /// Has Open Graph tags
    pub has_open_graph: bool,
    /// Has Twitter Card tags
    pub has_twitter_card: bool,
    /// H1 count
    pub h1_count: usize,
    /// Has structured data (JSON-LD)
    pub has_structured_data: bool,
    /// Language
    pub language: Option<String>,
}

/// AEO (AI Engine Optimization) analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[wasm_bindgen(getter_with_clone)]
pub struct AeoResult {
    /// AEO score 0-100
    pub score: u8,
    /// Readiness level
    pub readiness: String,
    /// JSON-LD block count
    pub json_ld_count: usize,
    /// Schema.org types found
    pub schema_types: Vec<String>,
    /// Has llms.txt
    pub has_llms_txt: bool,
    /// Text-to-HTML ratio percentage
    pub text_ratio: f32,
    /// Semantic HTML score
    pub semantic_score: u8,
    /// Word count
    pub word_count: usize,
}

/// Tech stack detection
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[wasm_bindgen(getter_with_clone)]
pub struct TechStackResult {
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

/// An issue found during analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct Issue {
    /// Severity: critical, high, medium, low
    pub severity: String,
    /// Category of the issue
    pub category: String,
    /// Issue message
    pub message: String,
}

/// Initialize the WASM module
#[wasm_bindgen(start)]
pub fn init() {
    // Set up panic hook for better error messages
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

    // Get response body
    let body_promise = response.text()
        .map_err(|e| format!("Failed to get response text: {:?}", e))?;
    let body_value = JsFuture::from(body_promise).await
        .map_err(|e| format!("Failed to read response body: {:?}", e))?;
    let body = body_value.as_string().unwrap_or_default();

    // Get timing information
    let timing = timing::get_resource_timing(&url).await;

    // Analyze headers
    let headers = analysis::analyze_headers(&response);

    // Analyze content
    let content = analysis::analyze_content(&body, &headers);

    // Analyze SEO
    let seo = analysis::analyze_seo(&body);

    // Analyze AEO
    let aeo = analysis::analyze_aeo(&body);

    // Detect tech stack
    let techstack = analysis::analyze_techstack(&body, &headers);

    // Generate issues
    let mut issues = Vec::new();
    issues.extend(analysis::generate_header_issues(&headers));
    issues.extend(analysis::generate_seo_issues(&seo));
    issues.extend(analysis::generate_aeo_issues(&aeo));
    issues.extend(analysis::generate_content_issues(&content));

    // Calculate health
    let health = calculate_health(&issues);

    // Document limitations
    let limitations = vec![
        "TLS certificate details not accessible in browser".to_string(),
        "HTTP/2 vs HTTP/3 protocol not detectable".to_string(),
        "Cross-origin requests may be blocked by CORS".to_string(),
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
    let has_critical = issues.iter().any(|i| i.severity == "critical");
    let has_high = issues.iter().any(|i| i.severity == "high");
    let has_medium = issues.iter().any(|i| i.severity == "medium");

    if has_critical || has_high {
        "Unhealthy".to_string()
    } else if has_medium {
        "Degraded".to_string()
    } else {
        "Healthy".to_string()
    }
}

// Re-export console_error_panic_hook
pub use console_error_panic_hook;
