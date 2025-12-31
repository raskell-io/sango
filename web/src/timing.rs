//! Performance API timing extraction

use wasm_bindgen::JsCast;
use web_sys::PerformanceResourceTiming;

use crate::TimingResult;

/// Get resource timing for a URL from the Performance API
pub async fn get_resource_timing(url: &str) -> Option<TimingResult> {
    let window = web_sys::window()?;
    let performance = window.performance()?;

    // Small delay to ensure timing entry is available
    gloo_timers::future::TimeoutFuture::new(100).await;

    // Get resource timing entries using JavaScript interop
    let entries = js_sys::Reflect::get(
        &performance,
        &wasm_bindgen::JsValue::from_str("getEntriesByType"),
    )
    .ok()?;

    let get_entries_fn: js_sys::Function = entries.dyn_into().ok()?;
    let result = get_entries_fn
        .call1(&performance, &wasm_bindgen::JsValue::from_str("resource"))
        .ok()?;
    let entries_array: js_sys::Array = result.dyn_into().ok()?;

    // Find the entry for our URL
    for i in 0..entries_array.length() {
        let entry = entries_array.get(i);
        let resource: PerformanceResourceTiming = match entry.dyn_into() {
            Ok(r) => r,
            Err(_) => continue,
        };

        let entry_name = resource.name();
        if entry_name.contains(url) || url.contains(&entry_name) {
            let dns_start = resource.domain_lookup_start();
            let dns_end = resource.domain_lookup_end();
            let connect_start = resource.connect_start();
            let connect_end = resource.connect_end();
            let secure_start = resource.secure_connection_start();
            let request_start = resource.request_start();
            let response_start = resource.response_start();
            let response_end = resource.response_end();

            // Calculate timing breakdown
            let dns_ms = dns_end - dns_start;
            let tcp_ms = if secure_start > 0.0 {
                secure_start - connect_start
            } else {
                connect_end - connect_start
            };
            let tls_ms = if secure_start > 0.0 {
                connect_end - secure_start
            } else {
                0.0
            };
            let ttfb_ms = response_start - request_start;
            let total_ms = response_end - dns_start;

            return Some(TimingResult {
                dns_ms: round_ms(dns_ms),
                tcp_ms: round_ms(tcp_ms),
                tls_ms: round_ms(tls_ms),
                ttfb_ms: round_ms(ttfb_ms),
                total_ms: round_ms(total_ms),
                available: true,
            });
        }
    }

    // Timing not available (possibly due to CORS or Timing-Allow-Origin)
    Some(TimingResult {
        dns_ms: 0.0,
        tcp_ms: 0.0,
        tls_ms: 0.0,
        ttfb_ms: 0.0,
        total_ms: 0.0,
        available: false,
    })
}

/// Round to 2 decimal places
fn round_ms(ms: f64) -> f64 {
    (ms * 100.0).round() / 100.0
}
