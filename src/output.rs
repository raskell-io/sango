//! Output formatting for diagnostic results
//!
//! Supports pretty (colored terminal), JSON, and compact formats.

use colored::Colorize;

use crate::checks::tls::Severity;
use crate::probe::{Health, ProbeResult};

/// Print results in a pretty, colored format
pub fn print_pretty(result: &ProbeResult) {
    // Header
    println!();
    println!(
        "{} {}",
        "sango".bold().cyan(),
        "edge diagnostics".dimmed()
    );
    println!("{}", "─".repeat(60).dimmed());
    println!();

    // Target info
    println!("  {} {}", "Target:".bold(), result.target);
    println!(
        "  {} {}",
        "Time:".bold(),
        result.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!();

    // Overall health
    let health_str = match result.overall_health {
        Health::Healthy => "Healthy".green().bold(),
        Health::Degraded => "Degraded".yellow().bold(),
        Health::Unhealthy => "Unhealthy".red().bold(),
        Health::Unknown => "Unknown".dimmed().bold(),
    };
    println!("  {} {}", "Status:".bold(), health_str);
    println!();

    // Errors if present
    if !result.errors.is_empty() {
        println!("  {}", "Errors".red().bold().underline());
        for error in &result.errors {
            println!("    {} {}", "!".red(), error.red());
        }
        println!();
    }

    // TLS results
    if let Some(ref tls) = result.tls {
        print_tls_section(tls);
    }

    // HTTP results
    if let Some(ref http) = result.http {
        print_http_section(http);
    }

    // Security headers results
    if let Some(ref headers) = result.headers {
        print_headers_section(headers);
    }

    // Latency results
    if let Some(ref latency) = result.latency {
        print_latency_section(latency);
    }

    // Footer
    println!("{}", "─".repeat(60).dimmed());
}

fn print_tls_section(tls: &crate::checks::tls::TlsResult) {
    println!("{}", "  TLS".bold().underline());
    println!();

    // Connection info
    let tls_status = if tls.valid { "OK".green() } else { "FAIL".red() };
    println!("    {} {}", "Connection:".dimmed(), tls_status);
    println!("    {} {}", "Version:".dimmed(), tls.tls_version);
    println!("    {} {}", "Cipher:".dimmed(), tls.cipher_suite);

    // ALPN
    let alpn = tls.alpn_negotiated.as_deref().unwrap_or("none");
    println!("    {} {}", "ALPN:".dimmed(), alpn);
    println!();

    // Certificate info
    println!("    {}", "Certificate".bold());

    // Subject (truncate if too long)
    let subject = truncate(&tls.subject, 50);
    println!("      {} {}", "Subject:".dimmed(), subject);

    // Issuer (truncate if too long)
    let issuer = truncate(&tls.issuer, 50);
    println!("      {} {}", "Issuer:".dimmed(), issuer);

    // Chain length
    println!(
        "      {} {}",
        "Chain:".dimmed(),
        format!("{} certificates", tls.chain_length)
    );

    // Expiry
    let expiry_str = format_expiry(tls.expires_in_days);
    println!("      {} {}", "Expires:".dimmed(), expiry_str);
    println!();

    // Issues
    print_issues(&tls.issues.iter().map(|i| (i.severity, &i.message)).collect::<Vec<_>>());
}

fn print_http_section(http: &crate::checks::http::HttpResult) {
    println!("{}", "  HTTP".bold().underline());
    println!();

    // Protocol info
    println!("    {} {}", "Version:".dimmed(), http.http_version);
    println!("    {} {}", "Status:".dimmed(), http.status_code);

    let h2_str = if http.http2_supported {
        "yes".green()
    } else {
        "no".dimmed()
    };
    println!("    {} {}", "HTTP/2:".dimmed(), h2_str);

    let h3_str = if http.http3_advertised {
        "advertised".green()
    } else {
        "no".dimmed()
    };
    println!("    {} {}", "HTTP/3:".dimmed(), h3_str);

    // Redirects
    if !http.redirect_chain.is_empty() {
        println!("    {} {} hops", "Redirects:".dimmed(), http.redirect_chain.len());
        for hop in &http.redirect_chain {
            println!("      {} {} -> {}", "·".dimmed(), hop.status, truncate(&hop.url, 40));
        }
    }
    println!();

    // Issues
    print_issues(&http.issues.iter().map(|i| (i.severity, &i.message)).collect::<Vec<_>>());
}

fn print_headers_section(headers: &crate::checks::headers::HeadersResult) {
    println!("{}", "  Security Headers".bold().underline());
    println!();

    // HSTS
    let hsts_str = match &headers.hsts {
        Some(hsts) => {
            if hsts.preload {
                format!("max-age={}, preload", hsts.max_age).green()
            } else if hsts.include_subdomains {
                format!("max-age={}, subdomains", hsts.max_age).green()
            } else {
                format!("max-age={}", hsts.max_age).yellow()
            }
        }
        None => "missing".red(),
    };
    println!("    {} {}", "HSTS:".dimmed(), hsts_str);

    // CSP
    let csp_str = match &headers.csp {
        Some(csp) => {
            if csp.report_only {
                "report-only".yellow()
            } else if csp.allows_unsafe_inline || csp.allows_unsafe_eval {
                "present (unsafe)".yellow()
            } else {
                "present".green()
            }
        }
        None => "missing".red(),
    };
    println!("    {} {}", "CSP:".dimmed(), csp_str);

    // X-Frame-Options
    let xfo_str = match &headers.x_frame_options {
        Some(v) => v.green(),
        None => "missing".yellow(),
    };
    println!("    {} {}", "X-Frame-Options:".dimmed(), xfo_str);

    // X-Content-Type-Options
    let xcto_str = match &headers.x_content_type_options {
        Some(v) if v.to_lowercase() == "nosniff" => "nosniff".green(),
        Some(v) => v.yellow(),
        None => "missing".yellow(),
    };
    println!("    {} {}", "X-Content-Type-Options:".dimmed(), xcto_str);

    // COOP
    let coop_str = match &headers.coop {
        Some(v) => v.green(),
        None => "missing".dimmed(),
    };
    println!("    {} {}", "COOP:".dimmed(), coop_str);

    // COEP
    let coep_str = match &headers.coep {
        Some(v) => v.green(),
        None => "missing".dimmed(),
    };
    println!("    {} {}", "COEP:".dimmed(), coep_str);
    println!();

    // Issues
    print_issues(
        &headers
            .issues
            .iter()
            .map(|i| (i.severity, &i.message))
            .collect::<Vec<_>>(),
    );
}

fn print_latency_section(latency: &crate::checks::latency::LatencyResult) {
    println!("{}", "  Latency".bold().underline());
    println!();

    // Timing breakdown
    println!(
        "    {} {}",
        "DNS:".dimmed(),
        format_latency(latency.dns_lookup.as_millis())
    );
    println!(
        "    {} {}",
        "TCP:".dimmed(),
        format_latency(latency.tcp_connect.as_millis())
    );
    println!(
        "    {} {}",
        "TLS:".dimmed(),
        format_latency(latency.tls_handshake.as_millis())
    );
    println!(
        "    {} {}",
        "TTFB:".dimmed(),
        format_latency(latency.time_to_first_byte.as_millis())
    );
    println!(
        "    {} {}",
        "Total:".dimmed(),
        format!("{}ms", latency.total.as_millis()).bold()
    );
    println!();

    // Issues
    print_issues(
        &latency
            .issues
            .iter()
            .map(|i| (i.severity, &i.message))
            .collect::<Vec<_>>(),
    );
}

fn print_issues(issues: &[(Severity, &String)]) {
    if issues.is_empty() {
        return;
    }

    println!("    {}", "Issues".bold());
    for (severity, message) in issues {
        let severity_icon = match severity {
            Severity::Critical => "!!".red().bold(),
            Severity::High => "!".red(),
            Severity::Medium => "~".yellow(),
            Severity::Low => "-".dimmed(),
        };
        let severity_label = match severity {
            Severity::Critical => "critical".red().bold(),
            Severity::High => "high".red(),
            Severity::Medium => "medium".yellow(),
            Severity::Low => "low".dimmed(),
        };
        println!("      {} [{}] {}", severity_icon, severity_label, message);
    }
    println!();
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len - 3])
    } else {
        s.to_string()
    }
}

fn format_expiry(days: i64) -> String {
    if days < 0 {
        format!("Expired {} days ago", -days).red().to_string()
    } else if days < 7 {
        format!("{} days", days).red().to_string()
    } else if days < 30 {
        format!("{} days", days).yellow().to_string()
    } else {
        format!("{} days", days).green().to_string()
    }
}

fn format_latency(ms: u128) -> String {
    if ms >= 1000 {
        format!("{}ms", ms).red().to_string()
    } else if ms >= 200 {
        format!("{}ms", ms).yellow().to_string()
    } else {
        format!("{}ms", ms).green().to_string()
    }
}

/// Print results as JSON
pub fn print_json(result: &ProbeResult) -> String {
    serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".to_string())
}

/// Print a compact single-line summary
pub fn print_compact(result: &ProbeResult) -> String {
    let health = match result.overall_health {
        Health::Healthy => "OK",
        Health::Degraded => "WARN",
        Health::Unhealthy => "FAIL",
        Health::Unknown => "?",
    };

    let mut parts = vec![format!("{}: {}", result.target, health)];

    if let Some(ref tls) = result.tls {
        parts.push(format!("tls={}", tls.tls_version));
        parts.push(format!("expires={}d", tls.expires_in_days));
        if let Some(ref alpn) = tls.alpn_negotiated {
            parts.push(format!("alpn={}", alpn));
        }
    }

    if let Some(ref http) = result.http {
        parts.push(format!("status={}", http.status_code));
        if http.http3_advertised {
            parts.push("h3=adv".to_string());
        }
    }

    if let Some(ref latency) = result.latency {
        parts.push(format!("total={}ms", latency.total.as_millis()));
    }

    // Count all issues
    let mut issue_counts = std::collections::HashMap::new();
    if let Some(ref tls) = result.tls {
        for issue in &tls.issues {
            *issue_counts.entry(issue.severity).or_insert(0) += 1;
        }
    }
    if let Some(ref http) = result.http {
        for issue in &http.issues {
            *issue_counts.entry(issue.severity).or_insert(0) += 1;
        }
    }
    if let Some(ref headers) = result.headers {
        for issue in &headers.issues {
            *issue_counts.entry(issue.severity).or_insert(0) += 1;
        }
    }
    if let Some(ref latency) = result.latency {
        for issue in &latency.issues {
            *issue_counts.entry(issue.severity).or_insert(0) += 1;
        }
    }

    if !issue_counts.is_empty() {
        let counts: Vec<String> = [
            (Severity::Critical, "crit"),
            (Severity::High, "high"),
            (Severity::Medium, "med"),
            (Severity::Low, "low"),
        ]
        .iter()
        .filter_map(|(sev, label)| {
            issue_counts
                .get(sev)
                .map(|count| format!("{}:{}", label, count))
        })
        .collect();
        if !counts.is_empty() {
            parts.push(format!("issues=[{}]", counts.join(",")));
        }
    }

    if !result.errors.is_empty() {
        parts.push(format!("errors={}", result.errors.len()));
    }

    parts.join(" ")
}
