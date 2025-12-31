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

    // Discovery results
    if let Some(ref discovery) = result.discovery {
        print_discovery_section(discovery);
    }

    // Tech stack results
    if let Some(ref techstack) = result.techstack {
        print_techstack_section(techstack);
    }

    // SEO results
    if let Some(ref seo) = result.seo {
        print_seo_section(seo);
    }

    // AEO results
    if let Some(ref aeo) = result.aeo {
        print_aeo_section(aeo);
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

fn print_discovery_section(discovery: &crate::checks::discovery::DiscoveryResult) {
    println!("{}", "  Discovery".bold().underline());
    println!();

    // robots.txt
    match &discovery.robots {
        Some(r) if r.exists => {
            let status = "present".green();
            println!("    {} {}", "robots.txt:".dimmed(), status);
            if !r.disallowed.is_empty() {
                println!(
                    "      {} {} paths",
                    "Disallowed:".dimmed(),
                    r.disallowed.len()
                );
            }
            if r.blocks_all {
                println!("      {} {}", "!".yellow(), "Blocks all crawlers".yellow());
            }
            if !r.sitemaps.is_empty() {
                println!(
                    "      {} {} referenced",
                    "Sitemaps:".dimmed(),
                    r.sitemaps.len()
                );
            }
        }
        Some(r) => {
            println!(
                "    {} {} (status {})",
                "robots.txt:".dimmed(),
                "not found".yellow(),
                r.status_code
            );
        }
        None => {
            println!("    {} {}", "robots.txt:".dimmed(), "error".red());
        }
    }

    // Sitemap
    match &discovery.sitemap {
        Some(s) if s.exists => {
            let type_str = match s.sitemap_type {
                crate::checks::discovery::SitemapType::Sitemap => "urlset",
                crate::checks::discovery::SitemapType::SitemapIndex => "index",
                crate::checks::discovery::SitemapType::Unknown => "unknown",
            };
            println!(
                "    {} {} ({}, {} entries)",
                "Sitemap:".dimmed(),
                "present".green(),
                type_str,
                s.entry_count
            );
            if !s.child_sitemaps.is_empty() {
                println!(
                    "      {} {} child sitemaps",
                    "Index:".dimmed(),
                    s.child_sitemaps.len()
                );
            }
        }
        _ => {
            println!("    {} {}", "Sitemap:".dimmed(), "not found".yellow());
        }
    }

    // Discovered paths
    if !discovery.discovered_paths.is_empty() {
        println!(
            "    {} {} paths found",
            "Paths:".dimmed(),
            discovery.discovered_paths.len()
        );
        for path in &discovery.discovered_paths {
            let status_color = if path.status_code == 200 {
                format!("{}", path.status_code).green()
            } else if path.status_code >= 300 && path.status_code < 400 {
                format!("{}", path.status_code).yellow()
            } else {
                format!("{}", path.status_code).red()
            };
            let content_type = path
                .content_type
                .as_ref()
                .map(|ct| {
                    // Shorten content type
                    ct.split(';').next().unwrap_or(ct).to_string()
                })
                .unwrap_or_default();
            println!(
                "      {} {} [{}] {}",
                "·".dimmed(),
                path.path,
                status_color,
                content_type.dimmed()
            );
        }
    }

    // Well-known endpoints
    if !discovery.well_known.is_empty() {
        println!(
            "    {} {} endpoints",
            "Well-known:".dimmed(),
            discovery.well_known.len()
        );
        for endpoint in &discovery.well_known {
            println!(
                "      {} {} - {}",
                "·".dimmed(),
                endpoint.path.green(),
                endpoint.description.dimmed()
            );
        }
    }
    println!();

    // Issues
    print_issues(
        &discovery
            .issues
            .iter()
            .map(|i| (i.severity, &i.message))
            .collect::<Vec<_>>(),
    );
}

fn print_techstack_section(techstack: &crate::checks::techstack::TechStackResult) {
    println!("{}", "  Tech Stack".bold().underline());
    println!();

    // Server
    match &techstack.server {
        Some(s) => {
            let version_str = s.version.as_ref()
                .map(|v| format!(" {}", v))
                .unwrap_or_default();
            println!(
                "    {} {}{}",
                "Server:".dimmed(),
                s.name.green(),
                version_str.dimmed()
            );
        }
        None => {
            println!("    {} {}", "Server:".dimmed(), "not detected".dimmed());
        }
    }

    // CDN
    match &techstack.cdn {
        Some(cdn) => {
            let edge_str = cdn.edge_location.as_ref()
                .map(|e| format!(" ({})", e))
                .unwrap_or_default();
            println!(
                "    {} {}{}",
                "CDN:".dimmed(),
                cdn.name.green(),
                edge_str.dimmed()
            );
            if !cdn.features.is_empty() {
                for feature in &cdn.features {
                    println!("      {} {}", "·".dimmed(), feature.dimmed());
                }
            }
        }
        None => {
            println!("    {} {}", "CDN:".dimmed(), "not detected".yellow());
        }
    }

    // Frameworks
    if !techstack.frameworks.is_empty() {
        println!("    {} {} detected", "Frameworks:".dimmed(), techstack.frameworks.len());
        for fw in &techstack.frameworks {
            let version_str = fw.version.as_ref()
                .map(|v| format!(" {}", v))
                .unwrap_or_default();
            let category = match fw.category {
                crate::checks::techstack::FrameworkCategory::Frontend => "frontend",
                crate::checks::techstack::FrameworkCategory::Backend => "backend",
                crate::checks::techstack::FrameworkCategory::Fullstack => "fullstack",
                crate::checks::techstack::FrameworkCategory::Static => "static",
            };
            println!(
                "      {} {}{} [{}] ({}%)",
                "·".dimmed(),
                fw.name.cyan(),
                version_str.dimmed(),
                category.dimmed(),
                (fw.confidence * 100.0) as u8
            );
        }
    }

    // CMS
    if let Some(ref cms) = techstack.cms {
        let version_str = cms.version.as_ref()
            .map(|v| format!(" {}", v))
            .unwrap_or_default();
        println!(
            "    {} {}{}",
            "CMS:".dimmed(),
            cms.name.cyan(),
            version_str.dimmed()
        );
    }

    // JS Libraries
    if !techstack.js_libraries.is_empty() {
        println!(
            "    {} {}",
            "Libraries:".dimmed(),
            techstack.js_libraries.iter()
                .map(|lib| {
                    let v = lib.version.as_ref()
                        .map(|v| format!(" {}", v))
                        .unwrap_or_default();
                    format!("{}{}", lib.name, v)
                })
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Analytics
    if !techstack.analytics.is_empty() {
        println!(
            "    {} {}",
            "Analytics:".dimmed(),
            techstack.analytics.iter()
                .map(|a| a.name.clone())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    println!();

    // Issues
    print_issues(
        &techstack
            .issues
            .iter()
            .map(|i| (i.severity, &i.message))
            .collect::<Vec<_>>(),
    );
}

fn print_seo_section(seo: &crate::checks::seo::SeoResult) {
    // Score header with color
    let score_color = if seo.score >= 80 {
        format!("{}", seo.score).green()
    } else if seo.score >= 60 {
        format!("{}", seo.score).yellow()
    } else {
        format!("{}", seo.score).red()
    };

    println!("{} {}", "  SEO".bold().underline(), format!("(score: {})", score_color).dimmed());
    println!();

    // Title
    match &seo.title {
        Some(t) => {
            let status = if t.length_optimal {
                "OK".green()
            } else if t.may_truncate {
                "long".yellow()
            } else {
                "short".yellow()
            };
            println!(
                "    {} {} ({} chars) [{}]",
                "Title:".dimmed(),
                truncate_str(&t.content, 40),
                t.length,
                status
            );
        }
        None => {
            println!("    {} {}", "Title:".dimmed(), "missing".red());
        }
    }

    // Description
    match &seo.description {
        Some(d) => {
            let status = if d.length_optimal {
                "OK".green()
            } else if d.may_truncate {
                "long".yellow()
            } else {
                "short".yellow()
            };
            println!(
                "    {} {} ({} chars) [{}]",
                "Description:".dimmed(),
                truncate_str(&d.content, 35),
                d.length,
                status
            );
        }
        None => {
            println!("    {} {}", "Description:".dimmed(), "missing".red());
        }
    }

    // Canonical
    match &seo.canonical {
        Some(c) => {
            let status = if c.is_self_referencing { "self".green() } else { "external".yellow() };
            println!(
                "    {} {} [{}]",
                "Canonical:".dimmed(),
                truncate_str(&c.url, 40),
                status
            );
        }
        None => {
            println!("    {} {}", "Canonical:".dimmed(), "missing".yellow());
        }
    }

    // Robots
    let robots_status = if seo.robots.index_allowed {
        "indexable".green()
    } else {
        "noindex".red()
    };
    println!("    {} {}", "Robots:".dimmed(), robots_status);

    // Open Graph
    let og_status = if seo.open_graph.is_complete {
        "complete".green()
    } else {
        "incomplete".yellow()
    };
    println!("    {} {}", "Open Graph:".dimmed(), og_status);

    // Headings
    let h1_status = match seo.headings.h1_count {
        0 => "missing".red(),
        1 => "OK".green(),
        n => format!("{} (multiple)", n).yellow(),
    };
    println!("    {} {}", "H1:".dimmed(), h1_status);
    if let Some(ref h1) = seo.headings.h1_content {
        println!("      {}", truncate_str(h1, 50).dimmed());
    }

    // Technical
    let mobile_status = if seo.technical.is_mobile_friendly {
        "yes".green()
    } else if seo.technical.has_viewport {
        "partial".yellow()
    } else {
        "no".red()
    };
    println!("    {} {}", "Mobile-friendly:".dimmed(), mobile_status);

    // Structured data
    if seo.structured_data.has_json_ld {
        let types = if seo.structured_data.json_ld_types.is_empty() {
            "present".to_string()
        } else {
            seo.structured_data.json_ld_types.join(", ")
        };
        println!("    {} {} ({})", "Structured data:".dimmed(), "JSON-LD".green(), types);
    } else if seo.structured_data.has_microdata {
        println!("    {} {}", "Structured data:".dimmed(), "Microdata".green());
    } else {
        println!("    {} {}", "Structured data:".dimmed(), "none".yellow());
    }

    // Language
    if let Some(ref lang) = seo.technical.html_lang {
        println!("    {} {}", "Language:".dimmed(), lang);
    }

    // I18n (if present)
    if !seo.i18n.hreflang_tags.is_empty() {
        println!(
            "    {} {} languages",
            "Hreflang:".dimmed(),
            seo.i18n.hreflang_tags.len()
        );
    }

    // Stats
    if seo.technical.image_count > 0 {
        let alt_status = if seo.technical.images_without_alt == 0 {
            format!("{} images, all with alt", seo.technical.image_count).green()
        } else {
            format!(
                "{} images, {} missing alt",
                seo.technical.image_count,
                seo.technical.images_without_alt
            ).yellow()
        };
        println!("    {} {}", "Images:".dimmed(), alt_status);
    }

    println!();

    // Issues
    print_issues(
        &seo.issues
            .iter()
            .map(|i| (i.severity, &i.message))
            .collect::<Vec<_>>(),
    );
}

fn print_aeo_section(aeo: &crate::checks::aeo::AeoResult) {
    // Score header with color and readiness
    let score_color = if aeo.score >= 80 {
        format!("{}", aeo.score).green()
    } else if aeo.score >= 60 {
        format!("{}", aeo.score).yellow()
    } else {
        format!("{}", aeo.score).red()
    };

    let readiness_color = match aeo.readiness {
        crate::checks::aeo::AeoReadiness::Excellent => "Excellent".green(),
        crate::checks::aeo::AeoReadiness::Good => "Good".green(),
        crate::checks::aeo::AeoReadiness::Basic => "Basic".yellow(),
        crate::checks::aeo::AeoReadiness::Poor => "Poor".red(),
    };

    println!(
        "{} {} {}",
        "  AEO".bold().underline(),
        format!("(score: {})", score_color).dimmed(),
        format!("[{}]", readiness_color)
    );
    println!();

    // Structured Data
    if !aeo.structured_data.json_ld_blocks.is_empty() {
        println!(
            "    {} {} blocks",
            "JSON-LD:".dimmed(),
            format!("{}", aeo.structured_data.json_ld_blocks.len()).green()
        );
        if !aeo.structured_data.schema_types.is_empty() {
            let types_str = aeo.structured_data.schema_types
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            println!("      {} {}", "Types:".dimmed(), types_str.cyan());
        }
        if aeo.structured_data.rich_snippet_eligible {
            println!("      {} {}", "·".dimmed(), "Rich snippet eligible".green());
        }
    } else {
        println!("    {} {}", "JSON-LD:".dimmed(), "none".yellow());
    }

    // AI Endpoints
    let has_llms = aeo.ai_endpoints.llms_txt.as_ref().map(|l| l.exists).unwrap_or(false);
    let has_plugin = aeo.ai_endpoints.ai_plugin.as_ref().map(|p| p.exists && p.is_valid).unwrap_or(false);

    if has_llms {
        let llms = aeo.ai_endpoints.llms_txt.as_ref().unwrap();
        let title_str = llms.title.as_ref()
            .map(|t| format!(" - {}", truncate_str(t, 30)))
            .unwrap_or_default();
        println!(
            "    {} {}{}",
            "llms.txt:".dimmed(),
            "present".green(),
            title_str.dimmed()
        );
        if llms.section_count > 0 || llms.link_count > 0 {
            println!(
                "      {} sections, {} links",
                llms.section_count,
                llms.link_count
            );
        }
    } else {
        println!("    {} {}", "llms.txt:".dimmed(), "not found".yellow());
    }

    if has_plugin {
        let plugin = aeo.ai_endpoints.ai_plugin.as_ref().unwrap();
        let name_str = plugin.name.as_ref()
            .map(|n| format!(" ({})", n))
            .unwrap_or_default();
        println!(
            "    {} {}{}",
            "AI Plugin:".dimmed(),
            "present".green(),
            name_str.dimmed()
        );
    }

    // robots.txt AI rules
    if let Some(ref rules) = aeo.ai_endpoints.robots_ai_rules {
        if rules.blocks_ai_bots {
            println!(
                "    {} {}",
                "AI Bots:".dimmed(),
                "blocked".red()
            );
            println!(
                "      {} {}",
                "Agents:".dimmed(),
                rules.ai_user_agents.join(", ").dimmed()
            );
        } else if rules.allows_ai_bots {
            println!(
                "    {} {}",
                "AI Bots:".dimmed(),
                "allowed".green()
            );
        }
    }

    // Content Structure
    let extractable_str = if aeo.content_structure.is_extractable {
        "extractable".green()
    } else {
        "limited".yellow()
    };
    println!(
        "    {} {} ({:.0}% text ratio, {}% semantic)",
        "Content:".dimmed(),
        extractable_str,
        aeo.content_structure.text_ratio * 100.0,
        aeo.content_structure.semantic_score
    );

    if aeo.content_structure.word_count > 0 {
        println!(
            "      {} words, ~{} min read",
            aeo.content_structure.word_count,
            aeo.content_structure.reading_time_minutes
        );
    }

    // API Discovery
    if aeo.api_discovery.openapi.is_some() || aeo.api_discovery.graphql.is_some() {
        print!("    {} ", "APIs:".dimmed());
        let mut apis = Vec::new();
        if let Some(ref openapi) = aeo.api_discovery.openapi {
            let version_str = openapi.version.as_ref()
                .map(|v| format!(" {}", v))
                .unwrap_or_default();
            apis.push(format!("OpenAPI{}", version_str).green().to_string());
        }
        if let Some(ref graphql) = aeo.api_discovery.graphql {
            let introspection_str = if graphql.introspection_enabled {
                " (introspection)"
            } else {
                ""
            };
            apis.push(format!("GraphQL{}", introspection_str).green().to_string());
        }
        println!("{}", apis.join(", "));
    }

    println!();

    // Issues
    print_issues(
        &aeo.issues
            .iter()
            .map(|i| (i.severity, &i.message))
            .collect::<Vec<_>>(),
    );
}

/// Truncate a string for display
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len - 3])
    } else {
        s.to_string()
    }
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

    if let Some(ref discovery) = result.discovery {
        if let Some(ref sitemap) = discovery.sitemap {
            if sitemap.exists {
                parts.push(format!("sitemap={}", sitemap.entry_count));
            }
        }
    }

    if let Some(ref techstack) = result.techstack {
        if let Some(ref cdn) = techstack.cdn {
            parts.push(format!("cdn={}", cdn.name));
        }
        if !techstack.frameworks.is_empty() {
            let fw_names: Vec<_> = techstack.frameworks.iter()
                .take(2)
                .map(|f| f.name.as_str())
                .collect();
            parts.push(format!("fw={}", fw_names.join("+")));
        }
    }

    if let Some(ref seo) = result.seo {
        parts.push(format!("seo={}", seo.score));
    }

    if let Some(ref aeo) = result.aeo {
        parts.push(format!("aeo={}", aeo.score));
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
    if let Some(ref discovery) = result.discovery {
        for issue in &discovery.issues {
            *issue_counts.entry(issue.severity).or_insert(0) += 1;
        }
    }
    if let Some(ref techstack) = result.techstack {
        for issue in &techstack.issues {
            *issue_counts.entry(issue.severity).or_insert(0) += 1;
        }
    }
    if let Some(ref seo) = result.seo {
        for issue in &seo.issues {
            *issue_counts.entry(issue.severity).or_insert(0) += 1;
        }
    }
    if let Some(ref aeo) = result.aeo {
        for issue in &aeo.issues {
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
