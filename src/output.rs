//! Output formatting for diagnostic results
//!
//! Supports pretty (colored terminal), JSON, and compact formats.

use colored::Colorize;

use crate::checks::tls::{OcspStatus, Severity};
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
    println!("{}", "─".repeat(50).dimmed());
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

    // Error if present
    if let Some(ref error) = result.error {
        println!("  {} {}", "Error:".red().bold(), error.red());
        println!();
        return;
    }

    // TLS results
    if let Some(ref tls) = result.tls {
        println!("{}", "  TLS".bold().underline());
        println!();

        // Connection info
        let tls_status = if tls.valid { "OK".green() } else { "FAIL".red() };
        println!("    {} {}", "Connection:".dimmed(), tls_status);
        println!("    {} {}", "TLS Version:".dimmed(), tls.tls_version);
        println!("    {} {}", "Cipher:".dimmed(), tls.cipher_suite);

        // ALPN
        let alpn = tls
            .alpn_negotiated
            .as_deref()
            .unwrap_or("none");
        println!("    {} {}", "ALPN:".dimmed(), alpn);
        println!();

        // Certificate info
        println!("    {}", "Certificate".bold());

        // Subject (truncate if too long)
        let subject = if tls.subject.len() > 60 {
            format!("{}...", &tls.subject[..57])
        } else {
            tls.subject.clone()
        };
        println!("      {} {}", "Subject:".dimmed(), subject);

        // Issuer (truncate if too long)
        let issuer = if tls.issuer.len() > 60 {
            format!("{}...", &tls.issuer[..57])
        } else {
            tls.issuer.clone()
        };
        println!("      {} {}", "Issuer:".dimmed(), issuer);

        // Chain length
        println!("      {} {}", "Chain:".dimmed(), format!("{} certificates", tls.chain_length));

        // Expiry
        let expiry_str = if tls.expires_in_days < 0 {
            format!("Expired {} days ago", -tls.expires_in_days).red().to_string()
        } else if tls.expires_in_days < 7 {
            format!("{} days", tls.expires_in_days).red().to_string()
        } else if tls.expires_in_days < 30 {
            format!("{} days", tls.expires_in_days).yellow().to_string()
        } else {
            format!("{} days", tls.expires_in_days).green().to_string()
        };
        println!("      {} {}", "Expires in:".dimmed(), expiry_str);

        // OCSP status
        let ocsp_str = match tls.ocsp_status {
            OcspStatus::Good => "Good".green(),
            OcspStatus::Revoked => "Revoked".red(),
            OcspStatus::Unknown => "Unknown".yellow(),
            OcspStatus::NotChecked => "Not checked".dimmed(),
        };
        println!("      {} {}", "OCSP:".dimmed(), ocsp_str);
        println!();

        // Issues
        if !tls.issues.is_empty() {
            println!("    {}", "Issues".bold());
            for issue in &tls.issues {
                let severity_icon = match issue.severity {
                    Severity::Critical => "!!".red().bold(),
                    Severity::High => "!".red(),
                    Severity::Medium => "~".yellow(),
                    Severity::Low => "-".dimmed(),
                };
                let severity_label = match issue.severity {
                    Severity::Critical => "critical".red().bold(),
                    Severity::High => "high".red(),
                    Severity::Medium => "medium".yellow(),
                    Severity::Low => "low".dimmed(),
                };
                println!(
                    "      {} [{}] {}",
                    severity_icon, severity_label, issue.message
                );
            }
            println!();
        } else {
            println!("    {} {}", "Issues:".dimmed(), "None".green());
            println!();
        }
    }

    // Footer
    println!("{}", "─".repeat(50).dimmed());
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

    let mut parts = vec![
        format!("{}: {}", result.target, health),
    ];

    if let Some(ref tls) = result.tls {
        parts.push(format!("tls={}", tls.tls_version));
        parts.push(format!("expires={}d", tls.expires_in_days));
        if let Some(ref alpn) = tls.alpn_negotiated {
            parts.push(format!("alpn={}", alpn));
        }
        if !tls.issues.is_empty() {
            let issue_counts: Vec<String> = [
                (Severity::Critical, "crit"),
                (Severity::High, "high"),
                (Severity::Medium, "med"),
                (Severity::Low, "low"),
            ]
            .iter()
            .filter_map(|(sev, label)| {
                let count = tls.issues.iter().filter(|i| i.severity == *sev).count();
                if count > 0 {
                    Some(format!("{}:{}", label, count))
                } else {
                    None
                }
            })
            .collect();
            if !issue_counts.is_empty() {
                parts.push(format!("issues=[{}]", issue_counts.join(",")));
            }
        }
    }

    if let Some(ref error) = result.error {
        parts.push(format!("error={}", error));
    }

    parts.join(" ")
}
