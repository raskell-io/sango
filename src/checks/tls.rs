//! TLS diagnostic checks
//!
//! - Certificate chain validation
//! - Expiry warnings
//! - OCSP status
//! - Cipher suite analysis
//! - ALPN negotiation (H1/H2/H3)

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;
use x509_parser::prelude::*;

/// Result of TLS diagnostic checks
#[derive(Debug, Serialize)]
pub struct TlsResult {
    /// Whether the TLS connection succeeded
    pub valid: bool,
    /// Number of certificates in the chain
    pub chain_length: usize,
    /// Days until the leaf certificate expires (negative if expired)
    pub expires_in_days: i64,
    /// Subject of the leaf certificate
    pub subject: String,
    /// Issuer of the leaf certificate
    pub issuer: String,
    /// OCSP stapling status
    pub ocsp_status: OcspStatus,
    /// Negotiated cipher suite
    pub cipher_suite: String,
    /// Negotiated TLS version
    pub tls_version: String,
    /// Negotiated ALPN protocol (h2, http/1.1, etc.)
    pub alpn_negotiated: Option<String>,
    /// List of detected issues
    pub issues: Vec<TlsIssue>,
}

/// OCSP stapling status
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
pub enum OcspStatus {
    Good,
    Revoked,
    Unknown,
    NotChecked,
}

/// A detected TLS issue
#[derive(Debug, Serialize, Clone)]
pub struct TlsIssue {
    pub severity: Severity,
    pub message: String,
}

/// Issue severity level
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// Parsed certificate information
struct CertInfo {
    subject: String,
    issuer: String,
    expires_at: SystemTime,
    is_self_signed: bool,
}

/// Parse target string into host and port
fn parse_target(target: &str) -> Result<(String, u16)> {
    // Try parsing as URL first
    if let Ok(url) = Url::parse(target) {
        // Only use URL parsing if we got a valid host
        // (handles case where "host:port" parses with host as scheme)
        if let Some(host) = url.host_str() {
            let port = url.port().unwrap_or(match url.scheme() {
                "https" => 443,
                "http" => 80,
                _ => 443,
            });
            return Ok((host.to_string(), port));
        }
        // URL parsed but no host - fall through to host:port parsing
    }

    // Try parsing as host:port
    if let Some((host, port_str)) = target.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return Ok((host.to_string(), port));
        }
    }

    // Assume it's just a hostname, default to 443
    Ok((target.to_string(), 443))
}

/// Build rustls ClientConfig with ALPN protocols
fn build_client_config() -> Result<ClientConfig> {
    let mut root_store = RootCertStore::empty();

    // Add webpki roots (Mozilla CA bundle)
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Try to add native certs too (ignore errors for individual certs)
    let native_result = rustls_native_certs::load_native_certs();
    for cert in native_result.certs {
        let _ = root_store.add(cert);
    }

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Set ALPN protocols in preference order
    config.alpn_protocols = vec![
        b"h2".to_vec(),       // HTTP/2
        b"http/1.1".to_vec(), // HTTP/1.1
    ];

    Ok(config)
}

/// Parse certificate chain and extract info from leaf cert
fn parse_leaf_certificate(cert_der: &[u8]) -> Result<CertInfo> {
    let (_, cert) = parse_x509_certificate(cert_der)
        .map_err(|e| anyhow!("Failed to parse certificate: {:?}", e))?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();

    let validity = cert.validity();
    let expires_at =
        SystemTime::UNIX_EPOCH + Duration::from_secs(validity.not_after.timestamp() as u64);

    let is_self_signed = subject == issuer;

    Ok(CertInfo {
        subject,
        issuer,
        expires_at,
        is_self_signed,
    })
}

/// Calculate days until expiry (negative if already expired)
fn days_until_expiry(expires_at: SystemTime) -> i64 {
    let now = SystemTime::now();

    if let Ok(duration) = expires_at.duration_since(now) {
        (duration.as_secs() / 86400) as i64
    } else if let Ok(duration) = now.duration_since(expires_at) {
        -((duration.as_secs() / 86400) as i64)
    } else {
        0
    }
}

/// Format TLS version for display
fn format_tls_version(version: rustls::ProtocolVersion) -> String {
    match version {
        rustls::ProtocolVersion::TLSv1_0 => "TLS 1.0".to_string(),
        rustls::ProtocolVersion::TLSv1_1 => "TLS 1.1".to_string(),
        rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2".to_string(),
        rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3".to_string(),
        _ => format!("{:?}", version),
    }
}

/// Check if a cipher suite is considered weak
fn is_weak_cipher(cipher_name: &str) -> bool {
    let weak_patterns = [
        "CBC",    // CBC mode has padding oracle vulnerabilities
        "3DES",   // Triple DES is deprecated
        "RC4",    // RC4 is broken
        "NULL",   // No encryption
        "EXPORT", // Export-grade crypto
        "anon",   // Anonymous (no authentication)
        "MD5",    // MD5 is broken for signatures
    ];

    weak_patterns.iter().any(|p| cipher_name.contains(p))
}

/// Generate issues based on TLS analysis
fn generate_issues(
    cert_info: &CertInfo,
    days_until: i64,
    tls_version: &str,
    cipher_name: &str,
    alpn: Option<&str>,
) -> Vec<TlsIssue> {
    let mut issues = Vec::new();

    // Certificate expiry checks
    if days_until < 0 {
        issues.push(TlsIssue {
            severity: Severity::Critical,
            message: format!("Certificate expired {} days ago", -days_until),
        });
    } else if days_until < 7 {
        issues.push(TlsIssue {
            severity: Severity::Critical,
            message: format!("Certificate expires in {} days", days_until),
        });
    } else if days_until < 30 {
        issues.push(TlsIssue {
            severity: Severity::High,
            message: format!("Certificate expires in {} days", days_until),
        });
    } else if days_until < 90 {
        issues.push(TlsIssue {
            severity: Severity::Medium,
            message: format!("Certificate expires in {} days", days_until),
        });
    }

    // Self-signed certificate
    if cert_info.is_self_signed {
        issues.push(TlsIssue {
            severity: Severity::Medium,
            message: "Self-signed certificate".to_string(),
        });
    }

    // TLS version checks
    if tls_version == "TLS 1.0" || tls_version == "TLS 1.1" {
        issues.push(TlsIssue {
            severity: Severity::High,
            message: format!("Deprecated TLS version: {}", tls_version),
        });
    } else if tls_version == "TLS 1.2" {
        issues.push(TlsIssue {
            severity: Severity::Low,
            message: "Using TLS 1.2 (consider upgrading to TLS 1.3)".to_string(),
        });
    }

    // Cipher suite checks
    if is_weak_cipher(cipher_name) {
        issues.push(TlsIssue {
            severity: Severity::Medium,
            message: format!("Weak cipher suite: {}", cipher_name),
        });
    }

    // ALPN checks
    if alpn.is_none() {
        issues.push(TlsIssue {
            severity: Severity::Low,
            message: "No ALPN protocol negotiated".to_string(),
        });
    }

    // Sort by severity (highest first)
    issues.sort_by(|a, b| b.severity.cmp(&a.severity));

    issues
}

/// Perform TLS diagnostics against a target
pub async fn check_tls(target: &str, timeout: Duration) -> Result<TlsResult> {
    let (host, port) = parse_target(target).context("Failed to parse target")?;

    // Build TLS config
    let config = build_client_config().context("Failed to build TLS config")?;
    let connector = TlsConnector::from(Arc::new(config));

    // Resolve and connect with timeout
    let addr = format!("{}:{}", host, port);
    let stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow!("Connection timed out after {:?}", timeout))?
        .context(format!("Failed to connect to {}", addr))?;

    // Perform TLS handshake
    let domain = ServerName::try_from(host.as_str())
        .map_err(|_| anyhow!("Invalid server name: {}", host))?
        .to_owned();

    let tls_stream = tokio::time::timeout(timeout, connector.connect(domain, stream))
        .await
        .map_err(|_| anyhow!("TLS handshake timed out"))?
        .context("TLS handshake failed")?;

    // Extract connection info
    let (_, conn) = tls_stream.get_ref();

    // Get negotiated cipher suite
    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()))
        .unwrap_or_else(|| "Unknown".to_string());

    // Get TLS version
    let tls_version = conn
        .protocol_version()
        .map(format_tls_version)
        .unwrap_or_else(|| "Unknown".to_string());

    // Get ALPN protocol
    let alpn_negotiated = conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).to_string());

    // Parse certificates
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| anyhow!("No peer certificates"))?;

    let chain_length = certs.len();

    // Parse leaf certificate
    let leaf_cert = certs
        .first()
        .ok_or_else(|| anyhow!("Empty certificate chain"))?;
    let cert_info = parse_leaf_certificate(leaf_cert.as_ref())?;

    let expires_in_days = days_until_expiry(cert_info.expires_at);

    // Generate issues
    let issues = generate_issues(
        &cert_info,
        expires_in_days,
        &tls_version,
        &cipher_suite,
        alpn_negotiated.as_deref(),
    );

    Ok(TlsResult {
        valid: true,
        chain_length,
        expires_in_days,
        subject: cert_info.subject,
        issuer: cert_info.issuer,
        ocsp_status: OcspStatus::NotChecked,
        cipher_suite,
        tls_version,
        alpn_negotiated,
        issues,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_target_url() {
        let (host, port) = parse_target("https://example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_target_url_with_port() {
        let (host, port) = parse_target("https://example.com:8443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn test_parse_target_hostname() {
        let (host, port) = parse_target("example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_target_hostname_with_port() {
        let (host, port) = parse_target("example.com:8443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn test_is_weak_cipher() {
        assert!(is_weak_cipher("TLS_RSA_WITH_3DES_EDE_CBC_SHA"));
        assert!(is_weak_cipher("TLS_RSA_WITH_RC4_128_SHA"));
        assert!(!is_weak_cipher("TLS_AES_256_GCM_SHA384"));
        assert!(!is_weak_cipher("TLS_CHACHA20_POLY1305_SHA256"));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }
}
