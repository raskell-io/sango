//! Latency breakdown diagnostic checks
//!
//! - DNS resolution time
//! - TCP connect time
//! - TLS handshake time
//! - Time to first byte (TTFB)
//! - Total request time

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

use super::tls::Severity;

/// Result of latency breakdown checks
#[derive(Debug, Serialize)]
pub struct LatencyResult {
    /// DNS resolution time
    #[serde(serialize_with = "serialize_duration")]
    pub dns_lookup: Duration,
    /// TCP connection time
    #[serde(serialize_with = "serialize_duration")]
    pub tcp_connect: Duration,
    /// TLS handshake time
    #[serde(serialize_with = "serialize_duration")]
    pub tls_handshake: Duration,
    /// Time to first byte (after sending request)
    #[serde(serialize_with = "serialize_duration")]
    pub time_to_first_byte: Duration,
    /// Total time for the request
    #[serde(serialize_with = "serialize_duration")]
    pub total: Duration,
    /// Detected issues
    pub issues: Vec<LatencyIssue>,
}

fn serialize_duration<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("{}ms", duration.as_millis()))
}

/// A latency-related issue
#[derive(Debug, Serialize, Clone)]
pub struct LatencyIssue {
    pub severity: Severity,
    pub phase: String,
    pub message: String,
}

/// Latency thresholds (in milliseconds)
struct Thresholds {
    dns_warn: u128,
    dns_high: u128,
    tcp_warn: u128,
    tcp_high: u128,
    tls_warn: u128,
    tls_high: u128,
    ttfb_warn: u128,
    ttfb_high: u128,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            dns_warn: 100,
            dns_high: 500,
            tcp_warn: 100,
            tcp_high: 500,
            tls_warn: 200,
            tls_high: 1000,
            ttfb_warn: 500,
            ttfb_high: 2000,
        }
    }
}

/// Check latency breakdown for a target
pub async fn check_latency(target: &str, timeout: Duration) -> Result<LatencyResult> {
    let (host, port, path) = parse_target(target)?;
    let total_start = Instant::now();

    // Phase 1: DNS resolution
    let dns_start = Instant::now();
    let addr = resolve_dns(&host, port, timeout).await?;
    let dns_lookup = dns_start.elapsed();

    // Phase 2: TCP connect
    let tcp_start = Instant::now();
    let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("TCP connect timed out"))?
        .context("TCP connect failed")?;
    let tcp_connect = tcp_start.elapsed();

    // Phase 3: TLS handshake
    let tls_start = Instant::now();
    let tls_stream = perform_tls_handshake(stream, &host, timeout).await?;
    let tls_handshake = tls_start.elapsed();

    // Phase 4: Send HTTP request and wait for first byte
    let ttfb_start = Instant::now();
    let _response = send_http_request(tls_stream, &host, &path, timeout).await?;
    let time_to_first_byte = ttfb_start.elapsed();

    let total = total_start.elapsed();

    // Generate issues based on thresholds
    let issues = generate_issues(&dns_lookup, &tcp_connect, &tls_handshake, &time_to_first_byte);

    Ok(LatencyResult {
        dns_lookup,
        tcp_connect,
        tls_handshake,
        time_to_first_byte,
        total,
        issues,
    })
}

/// Parse target into host, port, and path
fn parse_target(target: &str) -> Result<(String, u16, String)> {
    // Try parsing as URL
    if let Ok(url) = Url::parse(target) {
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("URL has no host"))?
            .to_string();
        let port = url.port().unwrap_or(443);
        let path = if url.path().is_empty() {
            "/".to_string()
        } else {
            url.path().to_string()
        };
        return Ok((host, port, path));
    }

    // Try parsing as host:port
    if let Some((host, port_str)) = target.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return Ok((host.to_string(), port, "/".to_string()));
        }
    }

    // Just a hostname
    Ok((target.to_string(), 443, "/".to_string()))
}

/// Resolve DNS
async fn resolve_dns(host: &str, port: u16, timeout: Duration) -> Result<SocketAddr> {
    use tokio::net::lookup_host;

    let addr_str = format!("{}:{}", host, port);
    let mut addrs = tokio::time::timeout(timeout, lookup_host(&addr_str))
        .await
        .map_err(|_| anyhow!("DNS lookup timed out"))?
        .context(format!("DNS lookup failed for {}", host))?;

    addrs
        .next()
        .ok_or_else(|| anyhow!("No addresses found for {}", host))
}

/// Build TLS client config
fn build_client_config() -> Result<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let native_result = rustls_native_certs::load_native_certs();
    for cert in native_result.certs {
        let _ = root_store.add(cert);
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(config)
}

/// Perform TLS handshake
async fn perform_tls_handshake(
    stream: TcpStream,
    host: &str,
    timeout: Duration,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let config = build_client_config()?;
    let connector = TlsConnector::from(Arc::new(config));

    let domain = ServerName::try_from(host)
        .map_err(|_| anyhow!("Invalid server name: {}", host))?
        .to_owned();

    let tls_stream = tokio::time::timeout(timeout, connector.connect(domain, stream))
        .await
        .map_err(|_| anyhow!("TLS handshake timed out"))?
        .context("TLS handshake failed")?;

    Ok(tls_stream)
}

/// Send HTTP request and receive first byte of response
async fn send_http_request(
    mut stream: tokio_rustls::client::TlsStream<TcpStream>,
    host: &str,
    path: &str,
    timeout: Duration,
) -> Result<Vec<u8>> {
    // Send minimal HTTP/1.1 GET request
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host
    );

    tokio::time::timeout(timeout, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| anyhow!("Request write timed out"))?
        .context("Failed to write request")?;

    // Read first chunk of response
    let mut buffer = vec![0u8; 1024];
    let n = tokio::time::timeout(timeout, stream.read(&mut buffer))
        .await
        .map_err(|_| anyhow!("Response read timed out"))?
        .context("Failed to read response")?;

    buffer.truncate(n);
    Ok(buffer)
}

/// Generate issues based on latency measurements
fn generate_issues(
    dns: &Duration,
    tcp: &Duration,
    tls: &Duration,
    ttfb: &Duration,
) -> Vec<LatencyIssue> {
    let mut issues = Vec::new();
    let thresholds = Thresholds::default();

    let dns_ms = dns.as_millis();
    let tcp_ms = tcp.as_millis();
    let tls_ms = tls.as_millis();
    let ttfb_ms = ttfb.as_millis();

    // DNS issues
    if dns_ms >= thresholds.dns_high {
        issues.push(LatencyIssue {
            severity: Severity::High,
            phase: "DNS".to_string(),
            message: format!("DNS resolution took {}ms (high)", dns_ms),
        });
    } else if dns_ms >= thresholds.dns_warn {
        issues.push(LatencyIssue {
            severity: Severity::Medium,
            phase: "DNS".to_string(),
            message: format!("DNS resolution took {}ms", dns_ms),
        });
    }

    // TCP issues
    if tcp_ms >= thresholds.tcp_high {
        issues.push(LatencyIssue {
            severity: Severity::High,
            phase: "TCP".to_string(),
            message: format!("TCP connect took {}ms (high)", tcp_ms),
        });
    } else if tcp_ms >= thresholds.tcp_warn {
        issues.push(LatencyIssue {
            severity: Severity::Medium,
            phase: "TCP".to_string(),
            message: format!("TCP connect took {}ms", tcp_ms),
        });
    }

    // TLS issues
    if tls_ms >= thresholds.tls_high {
        issues.push(LatencyIssue {
            severity: Severity::High,
            phase: "TLS".to_string(),
            message: format!("TLS handshake took {}ms (high) - check cert chain", tls_ms),
        });
    } else if tls_ms >= thresholds.tls_warn {
        issues.push(LatencyIssue {
            severity: Severity::Medium,
            phase: "TLS".to_string(),
            message: format!("TLS handshake took {}ms", tls_ms),
        });
    }

    // TTFB issues
    if ttfb_ms >= thresholds.ttfb_high {
        issues.push(LatencyIssue {
            severity: Severity::High,
            phase: "TTFB".to_string(),
            message: format!("Time to first byte took {}ms (high) - backend slow", ttfb_ms),
        });
    } else if ttfb_ms >= thresholds.ttfb_warn {
        issues.push(LatencyIssue {
            severity: Severity::Medium,
            phase: "TTFB".to_string(),
            message: format!("Time to first byte took {}ms", ttfb_ms),
        });
    }

    // Sort by severity
    issues.sort_by(|a, b| b.severity.cmp(&a.severity));

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_target_url() {
        let (host, port, path) = parse_target("https://example.com/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_parse_target_hostname() {
        let (host, port, path) = parse_target("example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/");
    }
}
