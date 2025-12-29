# Sango

**Operator-grade edge diagnostics CLI**

Sango (珊瑚, "coral") is a read-only diagnostic tool that tells you whether a web edge is sane, observable, and survivable. Like coral monitoring the health of a reef, Sango watches over your edge infrastructure.

## Problem

Edge incidents are rarely caused by a single failure. They emerge from small mismatches:
- TLS that works but is brittle
- HTTP/3 advertised but never negotiated
- Security headers that contradict each other
- WAFs that silently misbehave

Operators usually discover these too late.

## Solution

Sango performs active but safe diagnostics against a given endpoint and evaluates it against well-known edge invariants. It answers *questions*, not just metrics.

## Features

- **TLS Analysis**: Chain validation, expiry warnings, OCSP status, cipher overlap, ALPN negotiation
- **HTTP Protocol**: HTTP/1.1, HTTP/2, HTTP/3 support detection and misconfiguration alerts
- **Security Headers**: HSTS, CSP, COOP/COEP analysis with contradiction detection
- **Latency Breakdown**: DNS, TCP, TLS, TTFB timing analysis
- **WAF Signals**: Reachability and behavior indicators

## Installation

```bash
cargo install sango
```

## Usage

```bash
# Basic diagnostics
sango https://example.com

# JSON output for automation
sango https://example.com --format json

# Skip specific checks
sango https://example.com --skip-tls --skip-headers

# Verbose output
sango https://example.com -v
```

## Example Output

```
sango - edge diagnostics
Target: https://example.com

TLS: OK (OCSP missing - medium risk)
HTTP/3: advertised, never negotiated - misconfiguration
Security: CSP present, HSTS missing
Origin: TLS handshake latency high - investigate cert chain
```

## Philosophy

- **Zero-risk diagnostics** against production
- **Vendor-agnostic** edge reasoning
- **Operator-focused judgments**, not data dumps
- **Perfect companion** to security-first proxies like Sentinel

## Part of the Raskell.io Family

Sango is part of the [raskell.io](https://raskell.io) ecosystem, alongside:
- [Sentinel](https://sentinel.raskell.io) - Security-first reverse proxy
- [Tanuki](https://tanuki.raskell.io) - Agent registry

## License

MIT OR Apache-2.0
