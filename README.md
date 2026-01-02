<div align="center">

<h1 align="center">
  <img src=".github/static/sango-icon.png" alt="sango icon" width="96" />
  <br>
  Sango
</h1>

<p align="center">
  <em>Operator-grade edge diagnostics.</em><br>
  <em>Know your edge before it breaks.</em>
</p>

<p align="center">
  <a href="https://www.rust-lang.org/">
    <img alt="Rust" src="https://img.shields.io/badge/Rust-stable-000000?logo=rust&logoColor=white&style=for-the-badge">
  </a>
  <a href="https://github.com/raskell-io/sango">
    <img alt="CLI" src="https://img.shields.io/badge/CLI-diagnostic-f5a97f?style=for-the-badge">
  </a>
  <a href="LICENSE">
    <img alt="License" src="https://img.shields.io/badge/License-Apache--2.0-c6a0f6?style=for-the-badge">
  </a>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#features">Features</a> •
  <a href="#philosophy">Philosophy</a>
</p>

<hr />

</div>

Sango (珊瑚, "coral") is a read-only diagnostic CLI that tells you whether a web edge is sane, observable, and survivable. Like coral monitoring the health of a reef, Sango watches over your edge infrastructure.

It performs active but safe diagnostics against a target endpoint and evaluates it against well-known edge invariants. It answers *questions*, not just metrics.

---

## Why Sango exists

Edge incidents are rarely caused by a single failure. They emerge from small mismatches:
- TLS that works but is brittle
- HTTP/3 advertised but never negotiated
- Security headers that contradict each other
- Certificates expiring without warning

Operators usually discover these too late.

Sango helps you find these issues before they become incidents.

---

## Features

| Check | What it does |
|-------|--------------|
| **TLS** | Certificate chain, expiry warnings, cipher suite analysis, ALPN negotiation, TLS version |
| **HTTP** | HTTP/1.1, HTTP/2, HTTP/3 detection, redirect chain tracking, Alt-Svc parsing |
| **Security Headers** | HSTS, CSP (unsafe-inline/eval detection), COOP/COEP, X-Frame-Options, Referrer-Policy |
| **Latency** | DNS, TCP connect, TLS handshake, TTFB breakdown with threshold-based warnings |

---

## Installation

```bash
cargo install sango
```

Or build from source:

```bash
git clone https://github.com/raskell-io/sango.git
cd sango
cargo build --release
```

---

## Usage

```bash
# Full diagnostics with pretty output
sango https://example.com

# JSON output for automation
sango https://example.com -f json

# Compact single-line summary
sango https://example.com -f compact

# Skip specific checks
sango https://example.com --skip-tls --skip-headers

# Custom timeout
sango example.com:8443 -t 30
```

---

## Example Output

```
sango edge diagnostics
────────────────────────────────────────────────────────────

  Target: https://example.com
  Time: 2025-01-15 10:30:00 UTC

  Status: Degraded

  TLS

    Connection: OK
    Version: TLS 1.3
    Cipher: TLS13_AES_256_GCM_SHA384
    ALPN: h2

    Certificate
      Subject: CN=example.com
      Issuer: C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256
      Chain: 3 certificates
      Expires: 45 days

    Issues
      ~ [medium] Certificate expires in 45 days

  Security Headers

    HSTS: max-age=31536000, preload
    CSP: present
    X-Frame-Options: DENY
    X-Content-Type-Options: nosniff

  Latency

    DNS: 2ms
    TCP: 15ms
    TLS: 45ms
    TTFB: 120ms
    Total: 182ms

────────────────────────────────────────────────────────────
```

---

## Philosophy

- **Read-only**: No mutations, no agents, no config access
- **Safe for production**: All probes are standard HTTP/TLS operations
- **Opinionated output**: Judgments, not raw data dumps
- **Operator-focused**: Answers questions like "is this edge healthy?"

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Healthy or Degraded (non-critical issues) |
| 1 | Unhealthy (critical or high severity issues) |
| 2 | Unknown (probe failed to complete) |

---

## Part of the Raskell.io Family

Sango is part of the [raskell.io](https://raskell.io) ecosystem, alongside:
- [Sentinel](https://sentinel.raskell.io) - Security-first reverse proxy built on Pingora
- [Tanuki](https://tanuki.raskell.io) - Agent registry

---

## Support

If you find Sango useful, consider supporting its development:

<a href="https://ko-fi.com/raskell">
  <img src="https://img.shields.io/badge/Ko--fi-Support-ff5e5b?logo=ko-fi&logoColor=white&style=for-the-badge" alt="Ko-fi">
</a>

---

## License

Apache-2.0
