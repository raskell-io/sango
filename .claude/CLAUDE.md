# Sango - Operator-Grade Edge Diagnostics

## Purpose
Sango is a read-only diagnostic CLI that performs active but safe checks against web edge endpoints. It evaluates TLS, HTTP protocols, security headers, and latency to provide operator-focused judgments.

## Architecture

```
src/
├── main.rs          # CLI entry point (clap)
├── probe.rs         # Probe orchestration
├── output.rs        # Output formatting (pretty/json/compact)
└── checks/
    ├── mod.rs       # Check module exports
    ├── tls.rs       # TLS chain, expiry, OCSP, ciphers, ALPN
    ├── http.rs      # HTTP/1.1, H2, H3 detection
    ├── headers.rs   # Security headers (HSTS, CSP, COOP/COEP)
    └── latency.rs   # DNS, TCP, TLS, TTFB breakdown
```

## Design Principles

1. **Read-only**: No mutations, no agents, no config access
2. **Safe for production**: All probes are standard HTTP/TLS operations
3. **Opinionated output**: Judgments, not raw data dumps
4. **Operator-focused**: Answers questions like "is this edge healthy?"

## Key Dependencies

- `rustls` + `x509-parser`: TLS inspection
- `reqwest` + `hyper`: HTTP client
- `hickory-resolver`: DNS resolution
- `clap`: CLI framework
- `colored` + `tabled`: Pretty output

## Implementation Notes

- All checks are async and can run concurrently
- Each check module returns a structured result with issues list
- Severity levels: Low, Medium, High, Critical
- Output formats: pretty (default), json, compact

## Testing Strategy

- Unit tests for parsing and analysis logic
- Integration tests using wiremock for HTTP mocking
- No network tests in CI (use explicit integration test flag)
